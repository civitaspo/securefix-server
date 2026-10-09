use anyhow::{Context, Result, bail, ensure};
use reqwest::{Method, StatusCode, blocking::Client, redirect::Policy};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::{fmt, io::Read, time::Duration};

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub method: Method,
    pub path: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GitHub {} {} returned {}",
            self.method, self.path, self.status
        )
    }
}

impl std::error::Error for ApiError {}

#[derive(Clone)]
pub struct GitHub {
    client: Client,
    token: String,
    base: String,
    guard_writes: bool,
    source_sha: Option<String>,
}

impl GitHub {
    pub fn from_env(name: &str) -> Result<Self> {
        let token = std::env::var(name).with_context(|| format!("missing {name}"))?;
        ensure!(!token.is_empty(), "{name} is empty");
        let mut api = Self::new("https://api.github.com", token)?;
        api.guard_writes = true;
        api.source_sha = std::env::var("SECUREFIX_SOURCE_SHA").ok();
        Ok(api)
    }

    pub fn anonymous() -> Result<Self> {
        Self::new("https://api.github.com", String::new())
    }

    pub fn new(base: &str, token: String) -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .redirect(Policy::none())
                .build()?,
            base: base.trim_end_matches('/').to_string(),
            token,
            guard_writes: false,
            source_sha: None,
        })
    }

    pub fn with_runtime_revision(mut self, revision: &str) -> Result<Self> {
        crate::policy::validate_sha(revision)?;
        self.source_sha = Some(revision.to_owned());
        self.guard_writes = true;
        Ok(self)
    }

    fn url(&self, path: &str) -> Result<String> {
        ensure!(
            path.starts_with('/') && !path.starts_with("//") && !path.contains(['\r', '\n', '#']),
            "invalid API path"
        );
        Ok(format!("{}{path}", self.base))
    }

    fn builder(&self, method: Method, path: &str) -> Result<reqwest::blocking::RequestBuilder> {
        let mut request = self
            .client
            .request(method, self.url(path)?)
            .header("User-Agent", "civitaspo-securefix")
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if !self.token.is_empty() {
            request = request.bearer_auth(&self.token);
        }
        Ok(request)
    }

    pub fn request(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let read_only_graphql = path == "/graphql"
            && method == Method::POST
            && body
                .and_then(|body| body["query"].as_str())
                .is_some_and(read_only_query);
        if path == "/graphql" {
            ensure!(read_only_graphql, "unsupported GraphQL operation");
        }
        if method != Method::GET && method != Method::HEAD && !read_only_graphql {
            self.require_current_revision()?;
        }
        let mut request = self.builder(method.clone(), path)?;
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .with_context(|| format!("GitHub {method} {path}"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(ApiError {
                status,
                method,
                path: path.to_string(),
            }
            .into());
        }
        let bytes = bounded_read(response, 16 * 1024 * 1024)?;
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes).context("invalid GitHub JSON")
    }

    fn require_current_revision(&self) -> Result<()> {
        ensure!(self.guard_writes, "read-only API connection cannot write");
        let expected = self
            .source_sha
            .as_deref()
            .context("missing trusted runtime revision before write")?;
        crate::policy::validate_sha(expected)?;
        let commit: Value = self.get("/repos/civitaspo/securefix-server/commits/main")?;
        ensure!(
            commit["sha"] == expected,
            "runtime is no longer current; write denied"
        );
        Ok(())
    }

    pub fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        Ok(serde_json::from_value(self.request(
            Method::GET,
            path,
            None,
        )?)?)
    }
    pub fn post<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        Ok(serde_json::from_value(self.request(
            Method::POST,
            path,
            Some(body),
        )?)?)
    }
    pub fn patch<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        Ok(serde_json::from_value(self.request(
            Method::PATCH,
            path,
            Some(body),
        )?)?)
    }
    pub fn put<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        Ok(serde_json::from_value(self.request(
            Method::PUT,
            path,
            Some(body),
        )?)?)
    }
    pub fn delete(&self, path: &str) -> Result<()> {
        self.request(Method::DELETE, path, None)?;
        Ok(())
    }
    pub fn graphql(&self, query: &str, variables: Value) -> Result<Value> {
        ensure!(read_only_query(query), "only GraphQL queries are supported");
        let response: Value = self.post(
            "/graphql",
            &serde_json::json!({"query":query,"variables":variables}),
        )?;
        if response.get("errors").is_some() {
            bail!("GitHub GraphQL query failed");
        }
        response
            .get("data")
            .cloned()
            .context("missing GraphQL data")
    }

    pub fn paginate(&self, path: &str) -> Result<Vec<Value>> {
        let delimiter = if path.contains('?') { '&' } else { '?' };
        let mut result = Vec::new();
        for page in 1..=100 {
            let values: Vec<Value> =
                self.get(&format!("{path}{delimiter}per_page=100&page={page}"))?;
            let last = values.len() < 100;
            result.extend(values);
            if last {
                return Ok(result);
            }
        }
        bail!("GitHub pagination exceeded limit")
    }
    pub fn download(&self, path: &str, max: usize) -> Result<Vec<u8>> {
        let response = self.builder(Method::GET, path)?.send()?;
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .context("missing download redirect")?
                .to_str()?;
            let url = reqwest::Url::parse(location)?;
            ensure!(
                url.scheme() == "https" && url.username().is_empty() && url.password().is_none(),
                "unsafe download redirect"
            );
            let host = url.host_str().context("missing download host")?;
            ensure!(
                host.ends_with(".blob.core.windows.net")
                    || host.ends_with(".actions.githubusercontent.com")
                    || host == "objects.githubusercontent.com"
                    || host == "release-assets.githubusercontent.com",
                "unexpected artifact host"
            );
            let download = self
                .client
                .get(url)
                .send()
                .map_err(|_| anyhow::anyhow!("artifact download failed"))?;
            ensure!(
                download.status().is_success(),
                "artifact download returned {}",
                download.status()
            );
            return bounded_read(download, max);
        }
        if !response.status().is_success() {
            return Err(ApiError {
                status: response.status(),
                method: Method::GET,
                path: path.to_string(),
            }
            .into());
        }
        bounded_read(response, max)
    }
    pub fn upload(&self, path: &str, bytes: Vec<u8>, content_type: &str) -> Result<Value> {
        self.require_current_revision()?;
        let url = reqwest::Url::parse(path)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str() == Some("uploads.github.com")
                && url.username().is_empty()
                && url.password().is_none(),
            "invalid upload endpoint"
        );
        let response = self
            .client
            .post(url)
            .bearer_auth(&self.token)
            .header("User-Agent", "civitaspo-securefix")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("Content-Type", content_type)
            .body(bytes)
            .send()?;
        let status = response.status();
        ensure!(status.is_success(), "GitHub upload returned {status}");
        Ok(response.json()?)
    }
    pub fn content(&self, repository: &str, path: &str, revision: &str) -> Result<Vec<u8>> {
        use base64::Engine;
        let value: Value = self.get(&format!(
            "/repos/{repository}/contents/{path}?ref={revision}"
        ))?;
        ensure!(value["encoding"] == "base64", "unexpected content encoding");
        let content = value["content"]
            .as_str()
            .context("missing file content")?
            .replace('\n', "");
        Ok(base64::engine::general_purpose::STANDARD.decode(content)?)
    }
}

fn read_only_query(query: &str) -> bool {
    let query = query.trim_start();
    query
        .strip_prefix("query")
        .is_some_and(|rest| rest.starts_with([' ', '\n', '\r', '\t', '(', '{']))
        && !query.contains("mutation")
}

fn bounded_read(reader: impl Read, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(max as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max, "download exceeded size limit");
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_downloads_and_rejects_external_paths() {
        assert!(bounded_read(&b"12345"[..], 4).is_err());
        let api = GitHub::new("https://api.github.com", String::new()).unwrap();
        for path in [
            "//evil.example/x",
            "https://evil.example",
            "/x\nInjected: x",
        ] {
            assert!(api.url(path).is_err());
        }
    }
    #[test]
    fn graphql_only_accepts_explicit_read_operations() {
        assert!(read_only_query(
            "query($number:Int!){repository{pullRequest(number:$number){reviewDecision}}}"
        ));
        for query in [
            "mutation { mergePullRequest }",
            "{ viewer { login } }",
            "query {viewer{login}} mutation {mergePullRequest}",
        ] {
            assert!(!read_only_query(query));
        }
    }
    #[test]
    fn get_retries_one_connection_drop_and_returns_the_second_response() {
        use crate::fixtures::{Fixture, Route};
        let fixture = Fixture::new(vec![
            Route::disconnect("GET", "/repos/civitaspo/example"),
            Route::get("/repos/civitaspo/example", serde_json::json!({"ok":true})),
        ]);

        let result: Value = fixture.api.get("/repos/civitaspo/example").unwrap();

        assert_eq!(result, serde_json::json!({"ok":true}));
        fixture.finish();
    }
    #[test]
    fn get_retries_a_repeated_connection_drop_only_once() {
        use crate::fixtures::{Fixture, Route};
        let fixture = Fixture::new(vec![
            Route::disconnect("GET", "/repos/civitaspo/example"),
            Route::disconnect("GET", "/repos/civitaspo/example"),
        ]);

        assert!(
            fixture
                .api
                .get::<Value>("/repos/civitaspo/example")
                .is_err()
        );
        fixture.finish();
    }
    #[test]
    fn mutation_connection_drop_is_never_retried() {
        use crate::fixtures::{Fixture, Route};
        let path = "/repos/civitaspo/example/issues/7/comments";
        for (method, method_name) in [
            (Method::POST, "POST"),
            (Method::PATCH, "PATCH"),
            (Method::PUT, "PUT"),
            (Method::DELETE, "DELETE"),
        ] {
            let fixture = Fixture::new(vec![
                Route::get(
                    "/repos/civitaspo/securefix-server/commits/main",
                    serde_json::json!({"sha":"a".repeat(40)}),
                ),
                Route::disconnect(method_name, path),
            ]);

            let empty_body = serde_json::json!({});
            let body = (method != Method::DELETE).then_some(&empty_body);
            assert!(fixture.api.request(method, path, body).is_err());
            fixture.finish();
        }
    }
    #[test]
    fn invalid_json_response_is_not_retried() {
        use crate::fixtures::{Fixture, Route};
        let fixture = Fixture::new(vec![Route::raw(
            "GET",
            "/repos/civitaspo/example",
            200,
            b"{".to_vec(),
        )]);

        assert!(
            fixture
                .api
                .get::<Value>("/repos/civitaspo/example")
                .is_err()
        );
        fixture.finish();
    }
    #[test]
    fn every_write_rejects_a_stale_runtime_before_sending_the_mutation() {
        use crate::fixtures::{Fixture, Route};
        for method in [Method::POST, Method::PATCH, Method::PUT, Method::DELETE] {
            let fixture = Fixture::new(vec![Route::get(
                "/repos/civitaspo/securefix-server/commits/main",
                serde_json::json!({"sha":"b".repeat(40)}),
            )]);
            assert!(
                fixture
                    .api
                    .request(
                        method,
                        "/repos/civitaspo/example/labels",
                        Some(&serde_json::json!({"name":"request"}))
                    )
                    .is_err()
            );
            fixture.finish();
        }
    }
    #[test]
    fn a_current_runtime_can_write_and_read_only_connections_cannot() {
        use crate::fixtures::{Fixture, Route};
        let fixture = Fixture::new(vec![
            Route::get(
                "/repos/civitaspo/securefix-server/commits/main",
                serde_json::json!({"sha":"a".repeat(40)}),
            ),
            Route::request(
                "POST",
                "/repos/civitaspo/example/labels",
                201,
                serde_json::json!({"id":1}),
            )
            .with_request_body(serde_json::json!({"name":"request"})),
        ]);
        let result: Value = fixture
            .api
            .post(
                "/repos/civitaspo/example/labels",
                &serde_json::json!({"name":"request"}),
            )
            .unwrap();
        assert_eq!(result["id"], 1);
        fixture.finish();
        let read = GitHub::new("https://api.github.com", String::new()).unwrap();
        assert!(
            read.post::<Value>("/repos/civitaspo/example/labels", &serde_json::json!({}))
                .is_err()
        );
    }
}
