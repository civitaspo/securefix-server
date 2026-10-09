use anyhow::{Context, Result, bail, ensure};
use reqwest::{Method, StatusCode, blocking::Client, redirect::Policy};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::{collections::BTreeMap, fmt, io::Read, time::Duration};

pub const SCRATCH_REPOSITORY: &str = "civitaspo/testing-securefix-server";
pub const SCRATCH_REPOSITORY_ID: u64 = 1_410_312_556;

#[derive(Clone)]
enum WriteContext {
    ReadOnly,
    Production(Option<String>),
    Scratch { candidate_sha: String },
}

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
    writes: WriteContext,
}

impl GitHub {
    pub fn from_env(name: &str) -> Result<Self> {
        let token = std::env::var(name).with_context(|| format!("missing {name}"))?;
        ensure!(!token.is_empty(), "{name} is empty");
        let mut api = Self::new("https://api.github.com", token)?;
        api.writes = WriteContext::Production(std::env::var("SECUREFIX_SOURCE_SHA").ok());
        Ok(api)
    }

    pub fn anonymous() -> Result<Self> {
        Self::new("https://api.github.com", String::new())
    }

    pub fn new(base: &str, token: String) -> Result<Self> {
        let base = base.trim_end_matches('/').to_string();
        let retry_host = reqwest::Url::parse(&base)?
            .host_str()
            .context("GitHub API base URL has no host")?
            .to_owned();
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .redirect(Policy::none())
                .retry(
                    reqwest::retry::for_host(retry_host)
                        .max_retries_per_request(1)
                        .classify_fn(|request| {
                            let read_only =
                                matches!(request.method(), &Method::GET | &Method::HEAD);
                            let transport_error = request
                                .error()
                                .and_then(|error| error.downcast_ref::<reqwest::Error>())
                                .is_some_and(|error| error.is_request() || error.is_connect());
                            if read_only && transport_error {
                                request.retryable()
                            } else {
                                request.success()
                            }
                        }),
                )
                .build()?,
            base,
            token,
            writes: WriteContext::ReadOnly,
        })
    }

    pub fn with_runtime_revision(mut self, revision: &str) -> Result<Self> {
        crate::policy::validate_sha(revision)?;
        self.writes = WriteContext::Production(Some(revision.to_owned()));
        Ok(self)
    }

    pub fn scratch_from_env(name: &str, candidate_sha: &str) -> Result<Self> {
        crate::policy::validate_sha(candidate_sha)?;
        let token = std::env::var(name).with_context(|| format!("missing {name}"))?;
        ensure!(!token.is_empty(), "{name} is empty");
        let mut api = Self::new("https://api.github.com", token)?;
        let installation: Value = api.get("/installation/repositories?per_page=100")?;
        let repositories = installation["repositories"]
            .as_array()
            .context("not an installation token")?;
        ensure!(
            installation["total_count"] == 1
                && repositories.len() == 1
                && repositories[0]["full_name"] == SCRATCH_REPOSITORY
                && repositories[0]["id"].as_u64() == Some(SCRATCH_REPOSITORY_ID),
            "integration token must be installed only on the scratch repository"
        );
        api.writes = WriteContext::Scratch {
            candidate_sha: candidate_sha.to_owned(),
        };
        Ok(api)
    }

    fn require_write_target(&self, path: &str) -> Result<()> {
        if let WriteContext::Scratch { candidate_sha } = &self.writes {
            crate::policy::validate_sha(candidate_sha)?;
            let prefix = format!("/repos/{SCRATCH_REPOSITORY}/");
            ensure!(
                path.starts_with(&prefix)
                    && !path.contains(['%', '\\', '?'])
                    && !path.split('/').any(|part| part == "." || part == ".."),
                "integration write target is outside the scratch repository"
            );
        }
        Ok(())
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
            self.require_write_target(path)?;
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
        let expected = match &self.writes {
            WriteContext::ReadOnly => bail!("read-only API connection cannot write"),
            WriteContext::Scratch { .. } => return Ok(()),
            WriteContext::Production(revision) => revision
                .as_deref()
                .context("missing trusted runtime revision before write")?,
        };
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

    pub fn create_commit(
        &self,
        repository: &str,
        branch: &str,
        expected_head: &str,
        message: &str,
        additions: BTreeMap<String, Vec<u8>>,
        deletions: Vec<String>,
    ) -> Result<String> {
        use base64::Engine;
        crate::policy::validate_repository(repository)?;
        crate::policy::validate_sha(expected_head)?;
        ensure!(
            !branch.is_empty()
                && branch.len() <= 255
                && !branch.starts_with('/')
                && !branch.ends_with('/')
                && !branch.contains("..")
                && !branch.contains("//")
                && !branch.ends_with(".lock")
                && branch
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)),
            "invalid commit branch"
        );
        ensure!(
            !message.trim().is_empty() && message.len() <= 65536 && !message.contains('\0'),
            "invalid commit message"
        );
        ensure!(
            !additions.is_empty() || !deletions.is_empty(),
            "commit has no file changes"
        );
        ensure!(
            additions.len() + deletions.len() <= 1000,
            "too many commit files"
        );
        for path in additions.keys().chain(deletions.iter()) {
            ensure!(
                !path.is_empty()
                    && path.len() <= 4096
                    && !path.starts_with('/')
                    && !path.contains(['\\', '\0', '\r', '\n'])
                    && path.split('/').all(|part| !part.is_empty()
                        && part != "."
                        && part != ".."
                        && !part.eq_ignore_ascii_case(".git")),
                "invalid commit file path"
            );
        }
        ensure!(
            additions.values().map(Vec::len).sum::<usize>() <= 16 * 1024 * 1024,
            "commit contents exceed size limit"
        );
        ensure!(
            deletions
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                == deletions.len()
                && deletions.iter().all(|path| !additions.contains_key(path)),
            "duplicate commit file change"
        );
        self.require_write_target(&format!("/repos/{repository}/git/commits"))?;
        self.require_current_revision()?;
        let (headline, body) = message.split_once('\n').unwrap_or((message, ""));
        let input = serde_json::json!({
            "branch":{"repositoryNameWithOwner":repository,"branchName":branch},
            "expectedHeadOid":expected_head,
            "message":{"headline":headline,"body":body},
            "fileChanges":{
                "additions":additions.into_iter().map(|(path,bytes)| serde_json::json!({"path":path,"contents":base64::engine::general_purpose::STANDARD.encode(bytes)})).collect::<Vec<_>>(),
                "deletions":deletions.into_iter().map(|path| serde_json::json!({"path":path})).collect::<Vec<_>>()
            }
        });
        let response = self.builder(Method::POST, "/graphql")?.json(&serde_json::json!({
            "query":"mutation($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid parents(first:2){nodes{oid}} signature{isValid state}}}}",
            "variables":{"input":input}
        })).send().context("GitHub signed commit mutation failed")?;
        ensure!(
            response.status().is_success(),
            "GitHub signed commit returned {}",
            response.status()
        );
        let value: Value = serde_json::from_slice(&bounded_read(response, 1024 * 1024)?)?;
        ensure!(
            value.get("errors").is_none(),
            "GitHub signed commit mutation was rejected"
        );
        let commit = &value["data"]["createCommitOnBranch"]["commit"];
        let sha = commit["oid"]
            .as_str()
            .context("signed commit response has no SHA")?;
        crate::policy::validate_sha(sha)?;
        ensure!(
            commit["signature"]["isValid"] == true && commit["signature"]["state"] == "VALID",
            "created commit does not have a verified signature"
        );
        let parents = commit["parents"]["nodes"]
            .as_array()
            .context("commit parents missing")?;
        ensure!(
            parents.len() == 1 && parents[0]["oid"] == expected_head,
            "created commit has unexpected parent"
        );
        Ok(sha.to_owned())
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
        ensure!(
            !matches!(self.writes, WriteContext::Scratch { .. }),
            "integration cannot upload release assets"
        );
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
    fn scratch_writes_cannot_escape_the_fixed_repository() {
        let mut api = GitHub::new("https://api.github.com", String::new()).unwrap();
        api.writes = WriteContext::Scratch {
            candidate_sha: "a".repeat(40),
        };
        assert!(
            api.require_write_target(&format!("/repos/{SCRATCH_REPOSITORY}/issues/1/comments"))
                .is_ok()
        );
        for path in [
            "/repos/civitaspo/securefix-server/issues/1/comments",
            "/repos/civitaspo/testing-securefix-server-evil/git/refs",
            "/repos/civitaspo/testing-securefix-server/../securefix-server/git/refs",
            "/repos/civitaspo/testing-securefix-server/%2e%2e/git/refs",
            "/graphql",
            "/user/repos",
        ] {
            assert!(
                api.post::<Value>(path, &serde_json::json!({})).is_err(),
                "{path}"
            );
        }
        assert!(
            api.create_commit(
                "civitaspo/securefix-server",
                "main",
                &"a".repeat(40),
                "blocked",
                BTreeMap::from([("fixture.txt".into(), b"test".to_vec())]),
                vec![]
            )
            .is_err()
        );
    }

    #[test]
    fn signed_commit_rejects_unsafe_changes_before_network_access() {
        let api = GitHub::new("https://api.github.com", String::new()).unwrap();
        for path in [
            "../outside",
            "/absolute",
            ".git/config",
            "a//b",
            "a\\b",
            "a\nheader",
        ] {
            let result = api.create_commit(
                SCRATCH_REPOSITORY,
                "fixture",
                &"a".repeat(40),
                "test",
                BTreeMap::from([(path.into(), vec![1])]),
                vec![],
            );
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("invalid commit file path")
            );
        }
    }

    #[test]
    fn commit_response_must_prove_the_signature_and_expected_parent() {
        use crate::fixtures::{Fixture, Route};
        for (signed, parent, expected_ok) in
            [(true, 'a', true), (false, 'a', false), (true, 'c', false)]
        {
            let fixture = Fixture::new(vec![
                Route::get(
                    "/repos/civitaspo/securefix-server/commits/main",
                    serde_json::json!({"sha":"a".repeat(40)}),
                ),
                Route::request(
                    "POST",
                    "/graphql",
                    200,
                    serde_json::json!({"data":{"createCommitOnBranch":{"commit":{
                        "oid":"b".repeat(40), "parents":{"nodes":[{"oid":parent.to_string().repeat(40)}]},
                        "signature":{"isValid":signed,"state":"VALID"}
                    }}}}),
                ),
            ]);
            let result = fixture.api.create_commit(
                SCRATCH_REPOSITORY,
                "fixture",
                &"a".repeat(40),
                "test",
                BTreeMap::from([("file.txt".into(), b"test".to_vec())]),
                vec![],
            );
            assert_eq!(result.is_ok(), expected_ok);
            if expected_ok {
                assert_eq!(result.unwrap(), "b".repeat(40));
            }
            fixture.finish();
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
