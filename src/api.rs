use anyhow::{Context, Result, bail, ensure};
use reqwest::{
    Method, StatusCode,
    blocking::Client,
    header::{ACCEPT, HeaderMap, HeaderValue},
    redirect::Policy,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::Digest;
use std::{collections::BTreeMap, fmt, io::Read, time::Duration};

#[cfg(test)]
const SCRATCH_REPOSITORY: &str = "civitaspo/testing-securefix-server";
const NATIVE_PROOF_CHECK: &str = "securefix-native-request-policy-check";
const NATIVE_PROOF_TITLE: &str = "Native request slice accepted";
const NATIVE_PROOF_SUMMARY: &str = "Configured merge capability, owner producer and PR author identities, and the exact current PR head and base were verified. Signature and owner-review policy were not evaluated.";

pub const POLICY_FAILURE_COMMENT_MARKER: &str = "<!-- securefix:v1:policy-check -->";

pub struct NativeScratchTarget<'a> {
    pub repository: &'a str,
    pub repository_id: u64,
    pub pull_number: u64,
    pub head_sha: &'a str,
    pub head_repository_id: u64,
    pub base_ref: &'a str,
    pub author_id: u64,
    pub author_login: &'a str,
    pub actor_id: u64,
    pub actor_login: &'a str,
    pub request_sha256: &'a str,
}

#[derive(Clone)]
enum WriteContext {
    ReadOnly,
    ClientLabel {
        server: String,
    },
    Production {
        revision: Option<String>,
        control_id: Option<String>,
    },
    Scratch {
        candidate_sha: String,
    },
    NativeScratch(Box<NativeScratchWrite>),
}

#[derive(Clone)]
struct NativeScratchWrite {
    instance_repository: String,
    instance_id: u64,
    instance_owner_id: u64,
    default_branch: String,
    config_path: String,
    config_bytes: Vec<u8>,
    policy_workflow_path: String,
    policy_workflow_sha256: String,
    target_repository: String,
    target_id: u64,
    pull_number: u64,
    head_sha: String,
    head_repository_id: u64,
    base_ref: String,
    author_id: u64,
    author_login: String,
    actor_id: u64,
    actor_login: String,
    request_sha256: String,
    policy_app_id: u64,
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
    pub fn client_from_env(name: &str) -> Result<Self> {
        let token = std::env::var(name).with_context(|| format!("missing {name}"))?;
        ensure!(!token.is_empty(), "{name} is empty");
        let mut api = Self::new("https://api.github.com", token)?;
        api.writes = WriteContext::ClientLabel {
            server: crate::config::trusted()?
                .deployment
                .server
                .repository
                .clone(),
        };
        Ok(api)
    }
    pub fn from_env(name: &str) -> Result<Self> {
        let token = std::env::var(name).with_context(|| format!("missing {name}"))?;
        ensure!(!token.is_empty(), "{name} is empty");
        let mut api = Self::new("https://api.github.com", token)?;
        api.writes = WriteContext::Production {
            revision: std::env::var("SECUREFIX_SOURCE_SHA").ok(),
            control_id: std::env::var("SECUREFIX_CONTROL_ID").ok(),
        };
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
                            let safe_method =
                                matches!(request.method(), &Method::GET | &Method::HEAD);
                            let transient_failure = request
                                .error()
                                .and_then(|error| error.downcast_ref::<reqwest::Error>())
                                .is_some_and(|error| error.is_request() || error.is_connect())
                                || request
                                    .status()
                                    .is_some_and(|status| status.is_server_error());
                            if safe_method && transient_failure {
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
        self.writes = WriteContext::Production {
            revision: Some(revision.to_owned()),
            control_id: std::env::var("SECUREFIX_CONTROL_ID").ok(),
        };
        Ok(self)
    }

    pub fn with_control_revision(
        mut self,
        control: &crate::control::ControlRevision,
    ) -> Result<Self> {
        self.writes = WriteContext::Production {
            revision: Some(control.source_sha.clone()),
            control_id: Some(control.identity()?),
        };
        Ok(self)
    }

    pub fn scratch_from_env(name: &str, candidate_sha: &str) -> Result<Self> {
        crate::policy::validate_sha(candidate_sha)?;
        let token = std::env::var(name).with_context(|| format!("missing {name}"))?;
        ensure!(!token.is_empty(), "{name} is empty");
        let mut api = Self::new("https://api.github.com", token)?;
        let scratch = &crate::config::trusted()?.deployment.integration;
        let installation: Value = api.get("/installation/repositories?per_page=100")?;
        let repositories = installation["repositories"]
            .as_array()
            .context("not an installation token")?;
        ensure!(
            installation["total_count"] == 1
                && repositories.len() == 1
                && repositories[0]["full_name"] == scratch.repository
                && repositories[0]["id"].as_u64() == Some(scratch.id),
            "integration token must be installed only on the scratch repository"
        );
        api.writes = WriteContext::Scratch {
            candidate_sha: candidate_sha.to_owned(),
        };
        Ok(api)
    }

    /// Create the deliberately narrow writer for the first native request
    /// scratch slice. Every check-run write reauthenticates the installation,
    /// protected configuration snapshot, and exact PR head.
    pub fn native_scratch_from_env(
        name: &str,
        config: &crate::instance_config::InstanceConfig,
        config_path: &str,
        config_bytes: &[u8],
        request: &NativeScratchTarget<'_>,
    ) -> Result<Self> {
        validate_instance_config_path(config_path)?;
        crate::policy::validate_repository(request.repository)?;
        crate::policy::validate_sha(request.head_sha)?;
        crate::config::validate_branch(request.base_ref)?;
        ensure!(
            request.repository_id > 0
                && request.pull_number > 0
                && request.head_repository_id > 0
                && request.author_id > 0
                && crate::config::is_valid_login(request.author_login)
                && request.actor_id > 0
                && request.request_sha256.len() == 64
                && request
                    .request_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                && crate::config::is_valid_login(request.actor_login),
            "invalid native scratch target identity"
        );
        ensure!(
            config_bytes.len() <= 256 * 1024,
            "instance config exceeds size limit"
        );
        let configured_target = config
            .repositories
            .iter()
            .find(|repository| {
                repository.repository == request.repository
                    && repository.id == request.repository_id
            })
            .context("native request target is not configured")?;
        ensure!(
            configured_target
                .capabilities
                .contains(&crate::policy::Capability::Merge),
            "native request target lacks merge capability"
        );
        ensure!(
            config.identities.owner.id == request.actor_id
                && config.identities.owner.login == request.actor_login
                && config.identities.owner.id == request.author_id
                && config.identities.owner.login == request.author_login,
            "native scratch policy requires the configured owner as actor and PR author"
        );
        let execution_repository = std::env::var("GITHUB_REPOSITORY")
            .context("missing GITHUB_REPOSITORY for native Server instance")?;
        ensure!(
            execution_repository == config.instance.repository,
            "native Server instance differs from the current job repository"
        );
        let token = std::env::var(name).with_context(|| format!("missing {name}"))?;
        ensure!(!token.is_empty(), "{name} is empty");
        let mut api = Self::new("https://api.github.com", token)?;
        let installation: Value = api.get("/installation/repositories?per_page=100")?;
        let repositories = installation["repositories"]
            .as_array()
            .context("native scratch token is not an installation token")?;
        ensure!(
            installation["total_count"].as_u64() == Some(repositories.len() as u64)
                && repositories.len() == 1
                && repositories[0]["id"].as_u64() == Some(request.repository_id)
                && repositories[0]["full_name"].as_str() == Some(request.repository),
            "native scratch token must be installed only on the configured request repository"
        );
        let read_token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
        ensure!(!read_token.is_empty(), "GITHUB_TOKEN is empty");
        let server_reader = Self::new("https://api.github.com", read_token)?;
        let (remote_config, policy_workflow_path, policy_workflow_bytes) =
            server_reader.native_instance_snapshot(config, config_path, config_bytes)?;
        ensure!(
            remote_config == config_bytes,
            "local native Server config is not the protected default-branch snapshot"
        );
        api.writes = WriteContext::NativeScratch(Box::new(NativeScratchWrite {
            instance_repository: config.instance.repository.clone(),
            instance_id: config.instance.id,
            instance_owner_id: config.identities.repository_owner.id,
            default_branch: config.instance.default_branch.clone(),
            config_path: config_path.to_owned(),
            config_bytes: config_bytes.to_vec(),
            policy_workflow_path,
            policy_workflow_sha256: crate::hex_encode(sha2::Sha256::digest(&policy_workflow_bytes)),
            target_repository: request.repository.to_owned(),
            target_id: request.repository_id,
            pull_number: request.pull_number,
            head_sha: request.head_sha.to_owned(),
            head_repository_id: request.head_repository_id,
            base_ref: request.base_ref.to_owned(),
            author_id: request.author_id,
            author_login: request.author_login.to_owned(),
            actor_id: request.actor_id,
            actor_login: request.actor_login.to_owned(),
            request_sha256: request.request_sha256.to_owned(),
            policy_app_id: config.apps.policy_check_id,
        }));
        Ok(api)
    }

    fn native_instance_snapshot(
        &self,
        config: &crate::instance_config::InstanceConfig,
        config_path: &str,
        expected_config: &[u8],
    ) -> Result<(Vec<u8>, String, Vec<u8>)> {
        validate_instance_config_path(config_path)?;
        let execution_repository = std::env::var("GITHUB_REPOSITORY")
            .context("missing GITHUB_REPOSITORY for native Server instance")?;
        ensure!(
            execution_repository == config.instance.repository,
            "native Server instance differs from the current job repository"
        );
        let repository: Value = self.get(&format!("/repos/{execution_repository}"))?;
        ensure!(
            repository["id"].as_u64() == Some(config.instance.id)
                && repository["full_name"].as_str() == Some(config.instance.repository.as_str())
                && repository["default_branch"].as_str()
                    == Some(config.instance.default_branch.as_str())
                && repository["owner"]["id"].as_u64()
                    == Some(config.identities.repository_owner.id),
            "native Server instance repository identity mismatch"
        );
        let branch_path = format!(
            "/repos/{execution_repository}/branches/{}",
            encode_path_segment(&config.instance.default_branch)
        );
        let branch: Value = self.get(&branch_path)?;
        let source_sha = branch["commit"]["sha"]
            .as_str()
            .filter(|sha| crate::policy::validate_sha(sha).is_ok())
            .context("native Server default branch has no commit SHA")?;
        let tree: Value = self.get(&format!(
            "/repos/{execution_repository}/git/trees/{source_sha}?recursive=1"
        ))?;
        ensure!(
            tree["truncated"] == false,
            "native Server default-branch tree is incomplete"
        );
        let entries = tree["tree"]
            .as_array()
            .context("native Server default-branch tree is missing")?;
        let policy_workflow_path = config
            .workflow_roles
            .get(&crate::instance_config::WorkflowRole::PolicyCheck)
            .context("native Server policy-check role is missing")?
            .clone();
        for path in [config_path, policy_workflow_path.as_str()] {
            let matches: Vec<_> = entries
                .iter()
                .filter(|entry| entry["path"].as_str() == Some(path))
                .collect();
            ensure!(
                matches.len() == 1
                    && matches[0]["type"] == "blob"
                    && matches[0]["mode"] == "100644",
                "native Server config or policy-check wrapper is missing or not a regular tracked file"
            );
        }
        let remote_config = self.content(&execution_repository, config_path, source_sha)?;
        ensure!(
            remote_config == expected_config,
            "native Server config differs from the protected default-branch snapshot"
        );
        let current_config = crate::instance_config::InstanceConfig::parse(&remote_config)?;
        ensure!(
            current_config.instance.repository == config.instance.repository
                && current_config.instance.id == config.instance.id
                && current_config.instance.default_branch == config.instance.default_branch
                && current_config
                    .workflow_roles
                    .get(&crate::instance_config::WorkflowRole::PolicyCheck)
                    == Some(&policy_workflow_path),
            "native Server policy-check authority changed"
        );
        let workflow_bytes =
            self.content(&execution_repository, &policy_workflow_path, source_sha)?;
        ensure!(
            workflow_bytes.len() <= 256 * 1024,
            "native Server policy-check wrapper exceeds size limit"
        );
        Ok((remote_config, policy_workflow_path, workflow_bytes))
    }

    fn require_write_target(&self, method: &Method, path: &str) -> Result<()> {
        if let WriteContext::ClientLabel { server } = &self.writes {
            ensure!(
                path == format!("/repos/{server}/labels"),
                "client write target is not the configured request-label endpoint"
            );
        }
        if let WriteContext::Scratch { candidate_sha } = &self.writes {
            crate::policy::validate_sha(candidate_sha)?;
        }
        if let WriteContext::NativeScratch(write) = &self.writes {
            ensure!(
                *method == Method::POST
                    && path == format!("/repos/{}/check-runs", write.target_repository),
                "native scratch may only create the exact request-proof check run"
            );
        }
        let isolated = matches!(&self.writes, WriteContext::Scratch { .. })
            || (matches!(&self.writes, WriteContext::Production { .. })
                && crate::config::trusted()?
                    .deployment
                    .control_repository
                    .is_some());
        if isolated {
            let prefix = format!(
                "/repos/{}/",
                crate::config::trusted()?.deployment.integration.repository
            );
            let scratch_target = path.starts_with(&prefix)
                && !path.contains(['%', '\\', '?'])
                && !path.split('/').any(|part| part == "." || part == "..");
            let testing_label_cleanup = if scratch_target {
                false
            } else {
                self.is_testing_label_cleanup(method, path)?
            };
            ensure!(
                scratch_target || testing_label_cleanup,
                "integration write target is outside the scratch repository"
            );
        }
        Ok(())
    }

    fn is_testing_label_cleanup(&self, method: &Method, path: &str) -> Result<bool> {
        if *method != Method::DELETE || !matches!(self.writes, WriteContext::Production { .. }) {
            return Ok(false);
        }
        if std::env::var("GITHUB_EVENT_NAME").as_deref() != Ok("label")
            || std::env::var("GITHUB_RUN_ATTEMPT").as_deref() != Ok("1")
        {
            return Ok(false);
        }
        let trusted = crate::config::trusted()?;
        if trusted.deployment.workflow_prefix != "testing-"
            || trusted.deployment.control_repository.is_none()
        {
            return Ok(false);
        }
        let Ok(event_path) = std::env::var("GITHUB_EVENT_PATH") else {
            return Ok(false);
        };
        let Ok(bytes) = std::fs::read(event_path) else {
            return Ok(false);
        };
        let Ok(payload) = serde_json::from_slice::<Value>(&bytes) else {
            return Ok(false);
        };
        testing_label_cleanup_matches(trusted, method, path, &payload)
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
            .header("User-Agent", "securefix")
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if !self.token.is_empty() {
            request = request.bearer_auth(&self.token);
        }
        Ok(request)
    }

    pub fn request(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        if let WriteContext::ClientLabel { server } = &self.writes {
            ensure!(
                method == Method::POST && path == format!("/repos/{server}/labels"),
                "client may only create configured server request labels"
            );
        }
        if let WriteContext::NativeScratch(write) = &self.writes
            && method != Method::GET
            && method != Method::HEAD
        {
            validate_native_scratch_check_body(
                &method,
                path,
                &write.target_repository,
                &write.head_sha,
                &write.request_sha256,
                body.context("native scratch check body is missing")?,
            )?;
        }
        let read_only_graphql = path == "/graphql"
            && method == Method::POST
            && body
                .and_then(|body| body["query"].as_str())
                .is_some_and(read_only_query);
        if path == "/graphql" {
            ensure!(read_only_graphql, "unsupported GraphQL operation");
        }
        if method != Method::GET && method != Method::HEAD && !read_only_graphql {
            self.require_write_target(&method, path)?;
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
        let (expected, expected_control) = match &self.writes {
            WriteContext::ReadOnly => bail!("read-only API connection cannot write"),
            WriteContext::ClientLabel { .. } => {
                return Ok(());
            }
            WriteContext::Scratch { .. } => return Ok(()),
            WriteContext::NativeScratch(_) => {
                return self.require_native_scratch_current();
            }
            WriteContext::Production {
                revision,
                control_id,
            } => (
                revision
                    .as_deref()
                    .context("missing trusted runtime revision before write")?,
                control_id
                    .as_deref()
                    .context("missing trusted control identity before write")?,
            ),
        };
        crate::policy::validate_sha(expected)?;
        let server = crate::config::trusted()?.deployment.control_repository();
        let bytes = self.content(
            &server.repository,
            "control/active.json",
            &server.default_branch,
        )?;
        ensure!(
            bytes.len() <= 16 * 1024,
            "control descriptor exceeds size limit"
        );
        let active: crate::control::ControlRevision = serde_json::from_slice(&bytes)?;
        use sha2::Digest;
        let policy_sha =
            crate::hex_encode(sha2::Sha256::digest(crate::config::trusted_policy_bytes()?));
        ensure!(
            active.source_sha == expected
                && active.identity()? == expected_control
                && active.policy_sha256 == policy_sha,
            "control revision is no longer current; write denied"
        );
        Ok(())
    }

    fn require_native_scratch_current(&self) -> Result<()> {
        let WriteContext::NativeScratch(write) = &self.writes else {
            bail!("native scratch write context is missing");
        };
        let NativeScratchWrite {
            instance_repository,
            instance_id,
            instance_owner_id,
            default_branch,
            config_path,
            config_bytes,
            policy_workflow_path,
            policy_workflow_sha256,
            target_repository,
            target_id,
            pull_number,
            head_sha,
            head_repository_id,
            base_ref,
            author_id,
            author_login,
            actor_id,
            actor_login,
            request_sha256: _,
            policy_app_id,
        } = write.as_ref();

        validate_instance_config_path(config_path)?;
        let installation: Value = self.get("/installation/repositories?per_page=100")?;
        let repositories = installation["repositories"]
            .as_array()
            .context("native scratch token is not an installation token")?;
        ensure!(
            installation["total_count"].as_u64() == Some(repositories.len() as u64)
                && repositories.len() == 1
                && repositories[0]["id"].as_u64() == Some(*target_id)
                && repositories[0]["full_name"].as_str() == Some(target_repository.as_str()),
            "native scratch token installation changed"
        );

        let execution_repository = std::env::var("GITHUB_REPOSITORY")
            .context("missing GITHUB_REPOSITORY for native Server instance")?;
        ensure!(
            &execution_repository == instance_repository,
            "native Server instance differs from the current job repository"
        );
        let config = crate::instance_config::InstanceConfig::parse(config_bytes)?;
        ensure!(
            config.instance.repository == *instance_repository
                && config.instance.id == *instance_id
                && config.instance.default_branch == *default_branch
                && config.identities.repository_owner.id == *instance_owner_id
                && config.apps.policy_check_id == *policy_app_id
                && config.identities.owner.id == *actor_id
                && config.identities.owner.login == *actor_login
                && config.identities.owner.id == *author_id
                && config.identities.owner.login == *author_login
                && config.repositories.iter().any(|repository| {
                    repository.repository == *target_repository
                        && repository.id == *target_id
                        && repository
                            .capabilities
                            .contains(&crate::policy::Capability::Merge)
                }),
            "native request no longer matches the captured owner and repository policy"
        );
        let read_token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
        ensure!(!read_token.is_empty(), "GITHUB_TOKEN is empty");
        let server_reader = Self::new("https://api.github.com", read_token)?;
        let (remote_config, current_workflow_path, workflow_bytes) =
            server_reader.native_instance_snapshot(&config, config_path, config_bytes)?;
        ensure!(
            remote_config.as_slice() == config_bytes.as_slice()
                && current_workflow_path == policy_workflow_path.as_str()
                && crate::hex_encode(sha2::Sha256::digest(&workflow_bytes))
                    == *policy_workflow_sha256,
            "native Server config or policy-check wrapper changed before write"
        );
        let target: Value = self.get(&format!("/repos/{target_repository}"))?;
        ensure!(
            target["id"].as_u64() == Some(*target_id)
                && target["full_name"].as_str() == Some(target_repository.as_str())
                && target["default_branch"].as_str() == Some(base_ref.as_str()),
            "native request target repository identity changed"
        );
        let pull: Value = self.get(&format!("/repos/{target_repository}/pulls/{pull_number}"))?;
        ensure!(
            pull["number"].as_u64() == Some(*pull_number)
                && pull["state"] == "open"
                && pull["base"]["repo"]["id"].as_u64() == Some(*target_id)
                && pull["base"]["repo"]["full_name"].as_str() == Some(target_repository.as_str())
                && pull["base"]["ref"].as_str() == Some(base_ref.as_str())
                && pull["head"]["sha"].as_str() == Some(head_sha.as_str())
                && pull["head"]["repo"]["id"].as_u64() == Some(*head_repository_id)
                && pull["user"]["id"].as_u64() == Some(*author_id)
                && pull["user"]["login"].as_str() == Some(author_login.as_str())
                && *author_id == *actor_id
                && author_login == actor_login,
            "native request PR is closed, retargeted, or has a different head or identity"
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

    pub fn minimize_policy_comment(
        &self,
        repository: &str,
        number: u64,
        comment_id: u64,
    ) -> Result<()> {
        crate::policy::validate_repository(repository)?;
        ensure!(
            number > 0 && comment_id > 0,
            "invalid policy comment target"
        );
        ensure!(
            matches!(
                self.writes,
                WriteContext::Production { .. } | WriteContext::Scratch { .. }
            ),
            "policy comments can only be minimized by the server"
        );

        let path = format!("/repos/{repository}/issues/comments/{comment_id}");
        self.require_write_target(&Method::GET, &path)?;
        let comment: Value = self.get(&path)?;
        let policy = crate::config::trusted()?;
        let expected_issue_path = format!("/repos/{repository}/issues/{number}");
        let issue_url_matches = comment["issue_url"]
            .as_str()
            .and_then(|url| reqwest::Url::parse(url).ok())
            .is_some_and(|url| {
                url.scheme() == "https"
                    && url.host_str() == Some("api.github.com")
                    && url.path() == expected_issue_path
                    && url.query().is_none()
                    && url.fragment().is_none()
            });
        ensure!(
            comment["id"].as_u64() == Some(comment_id)
                && issue_url_matches
                && comment["user"]["id"].as_u64() == Some(policy.server_bot_id)
                && comment["user"]["login"].as_str()
                    == Some(policy.deployment.server_bot_login.as_str())
                && comment["user"]["type"] == "Bot"
                && comment["body"]
                    .as_str()
                    .is_some_and(|body| body.starts_with(POLICY_FAILURE_COMMENT_MARKER)),
            "comment is not a marked policy failure from the configured server bot on this PR"
        );
        let node_id = comment["node_id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .context("policy comment has no GraphQL node ID")?;

        self.require_current_revision()?;
        let query = "mutation($input:MinimizeCommentInput!){minimizeComment(input:$input){minimizedComment{isMinimized}}}";
        let response = self
            .builder(Method::POST, "/graphql")?
            .json(&serde_json::json!({
                "query":query,
                "variables":{"input":{"subjectId":node_id,"classifier":"OUTDATED"}}
            }))
            .send()
            .context("GitHub policy comment minimization failed")?;
        ensure!(
            response.status().is_success(),
            "GitHub policy comment minimization returned {}",
            response.status()
        );
        let value: Value = serde_json::from_slice(&bounded_read(response, 1024 * 1024)?)?;
        ensure!(
            value.get("errors").is_none()
                && value["data"]["minimizeComment"]["minimizedComment"]["isMinimized"] == true,
            "GitHub did not minimize the policy failure comment"
        );
        Ok(())
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
        self.require_write_target(&Method::POST, &format!("/repos/{repository}/git/commits"))?;
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

    pub fn enable_scratch_auto_merge(
        &self,
        repository: &str,
        number: u64,
        expected_head: &str,
    ) -> Result<()> {
        ensure!(
            matches!(self.writes, WriteContext::Scratch { .. }),
            "auto-merge probe requires scratch context"
        );
        crate::policy::validate_repository(repository)?;
        crate::policy::validate_sha(expected_head)?;
        ensure!(number > 0, "invalid auto-merge PR number");
        let path = format!("/repos/{repository}/pulls/{number}");
        self.require_write_target(&Method::GET, &path)?;
        let pull: Value = self.get(&path)?;
        ensure!(
            pull["number"] == number
                && pull["state"] == "open"
                && pull["base"]["repo"]["full_name"] == repository
                && pull["head"]["repo"]["full_name"] == repository
                && pull["head"]["sha"] == expected_head,
            "auto-merge PR no longer matches the accepted scratch head"
        );
        let node = pull["node_id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .context("PR node ID missing")?;
        let response = self.builder(Method::POST, "/graphql")?.json(&serde_json::json!({
            "query":"mutation($input:EnablePullRequestAutoMergeInput!){enablePullRequestAutoMerge(input:$input){pullRequest{id autoMergeRequest{mergeMethod}}}}",
            "variables":{"input":{"pullRequestId":node,"expectedHeadOid":expected_head,"mergeMethod":"SQUASH"}}
        })).send().context("scratch auto-merge mutation failed")?;
        ensure!(
            response.status().is_success(),
            "scratch auto-merge returned {}",
            response.status()
        );
        let value: Value = serde_json::from_slice(&bounded_read(response, 1024 * 1024)?)?;
        ensure!(
            value.get("errors").is_none(),
            "scratch auto-merge was rejected"
        );
        let result = &value["data"]["enablePullRequestAutoMerge"]["pullRequest"];
        ensure!(
            result["id"] == node && result["autoMergeRequest"]["mergeMethod"] == "SQUASH",
            "scratch auto-merge was not enabled for the expected PR"
        );
        Ok(())
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
        let mut request = self.builder(Method::GET, path)?;
        if path.contains("/releases/assets/") {
            let mut headers = HeaderMap::new();
            headers.insert(ACCEPT, HeaderValue::from_static("application/octet-stream"));
            request = request.headers(headers);
        }
        let response = request.send()?;
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
            !matches!(
                self.writes,
                WriteContext::Scratch { .. } | WriteContext::NativeScratch(_)
            ),
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
            .header("User-Agent", "securefix")
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

fn testing_label_cleanup_matches(
    trusted: &crate::config::TrustedConfig,
    method: &Method,
    path: &str,
    payload: &Value,
) -> Result<bool> {
    let deployment = &trusted.deployment;
    if *method != Method::DELETE
        || deployment.workflow_prefix != "testing-"
        || deployment.control_repository.is_none()
        || payload["action"] != "created"
        || payload["repository"]["id"].as_u64() != Some(deployment.server.id)
        || payload["repository"]["full_name"] != deployment.server.repository
        || payload["sender"]["id"].as_u64() != Some(trusted.client_bot_id)
        || payload["sender"]["type"] != "Bot"
    {
        return Ok(false);
    }
    let Some(label) = payload["label"]["name"].as_str() else {
        return Ok(false);
    };
    let Some(description) = payload["label"]["description"].as_str() else {
        return Ok(false);
    };
    if label.len() > 50
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || path != format!("/repos/{}/labels/{label}", deployment.server.repository)
    {
        return Ok(false);
    }
    let request_prefixes = [
        deployment.label_prefix("approve-request-"),
        deployment.label_prefix("merge-request-"),
        deployment.label_prefix("policy-request-"),
        deployment.label_prefix("release-request-"),
    ];
    let label_run = request_prefixes.iter().find_map(|prefix| {
        let suffix = label.strip_prefix(prefix)?;
        let suffix = suffix.strip_prefix("renovate-").unwrap_or(suffix);
        let run = suffix.parse::<u64>().ok()?;
        (run > 0 && run.to_string() == suffix).then_some(run)
    });
    let label_run = label_run.or_else(|| {
        let suffix = label.strip_prefix(&deployment.label_prefix("securefix-"))?;
        let (run, digest) = suffix.split_once('-')?;
        let parsed_run = run.parse::<u64>().ok()?;
        (parsed_run > 0
            && parsed_run.to_string() == run
            && digest.len() == 12
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        .then_some(parsed_run)
    });
    let Some(label_run) = label_run else {
        return Ok(false);
    };
    let Some((repository, described_run)) = description.rsplit_once('/') else {
        return Ok(false);
    };
    if repository != deployment.integration.repository {
        return Ok(false);
    }
    let Ok(described_run) = described_run.parse::<u64>() else {
        return Ok(false);
    };
    Ok(described_run > 0
        && described_run == label_run
        && described_run.to_string() == description.rsplit('/').next().unwrap_or_default())
}

fn validate_instance_config_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.len() <= 1024
            && !path.starts_with('/')
            && path.split('/').all(|component| {
                !component.is_empty()
                    && component != "."
                    && component != ".."
                    && component != ".git"
                    && component
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            }),
        "invalid native Server config path"
    );
    Ok(())
}

fn validate_native_scratch_check_body(
    method: &Method,
    path: &str,
    target_repository: &str,
    head_sha: &str,
    request_sha256: &str,
    body: &Value,
) -> Result<()> {
    ensure!(
        *method == Method::POST
            && path == format!("/repos/{target_repository}/check-runs")
            && body["name"] == NATIVE_PROOF_CHECK
            && body["head_sha"].as_str() == Some(head_sha)
            && body["status"] == "completed"
            && body["conclusion"] == "success"
            && body["output"]["title"] == NATIVE_PROOF_TITLE
            && body["output"]["summary"] == NATIVE_PROOF_SUMMARY
            && body["external_id"].as_str() == Some(request_sha256),
        "native scratch check body does not match the verified request"
    );
    Ok(())
}

pub fn validate_native_instance_config_path(path: &str) -> Result<()> {
    validate_instance_config_path(path)
}

fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
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

    fn native_scratch_api() -> GitHub {
        let mut api = GitHub::new("https://api.github.com", String::new()).unwrap();
        api.writes = WriteContext::NativeScratch(Box::new(NativeScratchWrite {
            instance_repository: "civitaspo/securefix-server".into(),
            instance_id: 1,
            instance_owner_id: 2,
            default_branch: "main".into(),
            config_path: "securefix-server.toml".into(),
            config_bytes: vec![],
            policy_workflow_path: ".github/workflows/policy-check.yml".into(),
            policy_workflow_sha256: "a".repeat(64),
            target_repository: SCRATCH_REPOSITORY.into(),
            target_id: 3,
            pull_number: 4,
            head_sha: "b".repeat(40),
            head_repository_id: 3,
            base_ref: "main".into(),
            author_id: 5,
            author_login: "maintainer".into(),
            actor_id: 5,
            actor_login: "maintainer".into(),
            request_sha256: "c".repeat(64),
            policy_app_id: 6,
        }));
        api
    }

    #[test]
    fn native_scratch_writer_allows_only_one_bound_check_run() {
        let api = native_scratch_api();
        let path = format!("/repos/{SCRATCH_REPOSITORY}/check-runs");
        assert!(api.require_write_target(&Method::POST, &path).is_ok());
        for (method, path) in [
            (Method::PATCH, path.as_str()),
            (Method::DELETE, path.as_str()),
            (Method::POST, "/graphql"),
            (Method::POST, "/repos/other/repo/check-runs"),
        ] {
            assert!(api.require_write_target(&method, path).is_err());
        }
        assert!(
            api.upload(
                "https://uploads.github.com/repos/owner/repo/releases/1/assets?name=x",
                Vec::new(),
                "application/octet-stream"
            )
            .is_err()
        );
        assert!(
            api.create_commit(
                SCRATCH_REPOSITORY,
                "fixture",
                &"b".repeat(40),
                "test",
                BTreeMap::from([("file.txt".into(), b"x".to_vec())]),
                vec![],
            )
            .is_err()
        );
    }

    #[test]
    fn native_scratch_check_body_is_bound_to_the_verified_request() {
        let path = format!("/repos/{SCRATCH_REPOSITORY}/check-runs");
        let body = serde_json::json!({
            "name": NATIVE_PROOF_CHECK,
            "head_sha": "b".repeat(40),
            "external_id": "c".repeat(64),
            "status": "completed",
            "conclusion": "success",
            "output": {"title": NATIVE_PROOF_TITLE, "summary": NATIVE_PROOF_SUMMARY}
        });
        assert!(
            validate_native_scratch_check_body(
                &Method::POST,
                &path,
                SCRATCH_REPOSITORY,
                &"b".repeat(40),
                &"c".repeat(64),
                &body,
            )
            .is_ok()
        );
        let mut forged = body;
        forged["external_id"] = "d".repeat(64).into();
        assert!(
            validate_native_scratch_check_body(
                &Method::POST,
                &path,
                SCRATCH_REPOSITORY,
                &"b".repeat(40),
                &"c".repeat(64),
                &forged,
            )
            .is_err()
        );
    }

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
    fn isolated_normal_cleanup_only_deletes_the_current_testing_server_label() {
        let mut trusted = crate::config::trusted().unwrap().clone();
        trusted.deployment.workflow_prefix = "testing-".into();
        trusted.deployment.control_repository = Some(trusted.deployment.integration.clone());
        let server = &trusted.deployment.server;
        for (label, run) in [
            ("testing-approve-request-11", "11"),
            ("testing-approve-request-renovate-12", "12"),
            ("testing-merge-request-13", "13"),
            ("testing-policy-request-14", "14"),
            ("testing-release-request-15", "15"),
            ("testing-securefix-16-012345abcdef", "16"),
        ] {
            let payload = serde_json::json!({
                "action":"created",
                "repository":{"id":server.id,"full_name":server.repository},
                "sender":{"id":trusted.client_bot_id,"type":"Bot"},
                "label":{"name":label,"description":format!("{}/{run}", trusted.deployment.integration.repository)}
            });
            let path = format!("/repos/{}/labels/{label}", server.repository);
            assert!(
                testing_label_cleanup_matches(&trusted, &Method::DELETE, &path, &payload).unwrap()
            );
            assert!(
                !testing_label_cleanup_matches(&trusted, &Method::POST, &path, &payload).unwrap()
            );
            assert!(
                !testing_label_cleanup_matches(
                    &trusted,
                    &Method::DELETE,
                    &format!("/repos/other/server/labels/{label}"),
                    &payload,
                )
                .unwrap()
            );
        }

        let other_caller = serde_json::json!({
            "action":"created",
            "repository":{"id":server.id,"full_name":server.repository},
            "sender":{"id":trusted.client_bot_id,"type":"Bot"},
            "label":{"name":"testing-merge-request-13","description":"civitaspo/production/13"}
        });
        assert!(
            !testing_label_cleanup_matches(
                &trusted,
                &Method::DELETE,
                &format!(
                    "/repos/{}/labels/testing-merge-request-13",
                    server.repository
                ),
                &other_caller,
            )
            .unwrap()
        );
        let production_label = serde_json::json!({
            "action":"created",
            "repository":{"id":server.id,"full_name":server.repository},
            "sender":{"id":trusted.client_bot_id,"type":"Bot"},
            "label":{"name":"merge-request-13","description":"civitaspo/example/13"}
        });
        assert!(
            !testing_label_cleanup_matches(
                &trusted,
                &Method::DELETE,
                &format!("/repos/{}/labels/merge-request-13", server.repository),
                &production_label,
            )
            .unwrap()
        );
    }
    #[test]
    fn release_asset_download_requests_binary_bytes() {
        use crate::fixtures::{Fixture, Route};
        let fixture = Fixture::new(vec![
            Route::raw(
                "GET",
                "/repos/example/repo/releases/assets/7",
                200,
                vec![0, 255, 1],
            )
            .with_request_header("Accept", "application/octet-stream"),
        ]);
        assert_eq!(
            fixture
                .api
                .download("/repos/example/repo/releases/assets/7", 10)
                .unwrap(),
            vec![0, 255, 1]
        );
        fixture.finish();
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
    fn scratch_auto_merge_binds_the_graphql_mutation_to_the_accepted_head() {
        use crate::fixtures::{Fixture, Route};
        let head = "b".repeat(40);
        let query = "mutation($input:EnablePullRequestAutoMergeInput!){enablePullRequestAutoMerge(input:$input){pullRequest{id autoMergeRequest{mergeMethod}}}}";
        let mut fixture = Fixture::new(vec![
            Route::get(
                format!("/repos/{SCRATCH_REPOSITORY}/pulls/7"),
                serde_json::json!({
                    "number":7,"state":"open","node_id":"PR_fixture",
                    "base":{"repo":{"full_name":SCRATCH_REPOSITORY}},
                    "head":{"repo":{"full_name":SCRATCH_REPOSITORY},"sha":head}
                }),
            ),
            Route::request(
                "POST",
                "/graphql",
                200,
                serde_json::json!({
                    "data":{"enablePullRequestAutoMerge":{"pullRequest":{
                        "id":"PR_fixture","autoMergeRequest":{"mergeMethod":"SQUASH"}
                    }}}
                }),
            )
            .with_request_body(serde_json::json!({
                "query":query,"variables":{"input":{
                    "pullRequestId":"PR_fixture","expectedHeadOid":head,"mergeMethod":"SQUASH"
                }}
            })),
        ]);
        fixture.api.writes = WriteContext::Scratch {
            candidate_sha: "a".repeat(40),
        };
        fixture
            .api
            .enable_scratch_auto_merge(SCRATCH_REPOSITORY, 7, &head)
            .unwrap();
        fixture.finish();
    }

    #[test]
    fn scratch_auto_merge_rejects_changed_heads_and_other_write_contexts() {
        use crate::fixtures::{Fixture, Route};
        let mut fixture = Fixture::new(vec![Route::get(
            format!("/repos/{SCRATCH_REPOSITORY}/pulls/7"),
            serde_json::json!({
                "number":7,"state":"open","node_id":"PR_fixture",
                "base":{"repo":{"full_name":SCRATCH_REPOSITORY}},
                "head":{"repo":{"full_name":SCRATCH_REPOSITORY},"sha":"c".repeat(40)}
            }),
        )]);
        fixture.api.writes = WriteContext::Scratch {
            candidate_sha: "a".repeat(40),
        };
        assert!(
            fixture
                .api
                .enable_scratch_auto_merge(SCRATCH_REPOSITORY, 7, &"b".repeat(40))
                .is_err()
        );
        assert!(
            fixture
                .api
                .enable_scratch_auto_merge("civitaspo/securefix-server", 7, &"b".repeat(40))
                .is_err()
        );
        fixture.finish();
        let api = GitHub::new("https://api.github.com", String::new()).unwrap();
        assert!(
            api.enable_scratch_auto_merge(SCRATCH_REPOSITORY, 7, &"b".repeat(40))
                .is_err()
        );
    }

    #[test]
    fn policy_comment_minimization_is_bound_to_the_configured_bot_pr_and_runtime() {
        use crate::fixtures::{Fixture, Route};
        let repository = "civitaspo/example";
        let number = 17;
        let comment_id = 23;
        let policy = crate::config::trusted().unwrap();
        let issue_url = format!("https://api.github.com/repos/{repository}/issues/{number}");
        let query = "mutation($input:MinimizeCommentInput!){minimizeComment(input:$input){minimizedComment{isMinimized}}}";
        let node_id = "IC_fixture";
        let mut fixture = Fixture::new(vec![
            Route::get(
                format!("/repos/{repository}/issues/comments/{comment_id}"),
                serde_json::json!({
                    "id":comment_id,"node_id":node_id,"issue_url":issue_url,
                    "body":format!("{POLICY_FAILURE_COMMENT_MARKER}\nPolicy check failed."),
                    "user":{"id":policy.server_bot_id,"login":policy.deployment.server_bot_login,"type":"Bot"}
                }),
            ),
            Route::active_control(&Fixture::control_revision()),
            Route::request(
                "POST",
                "/graphql",
                200,
                serde_json::json!({"data":{"minimizeComment":{"minimizedComment":{"isMinimized":true}}}}),
            )
            .with_request_body(serde_json::json!({
                "query":query,"variables":{"input":{"subjectId":node_id,"classifier":"OUTDATED"}}
            })),
        ]);
        fixture.api.writes = WriteContext::Production {
            revision: Some("a".repeat(40)),
            control_id: Some(Fixture::control_revision().identity().unwrap()),
        };
        fixture
            .api
            .minimize_policy_comment(repository, number, comment_id)
            .unwrap();
        fixture.finish();
    }

    #[test]
    fn policy_comment_minimization_rejects_unrelated_or_unowned_comments_before_writing() {
        use crate::fixtures::{Fixture, Route};
        let repository = "civitaspo/example";
        let number = 17;
        let comment_id = 23;
        let policy = crate::config::trusted().unwrap();
        let issue_url = format!("https://api.github.com/repos/{repository}/issues/{number}");
        let valid_user = serde_json::json!({
            "id":policy.server_bot_id,"login":policy.deployment.server_bot_login,"type":"Bot"
        });
        let invalid_comments = [
            serde_json::json!({"id":comment_id,"node_id":"IC_fixture","issue_url":issue_url,"body":format!("other {POLICY_FAILURE_COMMENT_MARKER}"),"user":valid_user}),
            serde_json::json!({"id":comment_id,"node_id":"IC_fixture","issue_url":issue_url,"body":POLICY_FAILURE_COMMENT_MARKER,"user":{"id":policy.owner_id,"login":"owner","type":"User"}}),
            serde_json::json!({"id":comment_id,"node_id":"IC_fixture","issue_url":"https://api.github.com/repos/civitaspo/other/issues/17","body":POLICY_FAILURE_COMMENT_MARKER,"user":valid_user}),
        ];
        for comment in invalid_comments {
            let mut fixture = Fixture::new(vec![Route::get(
                format!("/repos/{repository}/issues/comments/{comment_id}"),
                comment,
            )]);
            fixture.api.writes = WriteContext::Production {
                revision: Some("a".repeat(40)),
                control_id: Some(Fixture::control_revision().identity().unwrap()),
            };
            assert!(
                fixture
                    .api
                    .minimize_policy_comment(repository, number, comment_id)
                    .is_err()
            );
            fixture.finish();
        }
    }

    #[test]
    fn policy_comment_minimization_rejects_stale_runtime_before_graphql_mutation() {
        use crate::fixtures::{Fixture, Route};
        let repository = "civitaspo/example";
        let number = 17;
        let comment_id = 23;
        let policy = crate::config::trusted().unwrap();
        let issue_url = format!("https://api.github.com/repos/{repository}/issues/{number}");
        let mut fixture = Fixture::new(vec![
            Route::get(
                format!("/repos/{repository}/issues/comments/{comment_id}"),
                serde_json::json!({
                    "id":comment_id,"node_id":"IC_fixture","issue_url":issue_url,
                    "body":POLICY_FAILURE_COMMENT_MARKER,
                    "user":{"id":policy.server_bot_id,"login":policy.deployment.server_bot_login,"type":"Bot"}
                }),
            ),
            Route::active_control(&crate::control::ControlRevision {
                source_sha: "b".repeat(40),
                ..Fixture::control_revision()
            }),
        ]);
        fixture.api.writes = WriteContext::Production {
            revision: Some("a".repeat(40)),
            control_id: Some(Fixture::control_revision().identity().unwrap()),
        };
        assert!(
            fixture
                .api
                .minimize_policy_comment(repository, number, comment_id)
                .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn scratch_policy_comment_minimization_is_confined_to_the_scratch_repository() {
        use crate::fixtures::{Fixture, Route};
        let repository = SCRATCH_REPOSITORY;
        let number = 17;
        let comment_id = 23;
        let policy = crate::config::trusted().unwrap();
        let issue_url = format!("https://api.github.com/repos/{repository}/issues/{number}");
        let node_id = "IC_scratch";
        let query = "mutation($input:MinimizeCommentInput!){minimizeComment(input:$input){minimizedComment{isMinimized}}}";
        let mut fixture = Fixture::new(vec![
            Route::get(
                format!("/repos/{repository}/issues/comments/{comment_id}"),
                serde_json::json!({
                    "id":comment_id,"node_id":node_id,"issue_url":issue_url,
                    "body":POLICY_FAILURE_COMMENT_MARKER,
                    "user":{"id":policy.server_bot_id,"login":policy.deployment.server_bot_login,"type":"Bot"}
                }),
            ),
            Route::request(
                "POST",
                "/graphql",
                200,
                serde_json::json!({"data":{"minimizeComment":{"minimizedComment":{"isMinimized":true}}}}),
            )
            .with_request_body(serde_json::json!({
                "query":query,"variables":{"input":{"subjectId":node_id,"classifier":"OUTDATED"}}
            })),
        ]);
        fixture.api.writes = WriteContext::Scratch {
            candidate_sha: "a".repeat(40),
        };
        fixture
            .api
            .minimize_policy_comment(repository, number, comment_id)
            .unwrap();
        assert!(
            fixture
                .api
                .minimize_policy_comment("civitaspo/securefix-server", 17, 23)
                .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn client_can_only_create_request_labels_without_a_server_runtime_epoch() {
        use crate::fixtures::{Fixture, Route};
        let server = &crate::config::trusted()
            .unwrap()
            .deployment
            .server
            .repository;
        let path = format!("/repos/{server}/labels");
        let body = serde_json::json!({"name":"securefix-fixture","description":"owner/source/123"});
        let mut fixture = Fixture::new(vec![
            Route::request("POST", &path, 201, body.clone()).with_request_body(body.clone()),
        ]);
        fixture.api.writes = WriteContext::ClientLabel {
            server: server.clone(),
        };
        assert_eq!(fixture.api.post::<Value>(&path, &body).unwrap(), body);
        for target in [
            "/graphql",
            "/repos/other/server/labels",
            "/repos/owner/source/pulls",
            "/repos/owner/source/git/refs",
        ] {
            assert!(fixture.api.post::<Value>(target, &body).is_err());
        }
        assert!(fixture.api.patch::<Value>(&path, &body).is_err());
        assert!(fixture.api.delete(&path).is_err());
        assert!(fixture.api.get::<Value>("/user").is_err());
        assert!(
            fixture
                .api
                .post::<Value>(
                    "/graphql",
                    &serde_json::json!({"query":"query { viewer { login } }"})
                )
                .is_err()
        );
        fixture.finish();
    }
    #[test]
    fn scratch_writes_cannot_escape_the_fixed_repository() {
        let mut api = GitHub::new("https://api.github.com", String::new()).unwrap();
        api.writes = WriteContext::Scratch {
            candidate_sha: "a".repeat(40),
        };
        assert!(
            api.require_write_target(
                &Method::POST,
                &format!("/repos/{SCRATCH_REPOSITORY}/issues/1/comments"),
            )
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
            let mut fixture = Fixture::new(vec![Route::request(
                "POST",
                "/graphql",
                200,
                serde_json::json!({"data":{"createCommitOnBranch":{"commit":{
                    "oid":"b".repeat(40), "parents":{"nodes":[{"oid":parent.to_string().repeat(40)}]},
                    "signature":{"isValid":signed,"state":"VALID"}
                }}}}),
            )]);
            fixture.api.writes = WriteContext::Scratch {
                candidate_sha: "a".repeat(40),
            };
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
                Route::active_control(&Fixture::control_revision()),
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
            let fixture = Fixture::new(vec![Route::active_control(
                &crate::control::ControlRevision {
                    source_sha: "b".repeat(40),
                    ..Fixture::control_revision()
                },
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
    fn testing_control_readback_and_write_fence_use_only_the_fixture_state() {
        use crate::fixtures::{Fixture, Route};
        use base64::Engine;
        use serde_json::json;
        const CHILD: &str = "SECUREFIX_TEST_CONTROL_STORAGE";
        if std::env::var(CHILD).as_deref() != Ok("1") {
            let mut policy: Value =
                serde_json::from_slice(include_bytes!("../tests/fixtures/policy.json")).unwrap();
            policy["deployment"]["workflow_prefix"] = json!("testing-");
            policy["deployment"]["control_repository"] =
                policy["deployment"]["integration"].clone();
            let repository = policy["deployment"]["integration"]["repository"].clone();
            policy["repositories"] = json!([{"repository":repository,"capabilities":["approve","merge","securefix"],"release":null,"protect_tags":false}]);
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("policy.json");
            std::fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "api::tests::testing_control_readback_and_write_fence_use_only_the_fixture_state", "--nocapture"])
                .env(CHILD, "1").env("SECUREFIX_POLICY_PATH", path).status().unwrap().success());
            return;
        }
        let deployment = &crate::config::trusted().unwrap().deployment;
        let state = deployment.control_repository();
        assert_ne!(state, &deployment.server);
        let current = Fixture::control_revision();
        let default_head = "c".repeat(40);
        let content = json!({"encoding":"base64", "content":base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&current).unwrap())});
        let fixture = Fixture::new(vec![
            Route::get(
                format!("/repos/{}", state.repository),
                json!({"id":state.id,"default_branch":state.default_branch}),
            ),
            Route::get(
                format!(
                    "/repos/{}/commits/{}",
                    state.repository, state.default_branch
                ),
                json!({"sha":default_head}),
            ),
            Route::get(
                format!(
                    "/repos/{}/contents/control/active.json?ref={default_head}",
                    state.repository
                ),
                content,
            ),
            Route::active_control(&current),
            Route::request(
                "POST",
                format!("/repos/{}/labels", state.repository),
                201,
                json!({"id":1}),
            ),
        ]);
        assert_eq!(
            crate::control::ControlRevision::load(&fixture.api).unwrap(),
            current
        );
        for path in [
            format!("/repos/{}/labels", deployment.server.repository),
            format!("/repos/{}-other/labels", state.repository),
            format!("/repos/{}/../securefix-server/labels", state.repository),
            format!("/repos/{}/%2e%2e/labels", state.repository),
        ] {
            assert!(
                fixture
                    .api
                    .require_write_target(&Method::POST, &path)
                    .is_err()
            );
        }
        let _: Value = fixture
            .api
            .post(
                &format!("/repos/{}/labels", state.repository),
                &json!({"name":"testing-fixture"}),
            )
            .unwrap();
        fixture.finish();
        let successor = crate::control::ControlRevision {
            generation: 2,
            previous: current.identity().unwrap(),
            source_sha: "b".repeat(40),
            ..current
        };
        let fixture = Fixture::new(vec![Route::active_control(&successor)]);
        assert!(
            fixture
                .api
                .post::<Value>(&format!("/repos/{}/labels", state.repository), &json!({}))
                .unwrap_err()
                .to_string()
                .contains("control revision is no longer current")
        );
        fixture.finish();
    }

    #[test]
    fn unchanged_active_control_allows_write_without_a_main_tip_lookup() {
        use crate::fixtures::{Fixture, Route};
        let fixture = Fixture::new(vec![
            Route::active_control(&Fixture::control_revision()),
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

    #[test]
    fn same_source_with_a_new_control_generation_is_stale_before_write() {
        use crate::fixtures::{Fixture, Route};
        let captured = Fixture::control_revision();
        let active = crate::control::ControlRevision {
            generation: 2,
            previous: captured.identity().unwrap(),
            ..captured
        };
        let fixture = Fixture::new(vec![Route::active_control(&active)]);
        assert!(
            fixture
                .api
                .post::<Value>(
                    "/repos/civitaspo/example/labels",
                    &serde_json::json!({"name":"request"})
                )
                .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn production_write_without_captured_control_identity_fails_closed() {
        let mut api = GitHub::new("http://127.0.0.1:1", "fixture-token".into()).unwrap();
        api.writes = WriteContext::Production {
            revision: Some("a".repeat(40)),
            control_id: None,
        };
        assert!(
            api.post::<Value>(
                "/repos/civitaspo/example/labels",
                &serde_json::json!({"name":"request"})
            )
            .is_err()
        );
    }
}
