use crate::api::GitHub;
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use globset::{Glob, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashSet, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    Approve,
    Merge,
    Securefix,
    Release,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseStrategy {
    GithubRelease,
    TerraformProvider,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPolicy {
    pub repository: String,
    pub capabilities: Vec<Capability>,
    pub release: Option<ReleaseStrategy>,
    #[serde(default)]
    pub sensitive_paths: Vec<String>,
    pub protect_tags: bool,
}

impl RepositoryPolicy {
    pub fn require(&self, capability: Capability) -> Result<()> {
        ensure!(
            self.capabilities.contains(&capability),
            "operation is not enabled for {}",
            self.repository
        );
        Ok(())
    }

    pub fn sensitive<'a>(&self, paths: impl IntoIterator<Item = &'a str>) -> Result<bool> {
        let mut builder = GlobSetBuilder::new();
        for pattern in &self.sensitive_paths {
            builder.add(Glob::new(pattern)?);
        }
        let patterns = builder.build()?;
        Ok(paths.into_iter().any(|path| patterns.is_match(path)))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub deployment: crate::config::Deployment,
    pub owner_id: u64,
    pub client_bot_id: u64,
    pub server_bot_id: u64,
    pub trusted_committers: Vec<String>,
    pub default_sensitive_paths: Vec<String>,
    pub merge_controls_enabled: bool,
    pub repositories: Vec<RepositoryPolicy>,
    #[serde(skip)]
    pub revision: String,
}

impl Policy {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Self::parse(&std::fs::read(path)?)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 256 * 1024, "policy exceeds size limit");
        let mut policy: Self = serde_json::from_slice(bytes)?;
        ensure!(policy.version == 1, "unsupported policy version");
        policy.deployment.validate()?;
        ensure!(
            policy.owner_id > 0
                && policy.client_bot_id > 0
                && policy.server_bot_id > 0
                && policy.owner_id != policy.client_bot_id
                && policy.owner_id != policy.server_bot_id
                && policy.client_bot_id != policy.server_bot_id,
            "invalid security principals"
        );
        ensure!(
            !policy.trusted_committers.is_empty(),
            "no trusted committers"
        );
        ensure!(
            !policy.default_sensitive_paths.is_empty(),
            "missing default sensitive paths"
        );
        let mut names = HashSet::new();
        for repository in &mut policy.repositories {
            if repository.sensitive_paths.is_empty() {
                repository
                    .sensitive_paths
                    .clone_from(&policy.default_sensitive_paths);
            }
            validate_repository(&repository.repository)?;
            ensure!(
                repository.repository.split('/').next()
                    == Some(policy.deployment.repository_owner.login.as_str()),
                "repository must belong to the configured account"
            );
            ensure!(
                names.insert(&repository.repository),
                "duplicate repository policy"
            );
            let capabilities: HashSet<_> = repository.capabilities.iter().collect();
            ensure!(
                capabilities.len() == repository.capabilities.len() && !capabilities.is_empty(),
                "invalid capabilities"
            );
            ensure!(
                repository.release.is_some()
                    == repository.capabilities.contains(&Capability::Release),
                "release strategy/capability mismatch"
            );
            ensure!(
                !repository.sensitive_paths.is_empty(),
                "missing sensitive paths"
            );
            for pattern in &repository.sensitive_paths {
                Glob::new(pattern)?;
            }
        }
        Ok(policy)
    }
    pub fn active(api: &GitHub) -> Result<Self> {
        let revision = latest_revision(api, ".github/workflows/ci.yml")?;
        let bytes = api.content(
            &crate::config::trusted()?.deployment.server.repository,
            "policy.json",
            &revision,
        )?;
        let mut policy = Self::parse(&bytes)?;
        let trusted = crate::config::trusted()?;
        ensure!(
            policy.deployment == trusted.deployment
                && policy.owner_id == trusted.owner_id
                && policy.client_bot_id == trusted.client_bot_id
                && policy.server_bot_id == trusted.server_bot_id,
            "active policy identity differs from trusted runtime"
        );
        policy.revision = revision;
        Ok(policy)
    }
    pub fn repository(&self, full_name: &str) -> Result<&RepositoryPolicy> {
        self.repositories
            .iter()
            .find(|r| r.repository == full_name)
            .with_context(|| format!("repository is not allowed: {full_name}"))
    }
    pub fn latest_revision(api: &GitHub, workflow_path: &str) -> Result<String> {
        latest_revision(api, workflow_path)
    }
}

pub fn validate_repository(value: &str) -> Result<()> {
    let parts: Vec<_> = value.split('/').collect();
    ensure!(
        parts.len() == 2
            && parts.iter().all(|part| !part.is_empty()
                && *part != "."
                && *part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))),
        "invalid repository"
    );
    Ok(())
}

pub fn validate_sha(value: &str) -> Result<()> {
    ensure!(
        value.len() == 40
            && value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid commit SHA"
    );
    Ok(())
}

pub fn latest_revision(api: &GitHub, workflow_path: &str) -> Result<String> {
    ensure!(
        workflow_path.starts_with(".github/workflows/")
            && workflow_path.ends_with(".yml")
            && !workflow_path.contains(".."),
        "invalid reusable workflow path"
    );
    let server = &crate::config::trusted()?.deployment.server;
    let repository: Value = api.get(&format!("/repos/{}", server.repository))?;
    ensure!(
        repository["default_branch"] == server.default_branch
            && repository["id"].as_u64() == Some(server.id),
        "unexpected server default branch"
    );
    let commit: Value = api.get(&format!(
        "/repos/{}/commits/{}",
        server.repository, server.default_branch
    ))?;
    let sha = commit["sha"].as_str().context("missing server revision")?;
    validate_sha(sha)?;
    Ok(sha.to_string())
}

#[derive(Subcommand)]
pub enum Command {
    Validate {
        #[arg(long, default_value = "policy.json")]
        policy: String,
    },
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Validate { policy } => {
            Policy::load(policy)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn central_policy_is_exact_and_has_no_duplicate_repositories() {
        let policy = Policy::load("tests/fixtures/policy.json").unwrap();
        assert_eq!(policy.repositories.len(), 10);
        assert!(policy.repository("civitaspo/unlisted").is_err());
        let mut invalid = serde_json::to_value(&policy).unwrap();
        invalid["repositories"][0]["repository"] = Value::String("civitaspo/*".into());
        assert!(Policy::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    #[test]
    fn sensitive_paths_cover_code_workflows_and_dependencies() {
        let policy = Policy::load("tests/fixtures/policy.json").unwrap();
        let server = policy
            .repository(&policy.deployment.server.repository)
            .unwrap();
        assert!(server.sensitive(["README.md"]).unwrap());
        let client = policy
            .repository("civitaspo/dbt-authorized-models")
            .unwrap();
        for path in [
            ".github/workflows/ci.yml",
            "Cargo.lock",
            ".goreleaser.yaml",
            ".github/actions/setup/action.yml",
            "build.rs",
            "crates/client/build.rs",
            ".cargo/config.toml",
            "crates/client/.cargo/config.toml",
        ] {
            assert!(client.sensitive([path]).unwrap(), "{path}");
        }
        assert!(
            !client
                .sensitive(["README.md", "models/example.sql"])
                .unwrap()
        );
    }
    #[test]
    fn alternate_deployment_requires_no_personal_identities() {
        let mut value =
            serde_json::to_value(Policy::load("tests/fixtures/policy.json").unwrap()).unwrap();
        value["owner_id"] = 101.into();
        value["client_bot_id"] = 202.into();
        value["server_bot_id"] = 303.into();
        let deployment = &mut value["deployment"];
        deployment["server"] = serde_json::json!({"repository":"example-org/controller","id":404,"default_branch":"trunk"});
        deployment["integration"] = serde_json::json!({"repository":"example-org/sandbox","id":405,"default_branch":"trunk"});
        deployment["repository_owner"] = serde_json::json!({"login":"example-org","id":406});
        deployment["owner_login"] = "maintainer".into();
        deployment["client_app_id"] = 501.into();
        deployment["server_app_id"] = 502.into();
        deployment["client_bot_login"] = "example-client[bot]".into();
        deployment["server_bot_login"] = "example-server[bot]".into();
        deployment["approval_reviewer"] = serde_json::json!({"login":"reviewer","id":601});
        deployment["checks"] = serde_json::json!({"status_app_id":701,"policy_app_id":502});
        deployment["release_branch"] = "releases/candidate".into();
        deployment["runtime_update_branch"] = "automation/runtime".into();
        value["trusted_committers"] = serde_json::json!(["maintainer", "example-server[bot]"]);
        value["repositories"] = serde_json::json!([{"repository":"example-org/project","capabilities":["approve","merge","securefix","release"],"release":"github-release","protect_tags":true}]);
        let parsed = Policy::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(parsed.repository("example-org/project").is_ok());
        for (field, invalid) in [
            ("server_app_id", serde_json::json!(501)),
            ("integration", value["deployment"]["server"].clone()),
            ("runtime_update_branch", serde_json::json!("trunk")),
            ("release_branch", serde_json::json!("bad^branch")),
        ] {
            let mut malformed = value.clone();
            malformed["deployment"][field] = invalid;
            assert!(
                Policy::parse(&serde_json::to_vec(&malformed).unwrap()).is_err(),
                "{field}"
            );
        }
        value["repositories"][0]["repository"] = "other-org/project".into();
        assert!(Policy::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}
