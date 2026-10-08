use crate::api::GitHub;
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use globset::{Glob, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashSet, path::Path};

pub const SERVER: &str = "civitaspo/securefix-server";

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
        ensure!(
            policy.owner_id == 4525500
                && policy.client_bot_id == 288068203
                && policy.server_bot_id == 288069019,
            "unexpected security principal"
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
                repository.repository.starts_with("civitaspo/"),
                "repository must be owned by civitaspo"
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
        let bytes = api.content(SERVER, "policy.json", &revision)?;
        let mut policy = Self::parse(&bytes)?;
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
    let repository: Value = api.get(&format!("/repos/{SERVER}"))?;
    ensure!(
        repository["default_branch"] == "main",
        "unexpected server default branch"
    );
    let commit: Value = api.get(&format!("/repos/{SERVER}/commits/main"))?;
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
        let policy = Policy::load("policy.json").unwrap();
        assert_eq!(policy.repositories.len(), 10);
        assert!(policy.repository("civitaspo/unlisted").is_err());
        let mut invalid = serde_json::to_value(&policy).unwrap();
        invalid["repositories"][0]["repository"] = Value::String("civitaspo/*".into());
        assert!(Policy::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    #[test]
    fn sensitive_paths_cover_code_workflows_and_dependencies() {
        let policy = Policy::load("policy.json").unwrap();
        let server = policy.repository(SERVER).unwrap();
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
}
