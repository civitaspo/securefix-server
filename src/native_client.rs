use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
use std::{fs, path::PathBuf};

use securefix::{api::GitHub, policy::validate_sha};

const PROTOCOL: &str = "securefix-native-request/v1";
const MAX_REQUEST_BYTES: usize = 16 * 1024;

#[derive(Subcommand)]
pub enum Command {
    #[command(about = "Capture one exact pull request head for a policy check")]
    PolicyCheck {
        #[command(subcommand)]
        command: PolicyCheckCommand,
    },
}

#[derive(Subcommand)]
pub enum PolicyCheckCommand {
    Capture {
        #[arg(long)]
        pull_request_number: u64,
        /// Explicit path to this instance's protected-main TOML configuration.
        #[arg(long)]
        config_path: String,
        #[arg(long, default_value = "native-policy-check/manifest.json")]
        output: PathBuf,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestManifest {
    pub protocol: String,
    pub operation: String,
    pub repository: RepositoryIdentity,
    pub pull_request: PullRequestIdentity,
    pub producer: ProducerIdentity,
    pub authority: securefix::api::NativeAuthoritySnapshot,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryIdentity {
    pub id: u64,
    pub full_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PullRequestIdentity {
    pub number: u64,
    pub head_sha: String,
    pub head_repository_id: u64,
    pub base_ref: String,
    pub author_id: u64,
    pub author_login: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProducerIdentity {
    pub run_id: u64,
    pub run_attempt: u32,
    pub event: String,
    pub source_sha: String,
    pub workflow_path: String,
    pub workflow_sha: String,
    pub actor_id: u64,
    pub actor_login: String,
}

impl RequestManifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol == PROTOCOL && self.operation == "policy_check",
            "unsupported native request protocol or operation"
        );
        securefix::policy::validate_repository(&self.repository.full_name)?;
        ensure!(self.repository.id > 0, "invalid request repository ID");
        ensure!(
            self.pull_request.number > 0
                && self.pull_request.head_repository_id > 0
                && self.pull_request.author_id > 0,
            "invalid pull request identity"
        );
        validate_sha(&self.pull_request.head_sha)?;
        securefix::config::validate_branch(&self.pull_request.base_ref)?;
        ensure!(
            valid_login(&self.pull_request.author_login),
            "invalid pull request author login"
        );
        ensure!(
            self.producer.run_id > 0 && self.producer.run_attempt > 0,
            "invalid request producer run"
        );
        ensure!(
            matches!(
                self.producer.event.as_str(),
                "workflow_dispatch" | "pull_request_target" | "pull_request" | "issue_comment"
            ),
            "unsupported request producer event"
        );
        validate_sha(&self.producer.source_sha)?;
        validate_sha(&self.producer.workflow_sha)?;
        validate_workflow_path(&self.producer.workflow_path)?;
        securefix::api::validate_native_instance_config_path(&self.authority.config_path)?;
        validate_digest(&self.authority.config_sha256)?;
        validate_sha(&self.authority.config_epoch)?;
        validate_digest(&self.authority.workflow_sha256)?;
        validate_sha(&self.authority.workflow_epoch)?;
        ensure!(
            self.producer.actor_id > 0 && valid_login(&self.producer.actor_login),
            "invalid request producer actor"
        );
        Ok(())
    }
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::PolicyCheck { command } => match command {
            PolicyCheckCommand::Capture {
                pull_request_number,
                config_path,
                output,
            } => capture_policy_check(pull_request_number, &config_path, &output),
        },
    }
}

fn capture_policy_check(
    pull_request_number: u64,
    config_path: &str,
    output: &std::path::Path,
) -> Result<()> {
    ensure!(pull_request_number > 0, "invalid pull request number");
    let repository_name =
        std::env::var("GITHUB_REPOSITORY").context("missing GITHUB_REPOSITORY")?;
    securefix::policy::validate_repository(&repository_name)?;
    let run_id = parse_env::<u64>("GITHUB_RUN_ID")?;
    let run_attempt = parse_env::<u32>("GITHUB_RUN_ATTEMPT")?;
    let workflow_sha = std::env::var("SECUREFIX_CALLER_WORKFLOW_SHA")
        .context("missing SECUREFIX_CALLER_WORKFLOW_SHA")?;
    validate_sha(&workflow_sha)?;
    let token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
    ensure!(!token.is_empty(), "GITHUB_TOKEN is empty");
    let api = GitHub::new("https://api.github.com", token)?;

    let repository: Value = api.get(&format!("/repos/{repository_name}"))?;
    let repository_id = repository["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("request repository ID is missing")?;
    ensure!(
        repository["full_name"].as_str() == Some(repository_name.as_str()),
        "request repository identity mismatch"
    );
    let run: Value = api.get(&format!("/repos/{repository_name}/actions/runs/{run_id}"))?;
    ensure!(
        run["id"].as_u64() == Some(run_id)
            && run["run_attempt"].as_u64() == Some(u64::from(run_attempt))
            && run["repository"]["id"].as_u64() == Some(repository_id)
            && run["repository"]["full_name"].as_str() == Some(repository_name.as_str()),
        "request workflow run identity mismatch"
    );
    let event = run["event"]
        .as_str()
        .context("request workflow event is missing")?
        .to_owned();
    ensure!(
        run["status"] == "in_progress" || run["status"] == "queued",
        "request capture must run inside its active workflow run"
    );
    let source_sha = run["head_sha"]
        .as_str()
        .context("request workflow source SHA is missing")?
        .to_owned();
    validate_sha(&source_sha)?;
    let workflow_path = canonical_workflow_path(
        run["path"]
            .as_str()
            .context("request workflow path is missing")?,
    )?;
    let actor_id = run["actor"]["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("request workflow actor ID is missing")?;
    let actor_login = run["actor"]["login"]
        .as_str()
        .context("request workflow actor login is missing")?
        .to_owned();

    let pull_request: Value = api.get(&format!(
        "/repos/{repository_name}/pulls/{pull_request_number}"
    ))?;
    ensure!(
        pull_request["number"].as_u64() == Some(pull_request_number)
            && pull_request["state"] == "open"
            && pull_request["base"]["repo"]["id"].as_u64() == Some(repository_id)
            && pull_request["base"]["repo"]["full_name"].as_str() == Some(repository_name.as_str()),
        "pull request is closed or targets a different repository"
    );
    let base_ref = pull_request["base"]["ref"]
        .as_str()
        .context("pull request base branch is missing")?
        .to_owned();
    let head_sha = pull_request["head"]["sha"]
        .as_str()
        .context("pull request head SHA is missing")?
        .to_owned();
    let head_repository_id = pull_request["head"]["repo"]["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("pull request head repository ID is missing")?;
    let author_id = pull_request["user"]["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("pull request author ID is missing")?;
    let author_login = pull_request["user"]["login"]
        .as_str()
        .context("pull request author login is missing")?
        .to_owned();
    ensure!(
        pull_request["base"]["ref"].as_str() == repository["default_branch"].as_str(),
        "native request PR must target the repository default branch"
    );
    let default_branch = repository["default_branch"]
        .as_str()
        .context("request repository default branch is missing")?;
    let authority = securefix::api::capture_native_authority_snapshot(
        &api,
        &repository_name,
        repository_id,
        default_branch,
        config_path,
        &workflow_path,
        &workflow_sha,
    )?;

    let manifest = RequestManifest {
        protocol: PROTOCOL.to_owned(),
        operation: "policy_check".to_owned(),
        repository: RepositoryIdentity {
            id: repository_id,
            full_name: repository_name,
        },
        pull_request: PullRequestIdentity {
            number: pull_request_number,
            head_sha,
            head_repository_id,
            base_ref,
            author_id,
            author_login,
        },
        producer: ProducerIdentity {
            run_id,
            run_attempt,
            event,
            source_sha,
            workflow_path,
            workflow_sha,
            actor_id,
            actor_login,
        },
        authority,
    };
    manifest.validate()?;
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    ensure!(
        bytes.len() <= MAX_REQUEST_BYTES,
        "native request exceeds size limit"
    );
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, &bytes).with_context(|| format!("write request to {}", output.display()))?;
    println!(
        "request_sha256={}",
        securefix::hex_encode(sha2::Sha256::digest(&bytes))
    );
    println!("request_path={}", output.display());
    Ok(())
}

fn validate_digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "invalid native authority digest"
    );
    Ok(())
}

fn parse_env<T: std::str::FromStr>(name: &str) -> Result<T> {
    std::env::var(name)
        .with_context(|| format!("missing {name}"))?
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid {name}"))
}

fn canonical_workflow_path(path: &str) -> Result<String> {
    let path = path.split('@').next().context("invalid workflow path")?;
    validate_workflow_path(path)?;
    Ok(path.to_owned())
}

fn validate_workflow_path(path: &str) -> Result<()> {
    let name = path
        .strip_prefix(".github/workflows/")
        .context("workflow path must be under .github/workflows")?;
    ensure!(
        name.ends_with(".yml")
            && !name.is_empty()
            && !path.contains(['\\', '%', '?', '#'])
            && !name
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte)),
        "invalid workflow path"
    );
    Ok(())
}

fn valid_login(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= 100
        && login
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_[].".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> RequestManifest {
        RequestManifest {
            protocol: PROTOCOL.to_owned(),
            operation: "policy_check".to_owned(),
            repository: RepositoryIdentity {
                id: 1410312556,
                full_name: "civitaspo/testing-securefix-server".to_owned(),
            },
            pull_request: PullRequestIdentity {
                number: 12,
                head_sha: "a".repeat(40),
                head_repository_id: 1410312556,
                base_ref: "main".to_owned(),
                author_id: 4525500,
                author_login: "civitaspo".to_owned(),
            },
            producer: ProducerIdentity {
                run_id: 39553607441,
                run_attempt: 1,
                event: "workflow_dispatch".to_owned(),
                source_sha: "b".repeat(40),
                workflow_path: ".github/workflows/testing-ci.yml".to_owned(),
                workflow_sha: "c".repeat(40),
                actor_id: 4525500,
                actor_login: "civitaspo".to_owned(),
            },
            authority: securefix::api::NativeAuthoritySnapshot {
                config_path: "securefix-server.toml".to_owned(),
                config_sha256: "d".repeat(64),
                config_epoch: "e".repeat(40),
                workflow_sha256: "f".repeat(64),
                workflow_epoch: "1".repeat(40),
            },
        }
    }

    #[test]
    fn native_request_is_strict_and_binds_the_exact_head_and_producer() {
        let value = manifest();
        value.validate().unwrap();
        let mut json = serde_json::to_value(value).unwrap();
        json["pull_request"]["head_sha"] = serde_json::json!("not-a-sha");
        assert!(
            serde_json::from_value::<RequestManifest>(json)
                .unwrap()
                .validate()
                .is_err()
        );

        let mut json = serde_json::to_value(manifest()).unwrap();
        json["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RequestManifest>(json).is_err());
    }

    #[test]
    fn workflow_path_is_repository_relative_and_canonical() {
        assert_eq!(
            canonical_workflow_path(
                ".github/workflows/testing-ci.yml@refs/heads/testing/native-proof"
            )
            .unwrap(),
            ".github/workflows/testing-ci.yml"
        );
        for path in [
            "../evil.yml",
            ".github/workflows/../evil.yml",
            ".github/workflows\\evil.yml",
            ".github/workflows/not-yaml.yaml",
        ] {
            assert!(canonical_workflow_path(path).is_err(), "{path}");
        }
    }

    #[test]
    fn authority_snapshot_rejects_config_changes_and_change_revert_epochs() {
        let captured = securefix::api::NativeAuthoritySnapshot {
            config_path: "securefix-server.toml".to_owned(),
            config_sha256: "a".repeat(64),
            config_epoch: "b".repeat(40),
            workflow_sha256: "c".repeat(64),
            workflow_epoch: "d".repeat(40),
        };
        assert!(securefix::api::require_native_authority_unchanged(&captured, &captured).is_ok());

        let mut changed_config = captured.clone();
        changed_config.config_sha256 = "e".repeat(64);
        changed_config.config_epoch = "f".repeat(40);
        assert!(
            securefix::api::require_native_authority_unchanged(&captured, &changed_config).is_err()
        );

        let mut reverted_config = captured.clone();
        reverted_config.config_epoch = "e".repeat(40);
        assert_eq!(reverted_config.config_sha256, captured.config_sha256);
        assert!(
            securefix::api::require_native_authority_unchanged(&captured, &reverted_config)
                .is_err()
        );
    }
}
