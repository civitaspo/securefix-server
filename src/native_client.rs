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
    #[command(about = "Capture one Securefix artifact for an exact pull request head")]
    Securefix {
        #[command(subcommand)]
        command: SecurefixCommand,
    },
}

#[derive(Subcommand)]
pub enum PolicyCheckCommand {
    Capture {
        #[arg(long)]
        pull_request_number: u64,
        #[arg(long, default_value = "native-policy-check/manifest.json")]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum SecurefixCommand {
    Capture {
        #[arg(long)]
        pull_request_number: u64,
        #[arg(long)]
        artifact_name: String,
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
    #[serde(default)]
    pub securefix_artifact: Option<SecurefixArtifactIdentity>,
    pub client_workflow_epoch: String,
    pub server_authority: securefix::api::NativeAuthoritySnapshot,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecurefixArtifactIdentity {
    pub id: u64,
    pub name: String,
    pub digest: String,
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
    pub head_branch: String,
    pub head_repository_id: u64,
    /// PR base commit from the authenticated pull-request response.
    pub base_sha: String,
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
    /// GitHub's event context SHA (GITHUB_SHA); for pull_request_target this is
    /// the PR base SHA, while source_sha remains the Actions run's PR head SHA.
    pub context_sha: String,
    /// Actions run API head_sha, independently checked against the run and PR.
    pub source_sha: String,
    pub workflow_path: String,
    /// Suffix of GITHUB_WORKFLOW_REF, bound to the verified certificate.
    pub workflow_ref: String,
    pub workflow_sha: String,
    pub actor_id: u64,
    pub actor_login: String,
}

impl RequestManifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol == PROTOCOL,
            "unsupported native request protocol"
        );
        match self.operation.as_str() {
            "policy_check" => ensure!(
                self.securefix_artifact.is_none(),
                "policy-check request unexpectedly names a Securefix artifact"
            ),
            "securefix" => {
                let artifact = self
                    .securefix_artifact
                    .as_ref()
                    .context("Securefix request lacks its source artifact identity")?;
                ensure!(
                    artifact.id > 0
                        && crate::securefix_gate::artifact::valid_artifact_name_for_cli(
                            &artifact.name
                        )
                        && (artifact.name.starts_with("securefix-")
                            || artifact.name.starts_with("testing-securefix-"))
                        && artifact.digest.len() == 71
                        && artifact.digest.starts_with("sha256:")
                        && artifact.digest[7..]
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                    "invalid Securefix source artifact identity"
                );
            }
            _ => anyhow::bail!("unsupported native request operation"),
        }
        securefix::policy::validate_repository(&self.repository.full_name)?;
        ensure!(self.repository.id > 0, "invalid request repository ID");
        ensure!(
            self.pull_request.number > 0
                && self.pull_request.head_repository_id > 0
                && self.pull_request.author_id > 0,
            "invalid pull request identity"
        );
        validate_sha(&self.pull_request.head_sha)?;
        validate_sha(&self.pull_request.base_sha)?;
        securefix::config::validate_branch(&self.pull_request.head_branch)?;
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
        validate_sha(&self.producer.context_sha)?;
        validate_sha(&self.producer.workflow_sha)?;
        validate_workflow_path(&self.producer.workflow_path)?;
        validate_workflow_ref(&self.producer.workflow_ref)?;
        validate_sha(&self.client_workflow_epoch)?;
        securefix::api::validate_native_authority_snapshot(&self.server_authority)?;
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
                output,
            } => capture_policy_check(pull_request_number, &output),
        },
        Command::Securefix { command } => match command {
            SecurefixCommand::Capture {
                pull_request_number,
                artifact_name,
                output,
            } => capture_securefix(pull_request_number, &artifact_name, &output),
        },
    }
}

fn capture_policy_check(pull_request_number: u64, output: &std::path::Path) -> Result<()> {
    capture_request(pull_request_number, "policy_check", None, output)
}

fn capture_securefix(
    pull_request_number: u64,
    artifact_name: &str,
    output: &std::path::Path,
) -> Result<()> {
    ensure!(
        crate::securefix_gate::artifact::valid_artifact_name_for_cli(artifact_name)
            && (artifact_name.starts_with("securefix-")
                || artifact_name.starts_with("testing-securefix-")),
        "invalid Securefix source artifact name"
    );
    capture_request(
        pull_request_number,
        "securefix",
        Some(artifact_name),
        output,
    )
}

fn capture_request(
    pull_request_number: u64,
    operation: &str,
    artifact_name: Option<&str>,
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
    let context_sha = std::env::var("GITHUB_SHA").context("missing GITHUB_SHA")?;
    validate_sha(&context_sha)?;
    let workflow_path = canonical_workflow_path(
        run["path"]
            .as_str()
            .context("request workflow path is missing")?,
    )?;
    let workflow_ref = capture_workflow_ref(&repository_name, &workflow_path)?;
    let actor_id = run["actor"]["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("request workflow actor ID is missing")?;
    let actor_login = run["actor"]["login"]
        .as_str()
        .context("request workflow actor login is missing")?
        .to_owned();

    let securefix_artifact = match artifact_name {
        Some(name) => Some(capture_artifact_identity(
            &api,
            &repository_name,
            run_id,
            repository_id,
            &source_sha,
            name,
        )?),
        None => None,
    };

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
    let base_sha = pull_request["base"]["sha"]
        .as_str()
        .context("pull request base SHA is missing")?
        .to_owned();
    validate_sha(&base_sha)?;
    let head_sha = pull_request["head"]["sha"]
        .as_str()
        .context("pull request head SHA is missing")?
        .to_owned();
    validate_sha(&head_sha)?;
    let head_branch = pull_request["head"]["ref"]
        .as_str()
        .context("pull request head branch is missing")?
        .to_owned();
    validate_pull_request_target_identity(
        &event,
        &source_sha,
        &context_sha,
        run["head_branch"]
            .as_str()
            .context("request workflow head branch is missing")?,
        &head_sha,
        &head_branch,
        &base_sha,
    )?;
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
    let client_workflow_epoch = securefix::api::capture_native_client_workflow_epoch(
        &api,
        &repository_name,
        repository_id,
        default_branch,
        &workflow_path,
        &workflow_sha,
    )?;
    let server_repository = std::env::var("SECUREFIX_SERVER_REPOSITORY")
        .context("missing SECUREFIX_SERVER_REPOSITORY")?;
    let server_config_path = std::env::var("SECUREFIX_INSTANCE_CONFIG_PATH")
        .context("missing SECUREFIX_INSTANCE_CONFIG_PATH")?;
    let (_, server_authority) =
        api.capture_remote_native_server_authority(&server_repository, &server_config_path)?;

    let manifest = RequestManifest {
        protocol: PROTOCOL.to_owned(),
        operation: operation.to_owned(),
        repository: RepositoryIdentity {
            id: repository_id,
            full_name: repository_name,
        },
        pull_request: PullRequestIdentity {
            number: pull_request_number,
            head_sha,
            head_branch,
            head_repository_id,
            base_sha,
            base_ref,
            author_id,
            author_login,
        },
        producer: ProducerIdentity {
            run_id,
            run_attempt,
            event,
            context_sha,
            source_sha,
            workflow_path,
            workflow_ref,
            workflow_sha,
            actor_id,
            actor_login,
        },
        securefix_artifact,
        client_workflow_epoch,
        server_authority,
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

fn capture_artifact_identity(
    api: &GitHub,
    repository: &str,
    run_id: u64,
    repository_id: u64,
    source_sha: &str,
    name: &str,
) -> Result<SecurefixArtifactIdentity> {
    const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
    let list: Value = api.get(&format!(
        "/repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"
    ))?;
    let artifacts = list["artifacts"]
        .as_array()
        .context("source run artifact list is missing")?;
    ensure!(
        list["total_count"].as_u64() == Some(artifacts.len() as u64),
        "source run artifact listing is incomplete"
    );
    let matches: Vec<_> = artifacts
        .iter()
        .filter(|artifact| artifact["name"] == name)
        .collect();
    ensure!(
        matches.len() == 1,
        "Securefix source artifact is missing or duplicated"
    );
    let id = matches[0]["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("Securefix source artifact ID is missing")?;
    let artifact: Value = api.get(&format!("/repos/{repository}/actions/artifacts/{id}"))?;
    let size = artifact["size_in_bytes"]
        .as_u64()
        .filter(|size| *size > 0 && *size <= MAX_ARTIFACT_BYTES)
        .context("Securefix source artifact size is invalid")?;
    let digest = artifact["digest"]
        .as_str()
        .context("Securefix source artifact has no digest")?
        .to_owned();
    validate_artifact_run_binding(&artifact, id, name, run_id, repository_id, source_sha)?;
    ensure!(
        artifact["expired"] == false
            && digest.len() == 71
            && digest.starts_with("sha256:")
            && digest[7..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "Securefix source artifact identity or run binding mismatch"
    );
    let bytes = api.download(
        &format!("/repos/{repository}/actions/artifacts/{id}/zip"),
        MAX_ARTIFACT_BYTES as usize,
    )?;
    ensure!(
        bytes.len() as u64 == size
            && format!(
                "sha256:{}",
                securefix::hex_encode(sha2::Sha256::digest(&bytes))
            ) == digest,
        "Securefix source artifact bytes differ from GitHub metadata"
    );
    Ok(SecurefixArtifactIdentity {
        id,
        name: name.to_owned(),
        digest,
    })
}

pub(crate) fn validate_artifact_run_binding(
    artifact: &Value,
    artifact_id: u64,
    artifact_name: &str,
    run_id: u64,
    repository_id: u64,
    source_sha: &str,
) -> Result<()> {
    ensure!(
        artifact["id"].as_u64() == Some(artifact_id)
            && artifact["name"] == artifact_name
            && artifact["workflow_run"]["id"].as_u64() == Some(run_id)
            && artifact["workflow_run"]["repository_id"].as_u64() == Some(repository_id)
            && artifact["workflow_run"]["head_sha"].as_str() == Some(source_sha),
        "artifact identity or workflow run binding mismatch"
    );
    Ok(())
}

pub(crate) fn validate_pull_request_target_identity(
    event: &str,
    source_sha: &str,
    context_sha: &str,
    run_branch: &str,
    head_sha: &str,
    head_branch: &str,
    base_sha: &str,
) -> Result<()> {
    if event == "pull_request_target" {
        ensure!(
            source_sha == head_sha && run_branch == head_branch && context_sha == base_sha,
            "pull_request_target run head and event context do not match the exact PR head and base"
        );
    }
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

fn capture_workflow_ref(repository: &str, workflow_path: &str) -> Result<String> {
    let full_ref = std::env::var("GITHUB_WORKFLOW_REF").context("missing GITHUB_WORKFLOW_REF")?;
    let prefix = format!("{repository}/{workflow_path}@");
    let reference = full_ref
        .strip_prefix(&prefix)
        .context("GITHUB_WORKFLOW_REF does not identify the API-reported caller workflow")?;
    validate_workflow_ref(reference)?;
    Ok(reference.to_owned())
}

fn validate_workflow_ref(reference: &str) -> Result<()> {
    ensure!(
        reference.starts_with("refs/")
            && reference.len() <= 512
            && !reference.contains(['\\', '%', '?', '#', '@'])
            && reference
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && reference
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte)),
        "invalid caller workflow ref"
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
                head_branch: "scratch".to_owned(),
                head_repository_id: 1410312556,
                base_sha: "e".repeat(40),
                base_ref: "main".to_owned(),
                author_id: 4525500,
                author_login: "civitaspo".to_owned(),
            },
            producer: ProducerIdentity {
                run_id: 39553607441,
                run_attempt: 1,
                event: "workflow_dispatch".to_owned(),
                context_sha: "d".repeat(40),
                source_sha: "b".repeat(40),
                workflow_path: ".github/workflows/testing-ci.yml".to_owned(),
                workflow_ref: "refs/heads/main".to_owned(),
                workflow_sha: "c".repeat(40),
                actor_id: 4525500,
                actor_login: "civitaspo".to_owned(),
            },
            securefix_artifact: None,
            client_workflow_epoch: "1".repeat(40),
            server_authority: securefix::api::NativeAuthoritySnapshot {
                instance_repository: "civitaspo/securefix-server".to_owned(),
                instance_id: 1,
                default_branch: "main".to_owned(),
                config_path: "repo-settings/managed-files/securefix-server.toml".to_owned(),
                config_sha256: "2".repeat(64),
                epoch: "3".repeat(40),
                workflows: vec![securefix::api::NativeWorkflowAuthority {
                    role: securefix::instance_config::WorkflowRole::PolicyCheck,
                    path: ".github/workflows/policy-check.yml".to_owned(),
                    sha256: "4".repeat(64),
                    pins: Vec::new(),
                }],
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
    fn client_manifest_carries_a_canonical_workflow_epoch() {
        let mut value = manifest();
        value.validate().unwrap();
        value.client_workflow_epoch = "not-a-sha".to_owned();
        assert!(value.validate().is_err());
    }

    #[test]
    fn securefix_request_requires_a_canonical_source_artifact_identity() {
        let mut request = manifest();
        request.operation = "securefix".to_owned();
        request.securefix_artifact = Some(SecurefixArtifactIdentity {
            id: 42,
            name: "testing-securefix-7-abcd".to_owned(),
            digest: format!("sha256:{}", "a".repeat(64)),
        });
        request.validate().unwrap();
        request.securefix_artifact.as_mut().unwrap().digest = format!("sha256:{}", "A".repeat(64));
        assert!(request.validate().is_err());
        request.securefix_artifact = None;
        assert!(request.validate().is_err());
    }

    #[test]
    fn source_artifact_binding_accepts_real_github_metadata_without_run_attempt() {
        let artifact: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/native-producer-artifact-response.json"
        ))
        .unwrap();
        assert!(artifact["workflow_run"].get("run_attempt").is_none());
        validate_artifact_run_binding(
            &artifact,
            12351518519,
            "securefix-39614598405-283e20a98e65",
            39614598405,
            1410312556,
            "a499b4ede1752c1ddb83e0651d74d1ce73faa76d",
        )
        .unwrap();
    }
}
