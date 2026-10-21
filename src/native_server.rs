//! Receiver-side validation for the initial native request protocol.
//!
//! This module accepts only a bounded manifest whose local GitHub artifact
//! attestation is verified by the official `gh` verifier. It can publish one
//! narrowly scoped scratch check after current-state fences.

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::PathBuf, process::Command, time::Duration};

use crate::native_client::RequestManifest;

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;
const MAX_ARTIFACT_ARCHIVE_BYTES: usize = 2 * 1024 * 1024;
const MAX_VERIFIER_OUTPUT_BYTES: u64 = 1024 * 1024;
const SLSA_PREDICATE: &str = "https://slsa.dev/provenance/v1";
const REQUEST_ARTIFACT_NAME: &str = "native-request-proof";

#[derive(clap::Subcommand)]
pub enum CommandArgs {
    #[command(about = "Validate one native request and its producer attestation")]
    PolicyCheck {
        #[arg(long)]
        config: PathBuf,
        /// Explicit path, relative to the Server instance repository root.
        #[arg(long)]
        config_path: String,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        /// Create the scratch-only proof check after all current-state fences pass.
        #[arg(long, default_value_t = false)]
        publish: bool,
    },
}

pub fn run(command: CommandArgs) -> Result<()> {
    match command {
        CommandArgs::PolicyCheck {
            config,
            config_path,
            manifest,
            bundle,
            publish,
        } => {
            let verified = verify_request(&config, &config_path, &manifest, &bundle, publish)?;
            if publish {
                publish_scratch_result(&verified)?;
            }
            println!(
                "request_sha256={}",
                securefix::hex_encode(Sha256::digest(&verified.manifest_bytes))
            );
            println!("producer_run_id={}", verified.manifest.producer.run_id);
            println!(
                "producer_run_attempt={}",
                verified.manifest.producer.run_attempt
            );
            println!(
                "request_head_sha={}",
                verified.manifest.pull_request.head_sha
            );
            println!("result_published={publish}");
            Ok(())
        }
    }
}

struct VerifiedRequest {
    config: securefix::instance_config::InstanceConfig,
    manifest: RequestManifest,
    manifest_bytes: Vec<u8>,
    writer: Option<securefix::api::GitHub>,
}

fn verify_request(
    config_path: &std::path::Path,
    instance_config_path: &str,
    manifest_path: &std::path::Path,
    bundle_path: &std::path::Path,
    publish: bool,
) -> Result<VerifiedRequest> {
    let config_bytes = read_bounded(config_path, 256 * 1024)?;
    let config = securefix::instance_config::InstanceConfig::parse(&config_bytes)?;
    securefix::api::validate_native_instance_config_path(instance_config_path)?;
    let manifest_bytes = read_bounded(manifest_path, MAX_REQUEST_BYTES)?;
    let manifest: RequestManifest =
        serde_json::from_slice(&manifest_bytes).context("parse native request manifest")?;
    manifest.validate()?;
    ensure!(
        manifest.authority.config_path == instance_config_path
            && config.instance.repository == manifest.repository.full_name
            && config.instance.id == manifest.repository.id
            && config.instance.default_branch == manifest.pull_request.base_ref
            && securefix::hex_encode(Sha256::digest(&config_bytes))
                == manifest.authority.config_sha256,
        "native request was captured under a different instance configuration"
    );
    ensure!(
        config.repositories.iter().any(|repository| {
            repository.id == manifest.repository.id
                && repository.repository == manifest.repository.full_name
                && repository
                    .capabilities
                    .contains(&securefix::policy::Capability::Merge)
        }),
        "native request repository is not configured for policy checks"
    );
    validate_first_slice_policy(&config, &manifest)?;
    let writer = if publish {
        Some(native_scratch_writer(
            &config,
            &config_bytes,
            instance_config_path,
            &manifest,
            &manifest_bytes,
        )?)
    } else {
        None
    };
    let bundle_bytes = read_bounded(bundle_path, MAX_BUNDLE_BYTES)?;
    ensure!(!bundle_bytes.is_empty(), "attestation bundle is empty");

    let token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
    ensure!(!token.is_empty(), "GITHUB_TOKEN is empty");
    let api = securefix::api::GitHub::new("https://api.github.com", token)?;
    let acceptable_client: Value =
        api.get(&format!("/repos/{}", config.acceptable_clients.repository))?;
    ensure!(
        acceptable_client["id"].as_u64() == Some(config.acceptable_clients.id)
            && acceptable_client["full_name"].as_str()
                == Some(config.acceptable_clients.repository.as_str()),
        "configured Client repository identity mismatch"
    );
    let producer_repository = &manifest.repository.full_name;
    let run: Value = api.get(&format!(
        "/repos/{producer_repository}/actions/runs/{}",
        manifest.producer.run_id
    ))?;
    verify_run_identity(&run, &manifest)?;
    verify_artifact_binding(&api, &manifest, manifest_path, bundle_path)?;
    verify_current_pull_request(&api, &manifest)?;
    crate::request::validate_native_pr_commit_policy(
        &api,
        &manifest.repository.full_name,
        manifest.pull_request.number,
        &manifest.pull_request.head_sha,
        &config.policy.trusted_committers,
    )?;
    let current_authority = securefix::api::capture_native_authority_snapshot(
        &api,
        &manifest.repository.full_name,
        manifest.repository.id,
        &manifest.pull_request.base_ref,
        instance_config_path,
        &manifest.producer.workflow_path,
        &manifest.producer.workflow_sha,
    )?;
    securefix::api::require_native_authority_unchanged(&manifest.authority, &current_authority)?;

    let references: Vec<securefix::workflow::ReferencedWorkflow> = serde_json::from_value(
        run.get("referenced_workflows")
            .cloned()
            .context("source run has no reusable-workflow references")?,
    )
    .context("parse reusable-workflow references")?;
    let signer_prefix = format!(
        "{}/{}@",
        config.acceptable_clients.repository, config.acceptable_clients.producer_workflow
    );
    let signer_reference = references
        .iter()
        .filter(|reference| reference.path.starts_with(&signer_prefix))
        .collect::<Vec<_>>();
    ensure!(
        signer_reference.len() == 1,
        "source run does not name exactly one configured Client producer workflow"
    );
    let signer_sha = &signer_reference[0].sha;
    securefix::policy::validate_sha(signer_sha)?;
    let caller_yaml = api.content(
        &manifest.repository.full_name,
        &manifest.producer.workflow_path,
        &manifest.producer.workflow_sha,
    )?;
    securefix::workflow::require_reusable_correspondence(
        &references,
        &manifest.producer.workflow_sha,
        &caller_yaml,
        &config.acceptable_clients.repository,
        &config.acceptable_clients.producer_workflow,
        signer_sha,
    )?;

    let verified = verify_with_gh(
        manifest_path,
        bundle_path,
        &manifest.repository.full_name,
        &config.acceptable_clients.repository,
        &config.acceptable_clients.producer_workflow,
        signer_sha,
    )?;
    verify_certificate(
        &verified,
        &manifest,
        &run,
        &config.acceptable_clients.repository,
        &config.acceptable_clients.producer_workflow,
        signer_sha,
        &manifest_bytes,
    )?;
    Ok(VerifiedRequest {
        config,
        manifest,
        manifest_bytes,
        writer,
    })
}

fn verify_run_identity(run: &Value, manifest: &RequestManifest) -> Result<()> {
    ensure!(
        run["id"].as_u64() == Some(manifest.producer.run_id)
            && run["run_attempt"].as_u64() == Some(u64::from(manifest.producer.run_attempt))
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && run["event"].as_str() == Some(manifest.producer.event.as_str())
            && run["head_sha"].as_str() == Some(manifest.producer.source_sha.as_str())
            && run["repository"]["id"].as_u64() == Some(manifest.repository.id)
            && run["repository"]["full_name"].as_str()
                == Some(manifest.repository.full_name.as_str())
            && run["head_branch"]
                .as_str()
                .is_some_and(|branch| { securefix::config::validate_branch(branch).is_ok() })
            && run["actor"]["id"].as_u64() == Some(manifest.producer.actor_id)
            && run["actor"]["login"].as_str() == Some(manifest.producer.actor_login.as_str())
            && run["path"].as_str() == Some(manifest.producer.workflow_path.as_str()),
        "native request producer run identity or conclusion mismatch"
    );
    Ok(())
}

fn verify_current_pull_request(
    api: &securefix::api::GitHub,
    manifest: &RequestManifest,
) -> Result<()> {
    let repository = &manifest.repository.full_name;
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    let pull: Value = api.get(&format!(
        "/repos/{repository}/pulls/{}",
        manifest.pull_request.number
    ))?;
    validate_current_pull_request_state(&repo, &pull, manifest)
}

fn validate_current_pull_request_state(
    repo: &Value,
    pull: &Value,
    manifest: &RequestManifest,
) -> Result<()> {
    let repository = &manifest.repository.full_name;
    ensure!(
        repo["id"].as_u64() == Some(manifest.repository.id)
            && repo["full_name"].as_str() == Some(repository.as_str())
            && pull["number"].as_u64() == Some(manifest.pull_request.number)
            && pull["state"] == "open"
            && pull["base"]["repo"]["id"].as_u64() == Some(manifest.repository.id)
            && pull["base"]["repo"]["full_name"].as_str() == Some(repository.as_str())
            && pull["base"]["ref"].as_str() == Some(manifest.pull_request.base_ref.as_str())
            && pull["head"]["sha"].as_str() == Some(manifest.pull_request.head_sha.as_str())
            && pull["head"]["repo"]["id"].as_u64()
                == Some(manifest.pull_request.head_repository_id)
            && pull["user"]["id"].as_u64() == Some(manifest.pull_request.author_id)
            && manifest.pull_request.author_id == manifest.producer.actor_id
            && manifest.pull_request.author_login == manifest.producer.actor_login
            && pull["user"]["login"].as_str() == Some(manifest.pull_request.author_login.as_str()),
        "native request PR is closed, retargeted, or has a different head or identity"
    );
    ensure!(
        repo["default_branch"].as_str() == Some(manifest.pull_request.base_ref.as_str()),
        "native request PR does not target the repository default branch"
    );
    Ok(())
}

fn validate_first_slice_policy(
    config: &securefix::instance_config::InstanceConfig,
    manifest: &RequestManifest,
) -> Result<()> {
    let repository = config
        .repositories
        .iter()
        .find(|repository| {
            repository.repository == manifest.repository.full_name
                && repository.id == manifest.repository.id
        })
        .context("native request repository is not configured")?;
    ensure!(
        repository
            .capabilities
            .contains(&securefix::policy::Capability::Merge),
        "native request repository lacks merge capability"
    );
    ensure!(
        config.identities.owner.id == manifest.producer.actor_id
            && config.identities.owner.login == manifest.producer.actor_login
            && config.identities.owner.id == manifest.pull_request.author_id
            && config.identities.owner.login == manifest.pull_request.author_login,
        "first-slice policy requires the configured owner as producer actor and PR author"
    );
    Ok(())
}

fn native_scratch_writer(
    config: &securefix::instance_config::InstanceConfig,
    config_bytes: &[u8],
    config_path: &str,
    manifest: &RequestManifest,
    manifest_bytes: &[u8],
) -> Result<securefix::api::GitHub> {
    let request_sha256 = securefix::hex_encode(Sha256::digest(manifest_bytes));
    let target = securefix::api::NativeScratchTarget {
        repository: &manifest.repository.full_name,
        repository_id: manifest.repository.id,
        pull_number: manifest.pull_request.number,
        head_sha: &manifest.pull_request.head_sha,
        head_repository_id: manifest.pull_request.head_repository_id,
        base_ref: &manifest.pull_request.base_ref,
        author_id: manifest.pull_request.author_id,
        author_login: &manifest.pull_request.author_login,
        actor_id: manifest.producer.actor_id,
        actor_login: &manifest.producer.actor_login,
        request_sha256: &request_sha256,
        authority: &manifest.authority,
        caller_workflow_path: &manifest.producer.workflow_path,
        caller_workflow_sha: &manifest.producer.workflow_sha,
    };
    securefix::api::GitHub::native_scratch_from_env(
        "SECUREFIX_NATIVE_CHECK_TOKEN",
        config,
        config_path,
        config_bytes,
        &target,
    )
}

fn publish_scratch_result(verified: &VerifiedRequest) -> Result<()> {
    let manifest = &verified.manifest;
    let api = verified
        .writer
        .as_ref()
        .context("native scratch writer was not captured before proof validation")?;
    let checks: Value = api.get(&format!(
        "/repos/{}/commits/{}/check-runs?per_page=100&page=1&filter=latest&check_name={}&app_id={}",
        manifest.repository.full_name,
        manifest.pull_request.head_sha,
        securefix::api::NATIVE_POLICY_CHECK_NAME,
        verified.config.apps.policy_check_id
    ))?;
    let existing = checks["check_runs"]
        .as_array()
        .context("native check listing is missing")?;
    ensure!(
        checks["total_count"].as_u64() == Some(existing.len() as u64) && existing.is_empty(),
        "native request proof check already exists or check listing is incomplete"
    );
    let request_sha = securefix::hex_encode(Sha256::digest(&verified.manifest_bytes));
    let body =
        securefix::api::native_policy_check_body(&manifest.pull_request.head_sha, &request_sha);
    let result: Value = api.post(
        &format!("/repos/{}/check-runs", manifest.repository.full_name),
        &body,
    )?;
    ensure!(
        result["name"] == securefix::api::NATIVE_POLICY_CHECK_NAME
            && result["head_sha"].as_str() == Some(manifest.pull_request.head_sha.as_str())
            && result["status"] == "completed"
            && result["conclusion"] == "success"
            && result["app"]["id"].as_u64() == Some(verified.config.apps.policy_check_id),
        "GitHub returned a different native request proof check"
    );
    println!("native_check_run_id={}", result["id"]);
    Ok(())
}

fn verify_artifact_binding(
    api: &securefix::api::GitHub,
    manifest: &RequestManifest,
    manifest_path: &std::path::Path,
    bundle_path: &std::path::Path,
) -> Result<()> {
    let repository = &manifest.repository.full_name;
    let run_artifacts: Value = api.get(&format!(
        "/repos/{repository}/actions/runs/{}/artifacts?per_page=100",
        manifest.producer.run_id
    ))?;
    let artifacts = run_artifacts["artifacts"]
        .as_array()
        .context("producer artifact list is missing")?;
    ensure!(
        run_artifacts["total_count"].as_u64() == Some(artifacts.len() as u64),
        "producer artifact listing is incomplete"
    );
    let matches: Vec<_> = artifacts
        .iter()
        .filter(|artifact| artifact["name"] == REQUEST_ARTIFACT_NAME)
        .collect();
    ensure!(
        matches.len() == 1,
        "producer run must contain one native request artifact"
    );
    let artifact_id = matches[0]["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("native request artifact ID is missing")?;
    let artifact: Value = api.get(&format!(
        "/repos/{repository}/actions/artifacts/{artifact_id}"
    ))?;
    ensure!(
        artifact["id"].as_u64() == Some(artifact_id)
            && artifact["name"] == REQUEST_ARTIFACT_NAME
            && artifact["expired"] == false
            && artifact["workflow_run"]["id"].as_u64() == Some(manifest.producer.run_id)
            && artifact["workflow_run"]["repository_id"].as_u64() == Some(manifest.repository.id)
            && artifact["workflow_run"]["head_sha"].as_str()
                == Some(manifest.producer.source_sha.as_str()),
        "native request artifact is not bound to the claimed producer run"
    );
    let declared_size = artifact["size_in_bytes"]
        .as_u64()
        .filter(|size| *size > 0 && *size <= MAX_ARTIFACT_ARCHIVE_BYTES as u64)
        .context("native request artifact size is invalid")?;
    let declared_digest = artifact["digest"]
        .as_str()
        .and_then(|value| value.strip_prefix("sha256:"))
        .context("native request artifact has no SHA-256 digest")?;
    ensure!(
        declared_digest.len() == 64
            && declared_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "native request artifact digest is not canonical SHA-256"
    );
    let zip_bytes = api.download(
        &format!("/repos/{repository}/actions/artifacts/{artifact_id}/zip"),
        MAX_ARTIFACT_ARCHIVE_BYTES,
    )?;
    ensure!(
        zip_bytes.len() as u64 == declared_size
            && securefix::hex_encode(Sha256::digest(&zip_bytes)) == declared_digest,
        "native request artifact bytes differ from GitHub metadata"
    );
    let (archived_manifest, archived_bundle) = request_files_from_zip(&zip_bytes)?;
    ensure!(
        archived_manifest == read_bounded(manifest_path, MAX_REQUEST_BYTES)?
            && archived_bundle == read_bounded(bundle_path, MAX_BUNDLE_BYTES)?,
        "local request files differ from the identified producer artifact"
    );
    Ok(())
}

fn request_files_from_zip(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    ensure!(
        archive.len() == 2,
        "request artifact must contain exactly two files"
    );
    let mut manifest = None;
    let mut bundle = None;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        ensure!(
            file.is_file()
                && file
                    .unix_mode()
                    .is_none_or(|mode| { matches!(mode & 0o170000, 0 | 0o100000) }),
            "request artifact contains a non-regular file"
        );
        let (slot, max) = match file.name() {
            "manifest.json" => (&mut manifest, MAX_REQUEST_BYTES),
            "bundle.json" => (&mut bundle, MAX_BUNDLE_BYTES),
            _ => anyhow::bail!("request artifact contains an unexpected file"),
        };
        ensure!(slot.is_none(), "request artifact contains a duplicate file");
        let size = file.size();
        ensure!(
            size <= max as u64,
            "request artifact file exceeds size limit"
        );
        let mut content = Vec::with_capacity(size as usize);
        (&mut file).take(max as u64 + 1).read_to_end(&mut content)?;
        ensure!(
            content.len() as u64 == size,
            "request artifact file size mismatch"
        );
        *slot = Some(content);
    }
    Ok((
        manifest.context("request artifact is missing manifest.json")?,
        bundle.context("request artifact is missing bundle.json")?,
    ))
}

fn verify_with_gh(
    manifest: &std::path::Path,
    bundle: &std::path::Path,
    attestation_repository: &str,
    signer_repository: &str,
    signer_workflow: &str,
    signer_sha: &str,
) -> Result<Value> {
    let path = format!("{signer_repository}/{signer_workflow}");
    let isolation = tempfile::tempdir()?;
    let output_path = isolation.path().join("verifier-output.json");
    let output_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)?;
    let mut child = Command::new("gh")
        .arg("attestation")
        .arg("verify")
        .arg(manifest)
        .arg("--bundle")
        .arg(bundle)
        .arg("--repo")
        .arg(attestation_repository)
        .arg("--signer-workflow")
        .arg(path)
        .arg("--signer-digest")
        .arg(signer_sha)
        .arg("--cert-oidc-issuer")
        .arg("https://token.actions.githubusercontent.com")
        .arg("--predicate-type")
        .arg(SLSA_PREDICATE)
        .arg("--deny-self-hosted-runners")
        .arg("--format=json")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .env_remove("GH_ENTERPRISE_TOKEN")
        .env_remove("GITHUB_ENTERPRISE_TOKEN")
        .env("GH_CONFIG_DIR", isolation.path())
        .env("HOME", isolation.path())
        .env("XDG_CACHE_HOME", isolation.path().join("cache"))
        .stdout(output_file)
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start GitHub attestation verifier")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if fs::metadata(&output_path)?.len() > MAX_VERIFIER_OUTPUT_BYTES
            || std::time::Instant::now() >= deadline
        {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&output_path);
            anyhow::bail!("GitHub attestation verification exceeded its bounds");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let output = read_bounded(&output_path, MAX_VERIFIER_OUTPUT_BYTES as usize)?;
    let _ = fs::remove_file(&output_path);
    ensure!(status.success(), "GitHub attestation verification failed");
    serde_json::from_slice(&output).context("parse GitHub attestation verifier result")
}

fn verify_certificate(
    verified: &Value,
    manifest: &RequestManifest,
    run: &Value,
    signer_repository: &str,
    signer_workflow: &str,
    signer_sha: &str,
    manifest_bytes: &[u8],
) -> Result<()> {
    ensure!(
        verified
            .as_array()
            .is_some_and(|results| results.len() == 1),
        "attestation verifier must return exactly one result"
    );
    let result = &verified[0]["verificationResult"];
    let certificate = &result["signature"]["certificate"];
    let statement = &result["statement"];
    let expected_run = format!(
        "https://github.com/{}/actions/runs/{}/attempts/{}",
        manifest.repository.full_name, manifest.producer.run_id, manifest.producer.run_attempt
    );
    let expected_signer =
        format!("https://github.com/{signer_repository}/{signer_workflow}@{signer_sha}");
    let expected_config_prefix = format!(
        "https://github.com/{}/{}@",
        manifest.repository.full_name, manifest.producer.workflow_path
    );
    let workflow_ref = certificate["githubWorkflowRef"]
        .as_str()
        .context("attestation caller workflow ref is missing")?;
    let run_branch = run["head_branch"]
        .as_str()
        .context("producer run branch is missing")?;
    securefix::config::validate_branch(run_branch)?;
    let expected_workflow_ref = format!("refs/heads/{run_branch}");
    let expected_config = format!("{expected_config_prefix}{workflow_ref}");
    let owner_id = run["repository"]["owner"]["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("producer repository owner ID is missing")?;
    ensure!(
        certificate["issuer"] == "https://token.actions.githubusercontent.com"
            && certificate["githubWorkflowRepository"].as_str()
                == Some(manifest.repository.full_name.as_str())
            && certificate["githubWorkflowSHA"].as_str()
                == Some(manifest.producer.source_sha.as_str())
            && certificate["buildConfigDigest"].as_str()
                == Some(manifest.producer.workflow_sha.as_str())
            && workflow_ref == expected_workflow_ref
            && certificate["buildConfigURI"].as_str() == Some(expected_config.as_str())
            && certificate["githubWorkflowTrigger"].as_str()
                == Some(manifest.producer.event.as_str())
            && certificate["sourceRepositoryURI"]
                == format!("https://github.com/{}", manifest.repository.full_name)
            && certificate["sourceRepositoryDigest"].as_str()
                == Some(manifest.producer.source_sha.as_str())
            && certificate["sourceRepositoryIdentifier"]
                .as_str()
                .is_some_and(|value| value.parse::<u64>().ok() == Some(manifest.repository.id))
            && certificate["sourceRepositoryOwnerIdentifier"]
                .as_str()
                .is_some_and(|value| value.parse::<u64>().ok() == Some(owner_id))
            && certificate["runInvocationURI"].as_str() == Some(expected_run.as_str())
            && certificate["runnerEnvironment"] == "github-hosted"
            && certificate["buildSignerDigest"].as_str() == Some(signer_sha)
            && certificate["buildSignerURI"].as_str() == Some(expected_signer.as_str())
            && certificate["subjectAlternativeName"].as_str() == Some(expected_signer.as_str()),
        "attestation certificate does not match the configured producer run"
    );
    let expected_sha = securefix::hex_encode(Sha256::digest(manifest_bytes));
    let subjects = statement["subject"]
        .as_array()
        .context("attested subject is missing")?;
    ensure!(
        statement["predicateType"] == SLSA_PREDICATE
            && subjects.len() == 1
            && subjects[0]["name"] == "manifest.json"
            && subjects[0]["digest"]["sha256"].as_str() == Some(expected_sha.as_str()),
        "attestation subject differs from the request manifest bytes"
    );
    Ok(())
}

fn read_bounded(path: &std::path::Path, max: usize) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "{} is not a regular file",
        path.display()
    );
    let mut file = fs::File::open(path).with_context(|| format!("read {}", path.display()))?;
    let mut bytes = Vec::with_capacity(metadata.len().min(max as u64) as usize);
    (&mut file).take(max as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max, "{} exceeds size limit", path.display());
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> RequestManifest {
        RequestManifest {
            protocol: "securefix-native-request/v1".to_owned(),
            operation: "policy_check".to_owned(),
            repository: crate::native_client::RepositoryIdentity {
                id: 10,
                full_name: "owner/project".to_owned(),
            },
            pull_request: crate::native_client::PullRequestIdentity {
                number: 7,
                head_sha: "d".repeat(40),
                head_repository_id: 10,
                base_ref: "main".to_owned(),
                author_id: 11,
                author_login: "contributor".to_owned(),
            },
            producer: crate::native_client::ProducerIdentity {
                run_id: 42,
                run_attempt: 2,
                event: "workflow_dispatch".to_owned(),
                source_sha: "a".repeat(40),
                workflow_path: ".github/workflows/client.yml".to_owned(),
                workflow_sha: "b".repeat(40),
                actor_id: 12,
                actor_login: "maintainer".to_owned(),
            },
            authority: securefix::api::NativeAuthoritySnapshot {
                config_path: "securefix-server.toml".to_owned(),
                config_sha256: "1".repeat(64),
                config_epoch: "2".repeat(40),
                workflow_sha256: "3".repeat(64),
                workflow_epoch: "4".repeat(40),
            },
        }
    }

    fn verifier_result(manifest: &RequestManifest, run_invocation: String) -> Value {
        let bytes = serde_json::to_vec(manifest).unwrap();
        let subject_sha = securefix::hex_encode(Sha256::digest(&bytes));
        let signer_sha = "c".repeat(40);
        let signer = format!(
            "https://github.com/client-org/securefix-client/.github/workflows/request-producer.yml@{signer_sha}"
        );
        let config = format!(
            "https://github.com/{}/{}@refs/heads/main",
            manifest.repository.full_name, manifest.producer.workflow_path
        );
        serde_json::json!([{
            "verificationResult": {
                "signature": { "certificate": {
                    "issuer": "https://token.actions.githubusercontent.com",
                    "githubWorkflowRepository": manifest.repository.full_name,
                    "githubWorkflowSHA": manifest.producer.source_sha,
                    "buildConfigDigest": manifest.producer.workflow_sha,
                    "buildConfigURI": config,
                    "githubWorkflowRef": "refs/heads/main",
                    "githubWorkflowTrigger": manifest.producer.event,
                    "sourceRepositoryURI": format!("https://github.com/{}", manifest.repository.full_name),
                    "sourceRepositoryDigest": manifest.producer.source_sha,
                    "sourceRepositoryIdentifier": "10",
                    "sourceRepositoryOwnerIdentifier": "20",
                    "runInvocationURI": run_invocation,
                    "runnerEnvironment": "github-hosted",
                    "buildSignerDigest": signer_sha,
                    "buildSignerURI": signer,
                    "subjectAlternativeName": signer
                }},
                "statement": {
                    "predicateType": SLSA_PREDICATE,
                    "subject": [{"name":"manifest.json","digest":{"sha256":subject_sha}}],
                    "predicate": {"runDetails":{"metadata":{"invocationId":"untrusted"}}}
                }
            }
        }])
    }

    #[test]
    fn accepts_attested_caller_and_source_sha_as_distinct_claims() {
        let manifest = manifest();
        let run = serde_json::json!({
            "head_branch":"main",
            "repository":{"owner":{"id":20}}
        });
        let invocation = "https://github.com/owner/project/actions/runs/42/attempts/2";
        let verified = verifier_result(&manifest, invocation.to_owned());
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert!(
            verify_certificate(
                &verified,
                &manifest,
                &run,
                "client-org/securefix-client",
                ".github/workflows/request-producer.yml",
                &"c".repeat(40),
                &bytes,
            )
            .is_ok()
        );
        assert_ne!(manifest.producer.source_sha, manifest.producer.workflow_sha);
    }

    #[test]
    fn rejects_replayed_run_and_predicate_only_provenance() {
        let manifest = manifest();
        let run = serde_json::json!({
            "head_branch":"main",
            "repository":{"owner":{"id":20}}
        });
        let verified = verifier_result(
            &manifest,
            "https://github.com/owner/project/actions/runs/41/attempts/2".to_owned(),
        );
        let bytes = serde_json::to_vec(&manifest).unwrap();
        assert!(
            verify_certificate(
                &verified,
                &manifest,
                &run,
                "client-org/securefix-client",
                ".github/workflows/request-producer.yml",
                &"c".repeat(40),
                &bytes,
            )
            .is_err()
        );
    }

    #[test]
    fn bounded_reader_stops_after_limit_plus_one() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large");
        fs::write(&path, vec![b'x'; 64]).unwrap();
        assert!(read_bounded(&path, 32).is_err());
    }

    #[test]
    fn request_artifact_requires_exact_bounded_regular_files() {
        fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
            let cursor = std::io::Cursor::new(Vec::new());
            let mut writer = zip::ZipWriter::new(cursor);
            for (name, bytes) in entries {
                writer
                    .start_file(*name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                std::io::Write::write_all(&mut writer, bytes).unwrap();
            }
            writer.finish().unwrap().into_inner()
        }
        let manifest = b"{}";
        let bundle = b"{}";
        let valid = archive(&[("manifest.json", manifest), ("bundle.json", bundle)]);
        assert_eq!(
            request_files_from_zip(&valid).unwrap(),
            (manifest.to_vec(), bundle.to_vec())
        );
        let forged = archive(&[("manifest.json", manifest)]);
        assert!(request_files_from_zip(&forged).is_err());
        let extra = archive(&[
            ("manifest.json", manifest),
            ("bundle.json", bundle),
            ("extra.txt", b"x"),
        ]);
        assert!(request_files_from_zip(&extra).is_err());
    }

    #[test]
    fn first_slice_policy_requires_configured_merge_owner_actor_and_author() {
        let config = securefix::instance_config::InstanceConfig::parse(include_bytes!(
            "../tests/fixtures/instance-config.toml"
        ))
        .unwrap();
        let mut request = manifest();
        request.repository = crate::native_client::RepositoryIdentity {
            id: 987654,
            full_name: "example-org/project".to_owned(),
        };
        request.pull_request.head_repository_id = 987654;
        request.pull_request.author_id = 101;
        request.pull_request.author_login = "maintainer".to_owned();
        request.producer.actor_id = 101;
        request.producer.actor_login = "maintainer".to_owned();
        assert!(validate_first_slice_policy(&config, &request).is_ok());

        request.producer.actor_id = 12;
        assert!(validate_first_slice_policy(&config, &request).is_err());
        request.producer.actor_id = 101;
        request.pull_request.author_login = "contributor".to_owned();
        assert!(validate_first_slice_policy(&config, &request).is_err());
    }

    #[test]
    fn stale_pull_request_head_is_rejected() {
        let mut request = manifest();
        request.pull_request.author_id = request.producer.actor_id;
        request.pull_request.author_login = request.producer.actor_login.clone();
        let repo = serde_json::json!({
            "id":10,"full_name":"owner/project","default_branch":"main"
        });
        let pull = serde_json::json!({
            "number":7,"state":"open",
            "base":{"repo":{"id":10,"full_name":"owner/project"},"ref":"main"},
            "head":{"repo":{"id":10},"sha":request.pull_request.head_sha},
            "user":{"id":12,"login":"maintainer"}
        });
        assert!(validate_current_pull_request_state(&repo, &pull, &request).is_ok());
        request.pull_request.head_sha = "e".repeat(40);
        assert!(validate_current_pull_request_state(&repo, &pull, &request).is_err());
    }
}
