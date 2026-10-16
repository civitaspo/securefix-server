use crate::{
    api::{ApiError, GitHub},
    config, runtime,
};
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command as Process, Stdio},
};

const ACTIVE_PATH: &str = "control/active.json";
const CONTROL_WORKFLOW: &str = ".github/workflows/control-activation.yml";
const PUBLISH_WORKFLOW: &str = ".github/workflows/publish-runtime.yml";
const TEST_WORKFLOW: &str = ".github/workflows/testing-securefix-server.yml";
const SCRATCH_ARTIFACT: &str = "scratch-fixtures";
const MAX_ARTIFACT_SIZE: usize = 64 * 1024;
const MAX_FIXTURE_FILE: u64 = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedMetadata {
    version: u32,
    expected_control_id: String,
    next_control_id: String,
    source_sha: String,
    publisher_run_id: u64,
    verification_run_id: u64,
}

#[derive(Subcommand)]
pub enum Command {
    /// Print the validated identity of a control descriptor.
    Identify {
        #[arg(long)]
        descriptor: PathBuf,
    },
    /// Verify runtime publication and candidate testing, then write the successor descriptor.
    Prepare {
        #[arg(long)]
        source_sha: String,
        #[arg(long)]
        publisher_run_id: u64,
        #[arg(long)]
        verification_run_id: u64,
        #[arg(long)]
        expected_control_id: String,
        #[arg(long, default_value = "control-migration")]
        directory: PathBuf,
    },
    /// Revalidate prepared evidence and open the signed activation pull request.
    Propose {
        #[arg(long)]
        source_sha: String,
        #[arg(long)]
        publisher_run_id: u64,
        #[arg(long)]
        verification_run_id: u64,
        #[arg(long)]
        expected_control_id: String,
        #[arg(long, default_value = "control-migration")]
        directory: PathBuf,
    },
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Identify { descriptor } => identify(&descriptor),
        Command::Prepare {
            source_sha,
            publisher_run_id,
            verification_run_id,
            expected_control_id,
            directory,
        } => {
            require_activation_workflow()?;
            let api = read_api()?;
            let (current, successor) = validate_request(
                &api,
                &source_sha,
                publisher_run_id,
                verification_run_id,
                &expected_control_id,
            )?;
            write_prepared(&directory, &current, &successor)?;
            emit_descriptor(&successor)?;
            securefix::output("files", ACTIVE_PATH)?;
            securefix::output("repository_name", server_repository_name()?)
        }
        Command::Propose {
            source_sha,
            publisher_run_id,
            verification_run_id,
            expected_control_id,
            directory,
        } => {
            require_activation_workflow()?;
            let read = read_api()?;
            let (current, successor) = validate_request(
                &read,
                &source_sha,
                publisher_run_id,
                verification_run_id,
                &expected_control_id,
            )?;
            validate_prepared(&directory, &current, &successor)?;

            let write = GitHub::from_env("SECUREFIX_CONTROL_WRITE_TOKEN")?
                .with_control_revision(&current)?;
            let trusted = config::trusted()?;
            let installation: Value = write.get("/installation/repositories?per_page=100")?;
            let repositories = installation["repositories"].as_array();
            ensure!(
                installation["total_count"] == 1
                    && repositories.is_some_and(|repos| {
                        repos.len() == 1
                            && repos[0]["full_name"] == trusted.deployment.server.repository
                            && repos[0]["id"].as_u64() == Some(trusted.deployment.server.id)
                    }),
                "control write token must be installed only on the server repository"
            );
            let number = create_activation_pr(&write, &current, &successor)?;
            securefix::output("pull_request_number", number.to_string())
        }
    }
}

fn identify(path: &Path) -> Result<()> {
    let bytes = read_bounded(path, 16 * 1024)?;
    let descriptor = parse_descriptor(&bytes)?;
    println!("control-id={}", descriptor.identity()?);
    println!("source-sha={}", descriptor.source_sha);
    println!("generation={}", descriptor.generation);
    println!("policy-sha256={}", descriptor.policy_sha256);
    println!("archive-sha256={}", descriptor.archive_sha256);
    println!("release-id={}", descriptor.release_id);
    println!("asset-id={}", descriptor.asset_id);
    Ok(())
}

fn read_api() -> Result<GitHub> {
    let token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
    ensure!(!token.is_empty(), "GITHUB_TOKEN is empty");
    GitHub::new("https://api.github.com", token)
}

fn server_repository_name() -> Result<&'static str> {
    config::trusted()?
        .deployment
        .server
        .repository
        .split('/')
        .nth(1)
        .context("configured server repository is invalid")
}

fn require_activation_workflow() -> Result<()> {
    let trusted = config::trusted()?;
    let server = &trusted.deployment.server;
    ensure!(
        std::env::var("GITHUB_REPOSITORY").is_ok_and(|value| value == server.repository)
            && std::env::var("GITHUB_REF")
                .is_ok_and(|value| value == format!("refs/heads/{}", server.default_branch))
            && std::env::var("GITHUB_EVENT_NAME").is_ok_and(|value| value == "workflow_dispatch")
            && std::env::var("GITHUB_WORKFLOW_REF").is_ok_and(|value| {
                value
                    == format!(
                        "{}/{CONTROL_WORKFLOW}@refs/heads/{}",
                        server.repository, server.default_branch
                    )
            })
            && std::env::var("GITHUB_ACTOR_ID")
                .is_ok_and(|value| value.parse::<u64>().ok() == Some(trusted.owner_id))
            && std::env::var("GITHUB_RUN_ATTEMPT").is_ok_and(|value| value == "1"),
        "control activation requires a first-attempt owner dispatch from protected main"
    );
    let sha = std::env::var("GITHUB_SHA").context("missing workflow source SHA")?;
    crate::policy::validate_sha(&sha)?;
    Ok(())
}

fn validate_request(
    api: &GitHub,
    source_sha: &str,
    publisher_run_id: u64,
    verification_run_id: u64,
    expected_control_id: &str,
) -> Result<(
    securefix::control::ControlRevision,
    securefix::control::ControlRevision,
)> {
    crate::policy::validate_sha(source_sha)?;
    ensure!(
        publisher_run_id > 0 && verification_run_id > 0,
        "invalid evidence run ID"
    );
    validate_digest(expected_control_id)?;
    let current = securefix::control::ControlRevision::load(api)?;
    ensure!(
        current.identity()? == expected_control_id,
        "active control descriptor changed before activation"
    );
    let trusted = config::trusted()?;
    let repository = &trusted.deployment.server.repository;
    let main: Value = api.get(&format!(
        "/repos/{repository}/commits/{}",
        trusted.deployment.server.default_branch
    ))?;
    let main_sha = main["sha"].as_str().context("protected main SHA missing")?;
    crate::policy::validate_sha(main_sha)?;
    ensure!(
        std::env::var("GITHUB_SHA").is_ok_and(|sha| sha == main_sha),
        "activation workflow is not running from current protected main"
    );
    let active_policy = crate::policy::Policy::active(api)?;
    crate::settings::require_serialized_merges(api, &active_policy)?;
    require_ancestor(api, repository, source_sha, main_sha)?;
    verify_source_commit(api, repository, source_sha)?;
    verify_ci_status(api, repository, source_sha)?;
    let (publication, archive) = verify_publisher(api, repository, source_sha, publisher_run_id)?;
    verify_archive_attestation(
        archive.path(),
        repository,
        source_sha,
        &trusted.deployment.server.default_branch,
    )?;
    let policy_bytes = api.content(repository, "policy.json", source_sha)?;
    ensure!(
        policy_from_archive(archive.path())? == policy_bytes,
        "published runtime policy differs from the candidate source policy"
    );
    let candidate_policy =
        crate::policy::Policy::parse(&policy_bytes).context("candidate policy is invalid")?;
    ensure!(
        candidate_policy.deployment == trusted.deployment
            && candidate_policy.owner_id == trusted.owner_id
            && candidate_policy.client_bot_id == trusted.client_bot_id
            && candidate_policy.server_bot_id == trusted.server_bot_id,
        "candidate policy changes trusted deployment or credential identities"
    );
    let policy_sha256 = securefix::hex_encode(Sha256::digest(&policy_bytes));
    verify_candidate_test(api, repository, source_sha, verification_run_id)?;

    let successor = securefix::control::ControlRevision {
        version: 1,
        generation: current
            .generation
            .checked_add(1)
            .context("control generation overflow")?,
        source_sha: source_sha.to_owned(),
        policy_sha256,
        archive_sha256: publication.archive_sha256,
        release_id: publication.release_id,
        asset_id: publication.asset_id,
        publisher_run_id,
        verification_run_id,
        previous: current.identity()?,
    };
    current.validate_successor(&successor)?;
    Ok((current, successor))
}

fn require_ancestor(api: &GitHub, repository: &str, source: &str, main: &str) -> Result<()> {
    let compare: Value = api.get(&format!("/repos/{repository}/compare/{source}...{main}"))?;
    ensure!(
        compare["base_commit"]["sha"] == source
            && compare["merge_base_commit"]["sha"] == source
            && matches!(compare["status"].as_str(), Some("ahead" | "identical")),
        "candidate source is not an ancestor of protected main"
    );
    Ok(())
}

fn verify_source_commit(api: &GitHub, repository: &str, source: &str) -> Result<()> {
    let commit: Value = api.get(&format!("/repos/{repository}/commits/{source}"))?;
    ensure!(
        commit["sha"] == source && commit["commit"]["verification"]["verified"] == true,
        "candidate source commit identity or signature is invalid"
    );
    Ok(())
}

fn verify_ci_status(api: &GitHub, repository: &str, source: &str) -> Result<()> {
    let status: Value = api.get(&format!("/repos/{repository}/commits/{source}/status"))?;
    let status_count = status["total_count"]
        .as_u64()
        .context("candidate combined status count missing")?;
    if status_count > 0 {
        ensure!(
            status["state"] == "success",
            "candidate commit has a failing or pending status context"
        );
    }
    let mut matches = Vec::new();
    for page in 1..=100 {
        let value: Value = api.get(&format!(
            "/repos/{repository}/commits/{source}/check-runs?per_page=100&page={page}&filter=latest"
        ))?;
        let batch = value["check_runs"]
            .as_array()
            .context("candidate check runs malformed")?;
        let done = batch.len() < 100;
        let status_app_id = config::trusted()?.deployment.checks.status_app_id;
        matches.extend(
            batch
                .iter()
                .filter(|check| {
                    check["name"] == "status-check" && check["app"]["id"] == status_app_id
                })
                .cloned(),
        );
        if done {
            break;
        }
        ensure!(page < 100, "candidate check-run pagination exceeded limit");
    }
    ensure!(
        matches.len() == 1
            && matches[0]["status"] == "completed"
            && matches[0]["conclusion"] == "success",
        "candidate CI status-check is not a unique successful check"
    );
    Ok(())
}

fn verify_publisher(
    api: &GitHub,
    repository: &str,
    source: &str,
    run_id: u64,
) -> Result<(runtime::Publication, tempfile::NamedTempFile)> {
    let run = owner_dispatch_run(api, repository, run_id, PUBLISH_WORKFLOW)?;
    let trusted = config::trusted()?;
    validate_publisher_target(&run, source, &trusted.deployment.server.default_branch)?;
    let version = runtime::version_at_source(api, source)?;
    let release: Value = api.get(&format!(
        "/repos/{repository}/releases/tags/{}",
        version.tag()
    ))?;
    let asset_id = validate_release_metadata(&release)?;
    let bytes = api.download(
        &format!("/repos/{repository}/releases/assets/{asset_id}"),
        128 * 1024 * 1024,
    )?;
    let mut archive = tempfile::NamedTempFile::new()?;
    std::io::Write::write_all(&mut archive, &bytes)?;
    let publication = runtime::verify_publication(api, source, repository, archive.path())?;
    Ok((publication, archive))
}

fn verify_archive_attestation(
    path: &Path,
    repository: &str,
    source: &str,
    branch: &str,
) -> Result<()> {
    let output = Process::new("gh")
        .arg("attestation")
        .arg("verify")
        .arg(path)
        .arg("--repo")
        .arg(repository)
        .arg("--source-digest")
        .arg(source)
        .arg("--source-ref")
        .arg(format!("refs/heads/{branch}"))
        .arg("--signer-workflow")
        .arg(format!("{repository}/{PUBLISH_WORKFLOW}"))
        .arg("--signer-digest")
        .arg(source)
        .arg("--cert-oidc-issuer")
        .arg("https://token.actions.githubusercontent.com")
        .arg("--predicate-type")
        .arg("https://slsa.dev/provenance/v1")
        .arg("--deny-self-hosted-runners")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("run pinned runtime attestation verification")?;
    ensure!(
        output.status.success(),
        "runtime archive attestation verification failed"
    );
    Ok(())
}

fn policy_from_archive(path: &Path) -> Result<Vec<u8>> {
    let mut child = Process::new("tar")
        .arg("-xOf")
        .arg(path)
        .arg("./policy.json")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("extract policy.json from the attested runtime archive")?;
    let mut bytes = Vec::new();
    let read_result = child
        .stdout
        .take()
        .context("tar stdout missing")?
        .take(256 * 1024 + 1)
        .read_to_end(&mut bytes);
    if let Err(error) = read_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error.into());
    }
    if bytes.len() > 256 * 1024 {
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!("archived policy exceeds size limit");
    }
    ensure!(
        child.wait()?.success(),
        "runtime archive does not contain one readable policy.json"
    );
    Ok(bytes)
}

fn owner_dispatch_run(
    api: &GitHub,
    repository: &str,
    run_id: u64,
    workflow: &str,
) -> Result<Value> {
    let trusted = config::trusted()?;
    let run: Value = api.get(&format!("/repos/{repository}/actions/runs/{run_id}"))?;
    validate_owner_dispatch_run(
        &run,
        repository,
        run_id,
        trusted.deployment.server.id,
        trusted.owner_id,
        workflow,
        &trusted.deployment.server.default_branch,
    )?;
    Ok(run)
}

fn validate_owner_dispatch_run(
    run: &Value,
    repository: &str,
    run_id: u64,
    repository_id: u64,
    owner_id: u64,
    workflow: &str,
    branch: &str,
) -> Result<()> {
    ensure!(
        run["id"].as_u64() == Some(run_id)
            && run["repository"]["full_name"] == repository
            && run["repository"]["id"].as_u64() == Some(repository_id)
            && run["head_repository"]["full_name"] == repository
            && run["head_repository"]["id"].as_u64() == Some(repository_id)
            && run["path"] == format!("{workflow}@refs/heads/{branch}")
            && run["event"] == "workflow_dispatch"
            && run["run_attempt"] == 1
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && run["actor"]["id"].as_u64() == Some(owner_id)
            && run["triggering_actor"]["id"].as_u64() == Some(owner_id),
        "evidence is not a successful first-attempt owner dispatch of the trusted workflow"
    );
    Ok(())
}

fn validate_publisher_target(run: &Value, source: &str, branch: &str) -> Result<()> {
    ensure!(
        run["head_sha"] == source && run["head_branch"] == branch,
        "runtime publisher run does not target the candidate on protected main"
    );
    Ok(())
}

fn validate_release_metadata(release: &Value) -> Result<u64> {
    ensure!(
        release["immutable"] == true,
        "runtime release is not immutable"
    );
    let assets = release["assets"]
        .as_array()
        .context("published runtime assets missing")?;
    ensure!(assets.len() == 1, "published runtime has unexpected assets");
    assets[0]["id"].as_u64().context("runtime asset ID missing")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Verification {
    version: u32,
    repository: String,
    candidate_sha: String,
    positive_pr: u64,
    merged_sha: String,
    stale_pr: u64,
    stale_head_sha: String,
    distribution_pr: u64,
    managed_files: Vec<String>,
    annotated_tag_verified: bool,
    closed_or_merged: bool,
}

fn verify_candidate_test(api: &GitHub, repository: &str, source: &str, run_id: u64) -> Result<()> {
    let run = owner_dispatch_run(api, repository, run_id, TEST_WORKFLOW)?;
    let trusted = config::trusted()?;
    ensure!(
        run["head_branch"] == trusted.deployment.server.default_branch,
        "candidate test workflow did not run from protected main"
    );
    let current_main: Value = api.get(&format!(
        "/repos/{repository}/commits/{}",
        trusted.deployment.server.default_branch
    ))?;
    require_ancestor(
        api,
        repository,
        run["head_sha"]
            .as_str()
            .context("test workflow source SHA missing")?,
        current_main["sha"]
            .as_str()
            .context("protected main SHA missing")?,
    )?;
    let artifacts: Value = api.get(&format!(
        "/repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"
    ))?;
    let all = artifacts["artifacts"]
        .as_array()
        .context("candidate artifact list malformed")?;
    let matching: Vec<_> = all
        .iter()
        .filter(|a| a["name"] == SCRATCH_ARTIFACT)
        .collect();
    ensure!(
        matching.len() == 1,
        "scratch-fixtures artifact is missing or duplicated"
    );
    let artifact = matching[0];
    ensure!(
        artifact["expired"] == false
            && artifact["size_in_bytes"]
                .as_u64()
                .is_some_and(|size| size > 0 && size <= MAX_ARTIFACT_SIZE as u64),
        "scratch-fixtures artifact is expired or oversized"
    );
    let artifact_id = artifact["id"]
        .as_u64()
        .context("scratch artifact ID missing")?;
    let bytes = api.download(
        &format!("/repos/{repository}/actions/artifacts/{artifact_id}/zip"),
        MAX_ARTIFACT_SIZE,
    )?;
    ensure!(
        artifact["size_in_bytes"].as_u64() == Some(bytes.len() as u64),
        "scratch-fixtures archive size differs from API metadata"
    );
    if let Some(digest) = artifact["digest"].as_str() {
        let expected = digest
            .strip_prefix("sha256:")
            .context("scratch artifact digest algorithm is unsupported")?;
        ensure!(
            valid_digest(expected) && securefix::hex_encode(Sha256::digest(&bytes)) == expected,
            "scratch artifact digest mismatch"
        );
    } else {
        anyhow::bail!("scratch-fixtures artifact has no immutable digest metadata");
    }
    let (state, verification) = fixture_files(&bytes)?;
    validate_scratch_evidence(
        &state,
        &verification,
        &trusted.deployment.integration.repository,
        trusted.deployment.integration.id,
        source,
        run["head_sha"]
            .as_str()
            .context("test workflow source SHA missing")?,
    )?;
    verify_control_probe_artifact(api, repository, run_id, source)?;
    Ok(())
}

fn validate_scratch_evidence(
    state: &Value,
    verification: &Verification,
    repository: &str,
    repository_id: u64,
    source: &str,
    workflow_sha: &str,
) -> Result<()> {
    ensure!(
        state["candidate_sha"] == source
            && state["repository"] == repository
            && state["repository_id"].as_u64() == Some(repository_id)
            && state["workflow_sha"] == workflow_sha
            && state["positive"]["number"] == verification.positive_pr
            && verification.version == 2
            && verification.repository == repository
            && verification.candidate_sha == source
            && verification.positive_pr > 0
            && verification.stale_pr > 0
            && verification.distribution_pr > 0
            && crate::policy::validate_sha(&verification.merged_sha).is_ok()
            && crate::policy::validate_sha(&verification.stale_head_sha).is_ok()
            && verification.annotated_tag_verified
            && verification.closed_or_merged
            && !verification.managed_files.is_empty(),
        "scratch verification artifact does not prove the requested candidate"
    );
    Ok(())
}

fn verify_control_probe_artifact(
    api: &GitHub,
    repository: &str,
    run_id: u64,
    source: &str,
) -> Result<()> {
    let artifacts: Value = api.get(&format!(
        "/repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"
    ))?;
    let all = artifacts["artifacts"]
        .as_array()
        .context("control probe artifact list malformed")?;
    let matching: Vec<_> = all
        .iter()
        .filter(|a| a["name"] == "control-probe")
        .collect();
    ensure!(
        matching.len() == 1,
        "control-probe artifact is missing or duplicated"
    );
    let artifact = matching[0];
    ensure!(
        artifact["expired"] == false
            && artifact["size_in_bytes"]
                .as_u64()
                .is_some_and(|size| size > 0 && size <= 16 * 1024),
        "control-probe artifact is expired or oversized"
    );
    let artifact_id = artifact["id"]
        .as_u64()
        .context("control-probe artifact ID missing")?;
    let bytes = api.download(
        &format!("/repos/{repository}/actions/artifacts/{artifact_id}/zip"),
        16 * 1024,
    )?;
    ensure!(
        artifact["size_in_bytes"].as_u64() == Some(bytes.len() as u64),
        "control-probe archive size differs from API metadata"
    );
    let digest = artifact["digest"]
        .as_str()
        .context("control-probe artifact has no immutable digest")?;
    let digest = digest
        .strip_prefix("sha256:")
        .context("control-probe artifact digest algorithm is unsupported")?;
    ensure!(
        valid_digest(digest) && securefix::hex_encode(Sha256::digest(&bytes)) == digest,
        "control-probe artifact digest mismatch"
    );
    let verification = single_json_zip(&bytes, "control-verification.json")?;
    let trusted = config::trusted()?;
    validate_control_probe(
        &verification,
        &trusted.deployment.integration.repository,
        source,
    )?;
    Ok(())
}

fn validate_control_probe(verification: &Value, repository: &str, source: &str) -> Result<()> {
    ensure!(
        verification["version"] == 1
            && verification["repository"] == repository
            && verification["candidate_sha"] == source
            && verification["branch"]
                .as_str()
                .is_some_and(|branch| branch.starts_with("securefix-integration-control-"))
            && verification["base_sha"]
                .as_str()
                .is_some_and(|sha| crate::policy::validate_sha(sha).is_ok())
            && [
                "generation_one_commit_sha",
                "generation_two_commit_sha",
                "generation_three_commit_sha",
            ]
            .iter()
            .all(|field| {
                verification[*field]
                    .as_str()
                    .is_some_and(|sha| crate::policy::validate_sha(sha).is_ok())
            })
            && ["generation_one", "generation_two", "generation_three"]
                .iter()
                .all(|field| verification[*field].as_str().is_some_and(valid_digest))
            && verification["generation_one"] != verification["generation_two"]
            && verification["generation_two"] != verification["generation_three"]
            && verification["generation_one"] != verification["generation_three"]
            && verification["source_advance_kept_descriptor"] == true
            && verification["expected_head_conflict_rejected"] == true
            && verification["stale_identity_rejected_after_aba"] == true
            && verification["production_publication_verified"] == false
            && verification["production_activation_verified"] == false
            && verification["distribution_verified"] == false,
        "control-probe artifact does not prove the scratch-only control CAS scenario"
    );
    Ok(())
}

fn single_json_zip(bytes: &[u8], expected_name: &str) -> Result<Value> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    ensure!(
        zip.len() == 1,
        "control-probe must contain exactly one file"
    );
    let mut file = zip.by_index(0)?;
    ensure!(
        file.name() == expected_name
            && file.is_file()
            && file.size() <= 16 * 1024
            && file
                .unix_mode()
                .is_none_or(|mode| mode & 0o170000 != 0o120000),
        "control-probe contains an unsafe or unexpected file"
    );
    let declared = file.size();
    let mut content = Vec::new();
    (&mut file).take(16 * 1024 + 1).read_to_end(&mut content)?;
    ensure!(
        content.len() as u64 == declared && content.len() <= 16 * 1024,
        "control-probe file size mismatch"
    );
    Ok(serde_json::from_slice(&content)?)
}

fn fixture_files(bytes: &[u8]) -> Result<(Value, Verification)> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    ensure!(
        zip.len() == 2,
        "scratch-fixtures must contain exactly state.json and verification.json"
    );
    let mut names = std::collections::BTreeSet::new();
    let mut state = None;
    let mut verification = None;
    for index in 0..zip.len() {
        let mut file = zip.by_index(index)?;
        let name = file.name().to_owned();
        ensure!(
            (name == "state.json" || name == "verification.json")
                && file.is_file()
                && file.size() <= MAX_FIXTURE_FILE
                && file
                    .unix_mode()
                    .is_none_or(|mode| mode & 0o170000 != 0o120000)
                && names.insert(name.clone()),
            "scratch-fixtures contains an unsafe or duplicate entry"
        );
        let declared = file.size();
        let mut content = Vec::new();
        (&mut file)
            .take(MAX_FIXTURE_FILE + 1)
            .read_to_end(&mut content)?;
        ensure!(
            content.len() as u64 == declared && content.len() as u64 <= MAX_FIXTURE_FILE,
            "scratch fixture file size mismatch"
        );
        if name == "state.json" {
            state = Some(serde_json::from_slice(&content)?);
        } else {
            verification = Some(serde_json::from_slice(&content)?);
        }
    }
    Ok((
        state.context("scratch state is missing")?,
        verification.context("scratch verification is missing")?,
    ))
}

fn validate_request_for_active_descriptor(
    api: &GitHub,
    descriptor: &securefix::control::ControlRevision,
) -> Result<()> {
    let trusted = config::trusted()?;
    let repository = &trusted.deployment.server.repository;
    let policy = crate::policy::Policy::active(api)?;
    crate::settings::require_serialized_merges(api, &policy)?;
    let main: Value = api.get(&format!(
        "/repos/{repository}/commits/{}",
        trusted.deployment.server.default_branch
    ))?;
    require_ancestor(
        api,
        repository,
        &descriptor.source_sha,
        main["sha"].as_str().context("protected main SHA missing")?,
    )?;
    verify_source_commit(api, repository, &descriptor.source_sha)?;
    verify_ci_status(api, repository, &descriptor.source_sha)?;
    let (publication, archive) = verify_publisher(
        api,
        repository,
        &descriptor.source_sha,
        descriptor.publisher_run_id,
    )?;
    verify_archive_attestation(
        archive.path(),
        repository,
        &descriptor.source_sha,
        &trusted.deployment.server.default_branch,
    )?;
    let policy_bytes = api.content(repository, "policy.json", &descriptor.source_sha)?;
    ensure!(
        policy_from_archive(archive.path())? == policy_bytes
            && securefix::hex_encode(Sha256::digest(&policy_bytes)) == descriptor.policy_sha256,
        "activation descriptor policy digest differs from the attested runtime"
    );
    let candidate_policy = crate::policy::Policy::parse(&policy_bytes)?;
    ensure!(
        candidate_policy.deployment == trusted.deployment
            && candidate_policy.owner_id == trusted.owner_id
            && candidate_policy.client_bot_id == trusted.client_bot_id
            && candidate_policy.server_bot_id == trusted.server_bot_id,
        "activation candidate changes trusted deployment or credential identities"
    );
    ensure!(
        publication.archive_sha256 == descriptor.archive_sha256
            && publication.release_id == descriptor.release_id
            && publication.asset_id == descriptor.asset_id,
        "activation pull request publication metadata changed"
    );
    verify_candidate_test(
        api,
        repository,
        &descriptor.source_sha,
        descriptor.verification_run_id,
    )?;
    Ok(())
}

fn write_prepared(
    directory: &Path,
    expected_before: &securefix::control::ControlRevision,
    successor: &securefix::control::ControlRevision,
) -> Result<()> {
    expected_before.validate_successor(successor)?;
    fs::create_dir_all(directory)?;
    let dir = fs::canonicalize(directory)?;
    ensure!(dir.is_dir(), "control migration output is not a directory");
    let descriptor_path = dir.join(ACTIVE_PATH);
    let descriptor_parent = descriptor_path
        .parent()
        .context("descriptor path has no parent")?;
    fs::create_dir_all(descriptor_parent)?;
    let parent_metadata = fs::symlink_metadata(descriptor_parent)?;
    ensure!(
        parent_metadata.is_dir() && !parent_metadata.file_type().is_symlink(),
        "refusing unsafe control descriptor directory"
    );
    let bytes = serde_json::to_vec_pretty(successor)?;
    ensure!(
        bytes.len() <= 16 * 1024,
        "control descriptor exceeds size limit"
    );
    write_regular(&descriptor_path, &bytes)?;
    let metadata = serde_json::to_vec_pretty(&json!({
        "version": 1,
        "expected_control_id": expected_before.identity()?,
        "next_control_id": successor.identity()?,
        "source_sha": successor.source_sha,
        "publisher_run_id": successor.publisher_run_id,
        "verification_run_id": successor.verification_run_id
    }))?;
    write_regular(&dir.join("control-activation.json"), &metadata)?;
    Ok(())
}

fn write_regular(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "refusing unsafe control output file"
        );
    }
    fs::write(path, bytes)?;
    Ok(())
}

fn validate_prepared(
    directory: &Path,
    current: &securefix::control::ControlRevision,
    successor: &securefix::control::ControlRevision,
) -> Result<()> {
    let base = fs::canonicalize(directory)?;
    let descriptor_bytes = read_bounded(&base.join(ACTIVE_PATH), 16 * 1024)?;
    ensure!(
        parse_descriptor(&descriptor_bytes)? == *successor,
        "prepared descriptor differs from revalidated evidence"
    );
    let metadata: PreparedMetadata = serde_json::from_slice(&read_bounded(
        &base.join("control-activation.json"),
        16 * 1024,
    )?)?;
    ensure!(
        metadata.version == 1
            && metadata.expected_control_id == current.identity()?
            && metadata.next_control_id == successor.identity()?
            && metadata.source_sha == successor.source_sha
            && metadata.publisher_run_id == successor.publisher_run_id
            && metadata.verification_run_id == successor.verification_run_id,
        "prepared activation metadata differs from revalidated evidence"
    );
    Ok(())
}

fn create_activation_pr(
    api: &GitHub,
    current: &securefix::control::ControlRevision,
    successor: &securefix::control::ControlRevision,
) -> Result<u64> {
    securefix::control::ControlRevision::require_current(api, current)?;
    let trusted = config::trusted()?;
    let repository = &trusted.deployment.server.repository;
    let base = &trusted.deployment.server.default_branch;
    let main: Value = api.get(&format!("/repos/{repository}/commits/{base}"))?;
    let head = main["sha"].as_str().context("protected main SHA missing")?;
    crate::policy::validate_sha(head)?;
    require_ancestor(api, repository, &successor.source_sha, head)?;
    let branch = activation_branch(successor)?;
    let branch_path = format!("/repos/{repository}/git/ref/heads/{branch}");
    match api.get::<Value>(&branch_path) {
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|e| e.status == reqwest::StatusCode::NOT_FOUND) => {}
        Ok(_) => anyhow::bail!("activation branch already exists"),
        Err(error) => return Err(error),
    }
    let created: Value = api.post(
        &format!("/repos/{repository}/git/refs"),
        &json!({"ref": format!("refs/heads/{branch}"), "sha":head}),
    )?;
    ensure!(
        created["ref"] == format!("refs/heads/{branch}") && created["object"]["sha"] == head,
        "activation branch was created at an unexpected head"
    );
    let mut additions = BTreeMap::new();
    additions.insert(
        ACTIVE_PATH.to_owned(),
        serde_json::to_vec_pretty(successor)?,
    );
    let commit = api.create_commit(
        repository,
        &branch,
        head,
        "chore: activate verified Securefix control revision",
        additions,
        Vec::new(),
    )?;
    securefix::control::ControlRevision::require_current(api, current)?;
    let pr: Value = api.post(
        &format!("/repos/{repository}/pulls"),
        &json!({
            "head": branch,
            "base": base,
            "title": format!("Activate Securefix control revision {}", successor.generation),
            "body": format!("Activate the verified control revision for source {}.\n\nControl ID: {}", successor.source_sha, successor.identity()?),
            "draft": false
        }),
    )?;
    ensure!(
        pr["state"] == "open"
            && pr["head"]["sha"] == commit
            && pr["head"]["ref"] == branch
            && pr["head"]["repo"]["full_name"].as_str() == Some(repository.as_str())
            && pr["base"]["ref"].as_str() == Some(base.as_str())
            && pr["base"]["repo"]["full_name"].as_str() == Some(repository.as_str()),
        "activation pull request identity is invalid"
    );
    ensure!(
        pr["user"]["id"].as_u64() == Some(trusted.server_bot_id),
        "activation pull request author is not the configured server bot"
    );
    pr["number"]
        .as_u64()
        .context("activation pull request number missing")
}

fn activation_branch(descriptor: &securefix::control::ControlRevision) -> Result<String> {
    let root = &config::trusted()?.deployment.runtime_update_branch;
    let source = descriptor
        .source_sha
        .get(..12)
        .context("source SHA is too short")?;
    Ok(format!("{root}/control-{}-{source}", descriptor.generation))
}

/// Validate a server-owned control activation PR before the usual merge gates run.
pub(crate) fn validate_activation_merge(
    api: &GitHub,
    manifest: &crate::request::RequestManifest,
) -> Result<()> {
    let trusted = config::trusted()?;
    if manifest.repository.full_name != trusted.deployment.server.repository {
        return Ok(());
    }
    let repository = &trusted.deployment.server.repository;
    let current = securefix::control::ControlRevision::load(api)?;
    let bytes = api.content(repository, ACTIVE_PATH, &manifest.pull_request.head_sha)?;
    ensure!(
        bytes.len() <= 16 * 1024,
        "proposed control descriptor exceeds size limit"
    );
    let proposed = parse_descriptor(&bytes)?;
    if proposed == current {
        return Ok(());
    }
    current.validate_successor(&proposed)?;
    ensure!(
        current.identity()? == manifest.control.identity()?
            && proposed.previous == manifest.control.identity()?
            && manifest.pull_request.base_ref == trusted.deployment.server.default_branch,
        "activation PR does not follow the accepted control revision and protected base"
    );
    let pull: Value = api.get(&format!(
        "/repos/{repository}/pulls/{}",
        manifest.pull_request.number
    ))?;
    let branch = activation_branch(&proposed)?;
    ensure!(
        pull["state"] == "open"
            && pull["head"]["sha"] == manifest.pull_request.head_sha
            && pull["head"]["ref"] == branch
            && pull["head"]["repo"]["full_name"].as_str() == Some(repository.as_str())
            && pull["head"]["user"]["id"].as_u64() == Some(trusted.server_bot_id)
            && pull["head"]["user"]["login"].as_str().is_some_and(
                |login| login.eq_ignore_ascii_case(&trusted.deployment.server_bot_login)
            )
            && pull["base"]["repo"]["full_name"].as_str() == Some(repository.as_str())
            && pull["base"]["ref"] == trusted.deployment.server.default_branch,
        "control activation PR ownership or branch identity is invalid"
    );
    let main: Value = api.get(&format!(
        "/repos/{repository}/commits/{}",
        trusted.deployment.server.default_branch
    ))?;
    let main_sha = main["sha"].as_str().context("protected main SHA missing")?;
    let compare: Value = api.get(&format!(
        "/repos/{repository}/compare/{main_sha}...{}",
        manifest.pull_request.head_sha
    ))?;
    let files = compare["files"]
        .as_array()
        .context("activation PR file list missing")?;
    ensure!(
        files.len() == 1 && files[0]["filename"] == ACTIVE_PATH,
        "activation PR changes files outside the control descriptor"
    );
    validate_request_for_active_descriptor(api, &proposed)?;
    Ok(())
}

fn parse_descriptor(bytes: &[u8]) -> Result<securefix::control::ControlRevision> {
    ensure!(
        bytes.len() <= 16 * 1024,
        "control descriptor exceeds size limit"
    );
    let descriptor: securefix::control::ControlRevision =
        serde_json::from_slice(bytes).context("invalid control descriptor")?;
    descriptor.validate()?;
    Ok(descriptor)
}

fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= max as u64,
        "input file is unsafe or oversized"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max, "input file exceeds size limit");
    Ok(bytes)
}

fn emit_descriptor(descriptor: &securefix::control::ControlRevision) -> Result<()> {
    securefix::output("control_id", descriptor.identity()?)?;
    securefix::output("source_sha", &descriptor.source_sha)?;
    securefix::output("generation", descriptor.generation.to_string())?;
    securefix::output("policy_sha256", &descriptor.policy_sha256)?;
    securefix::output("archive_sha256", &descriptor.archive_sha256)?;
    securefix::output("release_id", descriptor.release_id.to_string())?;
    securefix::output("asset_id", descriptor.asset_id.to_string())
}

fn validate_digest(value: &str) -> Result<()> {
    ensure!(valid_digest(value), "invalid SHA-256 digest");
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixture_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, content) in entries {
            zip.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(content).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn fixture_artifact_requires_exact_safe_file_set() {
        let state = br#"{"candidate_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        let verification = br#"{"version":2,"repository":"owner/scratch","candidate_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","positive_pr":1,"merged_sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","stale_pr":2,"stale_head_sha":"cccccccccccccccccccccccccccccccccccccccc","distribution_pr":3,"managed_files":["workflow.yml"],"annotated_tag_verified":true,"closed_or_merged":true}"#;
        let bytes = fixture_zip(&[("state.json", state), ("verification.json", verification)]);
        let (_, parsed) = fixture_files(&bytes).unwrap();
        assert_eq!(parsed.candidate_sha, "a".repeat(40));

        let unsafe_bytes = fixture_zip(&[
            ("../state.json", state),
            ("verification.json", verification),
        ]);
        assert!(fixture_files(&unsafe_bytes).is_err());
    }

    #[test]
    fn scratch_fixture_requires_complete_positive_evidence() {
        let state = json!({
            "candidate_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "repository": "owner/scratch",
            "repository_id": 7,
            "workflow_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "positive": {"number": 1}
        });
        let valid_json = json!({
            "version": 2,
            "repository": "owner/scratch",
            "candidate_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "positive_pr": 1,
            "merged_sha": "cccccccccccccccccccccccccccccccccccccccc",
            "stale_pr": 2,
            "stale_head_sha": "dddddddddddddddddddddddddddddddddddddddd",
            "distribution_pr": 3,
            "managed_files": ["workflow.yml"],
            "annotated_tag_verified": true,
            "closed_or_merged": true
        });
        let valid: Verification = serde_json::from_value(valid_json.clone()).unwrap();
        validate_scratch_evidence(
            &state,
            &valid,
            "owner/scratch",
            7,
            &"a".repeat(40),
            &"b".repeat(40),
        )
        .unwrap();

        let mut false_value = valid_json.clone();
        false_value["annotated_tag_verified"] = json!(false);
        let false_value: Verification = serde_json::from_value(false_value).unwrap();
        assert!(
            validate_scratch_evidence(
                &state,
                &false_value,
                "owner/scratch",
                7,
                &"a".repeat(40),
                &"b".repeat(40),
            )
            .is_err()
        );

        let mut missing = valid_json;
        missing.as_object_mut().unwrap().remove("closed_or_merged");
        assert!(serde_json::from_value::<Verification>(missing).is_err());
    }

    #[test]
    fn publisher_evidence_requires_successful_owner_first_attempt_and_candidate_sha() {
        let success = json!({
            "id": 12,
            "repository": {"full_name": "owner/server", "id": 7},
            "head_repository": {"full_name": "owner/server", "id": 7},
            "path": ".github/workflows/publish-runtime.yml@refs/heads/main",
            "event": "workflow_dispatch",
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
            "actor": {"id": 8},
            "triggering_actor": {"id": 8},
            "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "head_branch": "main"
        });
        validate_owner_dispatch_run(&success, "owner/server", 12, 7, 8, PUBLISH_WORKFLOW, "main")
            .unwrap();
        validate_publisher_target(&success, &"a".repeat(40), "main").unwrap();

        let mut failed = success.clone();
        failed["conclusion"] = json!("failure");
        assert!(
            validate_owner_dispatch_run(
                &failed,
                "owner/server",
                12,
                7,
                8,
                PUBLISH_WORKFLOW,
                "main",
            )
            .is_err()
        );
        assert!(validate_publisher_target(&success, &"b".repeat(40), "main").is_err());
        assert!(validate_publisher_target(&success, &"a".repeat(40), "release").is_err());
    }

    #[test]
    fn publication_requires_immutable_release_with_one_identified_asset() {
        let release = json!({"immutable": true, "assets": [{"id": 42}]});
        assert_eq!(validate_release_metadata(&release).unwrap(), 42);
        assert!(
            validate_release_metadata(&json!({"immutable": false, "assets": [{"id":42}]})).is_err()
        );
        assert!(
            validate_release_metadata(
                &json!({"immutable": true, "assets": [{"id":42}, {"id":43}]})
            )
            .is_err()
        );
        assert!(
            validate_release_metadata(&json!({"immutable": true, "assets": [{"name":"runtime"}]}))
                .is_err()
        );
    }

    #[test]
    fn control_probe_requires_all_scratch_cas_assertions_and_no_production_claims() {
        let valid = json!({
            "version": 1,
            "repository": "owner/scratch",
            "candidate_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "branch": "securefix-integration-control-probe",
            "base_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "generation_one_commit_sha": "cccccccccccccccccccccccccccccccccccccccc",
            "generation_two_commit_sha": "dddddddddddddddddddddddddddddddddddddddd",
            "generation_three_commit_sha": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "generation_one": "1".repeat(64),
            "generation_two": "2".repeat(64),
            "generation_three": "3".repeat(64),
            "source_advance_kept_descriptor": true,
            "expected_head_conflict_rejected": true,
            "stale_identity_rejected_after_aba": true,
            "production_publication_verified": false,
            "production_activation_verified": false,
            "distribution_verified": false
        });
        validate_control_probe(&valid, "owner/scratch", &"a".repeat(40)).unwrap();

        let mut missing = valid.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("generation_two_commit_sha");
        assert!(validate_control_probe(&missing, "owner/scratch", &"a".repeat(40)).is_err());
        let mut false_claim = valid.clone();
        false_claim["expected_head_conflict_rejected"] = json!(false);
        assert!(validate_control_probe(&false_claim, "owner/scratch", &"a".repeat(40)).is_err());
        let mut production_claim = valid;
        production_claim["production_activation_verified"] = json!(true);
        assert!(
            validate_control_probe(&production_claim, "owner/scratch", &"a".repeat(40)).is_err()
        );
    }

    #[test]
    fn invalid_successor_is_rejected_before_preparation_writes_anything() {
        let before = securefix::control::ControlRevision {
            version: 1,
            generation: 1,
            source_sha: "a".repeat(40),
            policy_sha256: "1".repeat(64),
            archive_sha256: "2".repeat(64),
            release_id: 1,
            asset_id: 2,
            publisher_run_id: 3,
            verification_run_id: 4,
            previous: "0".repeat(64),
        };
        let mut invalid_next = before.clone();
        invalid_next.generation = 3;
        invalid_next.previous = before.identity().unwrap();
        let directory = tempfile::tempdir().unwrap().path().join("not-created");
        assert!(write_prepared(&directory, &before, &invalid_next).is_err());
        assert!(!directory.exists());
    }

    #[test]
    fn descriptor_parser_rejects_unknown_fields() {
        let bytes = br#"{"version":1,"generation":1,"source_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policy_sha256":"1111111111111111111111111111111111111111111111111111111111111111","archive_sha256":"2222222222222222222222222222222222222222222222222222222222222222","release_id":3,"asset_id":4,"publisher_run_id":5,"verification_run_id":6,"previous":"0000000000000000000000000000000000000000000000000000000000000000","extra":true}"#;
        assert!(parse_descriptor(bytes).is_err());
    }
}
