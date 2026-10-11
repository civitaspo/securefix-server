use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use clap::{Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    merge, policy_check,
    request::{self, Authorization, PullRequestRef, RepositoryRef, RequestKind, RequestManifest},
};
use securefix::{
    api::{ApiError, GitHub},
    policy::{Capability, Policy, ReleaseStrategy, validate_sha},
    workflow,
};

const WORKFLOW_PATH: &str = ".github/workflows/testing-securefix-server.yml";
const FIX_PATH_PREFIX: &str = ".securefix-integration/";
const BRANCH_PREFIX: &str = "securefix-integration-";
const STATE_VERSION: u32 = 2;
const OBSOLETE_SCRATCH_WORKFLOWS: [&str; 2] = [
    ".github/workflows/verify-published-runtime.yml",
    ".github/workflows/verify-server.yml",
];

fn trusted_config() -> Result<&'static crate::config::TrustedConfig> {
    crate::config::trusted()
}

fn integration_repository() -> Result<&'static str> {
    Ok(&trusted_config()?.deployment.integration.repository)
}

fn integration_repository_id() -> Result<u64> {
    Ok(trusted_config()?.deployment.integration.id)
}

fn server_repository() -> Result<&'static str> {
    Ok(&trusted_config()?.deployment.server.repository)
}

fn server_repository_id() -> Result<u64> {
    Ok(trusted_config()?.deployment.server.id)
}

fn owner_id() -> Result<u64> {
    Ok(trusted_config()?.owner_id)
}

#[derive(Subcommand)]
pub enum Command {
    /// Prepare or verify live integration fixtures in the one scratch repository.
    Run {
        #[arg(long, value_enum)]
        phase: Phase,
        #[arg(long)]
        candidate_sha: String,
        #[arg(long)]
        state_file: PathBuf,
        #[arg(long, default_value_t = 900)]
        timeout_seconds: u64,
    },
    /// Fetch fixture state only from the exact successful candidate workflow artifact.
    FetchState {
        #[arg(long)]
        candidate_sha: String,
        #[arg(long)]
        run_id: u64,
        #[arg(long)]
        state_file: PathBuf,
    },
    /// Validate this workflow's frozen producer branch before GitHub App tokens are minted.
    ValidateProducer {
        #[arg(long)]
        workflow_sha: String,
    },
    /// Resolve the exact default-branch runtime tag for the candidate integration harness.
    ResolveTestRuntime {
        #[arg(long)]
        published_runtime_sha: String,
        #[arg(long)]
        expected_tag: Option<String>,
    },
    /// Validate the bounded files emitted by the isolated candidate container.
    ValidateOutputs {
        #[arg(long, value_enum)]
        phase: Phase,
        #[arg(long)]
        candidate_sha: String,
        #[arg(long)]
        state_file: PathBuf,
    },
    /// Verify the final stable client action smoke artifact and request label.
    VerifyClient {
        #[arg(long)]
        artifact_name: String,
        #[arg(long)]
        run_id: u64,
        #[arg(long)]
        workflow_sha: String,
    },
    /// Prepare the exact scratch policy and file used by the client action smoke test.
    PrepareClientInput,
    /// Exercise refresh of the same managed release PR after main advances.
    ReleasePr {
        #[arg(long, value_enum)]
        phase: ReleasePrPhase,
        #[arg(long)]
        candidate_sha: String,
        #[arg(long)]
        state_file: PathBuf,
        #[arg(long)]
        scratch_checkout: PathBuf,
        #[arg(long)]
        prepare_run_id: Option<u64>,
        #[arg(long, default_value = "0.1.1")]
        version: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Phase {
    Prepare,
    Verify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReleasePrPhase {
    Prepare,
    Verify,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    version: u32,
    repository: String,
    repository_id: u64,
    candidate_sha: String,
    published_runtime_sha: String,
    workflow_sha: String,
    default_branch: String,
    base_sha: String,
    prepared_at: DateTime<Utc>,
    positive: PullRequestFixture,
    stale: PullRequestFixture,
    distribution: PullRequestFixture,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PullRequestFixture {
    number: u64,
    branch: String,
    head_sha: String,
    url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ClientVerification {
    version: u32,
    source_repository: String,
    run_id: u64,
    workflow_sha: String,
    artifact_name: String,
    destination_repository: String,
    destination_branch: String,
    request_label: String,
    request_label_description: String,
    verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasePrState {
    version: u32,
    candidate_sha: String,
    prepare_run_id: u64,
    repository: String,
    repository_id: u64,
    default_branch: String,
    base_sha: String,
    release_branch: String,
    release_pr: u64,
    first_head_sha: String,
    first_changelog: String,
    historical_changelog: String,
    stable_tag: String,
    stable_base_sha: String,
}

pub fn run(command: Command) -> Result<()> {
    crate::config::trusted()?;
    match command {
        Command::Run {
            phase,
            candidate_sha,
            state_file,
            timeout_seconds,
        } => {
            validate_sha(&candidate_sha)?;
            validate_state_path(&state_file)?;
            match phase {
                Phase::Prepare => prepare(&candidate_sha, &state_file),
                Phase::Verify => verify(&candidate_sha, &state_file, timeout_seconds),
            }
        }
        Command::FetchState {
            candidate_sha,
            run_id,
            state_file,
        } => {
            validate_sha(&candidate_sha)?;
            validate_state_path(&state_file)?;
            fetch_state(&candidate_sha, run_id, &state_file)
        }
        Command::ValidateProducer { workflow_sha } => validate_producer(&workflow_sha),
        Command::ValidateOutputs {
            phase,
            candidate_sha,
            state_file,
        } => {
            validate_sha(&candidate_sha)?;
            let workspace = std::env::current_dir()?;
            let published_runtime_sha = published_runtime_sha_from_env()?;
            let api = integration_read_api()?;
            let published_runtime_tag = validate_test_runtime_tag(
                &api,
                &published_runtime_sha,
                &published_runtime_tag_from_env()?,
            )?;
            validate_outputs(
                &workspace,
                &state_file,
                &candidate_sha,
                phase,
                &published_runtime_sha,
                &published_runtime_tag,
            )
        }
        Command::ResolveTestRuntime {
            published_runtime_sha,
            expected_tag,
        } => {
            validate_sha(&published_runtime_sha)?;
            let api = integration_read_api()?;
            let tag = resolve_test_runtime_tag(&api, &published_runtime_sha)?;
            if let Some(expected_tag) = expected_tag {
                ensure!(
                    tag == expected_tag,
                    "published runtime tag changed during integration test"
                );
            }
            securefix::output("published_runtime_sha", &published_runtime_sha)?;
            securefix::output("published_runtime_tag", &tag)
        }
        Command::VerifyClient {
            artifact_name,
            run_id,
            workflow_sha,
        } => {
            validate_sha(&workflow_sha)?;
            verify_client(&artifact_name, run_id, &workflow_sha)
        }
        Command::PrepareClientInput => prepare_client_input(),
        Command::ReleasePr {
            phase,
            candidate_sha,
            state_file,
            scratch_checkout,
            prepare_run_id,
            version,
        } => {
            validate_sha(&candidate_sha)?;
            validate_state_path(&state_file)?;
            ensure!(
                semver::Version::parse(&version).is_ok(),
                "invalid release fixture version"
            );
            ensure!(
                version == "0.1.1",
                "release fixture version is fixed at 0.1.1"
            );
            let state_path = std::env::current_dir()?.join(&state_file);
            release_pr(
                phase,
                &candidate_sha,
                &state_path,
                &scratch_checkout,
                prepare_run_id,
                &version,
            )
        }
    }
}

fn verify_client(artifact_name: &str, run_id: u64, workflow_sha: &str) -> Result<()> {
    ensure!(run_id > 0, "invalid client smoke workflow run ID");
    ensure!(
        crate::securefix_gate::artifact::valid_artifact_name_for_cli(artifact_name),
        "invalid client smoke artifact name"
    );
    let trusted = crate::config::trusted()?;
    let server = &trusted.deployment.server;
    let scratch = &trusted.deployment.integration;
    ensure!(
        std::env::var("GITHUB_REPOSITORY").is_ok_and(|repository| repository == server.repository)
            && std::env::var("GITHUB_RUN_ID")
                .is_ok_and(|id| id.parse::<u64>().ok() == Some(run_id))
            && std::env::var("GITHUB_SHA").is_ok_and(|sha| sha == workflow_sha),
        "client verification must run in the matching Securefix Server workflow context"
    );
    let token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
    ensure!(!token.is_empty(), "GITHUB_TOKEN is empty");
    let api = GitHub::new("https://api.github.com", token)?;
    let run: Value = api.get(&format!(
        "/repos/{}/actions/runs/{run_id}",
        server.repository
    ))?;
    let server_repo: Value = api.get(&format!("/repos/{}", server.repository))?;
    validate_client_source_run(
        &run,
        run_id,
        workflow_sha,
        &server.repository,
        server.id,
        trusted.owner_id,
    )?;
    ensure!(
        server_repo["id"].as_u64() == Some(server.id),
        "configured source repository ID does not match GitHub"
    );
    let artifacts: Value = api.get(&format!(
        "/repos/{}/actions/runs/{run_id}/artifacts",
        server.repository
    ))?;
    let matching = artifacts["artifacts"]
        .as_array()
        .context("client smoke artifact list is malformed")?
        .iter()
        .filter(|artifact| artifact["name"] == artifact_name)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "client smoke artifact is missing or duplicated"
    );
    let artifact = matching[0];
    ensure!(
        artifact["expired"] == false
            && artifact["size_in_bytes"]
                .as_u64()
                .is_some_and(|size| size > 0 && size <= 16 * 1024 * 1024),
        "client smoke artifact is expired or oversized"
    );
    let artifact_id = artifact["id"]
        .as_u64()
        .context("client smoke artifact has no ID")?;
    let bytes = api.download(
        &format!(
            "/repos/{}/actions/artifacts/{artifact_id}/zip",
            server.repository
        ),
        16 * 1024 * 1024,
    )?;
    let source_branch = run["head_branch"]
        .as_str()
        .context("workflow run has no source branch")?;
    let fix = crate::securefix_gate::artifact::parse(
        &bytes,
        artifact_name,
        &server.repository,
        run_id,
        workflow_sha,
        source_branch,
    )?;
    let branch = format!("securefix-client-smoke-{run_id}");
    validate_client_smoke_artifact(&fix, &scratch.repository, run_id, workflow_sha)?;
    let expected_description = format!("{}/{run_id}", server.repository);
    let scratch_api = GitHub::scratch_from_env("SECUREFIX_CLIENT_APP_TOKEN", workflow_sha)?;
    let scratch_repo: Value = scratch_api.get(&format!("/repos/{}", scratch.repository))?;
    ensure!(
        scratch_repo["id"].as_u64() == Some(scratch.id)
            && scratch_repo["full_name"] == scratch.repository,
        "client token destination repository identity changed"
    );
    let label: Value = scratch_api.get(&format!(
        "/repos/{}/labels/{artifact_name}",
        scratch.repository
    ))?;
    ensure!(
        label["name"] == artifact_name && label["description"] == expected_description,
        "client smoke request label does not match its source run and destination"
    );
    workflow::write_json(
        "client-verification.json",
        &ClientVerification {
            version: 1,
            source_repository: server.repository.clone(),
            run_id,
            workflow_sha: workflow_sha.to_owned(),
            artifact_name: artifact_name.to_owned(),
            destination_repository: scratch.repository.clone(),
            destination_branch: branch,
            request_label: artifact_name.to_owned(),
            request_label_description: expected_description,
            verified: true,
        },
    )?;
    println!("Verified client smoke artifact and request label for workflow run {run_id}.");
    Ok(())
}

fn release_pr(
    phase: ReleasePrPhase,
    candidate_sha: &str,
    state_file: &Path,
    scratch_checkout: &Path,
    prepare_run_id: Option<u64>,
    version: &str,
) -> Result<()> {
    let run_id = std::env::var("GITHUB_RUN_ID")?.parse::<u64>()?;
    ensure!(run_id > 0, "invalid release fixture run ID");
    ensure!(
        (phase == ReleasePrPhase::Prepare && prepare_run_id.is_none())
            || (phase == ReleasePrPhase::Verify && prepare_run_id.is_some()),
        "prepare run ID must be supplied only for the verify phase"
    );
    ensure!(
        std::env::var("GITHUB_REPOSITORY")
            .is_ok_and(|repo| repo == server_repository().unwrap_or_default())
            && std::env::var("GITHUB_SHA").is_ok_and(|sha| sha == candidate_sha)
            && std::env::var("GITHUB_ACTOR_ID").is_ok_and(
                |actor| actor.parse::<u64>().ok() == Some(owner_id().unwrap_or_default())
            )
            && std::env::var("GITHUB_RUN_ATTEMPT").is_ok_and(|attempt| attempt == "1"),
        "release fixture must run in a first-attempt owner-triggered candidate workflow"
    );
    let checkout = scratch_checkout.canonicalize()?;
    let remote = git_output(&checkout, &["remote", "get-url", "origin"])?;
    let repository_suffix = integration_repository()?;
    ensure!(
        remote == format!("https://github.com/{repository_suffix}")
            || remote == format!("https://github.com/{repository_suffix}.git")
            || remote == format!("git@github.com:{repository_suffix}")
            || remote == format!("git@github.com:{repository_suffix}.git"),
        "release fixture checkout remote is not the configured scratch repository"
    );
    ensure!(
        state_file.is_absolute(),
        "release fixture state path must be absolute"
    );
    let original_dir = std::env::current_dir()?;
    std::env::set_current_dir(&checkout)?;
    let api = GitHub::scratch_from_env("SECUREFIX_SERVER_APP_TOKEN", candidate_sha)?;
    crate::settings::validate_installation_scope(
        &api,
        &[integration_repository()?.to_owned()],
        trusted_config()?.deployment.repository_owner.id,
    )?;
    let policy = scratch_policy(candidate_sha)?;
    let repository: Value = api.get(&format!("/repos/{}", integration_repository()?))?;
    ensure!(
        repository["id"].as_u64() == Some(integration_repository_id()?)
            && repository["default_branch"]
                .as_str()
                .is_some_and(|branch| !branch.is_empty()),
        "release fixture scratch repository identity or default branch changed"
    );
    let default_branch = repository["default_branch"].as_str().unwrap().to_owned();
    let base: Value = api.get(&format!(
        "/repos/{}/commits/{default_branch}",
        integration_repository()?
    ))?;
    let base_sha = base["sha"]
        .as_str()
        .context("scratch main SHA missing")?
        .to_owned();
    validate_sha(&base_sha)?;
    let local_head = git_output(&checkout, &["rev-parse", "HEAD"])?;
    ensure!(
        local_head == base_sha,
        "scratch checkout is not at the live default branch head"
    );

    let state = match phase {
        ReleasePrPhase::Prepare => {
            let stable_base_sha = std::env::var("SECUREFIX_RELEASE_STABLE_SHA")?;
            validate_sha(&stable_base_sha)?;
            ensure!(
                base_sha != stable_base_sha,
                "scratch main must advance beyond the stable release boundary"
            );
            let comparison: Value = api.get(&format!(
                "/repos/{}/compare/{stable_base_sha}...{base_sha}",
                integration_repository()?
            ))?;
            ensure!(
                comparison["status"] == "ahead" && comparison["behind_by"] == 0,
                "stable release boundary must be an ancestor of scratch main"
            );
            let (stable_tag, _stable_changelog) =
                ensure_release_fixture_tag(&api, &checkout, &stable_base_sha)?;
            let changelog =
                api.content(integration_repository()?, "CHANGELOG.md", &stable_base_sha)?;
            ensure!(
                changelog.len() <= 256 * 1024,
                "stable changelog exceeds fixture limit"
            );
            crate::release::prepare_metadata(version)?;
            let additions = release_metadata_files(&checkout)?;
            let version_heading = format!("[{}]", version.trim_start_matches('v'));
            ensure!(
                std::str::from_utf8(&additions["CHANGELOG.md"])?.contains(&version_heading),
                "git-cliff output did not include the release version"
            );
            let release_branch = trusted_config()?.deployment.release_branch.clone();
            let body = release_pr_body(version, additions.len() > 2);
            let create_pull_request = json!({
                "title": format!("chore(release): v{version}"),
                "body": body,
                "base": default_branch,
            })
            .to_string();
            let label = format!("securefix-release-pr-{run_id}");
            let source = crate::securefix_gate::SourceRequest {
                repository: integration_repository()?,
                run_id,
                label: &label,
                branch: &default_branch,
                sha: &base_sha,
            };
            let fix = crate::securefix_gate::artifact::FixArtifact {
                repository: integration_repository()?.to_owned(),
                branch: release_branch.clone(),
                run_id,
                source_sha: base_sha.clone(),
                commit_message: format!("chore(release): prepare v{version}"),
                create_pull_request: Some(create_pull_request),
                additions,
                deletions: Vec::new(),
            };
            let destination =
                crate::securefix_gate::destination_head(&api, &source, &fix, &None, &policy)?;
            ensure!(
                !destination.branch_exists,
                "release fixture branch already exists; refusing to reuse stale state"
            );
            let plan = crate::securefix_gate::FixPlan {
                version: 1,
                source_repository: integration_repository()?.to_owned(),
                source_run_id: run_id,
                source_sha: base_sha.clone(),
                artifact_name: label.clone(),
                artifact_id: run_id,
                destination_repository: integration_repository()?.to_owned(),
                destination_branch: release_branch.clone(),
                expected_head: destination.sha,
                destination_branch_exists: destination.branch_exists,
                existing_pull_request: destination.pull_request,
            };
            let applied = crate::securefix_gate::apply_core(crate::securefix_gate::ApplyCore {
                read_api: &api,
                write_api: &api,
                policy: &policy,
                source,
                plan: &plan,
                fix: &fix,
                server_url: "https://github.com",
                server_repository: server_repository()?,
                server_run: &run_id.to_string(),
            })?;
            let pr_number = applied
                .pull_request_number
                .context("release fixture PR was not created")?;
            let pull: Value = api.get(&format!(
                "/repos/{}/pulls/{pr_number}",
                integration_repository()?
            ))?;
            ensure!(
                pull["state"] == "open"
                    && pull["head"]["ref"] == release_branch
                    && pull["head"]["sha"] == applied.commit_sha
                    && pull["base"]["sha"] == base_sha,
                "created managed release PR does not match the signed commit"
            );
            let first_changelog = String::from_utf8(api.content(
                integration_repository()?,
                "CHANGELOG.md",
                &applied.commit_sha,
            )?)?;
            ensure!(
                !first_changelog.contains("include final merged change in release PR refresh"),
                "initial release metadata unexpectedly includes the later fixture change"
            );
            ReleasePrState {
                version: 1,
                candidate_sha: candidate_sha.to_owned(),
                prepare_run_id: run_id,
                repository: integration_repository()?.to_owned(),
                repository_id: integration_repository_id()?,
                default_branch,
                base_sha,
                release_branch,
                release_pr: pr_number,
                first_head_sha: applied.commit_sha,
                first_changelog,
                historical_changelog: String::from_utf8(changelog)?,
                stable_tag,
                stable_base_sha,
            }
        }
        ReleasePrPhase::Verify => {
            let state: ReleasePrState = serde_json::from_slice(&fs::read(state_file)?)?;
            ensure!(
                state.version == 1
                    && state.candidate_sha == candidate_sha
                    && state.repository == integration_repository()?
                    && state.repository_id == integration_repository_id()?
                    && state.default_branch == default_branch,
                "release fixture state belongs to a different candidate or scratch repository"
            );
            let prepare_run_id =
                prepare_run_id.context("verify phase requires --prepare-run-id")?;
            ensure!(
                state.prepare_run_id == prepare_run_id,
                "state artifact came from a different prepare run"
            );
            validate_release_pr_prepare_run(prepare_run_id, candidate_sha)?;
            ensure!(
                base_sha != state.base_sha,
                "scratch main did not advance after release PR preparation"
            );
            let comparison: Value = api.get(&format!(
                "/repos/{}/compare/{}...{base_sha}",
                integration_repository()?,
                state.base_sha
            ))?;
            ensure!(
                comparison["status"] == "ahead" && comparison["behind_by"] == 0,
                "prepared scratch main is not an ancestor of current main"
            );
            let files = comparison["files"]
                .as_array()
                .context("main comparison files missing")?;
            ensure!(
                files
                    .iter()
                    .any(|file| file["filename"] == ".securefix-fixtures/release-pr-refresh.txt"),
                "normal owner PR fixture file is missing from main advancement"
            );
            let commit_messages = comparison["commits"]
                .as_array()
                .context("main comparison commits missing")?
                .iter()
                .filter_map(|commit| commit["commit"]["message"].as_str())
                .collect::<Vec<_>>();
            ensure!(
                commit_messages
                    .iter()
                    .any(|message| message
                        .contains("include final merged change in release PR refresh")),
                "normal owner PR commit message is absent from the main advancement"
            );
            ensure!(
                git_output(
                    &checkout,
                    &["rev-parse", &format!("{}^{{}}", state.stable_tag)]
                )? == state.stable_base_sha,
                "scratch checkout does not contain the exact disposable stable tag"
            );
            crate::release::prepare_metadata(version)?;
            let additions = release_metadata_files(&checkout)?;
            let changelog = std::str::from_utf8(&additions["CHANGELOG.md"])?;
            ensure!(
                !state
                    .first_changelog
                    .contains("include final merged change in release PR refresh")
                    && changelog.contains("include final merged change in release PR refresh"),
                "refreshed release changelog does not uniquely include the later main commit"
            );
            ensure_changelog_history(
                &state.historical_changelog,
                changelog,
                &version_heading(version),
            )?;
            let label = format!("securefix-release-pr-{run_id}");
            let source = crate::securefix_gate::SourceRequest {
                repository: integration_repository()?,
                run_id,
                label: &label,
                branch: &default_branch,
                sha: &base_sha,
            };
            let fix = crate::securefix_gate::artifact::FixArtifact {
                repository: integration_repository()?.to_owned(),
                branch: state.release_branch.clone(),
                run_id,
                source_sha: base_sha.clone(),
                commit_message: format!("chore(release): refresh v{version}"),
                create_pull_request: Some(
                    json!({
                        "title": format!("chore(release): v{version}"),
                        "body": release_pr_body(version, additions.len() > 2),
                        "base": default_branch,
                    })
                    .to_string(),
                ),
                additions,
                deletions: Vec::new(),
            };
            let destination =
                crate::securefix_gate::destination_head(&api, &source, &fix, &None, &policy)?;
            ensure!(
                destination.branch_exists
                    && destination.pull_request == Some(state.release_pr)
                    && destination.sha == state.first_head_sha,
                "managed release PR changed before refresh"
            );
            let plan = crate::securefix_gate::FixPlan {
                version: 1,
                source_repository: integration_repository()?.to_owned(),
                source_run_id: run_id,
                source_sha: base_sha.clone(),
                artifact_name: label.clone(),
                artifact_id: run_id,
                destination_repository: integration_repository()?.to_owned(),
                destination_branch: state.release_branch.clone(),
                expected_head: destination.sha.clone(),
                destination_branch_exists: true,
                existing_pull_request: Some(state.release_pr),
            };
            let applied = crate::securefix_gate::apply_core(crate::securefix_gate::ApplyCore {
                read_api: &api,
                write_api: &api,
                policy: &policy,
                source,
                plan: &plan,
                fix: &fix,
                server_url: "https://github.com",
                server_repository: server_repository()?,
                server_run: &run_id.to_string(),
            })?;
            ensure!(
                !applied.already_applied && applied.pull_request_number == Some(state.release_pr),
                "refresh did not update the same managed release PR"
            );
            let commit: Value = api.get(&format!(
                "/repos/{}/commits/{}",
                integration_repository()?,
                applied.commit_sha
            ))?;
            ensure!(
                commit["parents"].as_array().is_some_and(
                    |parents| parents.len() == 1 && parents[0]["sha"] == state.first_head_sha
                ) && commit["author"]["id"].as_u64() == Some(trusted_config()?.server_bot_id)
                    && commit["commit"]["verification"]["verified"] == true,
                "refreshed metadata commit is not signed or parented on the original managed PR head"
            );
            let deadline = Instant::now() + Duration::from_secs(30);
            let pull = loop {
                let pull: Value = api.get(&format!(
                    "/repos/{}/pulls/{}",
                    integration_repository()?,
                    state.release_pr
                ))?;
                ensure!(
                    pull["state"] == "open" && pull["head"]["ref"] == state.release_branch,
                    "managed release PR identity changed after refresh"
                );
                if pull["head"]["sha"] == applied.commit_sha {
                    break pull;
                }
                ensure!(
                    pull["head"]["sha"] == state.first_head_sha && Instant::now() < deadline,
                    "managed release PR was not refreshed in place"
                );
                thread::sleep(Duration::from_secs(1));
            };
            println!(
                "Verified managed release PR refresh for #{}.",
                state.release_pr
            );
            let verification = json!({
                "version": 1,
                "candidate_sha": candidate_sha,
                "prepare_run_id": state.prepare_run_id,
                "verify_run_id": run_id,
                "repository": state.repository,
                "repository_id": state.repository_id,
                "default_branch": state.default_branch,
                "initial_base_sha": state.base_sha,
                "verified_base_sha": base_sha,
                "release_branch": state.release_branch,
                "pull_number": state.release_pr,
                "initial_pr_head_sha": state.first_head_sha,
                "refreshed_pr_head_sha": applied.commit_sha,
                "stable_tag": state.stable_tag,
                "stable_base_sha": state.stable_base_sha,
                "new_fixture_change_in_changelog": true,
                "released_history_preserved": true,
                "verified": true,
            });
            cleanup_release_pr(&api, checkout, state_file, &pull, &state)?;
            workflow::write_json(
                state_file.with_file_name("verification.json"),
                &verification,
            )?;
            return Ok(());
        }
    };
    std::env::set_current_dir(original_dir)?;
    workflow::write_json(state_file, &state)?;
    println!(
        "Prepared managed release PR #{} for main advancement.",
        state.release_pr
    );
    Ok(())
}

fn release_metadata_files(checkout: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::from([
        (
            ".release-version".to_owned(),
            fs::read(checkout.join(".release-version"))?,
        ),
        (
            "CHANGELOG.md".to_owned(),
            fs::read(checkout.join("CHANGELOG.md"))?,
        ),
    ]);
    for path in ["dbt_project.yml", "pyproject.toml"] {
        if checkout.join(path).is_file() {
            files.insert(path.to_owned(), fs::read(checkout.join(path))?);
        }
    }
    Ok(files)
}

fn version_heading(version: &str) -> String {
    format!("[{}]", version.trim_start_matches('v'))
}

fn ensure_changelog_history(historical: &str, refreshed: &str, version: &str) -> Result<()> {
    let section = |content: &str, start: usize| {
        content[start + 1..]
            .find("\n## ")
            .map(|offset| start + 1 + offset + 1)
    };
    let old_start = historical
        .find("\n## ")
        .map(|offset| offset + 1)
        .context("historical changelog has no released version section")?;
    let new_start = refreshed
        .find("\n## ")
        .map(|offset| offset + 1)
        .context("refreshed changelog has no version section")?;
    let new_old_start = section(refreshed, new_start)
        .context("refreshed changelog omitted historical release sections")?;
    ensure!(
        refreshed[..new_start] == historical[..old_start]
            && refreshed[new_old_start..].trim_end() == historical[old_start..].trim_end()
            && refreshed[new_start..new_old_start].contains(version),
        "refreshed release changelog changed or lost its released history"
    );
    Ok(())
}

fn validate_release_pr_prepare_run(run_id: u64, candidate_sha: &str) -> Result<()> {
    let token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
    ensure!(!token.is_empty(), "GITHUB_TOKEN is empty");
    let api = GitHub::new("https://api.github.com", token)?;
    let run: Value = api.get(&format!(
        "/repos/{}/actions/runs/{run_id}",
        server_repository()?
    ))?;
    let allowed_paths = [
        ".github/workflows/testing-securefix-server.yml",
        ".github/workflows/testing-release-pr.yml",
    ];
    let branch = run["head_branch"]
        .as_str()
        .context("prepare run branch missing")?;
    ensure!(
        run["id"].as_u64() == Some(run_id)
            && run["repository"]["id"].as_u64() == Some(server_repository_id()?)
            && run["head_repository"]["id"].as_u64() == Some(server_repository_id()?)
            && run["head_sha"] == candidate_sha
            && run["event"] == "workflow_dispatch"
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && run["run_attempt"].as_u64() == Some(1)
            && run["actor"]["id"].as_u64() == Some(owner_id()?)
            && run["triggering_actor"]["id"].as_u64() == Some(owner_id()?)
            && run["path"]
                .as_str()
                .is_some_and(|path| allowed_paths.contains(&path))
            && branch.starts_with("integration/native-"),
        "release PR state is not from a successful owner-run candidate workflow"
    );
    validate_workflow_ref(candidate_sha, &format!("refs/heads/{branch}"))?;
    let source: Value = api.get(&format!(
        "/repos/{}/commits/{}",
        server_repository()?,
        branch.replace('/', "%2F")
    ))?;
    ensure!(
        source["sha"] == candidate_sha,
        "candidate branch moved after release PR prepare"
    );
    Ok(())
}

fn release_pr_body(version: &str, package: bool) -> String {
    let metadata = if package {
        "package version metadata"
    } else {
        "release metadata"
    };
    format!(
        "## Summary\n- Prepare release v{version}\n- Update the changelog and {metadata}\n\nThis pull request is managed by the Release PR workflow."
    )
}

fn git_output(repository: &Path, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(repository)
        .output()?;
    ensure!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn ensure_release_fixture_tag(
    api: &GitHub,
    checkout: &Path,
    stable_sha: &str,
) -> Result<(String, Vec<u8>)> {
    use crate::release::{CommitSha, ReleaseTag, Repository};
    let repo = Repository::parse(integration_repository()?)?;
    let tag = ReleaseTag::parse("v0.1.0")?;
    let path = format!(
        "/repos/{}/git/ref/tags/{}",
        integration_repository()?,
        tag.as_str()
    );
    match api.get::<Value>(&path) {
        Ok(_) => anyhow::bail!("stable fixture tag already exists; refusing to overwrite it"),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|api| api.status == reqwest::StatusCode::NOT_FOUND) => {}
        Err(error) => return Err(error).context("read scratch stable fixture tag"),
    }
    crate::release::create_annotated_tag(api, &repo, &tag, &CommitSha::parse(stable_sha)?)?;
    if git_output(
        checkout,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            "refs/tags/v0.1.0^{commit}",
        ],
    )
    .is_err()
    {
        git_output(checkout, &["tag", "v0.1.0", stable_sha])?;
    }
    let changelog = api.content(integration_repository()?, "CHANGELOG.md", stable_sha)?;
    Ok((tag.as_str().to_owned(), changelog))
}

fn cleanup_release_pr(
    api: &GitHub,
    checkout: PathBuf,
    state_file: &Path,
    pull: &Value,
    state: &ReleasePrState,
) -> Result<()> {
    let repo = integration_repository()?;
    let head = pull["head"]["sha"]
        .as_str()
        .context("verified release PR has no head SHA")?;
    let live_pull: Value = api.get(&format!("/repos/{repo}/pulls/{}", state.release_pr))?;
    ensure!(
        live_pull["number"].as_u64() == Some(state.release_pr)
            && live_pull["state"] == "open"
            && live_pull["head"]["ref"] == state.release_branch
            && live_pull["head"]["repo"]["id"].as_u64() == Some(integration_repository_id()?)
            && live_pull["base"]["repo"]["id"].as_u64() == Some(integration_repository_id()?)
            && live_pull["head"]["sha"] == head,
        "release PR identity or head changed before cleanup"
    );
    let branch: Value = api.get(&format!(
        "/repos/{repo}/git/ref/heads/{}",
        state.release_branch
    ))?;
    ensure!(
        branch["object"]["sha"] == head,
        "release branch changed before cleanup"
    );
    let tag: Value = api.get(&format!("/repos/{repo}/git/ref/tags/{}", state.stable_tag))?;
    let tag_object = tag["object"]["sha"]
        .as_str()
        .context("stable fixture tag object missing")?;
    let tag_commit = if tag["object"]["type"] == "tag" {
        let annotated: Value = api.get(&format!("/repos/{repo}/git/tags/{tag_object}"))?;
        annotated["object"]["sha"]
            .as_str()
            .context("stable fixture tag target missing")?
            .to_owned()
    } else {
        tag_object.to_owned()
    };
    ensure!(
        tag_commit == state.stable_base_sha,
        "stable fixture tag changed before cleanup"
    );
    let closed: Value = api.patch(
        &format!("/repos/{repo}/pulls/{}", state.release_pr),
        &json!({"state":"closed"}),
    )?;
    ensure!(
        closed["state"] == "closed" && closed["head"]["sha"] == head,
        "release PR changed while it was being closed"
    );
    let branch_after_close: Value = api.get(&format!(
        "/repos/{repo}/git/ref/heads/{}",
        state.release_branch
    ))?;
    ensure!(
        branch_after_close["object"]["sha"] == head,
        "release branch changed while the PR was being closed"
    );
    let tag_after_close: Value =
        api.get(&format!("/repos/{repo}/git/ref/tags/{}", state.stable_tag))?;
    ensure!(
        tag_after_close["object"]["sha"] == tag_object,
        "stable fixture tag changed while the PR was being closed"
    );
    let delete_branch = api.delete(&format!(
        "/repos/{repo}/git/refs/heads/{}",
        state.release_branch
    ));
    let delete_tag = api.delete(&format!("/repos/{repo}/git/refs/tags/{}", state.stable_tag));
    let _ = std::process::Command::new("git")
        .args(["tag", "-d", &state.stable_tag])
        .current_dir(checkout)
        .output();
    delete_branch?;
    delete_tag?;
    fs::remove_file(state_file)?;
    Ok(())
}

fn prepare_client_input() -> Result<()> {
    let trusted = crate::config::trusted()?;
    let server = &trusted.deployment.server;
    let workflow_sha = std::env::var("GITHUB_SHA").context("missing GITHUB_SHA")?;
    validate_sha(&workflow_sha)?;
    let workflow_ref = std::env::var("GITHUB_REF").context("missing GITHUB_REF")?;
    let run_id = std::env::var("GITHUB_RUN_ID")
        .context("missing GITHUB_RUN_ID")?
        .parse::<u64>()
        .context("invalid GITHUB_RUN_ID")?;
    ensure!(
        run_id > 0
            && std::env::var("GITHUB_REPOSITORY")
                .is_ok_and(|repository| repository == server.repository)
            && std::env::var("GITHUB_EVENT_NAME").is_ok_and(|event| event == "workflow_dispatch")
            && std::env::var("GITHUB_ACTOR_ID")
                .is_ok_and(|actor| actor.parse::<u64>().ok() == Some(trusted.owner_id))
            && std::env::var("GITHUB_RUN_ATTEMPT").is_ok_and(|attempt| attempt == "1"),
        "client input must be prepared by the first owner-triggered server workflow run"
    );
    validate_workflow_ref(&workflow_sha, &workflow_ref)?;

    let policy_bytes = scratch_client_policy(&crate::config::trusted_policy_bytes()?)?;
    ensure!(
        policy_bytes.len() <= 256 * 1024,
        "scratch policy is oversized"
    );
    fs::write("scratch-policy.json", policy_bytes)?;
    fs::create_dir_all(".securefix-client-smoke")?;
    fs::write(
        ".securefix-client-smoke/request.txt",
        format!("Securefix client smoke {run_id}\n"),
    )?;
    Ok(())
}

fn validate_client_source_run(
    run: &Value,
    run_id: u64,
    workflow_sha: &str,
    server_repository: &str,
    server_repository_id: u64,
    owner_id: u64,
) -> Result<()> {
    let workflow_matches = workflow_run_matches(run, workflow_sha)?;
    let actual_run_id = run["id"].as_u64();
    let repo_full_name = run["repository"]["full_name"].as_str().unwrap_or_default();
    let repo_id = run["repository"]["id"].as_u64();
    let head_repo_id = run["head_repository"]["id"].as_u64();
    let head_sha = run["head_sha"].as_str().unwrap_or_default();
    let event = run["event"].as_str().unwrap_or_default();
    let attempt = run["run_attempt"].as_u64();
    let actor_id = run["actor"]["id"].as_u64();
    let triggering_actor_id = run["triggering_actor"]["id"].as_u64();
    ensure!(
        run["id"].as_u64() == Some(run_id)
            && run["repository"]["full_name"] == server_repository
            && repo_id == Some(server_repository_id)
            && head_repo_id == Some(server_repository_id)
            && head_sha == workflow_sha
            && event == "workflow_dispatch"
            && attempt == Some(1)
            && actor_id == Some(owner_id)
            && triggering_actor_id == Some(owner_id)
            && workflow_matches,
        "client smoke run {run_id} provenance mismatch: actual_run_id={actual_run_id:?}, repository={repo_full_name}, repo_id={repo_id:?}, head_repo_id={head_repo_id:?}, head_sha={head_sha}, event={event}, attempt={attempt:?}, actor_id={actor_id:?}, triggering_actor_id={triggering_actor_id:?}, workflow_matches={workflow_matches}"
    );
    Ok(())
}

fn scratch_client_policy(trusted_policy: &[u8]) -> Result<Vec<u8>> {
    let mut policy: Value = serde_json::from_slice(trusted_policy)?;
    // Client-only fixtures have no approval capability and must also work with
    // the currently published runtime while a new policy schema is unreleased.
    policy
        .as_object_mut()
        .context("scratch client policy must be an object")?
        .remove("sensitive_path_approval_exemptions");
    let server_deployment = policy["deployment"]["server"].clone();
    policy["deployment"]["server"] = policy["deployment"]["integration"].clone();
    policy["deployment"]["integration"] = server_deployment;
    policy["repositories"] = json!([{
        "repository": policy["deployment"]["server"]["repository"],
        "capabilities": ["securefix"],
        "release": null,
        "protect_tags": false
    }]);
    let bytes = serde_json::to_vec_pretty(&policy)?;
    crate::policy::Policy::parse(&bytes)?;
    Ok(bytes)
}

fn validate_client_smoke_artifact(
    fix: &crate::securefix_gate::artifact::FixArtifact,
    scratch_repository: &str,
    run_id: u64,
    workflow_sha: &str,
) -> Result<()> {
    let expected_contents = format!("Securefix client smoke {run_id}\n").into_bytes();
    ensure!(
        fix.repository == scratch_repository
            && fix.branch == format!("securefix-client-smoke-{run_id}")
            && fix.source_sha == workflow_sha
            && fix.run_id == run_id
            && fix.deletions.is_empty()
            && fix.create_pull_request.is_none()
            && fix.additions.len() == 1
            && fix.additions.get(".securefix-client-smoke/request.txt") == Some(&expected_contents),
        "client smoke artifact does not match the exact scratch fixture"
    );
    Ok(())
}

fn validate_producer(workflow_sha: &str) -> Result<()> {
    validate_sha(workflow_sha)?;
    let trusted = crate::config::trusted()?;
    let configured_server = &trusted.deployment.server.repository;
    ensure!(
        std::env::var("GITHUB_REPOSITORY")
            .is_ok_and(|repository| repository == configured_server.as_str()),
        "producer must run in the Securefix Server repository"
    );
    ensure!(
        std::env::var("GITHUB_ACTOR_ID")
            .is_ok_and(|actor| actor.parse::<u64>().ok() == Some(trusted.owner_id))
            && std::env::var("GITHUB_ACTOR")
                .is_ok_and(|actor| actor == trusted.deployment.owner_login.as_str())
            && std::env::var("GITHUB_RUN_ATTEMPT").is_ok_and(|attempt| attempt == "1"),
        "producer must be an owner-triggered first attempt"
    );
    let workflow_ref = std::env::var("GITHUB_REF").context("missing GITHUB_REF")?;
    validate_workflow_ref(workflow_sha, &workflow_ref)?;

    let token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
    ensure!(!token.is_empty(), "GITHUB_TOKEN is empty");
    let api = GitHub::new("https://api.github.com", token)?;
    let repository: Value = api.get(&format!("/repos/{}", server_repository()?))?;
    ensure!(
        repository["full_name"] == server_repository()?
            && repository["id"].as_u64() == Some(server_repository_id()?),
        "producer repository identity changed"
    );
    let branch = workflow_ref
        .strip_prefix("refs/heads/")
        .context("integration producer must run from a branch")?;
    let encoded_branch = branch.replace('/', "%2F");
    let source: Value = api.get(&format!(
        "/repos/{}/commits/{encoded_branch}",
        server_repository()?
    ))?;
    ensure!(
        source["sha"] == workflow_sha,
        "trusted integration workflow branch moved from its source SHA"
    );
    let (published_runtime_sha, published_runtime_tag) = current_published_runtime(&api)?;
    securefix::output("published_runtime_sha", &published_runtime_sha)?;
    securefix::output("published_runtime_tag", &published_runtime_tag)?;
    Ok(())
}

fn integration_read_api() -> Result<GitHub> {
    let expected_repository = server_repository()?;
    ensure!(
        std::env::var("GITHUB_REPOSITORY")
            .is_ok_and(|repository| repository == expected_repository),
        "runtime metadata lookup must run in the Securefix Server repository"
    );
    let token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
    ensure!(!token.is_empty(), "GITHUB_TOKEN is empty");
    GitHub::new("https://api.github.com", token)
}

fn current_published_runtime(api: &GitHub) -> Result<(String, String)> {
    let trusted = crate::config::trusted()?;
    let server = &trusted.deployment.server;
    let repository: Value = api.get(&format!("/repos/{}", server.repository))?;
    ensure!(
        repository["full_name"] == server.repository
            && repository["id"].as_u64() == Some(server.id)
            && repository["owner"]["id"].as_u64() == Some(trusted.deployment.repository_owner.id)
            && repository["default_branch"] == server.default_branch.as_str(),
        "published runtime repository identity changed"
    );
    let main: Value = api.get(&format!(
        "/repos/{}/commits/{}",
        server.repository, server.default_branch
    ))?;
    let source_sha = main["sha"]
        .as_str()
        .context("server default branch SHA missing")?;
    validate_sha(source_sha)?;
    let version = crate::runtime::version_at_source(api, source_sha)?;
    let tag = version.tag();
    let tag_ref = optional_tag_ref(api, &tag)?.context("canonical runtime tag is missing")?;
    ensure!(
        tag_ref["ref"] == format!("refs/tags/{tag}")
            && tag_ref["object"]["type"] == "commit"
            && tag_ref["object"]["sha"] == source_sha,
        "canonical runtime tag does not directly target the default branch source"
    );
    validate_runtime_release(api, source_sha, &tag, !version.as_semver().pre.is_empty())?;
    Ok((source_sha.to_owned(), tag))
}

/// Candidate-only bridge for the first SemVer cutover. The trusted baseline CLI
/// validates the complete published runtime before this helper is called. This
/// helper only selects the source-derived tag format and never downloads or runs
/// a runtime release.
fn resolve_test_runtime_tag(api: &GitHub, expected_sha: &str) -> Result<String> {
    validate_sha(expected_sha)?;

    let trusted = crate::config::trusted()?;
    let server = &trusted.deployment.server;
    let repository: Value = api.get(&format!("/repos/{}", server.repository))?;
    ensure!(
        repository["full_name"] == server.repository
            && repository["id"].as_u64() == Some(server.id)
            && repository["owner"]["id"].as_u64() == Some(trusted.deployment.repository_owner.id)
            && repository["default_branch"] == server.default_branch.as_str(),
        "published runtime repository identity changed"
    );
    let main: Value = api.get(&format!(
        "/repos/{}/commits/{}",
        server.repository, server.default_branch
    ))?;
    let source_sha = main["sha"]
        .as_str()
        .context("server default branch SHA missing")?;
    validate_sha(source_sha)?;
    ensure!(
        source_sha == expected_sha,
        "server default branch moved after baseline runtime validation"
    );
    let version = crate::runtime::version_at_source(api, expected_sha)?;
    let canonical = version.tag();
    let legacy = format!("{canonical}+{expected_sha}");
    let canonical_ref = optional_tag_ref(api, &canonical)?;
    let canonical_annotation = match canonical_ref.as_ref() {
        Some(reference) if reference["object"]["type"] == "tag" => {
            let tag_sha = reference["object"]["sha"]
                .as_str()
                .context("annotated canonical baseline tag has no object SHA")?;
            validate_sha(tag_sha)?;
            Some(api.get(&format!("/repos/{}/git/tags/{tag_sha}", server.repository))?)
        }
        _ => None,
    };
    let legacy_ref = optional_tag_ref(api, &legacy)?;
    let tag = select_test_runtime_tag(
        &version,
        expected_sha,
        canonical_ref,
        canonical_annotation,
        legacy_ref,
    )?;
    let (release_tag, prerelease) = if tag == canonical {
        (canonical, !version.as_semver().pre.is_empty())
    } else {
        // The legacy version tag was an annotation. Its runtime release used
        // the separate SHA-keyed release name.
        (format!("securefix-runtime-{expected_sha}"), true)
    };
    validate_runtime_release(api, expected_sha, &release_tag, prerelease)?;
    Ok(tag)
}

fn select_test_runtime_tag(
    version: &crate::runtime::RuntimeVersion,
    expected_sha: &str,
    canonical_ref: Option<Value>,
    canonical_annotation: Option<Value>,
    legacy_ref: Option<Value>,
) -> Result<String> {
    validate_sha(expected_sha)?;
    let canonical = version.tag();
    let legacy = format!("{canonical}+{expected_sha}");
    let mut candidates = Vec::new();
    if let Some(reference) = canonical_ref {
        ensure!(
            reference["ref"] == format!("refs/tags/{canonical}"),
            "canonical baseline version tag ref identity is invalid"
        );
        match reference["object"]["type"].as_str() {
            Some("commit") => {
                ensure!(
                    canonical_annotation.is_none(),
                    "unexpected canonical tag object"
                );
                let target_sha = reference["object"]["sha"]
                    .as_str()
                    .context("canonical baseline version tag has no target SHA")?;
                validate_sha(target_sha)?;
                if target_sha == expected_sha {
                    candidates.push((canonical.clone(), reference));
                }
            }
            Some("tag") => {
                let tag_sha = reference["object"]["sha"]
                    .as_str()
                    .context("annotated canonical baseline tag has no object SHA")?;
                validate_sha(tag_sha)?;
                let annotation = canonical_annotation
                    .context("annotated canonical baseline tag object is missing")?;
                let target_sha = annotation["object"]["sha"]
                    .as_str()
                    .context("annotated canonical baseline tag target is missing")?;
                ensure!(
                    annotation["sha"] == tag_sha
                        && annotation["tag"] == canonical
                        && annotation["object"]["type"] == "commit",
                    "canonical baseline tag annotation identity or target type is invalid"
                );
                validate_sha(target_sha)?;
                ensure!(
                    target_sha != expected_sha,
                    "canonical annotated version tag cannot identify the current source"
                );
                // Historical canonical annotated tags are ignored only after
                // resolving exactly one annotation to an older direct commit.
            }
            _ => anyhow::bail!("canonical baseline version tag object type is invalid"),
        }
    } else {
        ensure!(
            canonical_annotation.is_none(),
            "unexpected canonical tag object"
        );
    }
    if let Some(reference) = legacy_ref {
        ensure!(
            reference["ref"] == format!("refs/tags/{legacy}")
                && reference["object"]["type"] == "commit"
                && reference["object"]["sha"] == expected_sha,
            "legacy source annotation does not directly target its exact source"
        );
        candidates.push((legacy.clone(), reference));
    }
    ensure!(
        candidates.len() == 1,
        "baseline source must have exactly one canonical or legacy version tag"
    );
    Ok(candidates.remove(0).0)
}

fn optional_tag_ref(api: &GitHub, tag: &str) -> Result<Option<Value>> {
    let path = format!("/repos/{}/git/ref/tags/{tag}", server_repository()?);
    match api.get(&path) {
        Ok(reference) => Ok(Some(reference)),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|api| api.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            Ok(None)
        }
        Err(error) => Err(error).with_context(|| format!("read baseline runtime tag {tag}")),
    }
}

fn validate_runtime_release(
    api: &GitHub,
    source_sha: &str,
    tag: &str,
    prerelease: bool,
) -> Result<()> {
    let release: Value = api.get(&format!(
        "/repos/{}/releases/tags/{tag}",
        server_repository()?
    ))?;
    let assets = release["assets"]
        .as_array()
        .context("published runtime assets missing")?;
    ensure!(
        release["tag_name"] == tag
            && release["name"] == tag
            && release["target_commitish"] == source_sha
            && release["draft"] == false
            && release["prerelease"] == prerelease
            && assets.len() == 1
            && assets[0]["name"] == "securefix-runtime-linux-x86_64.tar.gz"
            && assets[0]["state"] == "uploaded"
            && assets[0]["size"].as_u64().is_some_and(|size| size > 0)
            && assets[0]["digest"].as_str().is_some_and(|digest| {
                digest.strip_prefix("sha256:").is_some_and(|hex| {
                    hex.len() == 64
                        && hex
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
            }),
        "published runtime release metadata or asset is invalid"
    );
    Ok(())
}

fn published_runtime_tag_from_env() -> Result<String> {
    let tag = std::env::var("SECUREFIX_PUBLISHED_RUNTIME_TAG")
        .context("missing SECUREFIX_PUBLISHED_RUNTIME_TAG")?;
    ensure!(
        !tag.is_empty() && tag.len() <= 256,
        "invalid published runtime tag"
    );
    Ok(tag)
}

fn validate_test_runtime_tag(api: &GitHub, sha: &str, tag: &str) -> Result<String> {
    let expected = resolve_test_runtime_tag(api, sha)?;
    ensure!(tag == expected, "published runtime tag metadata changed");
    Ok(expected)
}

fn published_runtime_sha_from_env() -> Result<String> {
    let sha = std::env::var("SECUREFIX_PUBLISHED_RUNTIME_SHA")
        .context("missing SECUREFIX_PUBLISHED_RUNTIME_SHA")?;
    validate_sha(&sha)?;
    Ok(sha)
}

fn validate_workflow_ref(workflow_sha: &str, workflow_ref: &str) -> Result<()> {
    validate_sha(workflow_sha)?;
    let workflow_branch = workflow_ref
        .strip_prefix("refs/heads/")
        .context("integration producer must run from a branch")?;
    ensure!(
        workflow_run_matches(
            &json!({
                "head_sha":workflow_sha,
                "head_branch":workflow_branch,
                "path":format!("{WORKFLOW_PATH}@{workflow_ref}")
            }),
            workflow_sha,
        )?,
        "integration producer branch is not trusted"
    );
    Ok(())
}

fn fetch_state(candidate_sha: &str, run_id: u64, state_file: &Path) -> Result<()> {
    ensure!(run_id > 0, "invalid fixture workflow run ID");
    let token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
    ensure!(!token.is_empty(), "GITHUB_TOKEN is empty");
    let api = GitHub::new("https://api.github.com", token)?;
    let run: Value = api.get(&format!(
        "/repos/{}/actions/runs/{run_id}",
        server_repository()?
    ))?;
    let artifacts: Value = api.get(&format!(
        "/repos/{}/actions/runs/{run_id}/artifacts",
        server_repository()?
    ))?;
    let matching = artifacts["artifacts"]
        .as_array()
        .context("fixture workflow artifact list is malformed")?
        .iter()
        .filter(|artifact| artifact["name"] == "scratch-fixtures")
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "scratch fixture artifact is missing or duplicated"
    );
    let artifact = matching[0];
    ensure!(
        artifact["expired"] == false
            && artifact["size_in_bytes"]
                .as_u64()
                .is_some_and(|size| size <= 64 * 1024),
        "scratch fixture artifact is expired or oversized"
    );
    let artifact_id = artifact["id"]
        .as_u64()
        .context("scratch artifact has no ID")?;
    let bytes = api.download(
        &format!(
            "/repos/{}/actions/artifacts/{artifact_id}/zip",
            server_repository()?
        ),
        64 * 1024,
    )?;
    let scenario = scenario_from_zip(&bytes)?;
    let (published_runtime_sha, published_runtime_tag) = current_published_runtime(&api)?;
    validate_scenario(&scenario, candidate_sha, &published_runtime_sha)?;
    securefix::output("published_runtime_sha", &published_runtime_sha)?;
    securefix::output("published_runtime_tag", &published_runtime_tag)?;
    let server_repo: Value = api.get(&format!("/repos/{}", server_repository()?))?;
    let workflow_matches = workflow_run_matches(&run, &scenario.workflow_sha)?;
    ensure!(
        run["id"].as_u64() == Some(run_id)
            && run["repository"]["full_name"] == server_repository()?
            && run["repository"]["id"].as_u64() == Some(server_repository_id()?)
            && run["head_repository"]["id"].as_u64() == Some(server_repository_id()?)
            && server_repo["id"].as_u64() == Some(server_repository_id()?)
            && run["head_sha"] == scenario.workflow_sha
            && run["event"] == "workflow_dispatch"
            && run["run_attempt"] == 1
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && run["actor"]["id"].as_u64() == Some(owner_id()?)
            && run["triggering_actor"]["id"].as_u64() == Some(owner_id()?)
            && workflow_matches,
        "fixture state source is not the successful owner-run candidate workflow"
    );
    let candidate_artifacts = artifacts["artifacts"]
        .as_array()
        .context("candidate artifact list is malformed")?
        .iter()
        .filter(|artifact| artifact["name"] == "candidate-runtime")
        .collect::<Vec<_>>();
    ensure!(
        candidate_artifacts.len() == 1,
        "candidate runtime is missing or duplicated"
    );
    let candidate = candidate_artifacts[0];
    ensure!(
        candidate["expired"] == false
            && candidate["size_in_bytes"]
                .as_u64()
                .is_some_and(|size| size > 0 && size <= 64 * 1024 * 1024),
        "candidate runtime is expired or oversized"
    );
    let candidate_artifact_id = candidate["id"]
        .as_u64()
        .context("candidate runtime has no artifact ID")?;
    workflow::write_json(state_file, &scenario)?;
    securefix::output("candidate_artifact_id", candidate_artifact_id.to_string())?;
    securefix::output("candidate_sha", candidate_sha)?;
    println!("Fetched verified scratch state from owner candidate workflow run {run_id}.");
    println!("{}", serde_json::to_string(&scenario)?);
    Ok(())
}

fn scenario_from_zip(bytes: &[u8]) -> Result<Scenario> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    ensure!(
        archive.len() == 1,
        "scratch fixture artifact must contain one file"
    );
    let mut file = archive.by_index(0)?;
    ensure!(
        file.name() == "state.json"
            && file.is_file()
            && file.size() <= 16 * 1024
            && file
                .unix_mode()
                .is_none_or(|mode| mode & 0o170000 != 0o120000),
        "invalid scratch state artifact entry"
    );
    let declared_size = file.size();
    let mut content = Vec::new();
    use std::io::Read;
    (&mut file).take(16 * 1024 + 1).read_to_end(&mut content)?;
    ensure!(
        content.len() <= 16 * 1024 && content.len() as u64 == declared_size,
        "scratch state artifact size mismatch"
    );
    Ok(serde_json::from_slice(&content)?)
}

fn prepare(candidate_sha: &str, state_file: &Path) -> Result<()> {
    let workflow_sha = std::env::var("SECUREFIX_TEST_WORKFLOW_SHA")
        .context("missing SECUREFIX_TEST_WORKFLOW_SHA")?;
    validate_sha(&workflow_sha)?;
    let published_runtime_sha = std::env::var("SECUREFIX_PUBLISHED_RUNTIME_SHA")
        .context("missing SECUREFIX_PUBLISHED_RUNTIME_SHA")?;
    validate_sha(&published_runtime_sha)?;
    let published_runtime_tag = published_runtime_tag_from_env()?;
    let workflow_ref = std::env::var("GITHUB_REF").context("missing GITHUB_REF")?;
    validate_workflow_ref(&workflow_sha, &workflow_ref)?;
    let server = GitHub::scratch_from_env("SECUREFIX_SERVER_APP_TOKEN", candidate_sha)?;
    let _client = GitHub::scratch_from_env("SECUREFIX_CLIENT_APP_TOKEN", candidate_sha)?;
    crate::settings::validate_installation_scope(
        &server,
        &[integration_repository()?.to_owned()],
        trusted_config()?.deployment.repository_owner.id,
    )?;
    let repository: Value = server.get(&format!("/repos/{}", integration_repository()?))?;
    ensure!(
        repository["full_name"] == integration_repository()?
            && repository["id"].as_u64() == Some(integration_repository_id()?)
            && repository["owner"]["id"].as_u64()
                == Some(trusted_config()?.deployment.repository_owner.id),
        "scratch repository identity changed"
    );
    let default_branch = repository["default_branch"]
        .as_str()
        .context("scratch repository has no default branch")?
        .to_owned();
    let base: Value = server.get(&format!(
        "/repos/{}/commits/{default_branch}",
        integration_repository()?
    ))?;
    let base_sha = base["sha"]
        .as_str()
        .context("scratch default branch has no SHA")?
        .to_owned();
    validate_sha(&base_sha)?;

    approve_owner_fixture(&server, candidate_sha, &default_branch, &base_sha)?;

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let positive_branch = format!("{BRANCH_PREFIX}positive-{nonce}");
    let mut positive_fix = prepare_positive_artifact(candidate_sha, &positive_branch)?;
    positive_fix.create_pull_request = Some(
        json!({
            "title":format!("test: Securefix native apply integration {}", &candidate_sha[..12]),
            "body":"Created by the native Securefix integration apply core.",
            "base":default_branch.clone(),
        })
        .to_string(),
    );
    let scratch_policy = scratch_policy(candidate_sha)?;
    let positive = create_nativefix_positive_pr(
        &server,
        &scratch_policy,
        &base_sha,
        &default_branch,
        &positive_branch,
        &positive_fix,
        candidate_sha,
    )?;
    verify_sensitive_path_authorization(
        &server,
        &scratch_policy,
        &positive,
        &default_branch,
        candidate_sha,
    )?;
    let stale = create_pr(
        &server,
        &base_sha,
        &default_branch,
        &format!("{BRANCH_PREFIX}stale-{nonce}"),
        &format!(
            "test: Securefix stale-head integration {}",
            &candidate_sha[..12]
        ),
        BTreeMap::from([(
            format!("{FIX_PATH_PREFIX}stale-{nonce}.txt"),
            format!("candidate={candidate_sha}\nscenario=stale-head\n").into_bytes(),
        )]),
    )?;

    let rendered = distribution_fixture_files(
        &published_runtime_sha,
        &published_runtime_tag,
        &default_branch,
    )?;
    ensure!(
        !rendered.is_empty(),
        "distribution renderer returned no workflows"
    );
    let obsolete_workflows = existing_scratch_workflows(&server, &base_sha)?;
    let distribution = create_pr_with_changes(
        &server,
        &base_sha,
        &default_branch,
        &format!("{BRANCH_PREFIX}distribution-{nonce}"),
        &format!(
            "test: Securefix distribution integration {}",
            &candidate_sha[..12]
        ),
        rendered.clone(),
        obsolete_workflows,
    )?;
    validate_rendered_files(&rendered)?;

    let state = Scenario {
        version: STATE_VERSION,
        repository: integration_repository()?.to_owned(),
        repository_id: integration_repository_id()?,
        candidate_sha: candidate_sha.to_owned(),
        published_runtime_sha,
        workflow_sha,
        default_branch,
        base_sha,
        prepared_at: Utc::now(),
        positive,
        stale,
        distribution,
    };
    validate_scenario(&state, candidate_sha, &state.published_runtime_sha)?;
    workflow::write_json(state_file, &state)?;
    println!("Prepared Securefix scratch integration state.");
    println!(
        "Positive PR (post exact owner /approve and /merge; add a current-head review): {}",
        state.positive.url
    );
    println!(
        "Stale-head PR (post exact owner /merge before Verify): {}",
        state.stale.url
    );
    println!(
        "Distribution PR (managed workflow bytes are generated from candidate SHA): {}",
        state.distribution.url
    );
    println!("State file: {}", state_file.display());
    Ok(())
}

fn create_pr(
    api: &GitHub,
    base_sha: &str,
    base_branch: &str,
    branch: &str,
    title: &str,
    files: BTreeMap<String, Vec<u8>>,
) -> Result<PullRequestFixture> {
    create_pr_with_changes(api, base_sha, base_branch, branch, title, files, Vec::new())
}

fn create_pr_with_changes(
    api: &GitHub,
    base_sha: &str,
    base_branch: &str,
    branch: &str,
    title: &str,
    files: BTreeMap<String, Vec<u8>>,
    deletions: Vec<String>,
) -> Result<PullRequestFixture> {
    validate_branch(branch)?;
    ensure!(
        !files.is_empty() || !deletions.is_empty(),
        "integration fixture commit has no files"
    );
    let _: Value = api.post(
        &format!("/repos/{}/git/refs", integration_repository()?),
        &json!({"ref":format!("refs/heads/{branch}"),"sha":base_sha}),
    )?;
    let message = format!("{title}\n\nCandidate: {base_sha}");
    let head_sha = api.create_commit(
        integration_repository()?,
        branch,
        base_sha,
        &message,
        files,
        deletions,
    )?;
    let pull: Value = api.post(
        &format!("/repos/{}/pulls", integration_repository()?),
        &json!({"title":title,"head":branch,"base":base_branch,"body":"Created by the native Securefix scratch integration harness."}),
    )?;
    ensure!(
        pull["state"] == "open"
            && pull["base"]["ref"] == base_branch
            && pull["head"]["sha"] == head_sha
            && pull["head"]["ref"] == branch,
        "GitHub created an unexpected scratch pull request"
    );
    Ok(PullRequestFixture {
        number: pull["number"]
            .as_u64()
            .context("scratch pull request has no number")?,
        branch: branch.to_owned(),
        head_sha,
        url: pull["html_url"]
            .as_str()
            .context("scratch pull request has no URL")?
            .to_owned(),
    })
}

fn verify_sensitive_path_authorization(
    api: &GitHub,
    policy: &Policy,
    positive: &PullRequestFixture,
    default_branch: &str,
    candidate_sha: &str,
) -> Result<()> {
    const OWNER_REQUIRED: &str = "owner authorization for this exact pull request head is missing";

    let mut sensitive_policy = policy.clone();
    sensitive_policy.repositories[0].sensitive_paths = vec!["**".to_owned()];
    sensitive_policy.sensitive_path_approval_exemptions = Default::default();
    let existing_comments = api.paginate(&format!(
        "/repos/{}/issues/{}/comments",
        integration_repository()?,
        positive.number
    ))?;
    let marker_prefix = format!("<!-- securefix:v2:owner:{}:", positive.head_sha);
    ensure!(
        existing_comments.iter().all(|comment| {
            !comment["body"]
                .as_str()
                .is_some_and(|body| body.lines().any(|line| line.starts_with(&marker_prefix)))
        }),
        "positive Bot-authored fixture already has owner authorization before the sensitive-path probe"
    );
    expect_owner_authorization_required(
        request::validate_pr_authorization(
            api,
            &sensitive_policy,
            integration_repository()?,
            positive.number,
            &positive.head_sha,
            false,
        ),
        "Bot author without an exemption",
        OWNER_REQUIRED,
    )?;

    sensitive_policy
        .sensitive_path_approval_exemptions
        .github_apps
        .push(securefix::policy::SensitivePathApprovalGitHubApp {
            bot_id: policy.server_bot_id,
            bot_login: policy.deployment.server_bot_login.clone(),
        });
    ensure!(
        request::validate_pr_authorization(
            api,
            &sensitive_policy,
            integration_repository()?,
            positive.number,
            &positive.head_sha,
            false,
        )?,
        "configured GitHub App Bot did not trigger the sensitive-path exemption"
    );

    sensitive_policy.sensitive_path_approval_exemptions = Default::default();
    expect_owner_authorization_required(
        request::validate_pr_authorization(
            api,
            &sensitive_policy,
            integration_repository()?,
            positive.number,
            &positive.head_sha,
            false,
        ),
        "Bot author after restoring empty exemptions",
        OWNER_REQUIRED,
    )?;

    let owner_fixture_head = std::env::var("SECUREFIX_APPROVAL_FIXTURE_HEAD").unwrap_or_default();
    if !owner_fixture_head.is_empty() {
        validate_sha(&owner_fixture_head)?;
        sensitive_policy
            .sensitive_path_approval_exemptions
            .github_apps
            .push(securefix::policy::SensitivePathApprovalGitHubApp {
                bot_id: policy.server_bot_id,
                bot_login: policy.deployment.server_bot_login.clone(),
            });
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let branch = format!(
            "{BRANCH_PREFIX}sensitive-mixed-{}-{nonce}",
            &candidate_sha[..12]
        );
        validate_branch(&branch)?;
        // Record ownership only after GitHub confirms that this unique ref was created.
        let _: Value = api.post(
            &format!("/repos/{}/git/refs", integration_repository()?),
            &json!({"ref":format!("refs/heads/{branch}"),"sha":owner_fixture_head}),
        )?;
        let mut created_head = None;
        let fixture_result = (|| {
            let head_sha = api.create_commit(
                integration_repository()?,
                &branch,
                &owner_fixture_head,
                &format!(
                    "test: sensitive mixed actor authorization {}",
                    &candidate_sha[..12]
                ),
                BTreeMap::from([(
                    format!(
                        "{FIX_PATH_PREFIX}sensitive-mixed-{}.txt",
                        &candidate_sha[..12]
                    ),
                    format!("candidate={candidate_sha}\nscenario=sensitive-mixed-actor\n")
                        .into_bytes(),
                )]),
                Vec::new(),
            )?;
            created_head = Some(head_sha.clone());
            let title = format!(
                "test: sensitive mixed actor authorization {}",
                &candidate_sha[..12]
            );
            let pull: Value = api.post(
                &format!("/repos/{}/pulls", integration_repository()?),
                &json!({"title":title,"head":branch,"base":default_branch,"body":"Created by the native Securefix scratch integration harness."}),
            )?;
            ensure!(
                pull["state"] == "open"
                    && pull["base"]["ref"] == default_branch
                    && pull["head"]["sha"] == head_sha
                    && pull["head"]["ref"] == branch,
                "GitHub created an unexpected mixed-actor scratch pull request"
            );
            Ok(PullRequestFixture {
                number: pull["number"]
                    .as_u64()
                    .context("mixed-actor scratch pull request has no number")?,
                branch: branch.clone(),
                head_sha,
                url: pull["html_url"]
                    .as_str()
                    .context("mixed-actor scratch pull request has no URL")?
                    .to_owned(),
            })
        })();
        let fixture = match fixture_result {
            Ok(fixture) => fixture,
            Err(error) => {
                return match cleanup_failed_sensitive_probe_creation(
                    api,
                    &branch,
                    default_branch,
                    created_head.as_deref(),
                ) {
                    Ok(()) => Err(error.context("create mixed-actor sensitive-path fixture")),
                    Err(cleanup_error) => Err(error.context(format!(
                        "mixed-actor fixture creation failed; safe cleanup also failed: {cleanup_error:#}"
                    ))),
                };
            }
        };

        let probe = (|| {
            let pull: Value = api.get(&format!(
                "/repos/{}/pulls/{}",
                integration_repository()?,
                fixture.number
            ))?;
            ensure!(
                pull["user"]["id"].as_u64() == Some(policy.server_bot_id)
                    && pull["user"]["type"] == "Bot",
                "mixed-actor sensitive-path fixture was not created by the configured GitHub App Bot"
            );
            let commits = api.paginate(&format!(
                "/repos/{}/pulls/{}/commits",
                integration_repository()?,
                fixture.number
            ))?;
            ensure!(
                commits.len() == 2
                    && commits[0]["sha"] == owner_fixture_head
                    && commits[1]["sha"] == fixture.head_sha,
                "mixed-actor sensitive-path fixture does not contain exactly the owner and App commits"
            );
            expect_owner_authorization_required(
                request::validate_pr_authorization(
                    api,
                    &sensitive_policy,
                    integration_repository()?,
                    fixture.number,
                    &fixture.head_sha,
                    false,
                ),
                "mixed owner and App commit history",
                OWNER_REQUIRED,
            )
        })();
        let cleanup = cleanup_sensitive_probe(api, &fixture);
        match (probe, cleanup) {
            (Ok(()), Ok(())) => {}
            (Err(error), Ok(())) => return Err(error),
            (Ok(()), Err(error)) => {
                return Err(error.context("clean mixed-actor sensitive-path fixture"));
            }
            (Err(error), Err(cleanup_error)) => {
                return Err(error.context(format!(
                    "mixed-actor sensitive-path probe cleanup also failed: {cleanup_error:#}"
                )));
            }
        }
    }

    if owner_fixture_head.is_empty() {
        println!(
            "Verified sensitive-path authorization for the GitHub App Bot; mixed-actor probe skipped because no owner fixture was configured."
        );
    } else {
        println!(
            "Verified sensitive-path authorization for the GitHub App Bot and rejection of mixed owner/App commits."
        );
    }
    Ok(())
}

fn expect_owner_authorization_required(
    result: Result<bool>,
    scenario: &str,
    expected_error: &str,
) -> Result<()> {
    match result {
        Err(error) => {
            ensure!(
                error.to_string() == expected_error,
                "{scenario} failed for the wrong reason: {error}"
            );
            Ok(())
        }
        Ok(true) => anyhow::bail!("{scenario} unexpectedly bypassed owner authorization"),
        Ok(false) => anyhow::bail!("{scenario} did not match a sensitive path"),
    }
}

fn cleanup_sensitive_probe(api: &GitHub, fixture: &PullRequestFixture) -> Result<()> {
    let pull: Value = api.get(&format!(
        "/repos/{}/pulls/{}",
        integration_repository()?,
        fixture.number
    ))?;
    if pull["state"] == "open" {
        let _: Value = api.patch(
            &format!(
                "/repos/{}/pulls/{}",
                integration_repository()?,
                fixture.number
            ),
            &json!({"state":"closed"}),
        )?;
    }
    validate_branch(&fixture.branch)?;
    delete_scratch_branch(api, &fixture.branch)
}

fn cleanup_failed_sensitive_probe_creation(
    api: &GitHub,
    branch: &str,
    default_branch: &str,
    created_head: Option<&str>,
) -> Result<()> {
    validate_branch(branch)?;
    if let Some(head_sha) = created_head {
        validate_sha(head_sha)?;
        let repository = integration_repository()?;
        let owner = repository
            .split_once('/')
            .context("scratch repository has no owner")?
            .0;
        let pulls: Vec<Value> = api.paginate(&format!(
            "/repos/{repository}/pulls?state=all&head={owner}:{branch}"
        ))?;
        let matches = pulls
            .iter()
            .filter(|pull| pull["head"]["ref"] == branch)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() <= 1,
            "ambiguous mixed-actor fixture cleanup found multiple pull requests"
        );
        if let Some(pull) = matches.first() {
            ensure!(
                pull["head"]["sha"] == head_sha
                    && pull["head"]["repo"]["full_name"] == repository
                    && pull["head"]["repo"]["id"].as_u64() == Some(integration_repository_id()?)
                    && pull["base"]["ref"] == default_branch
                    && pull["user"]["id"].as_u64() == Some(trusted_config()?.server_bot_id)
                    && pull["user"]["type"] == "Bot",
                "ambiguous mixed-actor fixture cleanup found an unexpected pull request"
            );
            if pull["state"] == "open" {
                let number = pull["number"]
                    .as_u64()
                    .context("ambiguous mixed-actor pull request has no number")?;
                let _: Value = api.patch(
                    &format!("/repos/{repository}/pulls/{number}"),
                    &json!({"state":"closed"}),
                )?;
            }
        }
    }
    delete_scratch_branch(api, branch)
}

fn delete_scratch_branch(api: &GitHub, branch: &str) -> Result<()> {
    validate_branch(branch)?;
    match api.delete(&format!(
        "/repos/{}/git/refs/heads/{}",
        integration_repository()?,
        branch
    )) {
        Ok(()) => Ok(()),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|api| api.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            Ok(())
        }
        Err(error) => Err(error).context("delete scratch sensitive-probe branch"),
    }
}

fn create_nativefix_positive_pr(
    api: &GitHub,
    policy: &Policy,
    base_sha: &str,
    base_branch: &str,
    branch: &str,
    fix: &crate::securefix_gate::artifact::FixArtifact,
    candidate_sha: &str,
) -> Result<PullRequestFixture> {
    let label = format!("securefix-integration-{}", fix.run_id);
    let source = crate::securefix_gate::SourceRequest {
        repository: integration_repository()?,
        run_id: fix.run_id,
        label: &label,
        branch,
        sha: candidate_sha,
    };
    let plan = crate::securefix_gate::FixPlan {
        version: 1,
        source_repository: integration_repository()?.to_owned(),
        source_run_id: fix.run_id,
        source_sha: candidate_sha.to_owned(),
        artifact_name: label.clone(),
        artifact_id: 1,
        destination_repository: integration_repository()?.to_owned(),
        destination_branch: branch.to_owned(),
        expected_head: base_sha.to_owned(),
        destination_branch_exists: false,
        existing_pull_request: None,
    };
    let first = crate::securefix_gate::apply_core(crate::securefix_gate::ApplyCore {
        read_api: api,
        write_api: api,
        policy,
        source,
        plan: &plan,
        fix,
        server_url: "https://github.com",
        server_repository: integration_repository()?,
        server_run: "integration",
    })?;
    ensure!(
        !first.already_applied && first.pull_request_number.is_some(),
        "nativefix first apply did not create the signed commit and pull request"
    );
    let commit: Value = api.get(&format!(
        "/repos/{}/commits/{}",
        integration_repository()?,
        first.commit_sha
    ))?;
    ensure!(
        commit["author"]["id"].as_u64() == Some(policy.server_bot_id)
            && commit["author"]["type"] == "Bot"
            && commit["commit"]["verification"]["verified"] == true
            && commit["parents"]
                .as_array()
                .is_some_and(|parents| { parents.len() == 1 && parents[0]["sha"] == base_sha }),
        "nativefix scratch commit has invalid authorship, signature, or parent"
    );
    let actual = api.content(
        integration_repository()?,
        fix.additions
            .keys()
            .next()
            .context("nativefix artifact has no addition")?,
        &first.commit_sha,
    )?;
    ensure!(
        fix.additions.len() == 1
            && fix.deletions.is_empty()
            && fix.additions.values().next() == Some(&actual),
        "nativefix signed commit content differs from the parsed artifact"
    );
    let pr_number = first
        .pull_request_number
        .context("nativefix PR number missing")?;
    let retry_plan = crate::securefix_gate::FixPlan {
        expected_head: first.commit_sha.clone(),
        destination_branch_exists: true,
        existing_pull_request: Some(pr_number),
        ..plan
    };
    let retry = crate::securefix_gate::apply_core(crate::securefix_gate::ApplyCore {
        read_api: api,
        write_api: api,
        policy,
        source,
        plan: &retry_plan,
        fix,
        server_url: "https://github.com",
        server_repository: integration_repository()?,
        server_run: "integration",
    })?;
    ensure!(
        retry.already_applied
            && retry.commit_sha == first.commit_sha
            && retry.pull_request_number == Some(pr_number),
        "nativefix retry was not idempotent"
    );
    let pull: Value = api.get(&format!(
        "/repos/{}/pulls/{pr_number}",
        integration_repository()?
    ))?;
    ensure!(
        pull["state"] == "open"
            && pull["base"]["ref"] == base_branch
            && pull["head"]["sha"] == first.commit_sha
            && pull["head"]["ref"] == branch,
        "nativefix integration PR does not match the signed commit"
    );
    Ok(PullRequestFixture {
        number: pr_number,
        branch: branch.to_owned(),
        head_sha: first.commit_sha,
        url: pull["html_url"]
            .as_str()
            .context("nativefix scratch pull request has no URL")?
            .to_owned(),
    })
}

fn prepare_positive_artifact(
    candidate_sha: &str,
    branch: &str,
) -> Result<crate::securefix_gate::artifact::FixArtifact> {
    use std::io::Write;

    let workspace = tempfile::tempdir().context("create isolated client artifact workspace")?;
    let workspace_path = workspace.path();
    fs::create_dir_all(workspace_path.join("fixes"))?;
    let fixture_path = format!("{FIX_PATH_PREFIX}{branch}.txt");
    fs::create_dir_all(
        workspace_path.join("fixes").join(
            Path::new(&fixture_path)
                .parent()
                .context("fixture path has no parent")?,
        ),
    )?;
    fs::write(
        workspace_path.join("fixes").join(&fixture_path),
        format!("candidate={candidate_sha}\nscenario=positive\n"),
    )?;
    let event_path = workspace_path.join("event.json");
    fs::write(
        &event_path,
        serde_json::to_vec(&json!({
            "repository":{"full_name":integration_repository()?}
        }))?,
    )?;
    let output_path = workspace_path.join("github-output");
    fs::write(&output_path, [])?;
    let run_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .max(1);
    let executable = std::env::current_exe().context("locate candidate CLI executable")?;
    let result = std::process::Command::new(executable)
        .current_dir(workspace_path)
        .env_clear()
        .env("GITHUB_WORKSPACE", workspace_path)
        .env("GITHUB_OUTPUT", &output_path)
        .env("GITHUB_EVENT_PATH", &event_path)
        .env("GITHUB_REPOSITORY", integration_repository()?)
        .env("GITHUB_RUN_ID", run_id.to_string())
        .env("GITHUB_RUN_ATTEMPT", "1")
        .env("GITHUB_SHA", candidate_sha)
        .env("GITHUB_SERVER_URL", "https://github.com")
        .env("GITHUB_REF", format!("refs/heads/{branch}"))
        .env("GITHUB_EVENT_NAME", "workflow_dispatch")
        .env("GITHUB_ACTOR", &trusted_config()?.deployment.owner_login)
        .args([
            "securefix",
            "client-prepare",
            "--root-dir",
            "fixes",
            "--files",
        ])
        .arg(&fixture_path)
        .args([
            "--repository",
            integration_repository()?,
            "--branch",
            branch,
            "--commit-message",
            "test: Securefix artifact parser integration",
            "--output-dir",
            "artifacts",
        ])
        .output()
        .context("run the native Securefix client artifact producer")?;
    ensure!(
        result.status.success(),
        "native Securefix client artifact producer failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = fs::read_to_string(output_path)?;
    let artifact_name = output
        .lines()
        .find_map(|line| line.strip_prefix("artifact_name="))
        .context("native client did not report an artifact name")?;
    ensure!(
        artifact_name.starts_with("securefix-"),
        "native client produced an invalid artifact name"
    );
    let stage = workspace_path.join("artifacts").join(artifact_name);
    let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for name in [
        format!("{artifact_name}.json"),
        format!("{artifact_name}_files.txt"),
        fixture_path.clone(),
    ] {
        let content = fs::read(stage.join(&name))?;
        archive.start_file(name, zip::write::SimpleFileOptions::default())?;
        archive.write_all(&content)?;
    }
    let archive = archive.finish()?.into_inner();
    let fix = crate::securefix_gate::artifact::parse(
        &archive,
        artifact_name,
        integration_repository()?,
        run_id,
        candidate_sha,
        branch,
    )?;
    ensure!(
        fix.repository == integration_repository()?
            && fix.branch == branch
            && fix.additions.len() == 1
            && fix.additions.get(&fixture_path).is_some_and(|bytes| {
                bytes == format!("candidate={candidate_sha}\nscenario=positive\n").as_bytes()
            })
            && fix.deletions.is_empty(),
        "native artifact parser changed the positive fixture contents"
    );
    Ok(fix)
}

fn approve_owner_fixture(
    api: &GitHub,
    candidate_sha: &str,
    default_branch: &str,
    base_sha: &str,
) -> Result<()> {
    use base64::Engine as _;
    let number = std::env::var("SECUREFIX_APPROVAL_FIXTURE_PR").unwrap_or_default();
    let head = std::env::var("SECUREFIX_APPROVAL_FIXTURE_HEAD").unwrap_or_default();
    if number.is_empty() && head.is_empty() {
        return Ok(());
    }
    let number: u64 = number
        .parse()
        .context("invalid approval fixture PR number")?;
    ensure!(number > 0, "approval fixture PR number is zero");
    validate_sha(&head)?;
    let trusted = trusted_config()?;
    let repository = integration_repository()?;
    let branch = format!("{BRANCH_PREFIX}approval-{}", &candidate_sha[..12]);
    let path = format!("{FIX_PATH_PREFIX}approval-{candidate_sha}.txt");
    let fixture = PullRequestFixture {
        number,
        branch,
        head_sha: head.clone(),
        url: format!("https://github.com/{repository}/pull/{number}"),
    };
    let pull: Value = api.get(&format!("/repos/{repository}/pulls/{number}"))?;
    validate_owner_approval_target(&pull, &fixture, default_branch, base_sha)?;
    let commit: Value = api.get(&format!("/repos/{repository}/commits/{head}"))?;
    ensure!(
        commit["parents"]
            .as_array()
            .is_some_and(|parents| { parents.len() == 1 && parents[0]["sha"] == base_sha })
            && commit["author"]["id"].as_u64() == Some(trusted.owner_id),
        "approval fixture must be one owner-authored commit on the current scratch base"
    );
    let files = api.paginate(&format!("/repos/{repository}/pulls/{number}/files"))?;
    ensure!(
        files.len() == 1 && files[0]["filename"] == path && files[0]["status"] == "added",
        "approval fixture changed unexpected files"
    );
    let content: Value = api.get(&format!("/repos/{repository}/contents/{path}?ref={head}"))?;
    let encoded = content["content"]
        .as_str()
        .context("approval fixture content missing")?;
    ensure!(
        content["type"] == "file" && content["encoding"] == "base64" && encoded.len() <= 1024,
        "approval fixture content is invalid or oversized"
    );
    let encoded: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    ensure!(
        bytes == format!("candidate={candidate_sha}\nscenario=approval\n").as_bytes(),
        "approval fixture bytes do not match the candidate"
    );
    let policy = scratch_policy(candidate_sha)?;
    request::validate_pr_authorization(api, &policy, repository, number, &head, true)?;
    let comment = wait_for_owner_comment(
        api,
        &fixture,
        RequestKind::Approve,
        Instant::now() + Duration::from_secs(30),
    )?;
    let comment_id = comment["id"]
        .as_u64()
        .context("approval fixture comment ID missing")?;
    request::post_owner_marker(api, repository, number, &head, comment_id)?;
    let reviewer = crate::config::Principal {
        login: trusted.deployment.server_bot_login.clone(),
        id: trusted.server_bot_id,
    };
    crate::approval::approve_current_head(api, api, repository, number, &head, &reviewer, "Bot")?;
    request::validate_pr_authorization(api, &policy, repository, number, &head, true)?;
    println!("Verified the shared approval core on owner-authored scratch PR {number} at {head}.");
    Ok(())
}

fn validate_owner_approval_target(
    pull: &Value,
    fixture: &PullRequestFixture,
    default_branch: &str,
    base_sha: &str,
) -> Result<()> {
    ensure!(
        pull["number"].as_u64() == Some(fixture.number)
            && pull["state"] == "open"
            && pull["draft"] == false
            && pull["user"]["id"].as_u64() == Some(owner_id()?)
            && pull["user"]["type"] == "User"
            && pull["head"]["repo"]["id"].as_u64() == Some(integration_repository_id()?)
            && pull["head"]["repo"]["full_name"] == integration_repository()?
            && pull["head"]["ref"] == fixture.branch
            && pull["head"]["sha"] == fixture.head_sha
            && pull["base"]["repo"]["id"].as_u64() == Some(integration_repository_id()?)
            && pull["base"]["ref"] == default_branch
            && pull["base"]["sha"] == base_sha,
        "approval fixture is not the exact owner-authored scratch PR"
    );
    Ok(())
}

fn verify(candidate_sha: &str, state_file: &Path, timeout_seconds: u64) -> Result<()> {
    let metadata = fs::metadata(state_file).context("read integration state file metadata")?;
    ensure!(
        metadata.len() <= 16 * 1024,
        "integration state file exceeds size limit"
    );
    let scenario: Scenario =
        serde_json::from_slice(&fs::read(state_file).context("read integration state file")?)
            .context("parse integration state file")?;
    let published_runtime_sha = published_runtime_sha_from_env()?;
    let published_runtime_tag = published_runtime_tag_from_env()?;
    validate_scenario(&scenario, candidate_sha, &published_runtime_sha)?;
    let server = GitHub::scratch_from_env("SECUREFIX_SERVER_APP_TOKEN", candidate_sha)?;
    let _client = GitHub::scratch_from_env("SECUREFIX_CLIENT_APP_TOKEN", candidate_sha)?;
    let policy = scratch_policy(candidate_sha)?;
    verify_remote_identity(&server, &scenario)?;

    let result = verify_inner(
        &server,
        &policy,
        &scenario,
        &published_runtime_tag,
        timeout_seconds,
    );
    let cleanup = cleanup(&server, &scenario);
    match (result, cleanup) {
        (Ok(verification), Ok(())) => {
            workflow::write_json(
                state_file.with_file_name("verification.json"),
                &verification,
            )?;
            println!(
                "Verified native scratch integration; GitHub auto-merge and pinact consumer CI passed."
            );
            println!("{}", serde_json::to_string(&verification)?);
            Ok(())
        }
        (Err(error), Ok(())) => {
            Err(error.context("scratch integration failed; fixtures were cleaned up"))
        }
        (Ok(_), Err(error)) => {
            Err(error.context("scratch integration passed but fixture cleanup failed"))
        }
        (Err(error), Err(cleanup_error)) => {
            Err(error.context(format!("fixture cleanup also failed: {cleanup_error:#}")))
        }
    }
}

fn verify_inner(
    api: &GitHub,
    policy: &Policy,
    scenario: &Scenario,
    published_runtime_tag: &str,
    timeout_seconds: u64,
) -> Result<Verification> {
    let deadline = Instant::now() + Duration::from_secs(timeout_seconds.max(1));
    verify_pr_identity(
        api,
        &scenario.positive,
        &scenario.default_branch,
        &scenario.positive.head_sha,
    )?;
    verify_pr_identity(
        api,
        &scenario.stale,
        &scenario.default_branch,
        &scenario.stale.head_sha,
    )?;
    verify_pr_identity(
        api,
        &scenario.distribution,
        &scenario.default_branch,
        &scenario.distribution.head_sha,
    )?;

    let approve_comment =
        wait_for_owner_comment(api, &scenario.positive, RequestKind::Approve, deadline)?;
    let positive_merge_comment =
        wait_for_owner_comment(api, &scenario.positive, RequestKind::Merge, deadline)?;
    let stale_merge_comment =
        wait_for_owner_comment(api, &scenario.stale, RequestKind::Merge, deadline)?;
    ensure!(
        RequestKind::Approve.matches_comment_body(&approve_comment["body"]),
        "the owner approval comment is not an exact /approve command"
    );
    let server_bot_id = trusted_config()?.server_bot_id;
    for (comment, kind) in [
        (&approve_comment, RequestKind::Approve),
        (&positive_merge_comment, RequestKind::Merge),
    ] {
        let id = comment["id"]
            .as_u64()
            .context("fixture command has no ID")?;
        request::acknowledge_request(
            api,
            integration_repository()?,
            scenario.positive.number,
            id,
            kind,
        )?;
        let reactions = api.paginate(&format!(
            "/repos/{}/issues/comments/{id}/reactions",
            integration_repository()?
        ))?;
        ensure!(
            reactions
                .iter()
                .any(|reaction| reaction["content"] == "rocket"
                    && reaction["user"]["id"].as_u64() == Some(server_bot_id)),
            "owner request did not receive a receipt reaction"
        );
    }
    verify_policy_feedback(api, &scenario.distribution)?;

    request::validate_pr_authorization(
        api,
        policy,
        integration_repository()?,
        scenario.positive.number,
        &scenario.positive.head_sha,
        true,
    )?;
    let approve_comment_id = approve_comment["id"]
        .as_u64()
        .context("owner approval comment has no ID")?;
    request::post_owner_marker(
        api,
        integration_repository()?,
        scenario.positive.number,
        &scenario.positive.head_sha,
        approve_comment_id,
    )?;
    request::require_owner_marker(
        api,
        policy,
        integration_repository()?,
        scenario.positive.number,
        &scenario.positive.head_sha,
    )?;
    validate_signed_pr(api, policy, &scenario.distribution)?;
    verify_rendered_files(
        api,
        &scenario.distribution,
        &scenario.default_branch,
        &scenario.published_runtime_sha,
        published_runtime_tag,
    )?;
    wait_for_actions_status_check(
        api,
        &scenario.distribution,
        &scenario.default_branch,
        "status-check",
        deadline,
    )?;
    wait_for_actions_status_check(
        api,
        &scenario.distribution,
        &scenario.default_branch,
        "scratch-push-status-check",
        deadline,
    )?;
    let files = distribution_fixture_files(
        &scenario.published_runtime_sha,
        published_runtime_tag,
        &scenario.default_branch,
    )?;
    validate_rendered_files(&files)?;

    let positive_manifest = manifest(
        scenario,
        &scenario.positive,
        &positive_merge_comment,
        &scenario.candidate_sha,
    )?;
    merge::validate_state(api, policy, &positive_manifest)?;
    ensure!(
        !policy_check_exists(api, &scenario.positive.head_sha)?,
        "positive policy check was published before the native auto-merge probe"
    );
    wait_for_merge_gates_except_policy(api, &scenario.positive, deadline)?;
    ensure!(
        !merge::ready(api, &positive_manifest)?,
        "scratch positive PR became merge-ready without the Securefix policy check"
    );
    api.enable_scratch_auto_merge(
        integration_repository()?,
        scenario.positive.number,
        &scenario.positive.head_sha,
    )?;
    wait_for_auto_merge_pending(api, &scenario.positive, deadline)?;
    ensure!(
        !policy_check_exists(api, &scenario.positive.head_sha)?,
        "positive policy check appeared before it was published by the integration harness"
    );
    policy_check::publish(
        api,
        integration_repository()?,
        &scenario.positive.head_sha,
        true,
        "Integration fixture passed production PR authorization checks.",
    )?;
    wait_for_policy_check_success(api, &scenario.positive, deadline)?;
    ensure!(
        merge::ready(api, &positive_manifest)?,
        "scratch positive PR lacks required checks or approved review after policy check"
    );
    let merged_sha = wait_for_auto_merge(api, &scenario.positive, deadline)?;
    ensure!(
        merge::validate_state(api, policy, &positive_manifest).is_err(),
        "replayed merge manifest unexpectedly remained valid after merge"
    );
    verify_disposable_release_tag(
        api,
        &scenario.positive,
        &scenario.candidate_sha,
        &merged_sha,
    )?;

    request::validate_pr_authorization(
        api,
        policy,
        integration_repository()?,
        scenario.stale.number,
        &scenario.stale.head_sha,
        true,
    )?;
    let stale_manifest = manifest(
        scenario,
        &scenario.stale,
        &stale_merge_comment,
        &scenario.candidate_sha,
    )?;
    merge::validate_state(api, policy, &stale_manifest)?;
    ensure!(
        !request::has_current_head_approval(
            api,
            integration_repository()?,
            scenario.stale.number,
            &scenario.stale.head_sha,
        )? && !policy_check_exists(api, &scenario.stale.head_sha)?,
        "stale-head fixture unexpectedly has current review or policy check before its probe"
    );
    api.enable_scratch_auto_merge(
        integration_repository()?,
        scenario.stale.number,
        &scenario.stale.head_sha,
    )?;
    wait_for_auto_merge_pending(api, &scenario.stale, deadline)?;
    let stale_head_sha = api.create_commit(
        integration_repository()?,
        &scenario.stale.branch,
        &scenario.stale.head_sha,
        "test: advance scratch head after owner acceptance",
        BTreeMap::from([(
            format!("{FIX_PATH_PREFIX}stale-after-acceptance.txt"),
            b"this commit invalidates the accepted head\n".to_vec(),
        )]),
        Vec::new(),
    )?;
    ensure!(
        stale_head_sha != scenario.stale.head_sha,
        "stale test did not advance the head"
    );
    wait_for_pr_head_transition(
        api,
        &scenario.stale,
        &scenario.default_branch,
        &scenario.stale.head_sha,
        &stale_head_sha,
        deadline,
    )?;
    ensure!(
        request::validate_pr_authorization(
            api,
            policy,
            integration_repository()?,
            scenario.stale.number,
            &scenario.stale.head_sha,
            true,
        )
        .is_err(),
        "stale accepted PR head unexpectedly passed production authorization validation"
    );
    ensure!(
        merge::validate_state(api, policy, &stale_manifest).is_err(),
        "stale merge manifest unexpectedly remained valid"
    );
    ensure!(
        !request::has_current_head_approval(
            api,
            integration_repository()?,
            scenario.stale.number,
            &stale_head_sha,
        )? && !policy_check_exists(api, &stale_head_sha)?,
        "advanced stale-head fixture unexpectedly has current review or policy check"
    );
    ensure!(
        api.enable_scratch_auto_merge(
            integration_repository()?,
            scenario.stale.number,
            &scenario.stale.head_sha,
        )
        .is_err(),
        "native auto-merge accepted the owner authorization's stale head"
    );
    let stale_merge = api.put::<Value>(
        &format!(
            "/repos/{}/pulls/{}/merge",
            integration_repository()?,
            scenario.stale.number
        ),
        &json!({"sha":scenario.stale.head_sha,"merge_method":"squash"}),
    );
    ensure!(
        stale_merge
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<ApiError>())
            .is_some_and(|error| error.status == reqwest::StatusCode::CONFLICT),
        "GitHub did not reject the stale scratch merge head with HTTP 409"
    );
    let stale_pull: Value = api.get(&format!(
        "/repos/{}/pulls/{}",
        integration_repository()?,
        scenario.stale.number
    ))?;
    ensure!(
        stale_pull["state"] == "open" && stale_pull["merged"] == false,
        "queued stale-head auto-merge bypassed the new-head review or policy check"
    );

    verify_artifact_path_safety()?;
    ensure!(
        !files.is_empty(),
        "distribution output disappeared during verification"
    );
    let managed_files = files.keys().cloned().collect::<Vec<_>>();
    Ok(Verification {
        version: STATE_VERSION,
        repository: integration_repository()?.to_owned(),
        candidate_sha: scenario.candidate_sha.clone(),
        positive_pr: scenario.positive.number,
        merged_sha,
        stale_pr: scenario.stale.number,
        stale_head_sha,
        distribution_pr: scenario.distribution.number,
        managed_files,
        annotated_tag_verified: true,
        closed_or_merged: true,
    })
}

fn verify_policy_feedback(api: &GitHub, fixture: &PullRequestFixture) -> Result<()> {
    let repo = integration_repository()?;
    let server_bot_id = trusted_config()?.server_bot_id;
    let mut failure_ids = Vec::new();
    for reason in [
        "Integration probe: current-head approval is missing.",
        "Integration probe: policy rejection was superseded.",
    ] {
        policy_check::publish(api, repo, &fixture.head_sha, false, reason)?;
        policy_check::report_result(api, repo, fixture.number, &fixture.head_sha, false, reason)?;
        let comments =
            api.paginate(&format!("/repos/{repo}/issues/{}/comments", fixture.number))?;
        let comment = comments
            .iter()
            .rev()
            .find(|comment| {
                comment["body"].as_str().is_some_and(|body| {
                    body.starts_with(policy_check::COMMENT_MARKER) && body.contains(reason)
                }) && comment["user"]["id"].as_u64() == Some(server_bot_id)
            })
            .context("policy failure comment was not published")?;
        let body = comment["body"]
            .as_str()
            .context("missing policy failure body")?;
        ensure!(
            body.contains("<sub>")
                && body.contains("/actions/runs/")
                && body.contains(&fixture.head_sha),
            "policy comment does not identify its CI run and target commit"
        );
        failure_ids.push(
            comment["node_id"]
                .as_str()
                .context("missing comment node")?
                .to_owned(),
        );
        let states = api.graphql(
            "query($ids:[ID!]!){nodes(ids:$ids){...on IssueComment{id isMinimized}}}",
            json!({"ids":failure_ids}),
        )?;
        let nodes = states["nodes"]
            .as_array()
            .context("missing policy comment states")?;
        ensure!(
            nodes.len() == failure_ids.len()
                && nodes
                    .iter()
                    .enumerate()
                    .all(|(i, node)| node["id"] == failure_ids[i]
                        && node["isMinimized"] == (i + 1 < nodes.len())),
            "only the newest policy failure comment should remain visible"
        );
    }
    policy_check::publish(
        api,
        repo,
        &fixture.head_sha,
        true,
        "Integration feedback recovery succeeded.",
    )?;
    policy_check::report_result(
        api,
        repo,
        fixture.number,
        &fixture.head_sha,
        true,
        "Integration feedback recovery succeeded.",
    )?;
    let states = api.graphql(
        "query($ids:[ID!]!){nodes(ids:$ids){...on IssueComment{id isMinimized}}}",
        json!({"ids":failure_ids}),
    )?;
    ensure!(
        states["nodes"].as_array().is_some_and(
            |nodes| nodes.len() == 2 && nodes.iter().all(|node| node["isMinimized"] == true)
        ),
        "successful policy check did not hide both historical failure comments"
    );
    println!("Verified command receipt reactions and policy failure/success comment lifecycle.");
    Ok(())
}

fn verify_disposable_release_tag(
    api: &GitHub,
    fixture: &PullRequestFixture,
    candidate_sha: &str,
    merged_sha: &str,
) -> Result<()> {
    use crate::release::{CommitSha, ReleaseTag, Repository};

    let repository = Repository::parse(integration_repository()?)?;
    let target = CommitSha::parse(merged_sha)?;
    let tag = ReleaseTag::parse(&format!(
        "v0.0.0-securefix-integration.{}.{}",
        fixture.number,
        &candidate_sha[..12]
    ))?;
    crate::release::create_annotated_tag(api, &repository, &tag, &target)?;
    let verification = (|| {
        let ref_path = format!(
            "/repos/{}/git/ref/tags/{}",
            integration_repository()?,
            tag.as_str()
        );
        let reference = wait_for_created_tag_ref(api, &ref_path)?;
        ensure!(
            reference["object"]["type"] == "tag",
            "scratch release helper created a lightweight tag"
        );
        let object_sha = reference["object"]["sha"]
            .as_str()
            .context("scratch annotated tag ref lacks an object SHA")?;
        let object: Value = api.get(&format!(
            "/repos/{}/git/tags/{object_sha}",
            integration_repository()?
        ))?;
        ensure!(
            object["object"]["sha"] == merged_sha,
            "scratch annotated release tag targets the wrong commit"
        );
        crate::release::create_annotated_tag(api, &repository, &tag, &target)?;
        let stale_target = CommitSha::parse(&"0".repeat(40))?;
        ensure!(
            crate::release::create_annotated_tag(api, &repository, &tag, &stale_target).is_err(),
            "scratch release tag helper accepted a retry with a different target"
        );
        Ok(())
    })();
    let ref_path = format!(
        "/repos/{}/git/refs/tags/{}",
        integration_repository()?,
        tag.as_str()
    );
    let cleanup = api.delete(&ref_path);
    match (verification, cleanup) {
        (Err(error), _) => Err(error).context("verify disposable scratch release tag"),
        (Ok(()), Err(error)) => Err(error).context("delete disposable scratch release tag"),
        (Ok(()), Ok(())) => {
            let absent = api.get::<Value>(&format!(
                "/repos/{}/git/ref/tags/{}",
                integration_repository()?,
                tag.as_str()
            ));
            ensure!(
                absent
                    .as_ref()
                    .err()
                    .and_then(|error| error.downcast_ref::<ApiError>())
                    .is_some_and(|error| error.status == reqwest::StatusCode::NOT_FOUND),
                "scratch release tag still exists after cleanup"
            );
            Ok(())
        }
    }
}

fn wait_for_created_tag_ref(api: &GitHub, path: &str) -> Result<Value> {
    for attempt in 0..5 {
        match api.get(path) {
            Err(error)
                if attempt < 4
                    && error
                        .downcast_ref::<ApiError>()
                        .is_some_and(|error| error.status == reqwest::StatusCode::NOT_FOUND) =>
            {
                thread::sleep(Duration::from_secs(1));
            }
            result => return result,
        }
    }
    unreachable!()
}

fn validate_signed_pr(api: &GitHub, policy: &Policy, fixture: &PullRequestFixture) -> Result<()> {
    request::validate_pr_authorization(
        api,
        policy,
        integration_repository()?,
        fixture.number,
        &fixture.head_sha,
        true,
    )?;
    Ok(())
}

fn verify_rendered_files(
    api: &GitHub,
    fixture: &PullRequestFixture,
    default_branch: &str,
    published_runtime_sha: &str,
    published_runtime_tag: &str,
) -> Result<()> {
    let expected =
        distribution_fixture_files(published_runtime_sha, published_runtime_tag, default_branch)?;
    validate_rendered_files(&expected)?;
    for (path, expected_bytes) in expected {
        let actual = api.content(integration_repository()?, &path, &fixture.head_sha)?;
        ensure!(
            actual == expected_bytes,
            "scratch distribution PR changed managed workflow bytes at {path}"
        );
        let parsed: serde_yaml::Value = serde_yaml::from_slice(&actual)
            .with_context(|| format!("rendered workflow is invalid at {path}"))?;
        ensure!(
            parsed["name"].as_str().is_some(),
            "rendered workflow has no name at {path}"
        );
    }
    for path in OBSOLETE_SCRATCH_WORKFLOWS {
        ensure!(
            optional_file(api, path, &fixture.head_sha)?.is_none(),
            "scratch distribution PR retained obsolete test workflow {path}"
        );
    }
    Ok(())
}

fn existing_scratch_workflows(api: &GitHub, base_sha: &str) -> Result<Vec<String>> {
    OBSOLETE_SCRATCH_WORKFLOWS
        .into_iter()
        .filter_map(|path| match optional_file(api, path, base_sha) {
            Ok(Some(_)) => Some(Ok(path.to_owned())),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn optional_file(api: &GitHub, path: &str, revision: &str) -> Result<Option<Value>> {
    match api.get(&format!(
        "/repos/{}/contents/{path}?ref={revision}",
        integration_repository()?
    )) {
        Ok(value) => Ok(Some(value)),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|api| api.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            Ok(None)
        }
        Err(error) => Err(error)
            .with_context(|| format!("check scratch fixture workflow {path} at {revision}")),
    }
}

fn distribution_fixture_files(
    published_runtime_sha: &str,
    published_runtime_tag: &str,
    default_branch: &str,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut files = crate::distribution::caller::rendered_files(
        published_runtime_sha,
        published_runtime_tag,
        default_branch,
        true,
    )?;
    for (path, bytes) in crate::distribution::caller::rendered_client_fixture_files(
        published_runtime_sha,
        published_runtime_tag,
    )? {
        ensure!(
            files.insert(path.clone(), bytes).is_none(),
            "distribution fixture duplicates rendered caller path {path}"
        );
    }
    ensure!(
        files
            .insert(
                ".github/workflows/ci.yml".to_owned(),
                include_str!("integration_templates/ci.yml")
                    .as_bytes()
                    .to_vec(),
            )
            .is_none(),
        "distribution fixture unexpectedly contains the scratch CI workflow"
    );
    overlay_scratch_client_fixture(&mut files)?;
    let push = crate::distribution::caller::rendered_push_fixture(default_branch)?;
    let push = std::str::from_utf8(&push)?;
    let push = replace_once(
        push,
        "  workflow_dispatch:\n",
        "  workflow_dispatch:\n  pull_request:\n    types: [opened, synchronize, reopened]\n",
        ".github/workflows/push.yml",
    )?;
    let push = replace_once(
        &push,
        "    name: status-check\n",
        "    name: scratch-push-status-check\n",
        ".github/workflows/push.yml",
    )?;
    files.insert(".github/workflows/push.yml".to_owned(), push.into_bytes());
    files.insert(
        ".github/workflows/workflow_call_push.yml".to_owned(),
        include_bytes!("integration_templates/workflow_call_push.yml").to_vec(),
    );
    Ok(files)
}

fn overlay_scratch_client_fixture(files: &mut BTreeMap<String, Vec<u8>>) -> Result<()> {
    let trusted = crate::config::trusted()?;
    let scratch = &trusted.deployment.integration.repository;
    let server = &trusted.deployment.server.repository;
    let mut scratch_parts = scratch.split('/');
    let scratch_owner = scratch_parts.next().context("scratch owner missing")?;
    let scratch_name = scratch_parts.next().context("scratch name missing")?;
    ensure!(scratch_parts.next().is_none(), "invalid scratch repository");
    let mut server_parts = server.split('/');
    let server_owner = server_parts.next().context("server owner missing")?;
    let server_name = server_parts.next().context("server name missing")?;
    ensure!(server_parts.next().is_none(), "invalid server repository");
    let scratch_policy = scratch_client_policy(&crate::config::trusted_policy_bytes()?)?;
    use base64::Engine as _;
    let policy_base64 = base64::engine::general_purpose::STANDARD.encode(scratch_policy);

    let ci = files
        .get_mut(".github/workflows/ci.yml")
        .context("scratch CI workflow is missing")?;
    let ci = replace_once(
        std::str::from_utf8(ci)?,
        "      contents: read\n      attestations: read\n      pull-requests: read\n",
        "      actions: read\n      contents: read\n      attestations: read\n      pull-requests: read\n",
        ".github/workflows/ci.yml",
    )?;
    files.insert(".github/workflows/ci.yml".to_owned(), ci.into_bytes());

    for path in [
        ".github/workflows/pull_request.yml",
        ".github/workflows/workflow_call_pr.yml",
    ] {
        let bytes = files
            .get_mut(path)
            .context("scratch caller workflow is missing")?;
        let text = std::str::from_utf8(bytes)?;
        let text = replace_once(
            text,
            "    permissions:\n      contents: read\n",
            "    permissions:\n      actions: read\n      contents: read\n",
            path,
        )?;
        *bytes = text.into_bytes();
    }

    let autofix_path = ".github/workflows/wc-autofix.yml";
    let bytes = files
        .get_mut(autofix_path)
        .context("scratch autofix workflow is missing")?;
    let text = std::str::from_utf8(bytes)?;
    let text = replace_once(
        text,
        "      contents: read\n      attestations: read\n    env:\n      SECUREFIX_CLIENT_APP_ID: ${{ vars.SECUREFIX_CLIENT_APP_ID }}\n      SECUREFIX_SERVER_REPOSITORY: ${{ vars.SECUREFIX_SERVER_REPOSITORY }}\n",
        &format!(
            "      actions: read\n      contents: read\n      attestations: read\n    env:\n      SECUREFIX_CLIENT_APP_ID: {}\n      SECUREFIX_SERVER_REPOSITORY: {}\n",
            trusted.deployment.client_app_id, scratch
        ),
        autofix_path,
    )?;
    let text = replace_once(
        &text,
        "SECUREFIX_SCRATCH_POLICY_BASE64: \"__SECUREFIX_SCRATCH_POLICY_BASE64__\"",
        &format!("SECUREFIX_SCRATCH_POLICY_BASE64: \"{policy_base64}\""),
        autofix_path,
    )?;
    let text = replace_once(
        &text,
        &format!(
            "          owner: \"{server_owner}\"\n          repositories: \"{server_name}\"\n"
        ),
        &format!(
            "          owner: \"{scratch_owner}\"\n          repositories: \"{scratch_name}\"\n"
        ),
        autofix_path,
    )?;
    let text = replace_once(
        &text,
        "      - name: \"Request Securefix commit\"\n        if:",
        "      - name: \"Request Securefix commit\"\n        id: native-client-action\n        if:",
        autofix_path,
    )?;
    let text = replace_once(
        &text,
        &format!("          server-repository: \"{server}\"\n"),
        &format!(
            "          server-repository: \"{scratch}\"\n          runtime-repository: \"{server}\"\n"
        ),
        autofix_path,
    )?;
    let text = replace_once(
        &text,
        &format!(
            "          runtime-default-branch: {}\n",
            serde_json::to_string(&trusted.deployment.server.default_branch)?
        ),
        &format!(
            "          runtime-default-branch: \"{}\"\n          policy-path: scratch-policy.json\n          repository: \"{scratch}\"\n          branch: securefix-client-smoke-${{{{ github.run_id }}}}\n",
            trusted.deployment.server.default_branch
        ),
        autofix_path,
    )?;
    let text = replace_once(
        &text,
        "      - name: Require Securefix configuration\n",
        &format!(
            r#"      - name: Verify scratch client action outputs
        env:
          ARTIFACT_NAME: ${{{{ steps.native-client-action.outputs.artifact-name }}}}
          SOURCE_LABEL: ${{{{ steps.native-client-action.outputs.source-label }}}}
          RUNTIME_SOURCE: ${{{{ steps.native-client-action.outputs.runtime-source }}}}
          CLIENT_TOKEN: ${{{{ steps.securefix-client-token.outputs.token }}}}
          GH_TOKEN: ${{{{ github.token }}}}
          EXPECTED_REPOSITORY: "{scratch}"
        run: |
          set -euo pipefail
          test -n "$ARTIFACT_NAME"
          test "$ARTIFACT_NAME" = "$SOURCE_LABEL"
          test "$RUNTIME_SOURCE" = attested-release
          test "$GITHUB_REPOSITORY" = "$EXPECTED_REPOSITORY"
          gh api "/repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/artifacts?per_page=100" | jq -e --arg name "$ARTIFACT_NAME" '.artifacts | map(select(.name == $name and .expired == false and .size_in_bytes > 0 and .size_in_bytes <= 16777216)) | length == 1' >/dev/null
          label="$(GH_TOKEN="$CLIENT_TOKEN" gh api "/repos/$GITHUB_REPOSITORY/labels/$SOURCE_LABEL")"
          printf '%s' "$label" | jq -e --arg name "$SOURCE_LABEL" --arg description "$GITHUB_REPOSITORY/$GITHUB_RUN_ID" '.name == $name and .description == $description' >/dev/null
          GH_TOKEN="$CLIENT_TOKEN" gh api --method DELETE "/repos/$GITHUB_REPOSITORY/labels/$SOURCE_LABEL"
      - name: Require Securefix configuration
"#
        ),
        autofix_path,
    )?;
    *bytes = text.into_bytes();
    Ok(())
}

fn replace_once(source: &str, needle: &str, replacement: &str, path: &str) -> Result<String> {
    ensure!(
        source.matches(needle).count() == 1,
        "scratch fixture anchor is missing or duplicated in {path}"
    );
    Ok(source.replacen(needle, replacement, 1))
}

fn validate_rendered_files(files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    ensure!(
        !files.is_empty(),
        "distribution renderer returned no managed workflows"
    );
    for (path, bytes) in files {
        ensure!(
            path.starts_with(".github/workflows/")
                && path.ends_with(".yml")
                && crate::securefix_gate::artifact::safe_path(path),
            "distribution renderer returned an unsafe path"
        );
        let workflow: serde_yaml::Value = serde_yaml::from_slice(bytes)
            .with_context(|| format!("rendered workflow is invalid at {path}"))?;
        ensure!(
            workflow["name"].as_str().is_some(),
            "rendered workflow has no name at {path}"
        );
        let text = std::str::from_utf8(bytes)?;
        ensure!(
            !text.contains("@SECUREFIX_RUNTIME_SHA@")
                && !text.contains("@DEFAULT_BRANCH@")
                && !text.contains("csm-actions/securefix-action@"),
            "distribution workflow contains an unresolved placeholder or legacy action: {path}"
        );
    }
    Ok(())
}

fn wait_for_owner_comment(
    api: &GitHub,
    fixture: &PullRequestFixture,
    kind: RequestKind,
    deadline: Instant,
) -> Result<Value> {
    loop {
        let comments = api.paginate(&format!(
            "/repos/{}/issues/{}/comments",
            integration_repository()?,
            fixture.number
        ))?;
        let owner_id = owner_id()?;
        let matches = comments
            .into_iter()
            .filter(|comment| {
                comment["user"]["id"].as_u64() == Some(owner_id)
                    && comment["user"]["type"] == "User"
                    && comment["issue_url"]
                        .as_str()
                        .is_some_and(|url| url.ends_with(&format!("/issues/{}", fixture.number)))
                    && kind.matches_comment_body(&comment["body"])
            })
            .collect::<Vec<_>>();
        ensure!(
            matches.len() <= 1,
            "scratch PR has duplicate owner {} comments",
            kind.command()
        );
        if let Some(comment) = matches.into_iter().next() {
            return Ok(comment);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "timed out waiting for owner {} comment on {}",
            kind.command(),
            fixture.url
        );
        thread::sleep(remaining.min(Duration::from_secs(5)));
    }
}

fn wait_for_merge_gates_except_policy(
    api: &GitHub,
    fixture: &PullRequestFixture,
    deadline: Instant,
) -> Result<()> {
    loop {
        let checks = check_runs(api, &fixture.head_sha)?;
        ensure!(
            !policy_check_exists_in(&checks, trusted_config()?.deployment.checks.policy_app_id,),
            "policy check exists before native auto-merge is enabled"
        );
        let status_ready = latest_check_success(
            &checks,
            "status-check",
            trusted_config()?.deployment.checks.status_app_id,
            true,
        );
        let review = api.graphql(
            "query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewDecision}}}",
            json!({
                "owner":integration_repository()?.split('/').next().unwrap_or_default(),
                "name":integration_repository()?.split('/').nth(1).unwrap_or_default(),
                "number":fixture.number
            }),
        )?;
        let approved = review["repository"]["pullRequest"]["reviewDecision"] == "APPROVED"
            && request::has_current_head_approval(
                api,
                integration_repository()?,
                fixture.number,
                &fixture.head_sha,
            )?;
        if status_ready && approved {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "timed out waiting for required status check and current-head review on {}",
            fixture.url
        );
        thread::sleep(remaining.min(Duration::from_secs(5)));
    }
}

fn wait_for_auto_merge_pending(
    api: &GitHub,
    fixture: &PullRequestFixture,
    deadline: Instant,
) -> Result<()> {
    loop {
        let pull: Value = api.get(&format!(
            "/repos/{}/pulls/{}",
            integration_repository()?,
            fixture.number
        ))?;
        ensure!(
            pull["number"].as_u64() == Some(fixture.number)
                && pull["head"]["repo"]["full_name"] == integration_repository()?
                && pull["head"]["ref"] == fixture.branch
                && pull["head"]["sha"] == fixture.head_sha
                && pull["base"]["repo"]["full_name"] == integration_repository()?
                && pull["state"] == "open"
                && pull["merged"] == false,
            "scratch auto-merge PR changed or merged before its required gate"
        );
        if pull["auto_merge"].is_object() {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "GitHub did not expose queued auto-merge for {}",
            fixture.url
        );
        thread::sleep(remaining.min(Duration::from_secs(5)));
    }
}

fn wait_for_policy_check_success(
    api: &GitHub,
    fixture: &PullRequestFixture,
    deadline: Instant,
) -> Result<()> {
    loop {
        let checks = check_runs(api, &fixture.head_sha)?;
        let matches = policy_check_runs(&checks, trusted_config()?.deployment.checks.policy_app_id);
        ensure!(
            matches.len() <= 1,
            "duplicate Securefix policy checks on fixture head"
        );
        if let Some(check) = matches.first() {
            ensure!(
                check["status"] != "completed" || check["conclusion"] == "success",
                "Securefix policy check failed on fixture head"
            );
            if check["status"] == "completed" && check["conclusion"] == "success" {
                return Ok(());
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "timed out waiting for the Securefix policy check on {}",
            fixture.url
        );
        thread::sleep(remaining.min(Duration::from_secs(5)));
    }
}

fn wait_for_actions_status_check(
    api: &GitHub,
    fixture: &PullRequestFixture,
    default_branch: &str,
    check_name: &str,
    deadline: Instant,
) -> Result<()> {
    let app_id = trusted_config()?.deployment.checks.status_app_id;
    loop {
        verify_pr_identity(api, fixture, default_branch, &fixture.head_sha)?;
        let checks = check_runs(api, &fixture.head_sha)?;
        if latest_check_success(&checks, check_name, app_id, false) {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "timed out waiting for the real consumer {check_name} on {}",
            fixture.url
        );
        thread::sleep(remaining.min(Duration::from_secs(5)));
    }
}

fn wait_for_auto_merge(
    api: &GitHub,
    fixture: &PullRequestFixture,
    deadline: Instant,
) -> Result<String> {
    loop {
        let pull: Value = api.get(&format!(
            "/repos/{}/pulls/{}",
            integration_repository()?,
            fixture.number
        ))?;
        ensure!(
            pull["number"].as_u64() == Some(fixture.number)
                && pull["head"]["repo"]["full_name"] == integration_repository()?
                && pull["head"]["ref"] == fixture.branch
                && pull["head"]["sha"] == fixture.head_sha
                && pull["base"]["repo"]["full_name"] == integration_repository()?,
            "scratch auto-merge PR identity changed while waiting"
        );
        if pull["merged"] == true {
            ensure!(pull["state"] == "closed", "GitHub merged PR remains open");
            let sha = pull["merge_commit_sha"]
                .as_str()
                .context("merged scratch PR has no merge commit SHA")?;
            validate_sha(sha)?;
            return Ok(sha.to_owned());
        }
        ensure!(
            pull["state"] == "open",
            "GitHub closed the scratch auto-merge PR without merging"
        );
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "timed out waiting for GitHub native auto-merge of {}",
            fixture.url
        );
        thread::sleep(remaining.min(Duration::from_secs(5)));
    }
}

fn check_runs(api: &GitHub, sha: &str) -> Result<Vec<Value>> {
    let mut checks = Vec::new();
    for page in 1..=100 {
        let response: Value = api.get(&format!(
            "/repos/{}/commits/{sha}/check-runs?per_page=100&page={page}&filter=latest",
            integration_repository()?
        ))?;
        let batch = response["check_runs"]
            .as_array()
            .context("check runs are malformed")?;
        let done = batch.len() < 100;
        checks.extend(batch.iter().cloned());
        if done {
            return Ok(checks);
        }
    }
    anyhow::bail!("check run pagination exceeded limit")
}

fn policy_check_runs(checks: &[Value], app_id: u64) -> Vec<&Value> {
    checks
        .iter()
        .filter(|check| {
            check["name"] == "securefix-policy-check" && check["app"]["id"].as_u64() == Some(app_id)
        })
        .collect()
}

fn policy_check_exists_in(checks: &[Value], app_id: u64) -> bool {
    !policy_check_runs(checks, app_id).is_empty()
}

fn policy_check_exists(api: &GitHub, sha: &str) -> Result<bool> {
    Ok(policy_check_exists_in(
        &check_runs(api, sha)?,
        trusted_config()?.deployment.checks.policy_app_id,
    ))
}

fn latest_check_success(checks: &[Value], name: &str, app_id: u64, allow_skipped: bool) -> bool {
    checks
        .iter()
        .filter(|check| check["name"] == name && check["app"]["id"].as_u64() == Some(app_id))
        .max_by_key(|check| check["id"].as_u64().unwrap_or_default())
        .is_some_and(|check| {
            check["status"] == "completed"
                && (check["conclusion"] == "success"
                    || allow_skipped && check["conclusion"] == "skipped")
        })
}

fn manifest(
    scenario: &Scenario,
    fixture: &PullRequestFixture,
    comment: &Value,
    candidate_sha: &str,
) -> Result<RequestManifest> {
    let created = parse_time(&comment["created_at"])?;
    let updated_at = comment["updated_at"]
        .as_str()
        .map(DateTime::parse_from_rfc3339)
        .transpose()?
        .map(|time| time.with_timezone(&Utc));
    let id = comment["id"].as_u64().context("owner comment has no ID")?;
    let run_id = std::env::var("GITHUB_RUN_ID")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|id| *id > 0)
        .unwrap_or_else(|| created.timestamp().unsigned_abs().max(1));
    let manifest = RequestManifest {
        version: 1,
        kind: RequestKind::Merge,
        repository: RepositoryRef {
            id: scenario.repository_id,
            full_name: scenario.repository.clone(),
        },
        pull_request: PullRequestRef {
            number: fixture.number,
            head_sha: fixture.head_sha.clone(),
            base_ref: scenario.default_branch.clone(),
        },
        authorization: Authorization::OwnerComment {
            comment_id: id,
            updated_at,
        },
        accepted_at: created,
        run_id,
        run_attempt: 1,
        workflow_sha: candidate_sha.to_owned(),
        caller_workflow_sha: candidate_sha.to_owned(),
    };
    manifest.validate()?;
    Ok(manifest)
}

fn parse_time(value: &Value) -> Result<DateTime<Utc>> {
    value
        .as_str()
        .context("timestamp is missing")?
        .parse::<DateTime<Utc>>()
        .context("timestamp is invalid")
}

fn verify_pr_identity(
    api: &GitHub,
    fixture: &PullRequestFixture,
    base: &str,
    expected_head: &str,
) -> Result<()> {
    let pull: Value = api.get(&format!(
        "/repos/{}/pulls/{}",
        integration_repository()?,
        fixture.number
    ))?;
    ensure!(
        pull["state"] == "open"
            && pull["base"]["repo"]["full_name"] == integration_repository()?
            && pull["base"]["ref"] == base
            && pull["head"]["repo"]["full_name"] == integration_repository()?
            && pull["head"]["ref"] == fixture.branch
            && pull["head"]["sha"] == expected_head,
        "scratch pull request changed after preparation"
    );
    Ok(())
}

fn pr_head_observation_is_advanced(
    pull: &Value,
    repository: &str,
    fixture: &PullRequestFixture,
    base: &str,
    old_head: &str,
    new_head: &str,
) -> Result<bool> {
    ensure!(
        pull["number"].as_u64() == Some(fixture.number)
            && pull["state"] == "open"
            && pull["base"]["repo"]["full_name"] == repository
            && pull["base"]["ref"] == base
            && pull["head"]["repo"]["full_name"] == repository
            && pull["head"]["ref"] == fixture.branch,
        "stale-head PR identity changed during head visibility wait"
    );
    let observed_head = pull["head"]["sha"]
        .as_str()
        .context("stale-head PR response has no head SHA")?;
    ensure!(
        observed_head == old_head || observed_head == new_head,
        "stale-head PR observed an unexpected commit"
    );
    Ok(observed_head == new_head)
}

fn wait_for_pr_head_transition(
    api: &GitHub,
    fixture: &PullRequestFixture,
    base: &str,
    old_head: &str,
    new_head: &str,
    deadline: Instant,
) -> Result<()> {
    let repository = integration_repository()?;
    loop {
        let pull: Value = api.get(&format!("/repos/{repository}/pulls/{}", fixture.number))?;
        if pr_head_observation_is_advanced(&pull, repository, fixture, base, old_head, new_head)? {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "timed out waiting for scratch PR {} to expose its new head",
            fixture.number
        );
        thread::sleep(remaining.min(Duration::from_secs(5)));
    }
}

fn verify_remote_identity(api: &GitHub, scenario: &Scenario) -> Result<()> {
    let repo: Value = api.get(&format!("/repos/{}", scenario.repository))?;
    ensure!(
        scenario.repository == integration_repository()?
            && scenario.repository_id == integration_repository_id()?
            && repo["full_name"] == integration_repository()?
            && repo["id"].as_u64() == Some(integration_repository_id()?),
        "integration state is not bound to the dedicated scratch repository"
    );
    Ok(())
}

fn cleanup(api: &GitHub, scenario: &Scenario) -> Result<()> {
    for fixture in [&scenario.positive, &scenario.stale, &scenario.distribution] {
        let pull: Value = api.get(&format!(
            "/repos/{}/pulls/{}",
            integration_repository()?,
            fixture.number
        ))?;
        if pull["state"] == "open" {
            let _: Value = api.patch(
                &format!(
                    "/repos/{}/pulls/{}",
                    integration_repository()?,
                    fixture.number
                ),
                &json!({"state":"closed"}),
            )?;
        }
        validate_branch(&fixture.branch)?;
        match api.delete(&format!(
            "/repos/{}/git/refs/heads/{}",
            integration_repository()?,
            fixture.branch
        )) {
            Ok(()) => {}
            Err(error)
                if error
                    .downcast_ref::<ApiError>()
                    .is_some_and(|api| api.status == reqwest::StatusCode::NOT_FOUND) => {}
            Err(error) => return Err(error).context("delete scratch integration branch"),
        }
    }
    Ok(())
}

fn validate_scenario(
    scenario: &Scenario,
    candidate_sha: &str,
    published_runtime_sha: &str,
) -> Result<()> {
    ensure!(
        scenario.version == STATE_VERSION
            && scenario.repository == integration_repository()?
            && scenario.repository_id == integration_repository_id()?
            && scenario.candidate_sha == candidate_sha,
        "integration state identity mismatch"
    );
    validate_sha(&scenario.candidate_sha)?;
    validate_sha(&scenario.published_runtime_sha)?;
    ensure!(
        scenario.published_runtime_sha == published_runtime_sha,
        "integration state is bound to a different published runtime"
    );
    validate_sha(&scenario.workflow_sha)?;
    validate_sha(&scenario.base_sha)?;
    ensure!(
        !scenario.default_branch.is_empty()
            && scenario.default_branch.len() <= 255
            && !scenario
                .default_branch
                .contains(['?', '#', '\\', '\r', '\n'])
            && !scenario
                .default_branch
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".."),
        "invalid scratch default branch in integration state"
    );
    for fixture in [&scenario.positive, &scenario.stale, &scenario.distribution] {
        ensure!(
            fixture.number > 0
                && fixture.url.starts_with(&format!(
                    "https://github.com/{}/pull/",
                    integration_repository()?
                )),
            "invalid scratch pull request URL"
        );
        validate_sha(&fixture.head_sha)?;
        validate_branch(&fixture.branch)?;
    }
    ensure!(
        scenario.positive.number != scenario.stale.number
            && scenario.positive.number != scenario.distribution.number
            && scenario.stale.number != scenario.distribution.number,
        "integration state reuses a pull request"
    );
    Ok(())
}

fn workflow_run_matches(run: &Value, workflow_sha: &str) -> Result<bool> {
    let default_branch = &crate::config::trusted()?.deployment.server.default_branch;
    Ok(workflow_run_matches_for_default_branch(
        run,
        workflow_sha,
        default_branch,
    ))
}

fn workflow_run_matches_for_default_branch(
    run: &Value,
    workflow_sha: &str,
    default_branch: &str,
) -> bool {
    let expected_branch = format!("integration/native-{}", &workflow_sha[..12]);
    let path = run["path"].as_str().unwrap_or_default();
    let (workflow_path, reference) = path.split_once('@').unwrap_or((path, ""));
    workflow_path == WORKFLOW_PATH
        && run["head_sha"] == workflow_sha
        && run["head_branch"]
            .as_str()
            .is_some_and(|branch| branch == default_branch || branch == expected_branch)
        && (reference.is_empty()
            || reference == format!("refs/heads/{default_branch}")
            || reference == format!("refs/heads/{expected_branch}"))
}

fn validate_state_path(path: &Path) -> Result<()> {
    ensure!(
        !path.is_absolute()
            && !path.as_os_str().is_empty()
            && path
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_))),
        "integration state path must be relative and cannot contain traversal"
    );
    Ok(())
}

fn validate_outputs(
    workspace: &Path,
    state_file: &Path,
    candidate_sha: &str,
    phase: Phase,
    published_runtime_sha: &str,
    published_runtime_tag: &str,
) -> Result<()> {
    validate_state_path(state_file)?;
    ensure!(
        !published_runtime_tag.is_empty(),
        "published runtime tag metadata is empty"
    );
    ensure!(
        state_file.file_name().and_then(|name| name.to_str()) == Some("state.json"),
        "integration output must use state.json"
    );
    let workspace = fs::canonicalize(workspace).context("resolve candidate workspace")?;
    let directory = state_file.parent().context("state file has no directory")?;
    let dir_meta = safe_output_metadata(&workspace, directory)?;
    ensure!(
        dir_meta.is_dir(),
        "integration output directory is not a directory"
    );

    let expected: &[&str] = match phase {
        Phase::Prepare => &["state.json"],
        Phase::Verify => &["state.json", "verification.json"],
    };
    let mut names = std::collections::BTreeSet::new();
    for entry in fs::read_dir(workspace.join(directory))? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("integration output filename is not UTF-8"))?;
        ensure!(
            expected.contains(&name.as_str()),
            "unexpected integration output file: {name}"
        );
        let relative = directory.join(&name);
        let metadata = safe_output_metadata(&workspace, &relative)?;
        ensure!(
            metadata.is_file(),
            "integration output is not a regular file: {name}"
        );
        ensure!(
            metadata.len() <= 16 * 1024,
            "integration output exceeds size limit: {name}"
        );
        names.insert(name);
    }
    ensure!(
        names.len() == expected.len() && expected.iter().all(|name| names.contains(*name)),
        "integration output file set is incomplete"
    );

    let state_bytes = read_output_file(&workspace, state_file)?;
    let scenario: Scenario =
        serde_json::from_slice(&state_bytes).context("parse output scenario")?;
    validate_scenario(&scenario, candidate_sha, published_runtime_sha)?;
    if phase == Phase::Verify {
        let verification_path = directory.join("verification.json");
        let bytes = read_output_file(&workspace, &verification_path)?;
        let verification: Verification =
            serde_json::from_slice(&bytes).context("parse verification output")?;
        ensure!(
            verification.version == STATE_VERSION
                && verification.repository == integration_repository()?
                && verification.candidate_sha == candidate_sha
                && verification.positive_pr == scenario.positive.number
                && validate_sha(&verification.merged_sha).is_ok()
                && validate_sha(&verification.stale_head_sha).is_ok()
                && verification.annotated_tag_verified
                && verification.closed_or_merged,
            "verification output does not match the validated scenario"
        );
    }
    Ok(())
}

fn safe_output_metadata(workspace: &Path, relative: &Path) -> Result<fs::Metadata> {
    ensure!(
        relative.is_relative()
            && !relative.as_os_str().is_empty()
            && relative
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_))),
        "integration output path must stay beneath the workspace"
    );
    let mut current = PathBuf::new();
    let components = relative.components().collect::<Vec<_>>();
    let mut metadata = None;
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        let next = fs::symlink_metadata(workspace.join(&current))?;
        ensure!(
            !next.file_type().is_symlink(),
            "integration output contains a symbolic link"
        );
        if index + 1 < components.len() {
            ensure!(
                next.is_dir(),
                "integration output parent is not a directory"
            );
        }
        metadata = Some(next);
    }
    metadata.context("integration output path is empty")
}

fn read_output_file(workspace: &Path, relative: &Path) -> Result<Vec<u8>> {
    use std::io::Read;

    let metadata = safe_output_metadata(workspace, relative)?;
    ensure!(
        metadata.is_file(),
        "integration output is not a regular file"
    );
    ensure!(
        metadata.len() <= 16 * 1024,
        "integration output exceeds size limit"
    );
    let mut bytes = Vec::new();
    fs::File::open(workspace.join(relative))?
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16 * 1024 && bytes.len() as u64 == metadata.len(),
        "integration output size changed while reading"
    );
    Ok(bytes)
}

fn validate_branch(branch: &str) -> Result<()> {
    ensure!(
        branch.starts_with(BRANCH_PREFIX)
            && branch.len() <= 100
            && branch
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)),
        "invalid scratch integration branch"
    );
    Ok(())
}

fn scratch_policy(candidate_sha: &str) -> Result<Policy> {
    validate_sha(candidate_sha)?;
    let mut policy = Policy::parse(&crate::config::trusted_policy_bytes()?)?;
    policy.repositories = vec![securefix::policy::RepositoryPolicy {
        repository: integration_repository()?.to_owned(),
        capabilities: vec![
            Capability::Approve,
            Capability::Merge,
            Capability::Securefix,
            Capability::Release,
        ],
        release: Some(ReleaseStrategy::GithubRelease),
        sensitive_paths: policy.default_sensitive_paths.clone(),
        protect_tags: false,
    }];
    policy.revision = candidate_sha.to_owned();
    ensure!(
        policy
            .repository(integration_repository()?)?
            .capabilities
            .contains(&Capability::Merge),
        "scratch policy lacks merge capability"
    );
    Ok(policy)
}

fn verify_artifact_path_safety() -> Result<()> {
    let bytes = b"{}";
    let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    archive.start_file("../manifest.json", zip::write::SimpleFileOptions::default())?;
    use std::io::Write;
    archive.write_all(bytes)?;
    let bytes = archive.finish()?.into_inner();
    ensure!(
        workflow::manifest_from_zip::<Value>(&bytes).is_err(),
        "manifest ZIP traversal path unexpectedly passed validation"
    );
    Ok(())
}

impl RequestKind {
    fn command(self) -> &'static str {
        match self {
            Self::Approve => "/approve",
            Self::Merge => "/merge",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_tag_read_waits_for_visibility_but_does_not_retry_permission_errors() {
        use crate::fixtures::{Fixture, Route};
        let path = "/repos/civitaspo/testing-securefix-server/git/ref/tags/v0.0.0-test";
        let expected = json!({"object":{"type":"tag","sha":"a".repeat(40)}});
        let fixture = Fixture::new(vec![
            Route::request("GET", path, 404, json!({"message":"Not Found"})),
            Route::get(path, expected.clone()),
        ]);
        assert_eq!(
            wait_for_created_tag_ref(&fixture.api, path).unwrap(),
            expected
        );
        fixture.finish();
        let fixture = Fixture::new(vec![Route::request(
            "GET",
            path,
            403,
            json!({"message":"Forbidden"}),
        )]);
        assert!(wait_for_created_tag_ref(&fixture.api, path).is_err());
        fixture.finish();
    }

    #[test]
    fn first_cutover_ignores_only_a_historical_canonical_tag_at_another_source() {
        let sha = "a".repeat(40);
        let historical_sha = "b".repeat(40);
        let annotation_sha = "c".repeat(40);
        let version = crate::runtime::RuntimeVersion::parse("0.1.0").unwrap();
        let direct = |tag: &str, target: &str| {
            json!({
                "ref": format!("refs/tags/{tag}"),
                "object": {"type":"commit", "sha":target}
            })
        };
        let selected = select_test_runtime_tag(
            &version,
            &sha,
            Some(direct("v0.1.0", &historical_sha)),
            None,
            Some(direct(&format!("v0.1.0+{sha}"), &sha)),
        )
        .unwrap();
        assert_eq!(selected, format!("v0.1.0+{sha}"));
        assert!(
            select_test_runtime_tag(
                &version,
                &sha,
                Some(direct("v0.1.0", &sha)),
                None,
                Some(direct(&format!("v0.1.0+{sha}"), &sha)),
            )
            .is_err(),
            "two tag forms for the current source must fail closed"
        );
        assert!(
            select_test_runtime_tag(&version, &sha, None, None, None).is_err(),
            "missing source tag must fail closed"
        );
        assert!(
            select_test_runtime_tag(
                &version,
                &sha,
                Some(json!({"ref":"refs/tags/v0.1.0", "object":{"type":"tag", "sha":annotation_sha}})),
                Some(json!({"sha":annotation_sha,"tag":"v0.1.0","object":{"type":"commit","sha":historical_sha}})),
                Some(direct(&format!("v0.1.0+{sha}"), &sha)),
            )
            .is_ok(),
            "valid annotated historical canonical tag must be ignored"
        );
        assert!(
            select_test_runtime_tag(
                &version,
                &sha,
                Some(json!({"ref":"refs/tags/v0.1.0", "object":{"type":"tag", "sha":annotation_sha}})),
                Some(json!({"sha":annotation_sha,"tag":"v0.1.0","object":{"type":"commit","sha":sha}})),
                Some(direct(&format!("v0.1.0+{sha}"), &sha)),
            ).is_err(),
            "annotated canonical tag pointing at current source must fail closed"
        );
        assert!(
            select_test_runtime_tag(
                &version,
                &sha,
                Some(json!({"ref":"refs/tags/v0.1.0", "object":{"type":"tag", "sha":annotation_sha}})),
                Some(json!({"sha":annotation_sha,"tag":"v0.1.0","object":{"type":"tag","sha":historical_sha}})),
                Some(direct(&format!("v0.1.0+{sha}"), &sha)),
            ).is_err(),
            "nested annotated tags must fail closed"
        );
        assert!(
            select_test_runtime_tag(
                &version,
                &sha,
                Some(json!({"ref":"refs/tags/v0.1.0", "object":{"type":"tag", "sha":annotation_sha}})),
                Some(json!({"sha":annotation_sha,"tag":"v0.1.1","object":{"type":"commit","sha":historical_sha}})),
                Some(direct(&format!("v0.1.0+{sha}"), &sha)),
            ).is_err(),
            "mismatched annotated tag identity must fail closed"
        );
    }

    #[test]
    fn approval_probe_rejects_other_authors_repositories_refs_and_heads() {
        let head = "a".repeat(40);
        let base = "b".repeat(40);
        let fixture = PullRequestFixture {
            number: 7,
            branch: "securefix-integration-approval-aaaaaaaaaaaa".into(),
            head_sha: head.clone(),
            url: "fixture".into(),
        };
        let pull = json!({
            "number":7,"state":"open","draft":false,
            "user":{"id":owner_id().unwrap(),"type":"User"},
            "head":{"repo":{"id":integration_repository_id().unwrap(),"full_name":integration_repository().unwrap()},"ref":fixture.branch,"sha":head},
            "base":{"repo":{"id":integration_repository_id().unwrap()},"ref":"main","sha":base}
        });
        validate_owner_approval_target(&pull, &fixture, "main", &base).unwrap();
        for (pointer, replacement) in [
            ("/number", json!(8)),
            ("/state", json!("closed")),
            ("/draft", json!(true)),
            ("/user/id", json!(1)),
            ("/user/type", json!("Bot")),
            ("/head/repo/id", json!(1)),
            ("/head/repo/full_name", json!("other/repository")),
            ("/head/ref", json!("main")),
            ("/head/sha", json!("c".repeat(40))),
            ("/base/repo/id", json!(1)),
            ("/base/ref", json!("other")),
            ("/base/sha", json!("c".repeat(40))),
        ] {
            let mut changed = pull.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(validate_owner_approval_target(&changed, &fixture, "main", &base).is_err());
        }
    }

    #[test]
    fn client_smoke_artifact_must_match_the_exact_source_and_fixture() {
        let run_id = 42;
        let workflow_sha = "a".repeat(40);
        let mut additions = BTreeMap::new();
        additions.insert(
            ".securefix-client-smoke/request.txt".into(),
            format!("Securefix client smoke {run_id}\n").into_bytes(),
        );
        let fix = crate::securefix_gate::artifact::FixArtifact {
            repository: integration_repository().unwrap().to_owned(),
            branch: format!("securefix-client-smoke-{run_id}"),
            run_id,
            source_sha: workflow_sha.clone(),
            commit_message: "test fixture".into(),
            create_pull_request: None,
            additions,
            deletions: Vec::new(),
        };
        assert!(
            validate_client_smoke_artifact(
                &fix,
                integration_repository().unwrap(),
                run_id,
                &workflow_sha
            )
            .is_ok()
        );
        assert!(
            validate_client_smoke_artifact(
                &fix,
                integration_repository().unwrap(),
                run_id + 1,
                &workflow_sha
            )
            .is_err()
        );
    }

    #[test]
    fn client_smoke_policy_swaps_only_server_and_scratch_deployments() {
        let mut original: Value =
            serde_json::from_slice(&crate::config::trusted_policy_bytes().unwrap()).unwrap();
        original["sensitive_path_approval_exemptions"] = json!({"users":[],"github_apps":[]});
        let scratch = scratch_client_policy(&serde_json::to_vec(&original).unwrap()).unwrap();
        let scratch: Value = serde_json::from_slice(&scratch).unwrap();
        assert!(scratch.get("sensitive_path_approval_exemptions").is_none());
        assert_eq!(
            scratch["deployment"]["server"],
            original["deployment"]["integration"]
        );
        assert_eq!(
            scratch["deployment"]["integration"],
            original["deployment"]["server"]
        );
        assert_eq!(scratch["repositories"].as_array().unwrap().len(), 1);
        assert_eq!(
            scratch["repositories"][0]["repository"],
            original["deployment"]["integration"]["repository"]
        );
        assert_eq!(
            scratch["repositories"][0]["capabilities"],
            json!(["securefix"])
        );
        assert_eq!(scratch["owner_id"], original["owner_id"]);
    }

    #[test]
    fn client_source_run_accepts_nonterminal_status_but_rejects_identity_mismatches() {
        let trusted = trusted_config().unwrap();
        let server = &trusted.deployment.server;
        let run_id = 42;
        let workflow_sha = "a".repeat(40);
        let branch = format!("integration/native-{}", &workflow_sha[..12]);
        let run = json!({
            "id": run_id,
            "repository": {"full_name": server.repository, "id": server.id},
            "head_repository": {"id": server.id},
            "head_sha": workflow_sha,
            "head_branch": branch,
            "path": format!("{WORKFLOW_PATH}@refs/heads/{branch}"),
            "event": "workflow_dispatch",
            "run_attempt": 1,
            "status": "queued",
            "actor": {"id": trusted.owner_id},
            "triggering_actor": {"id": trusted.owner_id}
        });
        assert!(
            validate_client_source_run(
                &run,
                run_id,
                &workflow_sha,
                &server.repository,
                server.id,
                trusted.owner_id
            )
            .is_ok()
        );

        let mut wrong_actor = run.clone();
        wrong_actor["actor"]["id"] = json!(trusted.owner_id + 1);
        let mut wrong_sha = run.clone();
        wrong_sha["head_sha"] = json!("b".repeat(40));
        let mut wrong_repository = run.clone();
        wrong_repository["repository"]["id"] = json!(server.id + 1);
        let mut wrong_attempt = run.clone();
        wrong_attempt["run_attempt"] = json!(2);
        for wrong in [wrong_actor, wrong_sha, wrong_repository, wrong_attempt] {
            assert!(
                validate_client_source_run(
                    &wrong,
                    run_id,
                    &workflow_sha,
                    &server.repository,
                    server.id,
                    trusted.owner_id
                )
                .is_err()
            );
        }
    }

    #[test]
    fn auto_merge_probe_uses_the_latest_check_from_the_configured_app() {
        let app_id = trusted_config().unwrap().deployment.checks.status_app_id;
        let checks = vec![
            json!({
                "id":1,
                "name":"status-check",
                "app":{"id":app_id},
                "status":"completed",
                "conclusion":"success"
            }),
            json!({
                "id":2,
                "name":"status-check",
                "app":{"id":app_id + 1},
                "status":"completed",
                "conclusion":"failure"
            }),
        ];
        assert!(latest_check_success(&checks, "status-check", app_id, true));

        let checks = vec![
            json!({
                "id":1,
                "name":"status-check",
                "app":{"id":app_id},
                "status":"completed",
                "conclusion":"success"
            }),
            json!({
                "id":2,
                "name":"status-check",
                "app":{"id":app_id},
                "status":"completed",
                "conclusion":"failure"
            }),
        ];
        assert!(!latest_check_success(&checks, "status-check", app_id, true));
    }

    #[test]
    fn policy_check_probe_requires_the_configured_app_identity() {
        let app_id = trusted_config().unwrap().deployment.checks.policy_app_id;
        let check = json!({
            "id":1,
            "name":"securefix-policy-check",
            "app":{"id":app_id + 1},
            "status":"completed",
            "conclusion":"success"
        });
        assert!(!policy_check_exists_in(&[check], app_id));
    }

    #[test]
    fn distribution_fixture_includes_the_checked_in_pinact_consumer_workflow() {
        let sha = "a".repeat(40);
        let files = distribution_fixture_files(&sha, "v0.2.0-pre.1", "main").unwrap();
        let ci = std::str::from_utf8(files.get(".github/workflows/ci.yml").unwrap()).unwrap();
        assert!(ci.contains("      actions: read\n      contents: read\n      attestations: read\n      pull-requests: read\n"));
        let autofix = std::str::from_utf8(
            files
                .get(".github/workflows/wc-autofix.yml")
                .expect("migrated autofix workflow is present"),
        )
        .unwrap();
        let workflow: serde_yaml::Value = serde_yaml::from_str(autofix).unwrap();
        assert!(
            workflow["jobs"]["autofix"]["steps"]
                .as_sequence()
                .unwrap()
                .iter()
                .any(|step| step["uses"].as_str()
                    == Some(&format!(
                        "{}/.github/actions/client@{sha}",
                        server_repository().unwrap()
                    )))
        );
        assert!(!autofix.contains("csm-actions/securefix-action@"));
        assert!(!autofix.contains("__SECUREFIX_SCRATCH_POLICY_BASE64__"));
        assert!(autofix.contains("id: native-client-action"));
        assert!(autofix.contains("files: ${{ steps.securefix-files.outputs.files }}"));
        assert!(autofix.contains(&format!(
            "server-repository: \"{}\"\n          runtime-repository: \"{}\"",
            integration_repository().unwrap(),
            server_repository().unwrap()
        )));
        assert!(autofix.contains("name: Verify scratch client action outputs"));
        assert!(autofix.contains("gh api --method DELETE"));
        assert!(autofix.contains("actions: read\n      contents: read"));
        for path in [
            ".github/workflows/pull_request.yml",
            ".github/workflows/workflow_call_pr.yml",
        ] {
            assert!(
                files.contains_key(path),
                "migrated workflow is missing: {path}"
            );
        }
        for path in [
            ".github/workflows/pull_request.yml",
            ".github/workflows/workflow_call_pr.yml",
        ] {
            let workflow = std::str::from_utf8(files.get(path).unwrap()).unwrap();
            assert!(workflow.contains("      actions: read\n      contents: read"));
        }
        validate_rendered_files(&files).unwrap();
    }

    #[test]
    fn scratch_policy_is_narrowed_to_one_repository_and_candidate_revision() {
        let revision = "a".repeat(40);
        let policy = scratch_policy(&revision).unwrap();
        assert_eq!(policy.repositories.len(), 1);
        assert_eq!(
            policy.repositories[0].repository,
            integration_repository().unwrap()
        );
        assert_eq!(policy.revision, revision);
        assert!(policy.repository(server_repository().unwrap()).is_err());
    }

    #[test]
    fn comment_commands_accept_only_whitespace_wrapped_exact_commands() {
        for (kind, accepted, rejected) in [
            (RequestKind::Approve, " \t/approve\r\n ", "/approve extra"),
            (RequestKind::Merge, "\n/merge\t", "/merge\n/approve"),
        ] {
            assert!(kind.matches_comment_body(&json!(accepted)));
            assert!(!kind.matches_comment_body(&json!(rejected)));
        }
    }

    #[test]
    fn producer_workflow_sha_is_distinct_from_candidate_and_branch_pinned() {
        let sha = "a".repeat(40);
        let default_branch = crate::config::trusted()
            .unwrap()
            .deployment
            .server
            .default_branch
            .clone();
        let run = json!({
            "head_sha":sha,
            "head_branch":default_branch,
            "path":format!("{WORKFLOW_PATH}@refs/heads/{default_branch}")
        });
        assert!(workflow_run_matches(&run, &sha).unwrap());
        assert!(validate_workflow_ref(&sha, &format!("refs/heads/{default_branch}")).is_ok());
        let mut wrong_branch = run.clone();
        wrong_branch["head_branch"] = json!("feature/untrusted");
        assert!(!workflow_run_matches(&wrong_branch, &sha).unwrap());
        let frozen = format!("integration/native-{}", &sha[..12]);
        let frozen_run = json!({
            "head_sha":sha,
            "head_branch":frozen,
            "path":format!("{WORKFLOW_PATH}@refs/heads/{frozen}")
        });
        assert!(workflow_run_matches(&frozen_run, &sha).unwrap());
        assert!(validate_workflow_ref(&sha, &format!("refs/heads/{frozen}")).is_ok());
        assert!(validate_workflow_ref(&sha, "refs/heads/feature/untrusted").is_err());
        assert!(validate_workflow_ref(&sha, "refs/tags/v1.0.0").is_err());

        let alternate_default = "trunk";
        let trunk_run = json!({
            "head_sha":sha,
            "head_branch":alternate_default,
            "path":format!("{WORKFLOW_PATH}@refs/heads/{alternate_default}")
        });
        assert!(workflow_run_matches_for_default_branch(
            &trunk_run,
            &sha,
            alternate_default
        ));
    }

    #[test]
    fn stale_pr_head_observation_waits_for_expected_transition_and_rejects_invalid_identity() {
        let fixture = fixture(17);
        let repository = integration_repository().unwrap();
        let old_head = "c".repeat(40);
        let new_head = "d".repeat(40);
        let mut pull = json!({
            "number":fixture.number,
            "state":"open",
            "base":{"repo":{"full_name":repository},"ref":"main"},
            "head":{"repo":{"full_name":repository},"ref":fixture.branch,"sha":old_head}
        });
        assert!(
            !pr_head_observation_is_advanced(
                &pull, repository, &fixture, "main", &old_head, &new_head,
            )
            .unwrap()
        );
        pull["head"]["sha"] = json!(new_head);
        assert!(
            pr_head_observation_is_advanced(
                &pull, repository, &fixture, "main", &old_head, &new_head,
            )
            .unwrap()
        );

        pull["head"]["sha"] = json!("e".repeat(40));
        assert!(
            pr_head_observation_is_advanced(
                &pull, repository, &fixture, "main", &old_head, &new_head,
            )
            .is_err()
        );
        pull["head"]["sha"] = json!(new_head);
        pull["base"]["repo"]["full_name"] = json!("other/repo");
        assert!(
            pr_head_observation_is_advanced(
                &pull, repository, &fixture, "main", &old_head, &new_head,
            )
            .is_err()
        );
        pull["base"]["repo"]["full_name"] = json!(repository);
        pull["head"]["repo"]["full_name"] = json!("other/repo");
        assert!(
            pr_head_observation_is_advanced(
                &pull, repository, &fixture, "main", &old_head, &new_head,
            )
            .is_err()
        );
        pull["head"]["repo"]["full_name"] = json!(repository);
        pull["base"]["ref"] = json!("other-base");
        assert!(
            pr_head_observation_is_advanced(
                &pull, repository, &fixture, "main", &old_head, &new_head,
            )
            .is_err()
        );
        pull["base"]["ref"] = json!("main");
        pull["state"] = json!("closed");
        assert!(
            pr_head_observation_is_advanced(
                &pull, repository, &fixture, "main", &old_head, &new_head,
            )
            .is_err()
        );
    }

    #[test]
    fn state_path_rejects_absolute_and_parent_traversal() {
        assert!(validate_state_path(Path::new("fixtures/state.json")).is_ok());
        assert!(validate_state_path(Path::new("../state.json")).is_err());
        assert!(validate_state_path(Path::new("/tmp/state.json")).is_err());
    }

    #[test]
    fn candidate_outputs_are_bounded_and_match_the_validated_scenario() {
        let workspace = tempfile::tempdir().unwrap();
        let fixtures = workspace.path().join("fixtures");
        fs::create_dir(&fixtures).unwrap();
        let candidate_sha = "a".repeat(40);
        let scenario = Scenario {
            version: STATE_VERSION,
            repository: integration_repository().unwrap().into(),
            repository_id: integration_repository_id().unwrap(),
            candidate_sha: candidate_sha.clone(),
            published_runtime_sha: "f".repeat(40),
            workflow_sha: "b".repeat(40),
            default_branch: "main".into(),
            base_sha: "c".repeat(40),
            prepared_at: Utc::now(),
            positive: fixture(17),
            stale: fixture(18),
            distribution: fixture(19),
        };
        let state_file = Path::new("fixtures/state.json");
        fs::write(
            workspace.path().join(state_file),
            serde_json::to_vec(&scenario).unwrap(),
        )
        .unwrap();
        assert!(
            validate_outputs(
                workspace.path(),
                state_file,
                &candidate_sha,
                Phase::Prepare,
                &scenario.published_runtime_sha,
                "v0.2.0-pre.1",
            )
            .is_ok()
        );

        let verification = Verification {
            version: STATE_VERSION,
            repository: integration_repository().unwrap().into(),
            candidate_sha: candidate_sha.clone(),
            positive_pr: scenario.positive.number,
            merged_sha: "d".repeat(40),
            stale_pr: scenario.stale.number,
            stale_head_sha: "e".repeat(40),
            distribution_pr: scenario.distribution.number,
            managed_files: vec![],
            annotated_tag_verified: true,
            closed_or_merged: true,
        };
        fs::write(
            fixtures.join("verification.json"),
            serde_json::to_vec(&verification).unwrap(),
        )
        .unwrap();
        assert!(
            validate_outputs(
                workspace.path(),
                state_file,
                &candidate_sha,
                Phase::Verify,
                &scenario.published_runtime_sha,
                "v0.2.0-pre.1",
            )
            .is_ok()
        );
        let mut wrong = verification;
        wrong.positive_pr += 1;
        fs::write(
            fixtures.join("verification.json"),
            serde_json::to_vec(&wrong).unwrap(),
        )
        .unwrap();
        assert!(
            validate_outputs(
                workspace.path(),
                state_file,
                &candidate_sha,
                Phase::Verify,
                &scenario.published_runtime_sha,
                "v0.2.0-pre.1",
            )
            .is_err()
        );
    }

    #[test]
    fn candidate_output_rejects_symlinked_fixture_directory() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("state.json"), b"{}").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), workspace.path().join("fixtures")).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(outside.path(), workspace.path().join("fixtures"))
            .unwrap();
        assert!(
            validate_outputs(
                workspace.path(),
                Path::new("fixtures/state.json"),
                &"a".repeat(40),
                Phase::Prepare,
                &"b".repeat(40),
                "v0.2.0-pre.1",
            )
            .is_err()
        );
    }

    #[test]
    fn integration_state_cannot_retarget_outside_the_scratch_repository() {
        let sha = "a".repeat(40);
        let fixture = PullRequestFixture {
            number: 17,
            branch: format!("{BRANCH_PREFIX}test"),
            head_sha: sha.clone(),
            url: format!(
                "https://github.com/{}/pull/17",
                integration_repository().unwrap()
            ),
        };
        let mut scenario = Scenario {
            version: STATE_VERSION,
            repository: integration_repository().unwrap().into(),
            repository_id: integration_repository_id().unwrap(),
            candidate_sha: sha.clone(),
            published_runtime_sha: "f".repeat(40),
            workflow_sha: "b".repeat(40),
            default_branch: "main".into(),
            base_sha: sha.clone(),
            prepared_at: Utc::now(),
            positive: fixture.clone(),
            stale: PullRequestFixture {
                number: 18,
                ..fixture.clone()
            },
            distribution: PullRequestFixture {
                number: 19,
                ..fixture
            },
        };
        assert!(validate_scenario(&scenario, &sha, &scenario.published_runtime_sha).is_ok());
        assert!(validate_scenario(&scenario, &sha, &"e".repeat(40)).is_err());
        scenario.repository = server_repository().unwrap().into();
        assert!(validate_scenario(&scenario, &sha, &scenario.published_runtime_sha).is_err());
    }

    #[test]
    fn artifact_manifest_loader_rejects_zip_path_traversal() {
        verify_artifact_path_safety().unwrap();
    }

    #[test]
    fn fixture_state_zip_requires_one_safe_state_json_entry() {
        let scenario = Scenario {
            version: STATE_VERSION,
            repository: integration_repository().unwrap().into(),
            repository_id: integration_repository_id().unwrap(),
            candidate_sha: "a".repeat(40),
            published_runtime_sha: "d".repeat(40),
            workflow_sha: "c".repeat(40),
            default_branch: "main".into(),
            base_sha: "b".repeat(40),
            prepared_at: Utc::now(),
            positive: fixture(17),
            stale: fixture(18),
            distribution: fixture(19),
        };
        let encoded = serde_json::to_vec(&scenario).unwrap();
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        archive
            .start_file("state.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        use std::io::Write;
        archive.write_all(&encoded).unwrap();
        assert_eq!(
            scenario_from_zip(&archive.finish().unwrap().into_inner())
                .unwrap()
                .candidate_sha,
            scenario.candidate_sha
        );

        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        archive
            .start_file("../state.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(&encoded).unwrap();
        assert!(scenario_from_zip(&archive.finish().unwrap().into_inner()).is_err());
    }

    fn fixture(number: u64) -> PullRequestFixture {
        PullRequestFixture {
            number,
            branch: format!("{BRANCH_PREFIX}{number}"),
            head_sha: "c".repeat(40),
            url: format!(
                "https://github.com/{}/pull/{number}",
                integration_repository().unwrap()
            ),
        }
    }
}
