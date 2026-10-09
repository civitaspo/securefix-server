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
    api::{ApiError, GitHub, SCRATCH_REPOSITORY, SCRATCH_REPOSITORY_ID},
    policy::{Capability, Policy, ReleaseStrategy, validate_sha},
    workflow,
};

const OWNER_ID: u64 = 4_525_500;
const SERVER_REPOSITORY_ID: u64 = 1_250_079_425;
const WORKFLOW_PATH: &str = ".github/workflows/testing-securefix-server.yml";
const FIX_PATH_PREFIX: &str = ".securefix-integration/";
const BRANCH_PREFIX: &str = "securefix-integration-";
const STATE_VERSION: u32 = 1;

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
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Phase {
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

pub fn run(command: Command) -> Result<()> {
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
    }
}

fn fetch_state(candidate_sha: &str, run_id: u64, state_file: &Path) -> Result<()> {
    ensure!(run_id > 0, "invalid fixture workflow run ID");
    let token = std::env::var("GITHUB_TOKEN").context("missing GITHUB_TOKEN")?;
    ensure!(!token.is_empty(), "GITHUB_TOKEN is empty");
    let api = GitHub::new("https://api.github.com", token)?;
    let run: Value = api.get(&format!(
        "/repos/{}/actions/runs/{run_id}",
        securefix::policy::SERVER
    ))?;
    let artifacts: Value = api.get(&format!(
        "/repos/{}/actions/runs/{run_id}/artifacts",
        securefix::policy::SERVER
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
            securefix::policy::SERVER
        ),
        64 * 1024,
    )?;
    let scenario = scenario_from_zip(&bytes)?;
    validate_scenario(&scenario, candidate_sha)?;
    let server_repo: Value = api.get(&format!("/repos/{}", securefix::policy::SERVER))?;
    ensure!(
        run["id"].as_u64() == Some(run_id)
            && run["repository"]["full_name"] == securefix::policy::SERVER
            && run["repository"]["id"].as_u64() == Some(SERVER_REPOSITORY_ID)
            && run["head_repository"]["id"].as_u64() == Some(SERVER_REPOSITORY_ID)
            && server_repo["id"].as_u64() == Some(SERVER_REPOSITORY_ID)
            && run["head_sha"] == scenario.workflow_sha
            && run["event"] == "workflow_dispatch"
            && run["run_attempt"] == 1
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && run["actor"]["id"].as_u64() == Some(OWNER_ID)
            && run["triggering_actor"]["id"].as_u64() == Some(OWNER_ID)
            && workflow_run_matches(&run, &scenario.workflow_sha),
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
    let workflow_ref = std::env::var("GITHUB_REF").context("missing GITHUB_REF")?;
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
            &workflow_sha,
        ),
        "integration producer branch is not trusted"
    );
    let encoded_branch = workflow_branch.replace('/', "%2F");
    let source: Value = GitHub::anonymous()?.get(&format!(
        "/repos/{}/commits/{encoded_branch}",
        securefix::policy::SERVER
    ))?;
    ensure!(
        source["sha"] == workflow_sha,
        "trusted integration workflow branch moved from its source SHA"
    );
    let server = GitHub::scratch_from_env("SECUREFIX_SERVER_TOKEN", candidate_sha)?;
    let _client = GitHub::scratch_from_env("SECUREFIX_CLIENT_TOKEN", candidate_sha)?;
    let repository: Value = server.get(&format!("/repos/{SCRATCH_REPOSITORY}"))?;
    ensure!(
        repository["full_name"] == SCRATCH_REPOSITORY
            && repository["id"].as_u64() == Some(SCRATCH_REPOSITORY_ID)
            && repository["owner"]["id"].as_u64() == Some(OWNER_ID),
        "scratch repository identity changed"
    );
    let default_branch = repository["default_branch"]
        .as_str()
        .context("scratch repository has no default branch")?
        .to_owned();
    let base: Value = server.get(&format!(
        "/repos/{SCRATCH_REPOSITORY}/commits/{default_branch}"
    ))?;
    let base_sha = base["sha"]
        .as_str()
        .context("scratch default branch has no SHA")?
        .to_owned();
    validate_sha(&base_sha)?;

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

    let rendered =
        crate::distribution::caller::rendered_files(candidate_sha, &default_branch, true)?;
    ensure!(
        !rendered.is_empty(),
        "distribution renderer returned no workflows"
    );
    let distribution = create_pr(
        &server,
        &base_sha,
        &default_branch,
        &format!("{BRANCH_PREFIX}distribution-{nonce}"),
        &format!(
            "test: Securefix distribution integration {}",
            &candidate_sha[..12]
        ),
        rendered.clone(),
    )?;
    validate_rendered_files(&rendered)?;

    let state = Scenario {
        version: STATE_VERSION,
        repository: SCRATCH_REPOSITORY.to_owned(),
        repository_id: SCRATCH_REPOSITORY_ID,
        candidate_sha: candidate_sha.to_owned(),
        workflow_sha,
        default_branch,
        base_sha,
        prepared_at: Utc::now(),
        positive,
        stale,
        distribution,
    };
    validate_scenario(&state, candidate_sha)?;
    workflow::write_json(state_file, &state)?;
    println!("Prepared Securefix scratch integration state.");
    println!(
        "Positive PR (post exact owner /approve and /merge; obtain a current non-author bot approval): {}",
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
        &format!("/repos/{SCRATCH_REPOSITORY}/git/refs"),
        &json!({"ref":format!("refs/heads/{branch}"),"sha":base_sha}),
    )?;
    let message = format!("{title}\n\nCandidate: {base_sha}");
    let head_sha = api.create_commit(
        SCRATCH_REPOSITORY,
        branch,
        base_sha,
        &message,
        files,
        deletions,
    )?;
    let pull: Value = api.post(
        &format!("/repos/{SCRATCH_REPOSITORY}/pulls"),
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
        repository: SCRATCH_REPOSITORY,
        run_id: fix.run_id,
        label: &label,
        branch,
        sha: candidate_sha,
    };
    let plan = crate::securefix_gate::FixPlan {
        version: 1,
        source_repository: SCRATCH_REPOSITORY.to_owned(),
        source_run_id: fix.run_id,
        source_sha: candidate_sha.to_owned(),
        artifact_name: label.clone(),
        artifact_id: 1,
        destination_repository: SCRATCH_REPOSITORY.to_owned(),
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
        server_repository: SCRATCH_REPOSITORY,
        server_run: "integration",
    })?;
    ensure!(
        !first.already_applied && first.pull_request_number.is_some(),
        "nativefix first apply did not create the signed commit and pull request"
    );
    let commit: Value = api.get(&format!(
        "/repos/{SCRATCH_REPOSITORY}/commits/{}",
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
        SCRATCH_REPOSITORY,
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
        server_repository: SCRATCH_REPOSITORY,
        server_run: "integration",
    })?;
    ensure!(
        retry.already_applied
            && retry.commit_sha == first.commit_sha
            && retry.pull_request_number == Some(pr_number),
        "nativefix retry was not idempotent"
    );
    let pull: Value = api.get(&format!("/repos/{SCRATCH_REPOSITORY}/pulls/{pr_number}"))?;
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
            "repository":{"full_name":SCRATCH_REPOSITORY}
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
        .env("GITHUB_REPOSITORY", SCRATCH_REPOSITORY)
        .env("GITHUB_RUN_ID", run_id.to_string())
        .env("GITHUB_RUN_ATTEMPT", "1")
        .env("GITHUB_SHA", candidate_sha)
        .env("GITHUB_SERVER_URL", "https://github.com")
        .env("GITHUB_REF", format!("refs/heads/{branch}"))
        .env("GITHUB_EVENT_NAME", "workflow_dispatch")
        .env("GITHUB_ACTOR", "civitaspo")
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
            SCRATCH_REPOSITORY,
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
        SCRATCH_REPOSITORY,
        run_id,
        candidate_sha,
        branch,
    )?;
    ensure!(
        fix.repository == SCRATCH_REPOSITORY
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

fn verify(candidate_sha: &str, state_file: &Path, timeout_seconds: u64) -> Result<()> {
    let metadata = fs::metadata(state_file).context("read integration state file metadata")?;
    ensure!(
        metadata.len() <= 16 * 1024,
        "integration state file exceeds size limit"
    );
    let scenario: Scenario =
        serde_json::from_slice(&fs::read(state_file).context("read integration state file")?)
            .context("parse integration state file")?;
    validate_scenario(&scenario, candidate_sha)?;
    let server = GitHub::scratch_from_env("SECUREFIX_SERVER_TOKEN", candidate_sha)?;
    let _client = GitHub::scratch_from_env("SECUREFIX_CLIENT_TOKEN", candidate_sha)?;
    let policy = scratch_policy(candidate_sha)?;
    verify_remote_identity(&server, &scenario)?;

    let result = verify_inner(&server, &policy, &scenario, timeout_seconds);
    let cleanup = cleanup(&server, &scenario);
    match (result, cleanup) {
        (Ok(verification), Ok(())) => {
            workflow::write_json(state_file, &verification)?;
            println!("Verified native scratch integration; all fixtures were merged or closed.");
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

    request::validate_pr_authorization(
        api,
        policy,
        SCRATCH_REPOSITORY,
        scenario.positive.number,
        &scenario.positive.head_sha,
        true,
    )?;
    let approve_comment_id = approve_comment["id"]
        .as_u64()
        .context("owner approval comment has no ID")?;
    request::post_owner_marker(
        api,
        SCRATCH_REPOSITORY,
        scenario.positive.number,
        &scenario.positive.head_sha,
        approve_comment_id,
    )?;
    request::require_owner_marker(
        api,
        policy,
        SCRATCH_REPOSITORY,
        scenario.positive.number,
        &scenario.positive.head_sha,
    )?;
    policy_check::publish(
        api,
        SCRATCH_REPOSITORY,
        &scenario.positive.head_sha,
        true,
        "Integration fixture passed production PR authorization checks.",
    )?;
    validate_signed_pr(api, policy, &scenario.distribution)?;
    verify_rendered_files(
        api,
        &scenario.distribution,
        &scenario.default_branch,
        &scenario.candidate_sha,
    )?;
    let files = crate::distribution::caller::rendered_files(
        &scenario.candidate_sha,
        &scenario.default_branch,
        true,
    )?;
    validate_rendered_files(&files)?;

    wait_for_current_head_approval(api, &scenario.positive, deadline)?;
    let positive_manifest = manifest(
        scenario,
        &scenario.positive,
        &positive_merge_comment,
        &scenario.candidate_sha,
    )?;
    merge::validate_state(api, policy, &positive_manifest)?;
    ensure!(
        merge::ready(api, &positive_manifest)?,
        "scratch positive PR lacks required checks or approved review"
    );
    let merged: Value = api.put(
        &format!("/repos/{SCRATCH_REPOSITORY}/pulls/{}/merge", scenario.positive.number),
        &json!({"sha":scenario.positive.head_sha,"merge_method":"squash","commit_message":format!("Securefix integration test for {}", scenario.candidate_sha)}),
    )?;
    ensure!(
        merged["merged"] == true,
        "GitHub did not confirm the scratch squash merge"
    );
    let merged_sha = merged["sha"]
        .as_str()
        .context("merge response lacks SHA")?
        .to_owned();
    validate_sha(&merged_sha)?;
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
        SCRATCH_REPOSITORY,
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
    let stale_head_sha = api.create_commit(
        SCRATCH_REPOSITORY,
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
    ensure!(
        request::validate_pr_authorization(
            api,
            policy,
            SCRATCH_REPOSITORY,
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
    let stale_merge = api.put::<Value>(
        &format!(
            "/repos/{SCRATCH_REPOSITORY}/pulls/{}/merge",
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

    verify_artifact_path_safety()?;
    ensure!(
        !files.is_empty(),
        "distribution output disappeared during verification"
    );
    let managed_files = files.keys().cloned().collect::<Vec<_>>();
    Ok(Verification {
        version: STATE_VERSION,
        repository: SCRATCH_REPOSITORY.to_owned(),
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

fn verify_disposable_release_tag(
    api: &GitHub,
    fixture: &PullRequestFixture,
    candidate_sha: &str,
    merged_sha: &str,
) -> Result<()> {
    use crate::release::{CommitSha, ReleaseTag, Repository};

    let repository = Repository::parse(SCRATCH_REPOSITORY)?;
    let target = CommitSha::parse(merged_sha)?;
    let tag = ReleaseTag::parse(&format!(
        "v0.0.0-securefix-integration.{}.{}",
        fixture.number,
        &candidate_sha[..12]
    ))?;
    crate::release::create_annotated_tag(api, &repository, &tag, &target)?;
    let verification = (|| {
        let ref_path = format!("/repos/{SCRATCH_REPOSITORY}/git/ref/tags/{}", tag.as_str());
        let reference: Value = api.get(&ref_path)?;
        ensure!(
            reference["object"]["type"] == "tag",
            "scratch release helper created a lightweight tag"
        );
        let object_sha = reference["object"]["sha"]
            .as_str()
            .context("scratch annotated tag ref lacks an object SHA")?;
        let object: Value = api.get(&format!(
            "/repos/{SCRATCH_REPOSITORY}/git/tags/{object_sha}"
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
    let ref_path = format!("/repos/{SCRATCH_REPOSITORY}/git/refs/tags/{}", tag.as_str());
    let cleanup = api.delete(&ref_path);
    match (verification, cleanup) {
        (Err(error), _) => Err(error).context("verify disposable scratch release tag"),
        (Ok(()), Err(error)) => Err(error).context("delete disposable scratch release tag"),
        (Ok(()), Ok(())) => {
            let absent = api.get::<Value>(&format!(
                "/repos/{SCRATCH_REPOSITORY}/git/ref/tags/{}",
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

fn validate_signed_pr(api: &GitHub, policy: &Policy, fixture: &PullRequestFixture) -> Result<()> {
    request::validate_pr_authorization(
        api,
        policy,
        SCRATCH_REPOSITORY,
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
    candidate_sha: &str,
) -> Result<()> {
    let expected =
        crate::distribution::caller::rendered_files(candidate_sha, default_branch, true)?;
    validate_rendered_files(&expected)?;
    for (path, expected_bytes) in expected {
        let actual = api.content(SCRATCH_REPOSITORY, &path, &fixture.head_sha)?;
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
    Ok(())
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
            "/repos/{SCRATCH_REPOSITORY}/issues/{}/comments",
            fixture.number
        ))?;
        let matches = comments
            .into_iter()
            .filter(|comment| {
                comment["user"]["id"].as_u64() == Some(OWNER_ID)
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

fn wait_for_current_head_approval(
    api: &GitHub,
    fixture: &PullRequestFixture,
    deadline: Instant,
) -> Result<()> {
    loop {
        if request::has_current_head_approval(
            api,
            SCRATCH_REPOSITORY,
            fixture.number,
            &fixture.head_sha,
        )? {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "timed out waiting for a non-author approval on the current head of {}",
            fixture.url
        );
        thread::sleep(remaining.min(Duration::from_secs(5)));
    }
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
        "/repos/{SCRATCH_REPOSITORY}/pulls/{}",
        fixture.number
    ))?;
    ensure!(
        pull["state"] == "open"
            && pull["base"]["repo"]["full_name"] == SCRATCH_REPOSITORY
            && pull["base"]["ref"] == base
            && pull["head"]["repo"]["full_name"] == SCRATCH_REPOSITORY
            && pull["head"]["ref"] == fixture.branch
            && pull["head"]["sha"] == expected_head,
        "scratch pull request changed after preparation"
    );
    Ok(())
}

fn verify_remote_identity(api: &GitHub, scenario: &Scenario) -> Result<()> {
    let repo: Value = api.get(&format!("/repos/{}", scenario.repository))?;
    ensure!(
        scenario.repository == SCRATCH_REPOSITORY
            && scenario.repository_id == SCRATCH_REPOSITORY_ID
            && repo["full_name"] == SCRATCH_REPOSITORY
            && repo["id"].as_u64() == Some(SCRATCH_REPOSITORY_ID),
        "integration state is not bound to the dedicated scratch repository"
    );
    Ok(())
}

fn cleanup(api: &GitHub, scenario: &Scenario) -> Result<()> {
    for fixture in [&scenario.positive, &scenario.stale, &scenario.distribution] {
        let pull: Value = api.get(&format!(
            "/repos/{SCRATCH_REPOSITORY}/pulls/{}",
            fixture.number
        ))?;
        if pull["state"] == "open" {
            let _: Value = api.patch(
                &format!("/repos/{SCRATCH_REPOSITORY}/pulls/{}", fixture.number),
                &json!({"state":"closed"}),
            )?;
        }
        validate_branch(&fixture.branch)?;
        match api.delete(&format!(
            "/repos/{SCRATCH_REPOSITORY}/git/refs/heads/{}",
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

fn validate_scenario(scenario: &Scenario, candidate_sha: &str) -> Result<()> {
    ensure!(
        scenario.version == STATE_VERSION
            && scenario.repository == SCRATCH_REPOSITORY
            && scenario.repository_id == SCRATCH_REPOSITORY_ID
            && scenario.candidate_sha == candidate_sha,
        "integration state identity mismatch"
    );
    validate_sha(&scenario.candidate_sha)?;
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
                && fixture
                    .url
                    .starts_with("https://github.com/civitaspo/testing-securefix-server/pull/"),
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

fn workflow_run_matches(run: &Value, workflow_sha: &str) -> bool {
    let expected_branch = format!("integration/native-{}", &workflow_sha[..12]);
    let path = run["path"].as_str().unwrap_or_default();
    let (workflow_path, reference) = path.split_once('@').unwrap_or((path, ""));
    workflow_path == WORKFLOW_PATH
        && run["head_sha"] == workflow_sha
        && run["head_branch"]
            .as_str()
            .is_some_and(|branch| branch == "main" || branch == expected_branch)
        && (reference.is_empty()
            || reference == "refs/heads/main"
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
    let mut policy = Policy::parse(include_bytes!("../policy.json"))?;
    policy.repositories = vec![securefix::policy::RepositoryPolicy {
        repository: SCRATCH_REPOSITORY.to_owned(),
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
            .repository(SCRATCH_REPOSITORY)?
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
    fn scratch_policy_is_narrowed_to_one_repository_and_candidate_revision() {
        let revision = "a".repeat(40);
        let policy = scratch_policy(&revision).unwrap();
        assert_eq!(policy.repositories.len(), 1);
        assert_eq!(policy.repositories[0].repository, SCRATCH_REPOSITORY);
        assert_eq!(policy.revision, revision);
        assert!(policy.repository("civitaspo/securefix-server").is_err());
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
        let run = json!({
            "head_sha":sha,
            "head_branch":"main",
            "path":".github/workflows/testing-securefix-server.yml@refs/heads/main"
        });
        assert!(workflow_run_matches(&run, &sha));
        let mut wrong_branch = run.clone();
        wrong_branch["head_branch"] = json!("feature/untrusted");
        assert!(!workflow_run_matches(&wrong_branch, &sha));
        let frozen = format!("integration/native-{}", &sha[..12]);
        let frozen_run = json!({
            "head_sha":sha,
            "head_branch":frozen,
            "path":format!("{WORKFLOW_PATH}@refs/heads/{frozen}")
        });
        assert!(workflow_run_matches(&frozen_run, &sha));
    }

    #[test]
    fn state_path_rejects_absolute_and_parent_traversal() {
        assert!(validate_state_path(Path::new("fixtures/state.json")).is_ok());
        assert!(validate_state_path(Path::new("../state.json")).is_err());
        assert!(validate_state_path(Path::new("/tmp/state.json")).is_err());
    }

    #[test]
    fn integration_state_cannot_retarget_outside_the_scratch_repository() {
        let sha = "a".repeat(40);
        let fixture = PullRequestFixture {
            number: 17,
            branch: format!("{BRANCH_PREFIX}test"),
            head_sha: sha.clone(),
            url: "https://github.com/civitaspo/testing-securefix-server/pull/17".into(),
        };
        let mut scenario = Scenario {
            version: STATE_VERSION,
            repository: SCRATCH_REPOSITORY.into(),
            repository_id: SCRATCH_REPOSITORY_ID,
            candidate_sha: sha.clone(),
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
        assert!(validate_scenario(&scenario, &sha).is_ok());
        scenario.repository = "civitaspo/securefix-server".into();
        assert!(validate_scenario(&scenario, &sha).is_err());
    }

    #[test]
    fn artifact_manifest_loader_rejects_zip_path_traversal() {
        verify_artifact_path_safety().unwrap();
    }

    #[test]
    fn fixture_state_zip_requires_one_safe_state_json_entry() {
        let scenario = Scenario {
            version: STATE_VERSION,
            repository: SCRATCH_REPOSITORY.into(),
            repository_id: SCRATCH_REPOSITORY_ID,
            candidate_sha: "a".repeat(40),
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
            url: format!("https://github.com/{SCRATCH_REPOSITORY}/pull/{number}"),
        }
    }
}
