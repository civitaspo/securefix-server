use anyhow::{Context, Result, ensure};
use base64::Engine;
use clap::Subcommand;
use securefix::{
    api::{ApiError, CommitAddition, CommitOnBranch, GitHub},
    event, output,
    policy::{Capability, Policy, SERVER, validate_repository, validate_sha},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, io::Read};

const CLIENT_BOT_ID: u64 = 288_068_203;
const OWNER_ID: u64 = 4_525_500;
const LABEL_PREFIX: &str = "securefix-";
const CLIENT_CI_WORKFLOW: &str = ".github/workflows/pull_request.yml";
const RELEASE_PR_WORKFLOW: &str = ".github/workflows/release-pr.yml";
const REUSABLE_RELEASE_PR: &str = ".github/workflows/reusable-release-pr.yml";
const SOURCE_ARCHIVE: &str = "securefix-source-artifact.zip";
const SOURCE_PLAN: &str = "securefix-source-plan.json";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidatedSource {
    repository: String,
    run_id: u64,
    label: String,
    run_sha: String,
    source_branch: String,
    default_branch: String,
    destination_branch: String,
    expected_destination_head: String,
    destination_was_absent: bool,
    artifact_id: u64,
    archive_sha256: String,
    files: Vec<String>,
    metadata: Value,
    pull_request_number: Option<u64>,
}

#[derive(Subcommand)]
pub enum Command {
    ValidateEvent,
    ValidateSource,
    Apply,
    Cleanup,
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::ValidateEvent => validate_event(),
        Command::ValidateSource => validate_source(),
        Command::Apply => apply(),
        Command::Cleanup => cleanup(),
    }
}

fn policy(api: &GitHub) -> Result<Policy> {
    let p = Policy::active(api)?;
    let source = std::env::var("SECUREFIX_SOURCE_SHA")?;
    ensure!(source == p.revision, "runtime revision is not current");
    Ok(p)
}

fn validate_event() -> Result<()> {
    let api = GitHub::from_env("GITHUB_TOKEN")?;
    let p = policy(&api)?;
    let payload = event()?;
    let repo = std::env::var("GITHUB_REPOSITORY")?;
    let (source_repo, run_id, label) = parse_label_event(&p, &payload, &repo)?;
    output("source_repository", source_repo)?;
    output("source_run_id", run_id.to_string())?;
    output("source_label", label)?;
    Ok(())
}

fn parse_label_event(p: &Policy, payload: &Value, repo: &str) -> Result<(String, u64, String)> {
    validate_repository(repo)?;
    ensure!(
        repo.eq_ignore_ascii_case(SERVER)
            && payload["repository"]["full_name"] == repo
            && payload["repository"]["owner"]["id"].as_u64() == Some(OWNER_ID),
        "unexpected event repository"
    );
    ensure!(
        payload["sender"]["id"].as_u64() == Some(CLIENT_BOT_ID)
            && payload["sender"]["type"] == "Bot",
        "label was not created by Securefix Client"
    );
    let label = payload["label"]["name"].as_str().context("missing label")?;
    ensure!(
        label.starts_with(LABEL_PREFIX) && label.len() <= 50,
        "invalid Securefix label"
    );
    let description = payload["label"]["description"]
        .as_str()
        .context("missing label locator")?;
    let (source_repo, run) = description
        .rsplit_once('/')
        .context("label locator must be owner/repository/run_id")?;
    validate_repository(source_repo)?;
    let run_id: u64 = run.parse().context("invalid source run ID")?;
    ensure!(
        run_id > 0
            && label[LABEL_PREFIX.len()..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid Securefix artifact label"
    );
    let capability = p.repository(source_repo)?;
    capability.require(Capability::Securefix)?;
    Ok((source_repo.to_owned(), run_id, label.to_owned()))
}

fn cleanup() -> Result<()> {
    let api = GitHub::from_env("GITHUB_TOKEN")?;
    let p = policy(&api)?;
    let payload = event()?;
    let repo = std::env::var("GITHUB_REPOSITORY")?;
    let (_, _, label) = parse_label_event(&p, &payload, &repo)?;
    match api.delete(&format!("/repos/{SERVER}/labels/{label}")) {
        Ok(()) => Ok(()),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|api_error| api_error.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn validate_source() -> Result<()> {
    let api = GitHub::from_env("SECUREFIX_READ_TOKEN")?;
    let p = policy(&GitHub::from_env("GITHUB_TOKEN")?)?;
    let source_repo = std::env::var("SOURCE_REPOSITORY")?;
    let run_id: u64 = std::env::var("SOURCE_RUN_ID")?.parse()?;
    let label = std::env::var("SOURCE_LABEL")?;
    validate_repository(&source_repo)?;
    p.repository(&source_repo)?.require(Capability::Securefix)?;
    let run = securefix::workflow::successful_source_run(&api, &source_repo, run_id)?;
    ensure!(
        run["repository"]["full_name"] == source_repo,
        "source run repository mismatch"
    );
    ensure!(
        run["path"].as_str().is_some_and(allowed_source_workflow),
        "source run is not an approved workflow"
    );
    ensure!(
        run["head_branch"]
            .as_str()
            .is_some_and(|b| !b.is_empty() && b.len() <= 255),
        "source run branch is invalid"
    );
    let repo_data: Value = api.get(&format!("/repos/{source_repo}"))?;
    let source_branch = run["head_branch"]
        .as_str()
        .context("source branch missing")?;
    let source_default = repo_data["default_branch"]
        .as_str()
        .context("default branch missing")?;
    if source_branch == source_default {
        ensure!(
            run["path"] == RELEASE_PR_WORKFLOW,
            "default-branch Securefix runs are limited to the release PR workflow"
        );
        let caller_sha = run["head_sha"]
            .as_str()
            .context("source run has no caller SHA")?;
        validate_sha(caller_sha)?;
        let current_default: Value =
            api.get(&format!("/repos/{source_repo}/commits/{source_default}"))?;
        let current_default_sha = current_default["sha"]
            .as_str()
            .context("client default branch has no SHA")?;
        let ancestry: Value = api.get(&format!(
            "/repos/{source_repo}/compare/{caller_sha}...{current_default_sha}"
        ))?;
        ensure!(
            matches!(ancestry["status"].as_str(), Some("ahead" | "identical")),
            "release PR caller is not on default-branch history"
        );
        let wrapper = api.content(&source_repo, RELEASE_PR_WORKFLOW, caller_sha)?;
        securefix::workflow::require_reusable_pin(&wrapper, REUSABLE_RELEASE_PR, &p.revision)?;
        let referenced: Vec<securefix::workflow::ReferencedWorkflow> =
            serde_json::from_value(run["referenced_workflows"].clone())
                .context("release PR run lacks reusable workflow provenance")?;
        securefix::workflow::referenced_revision(&referenced, REUSABLE_RELEASE_PR, &p.revision)?;
    } else {
        ensure!(
            run["path"] == CLIENT_CI_WORKFLOW && run["event"] == "pull_request",
            "client PR fixes must come from the pull-request CI workflow"
        );
    }
    let sha = run["head_sha"]
        .as_str()
        .context("source run has no head SHA")?;
    validate_sha(sha)?;
    let artifacts: Value = api.get(&format!(
        "/repos/{source_repo}/actions/runs/{run_id}/artifacts"
    ))?;
    let artifacts = artifacts["artifacts"]
        .as_array()
        .context("source artifacts missing")?;
    let matches = artifacts
        .iter()
        .filter(|a| {
            a["name"] == label
                && a["expired"] == false
                && a["size_in_bytes"]
                    .as_u64()
                    .is_some_and(|s| s <= 64 * 1024 * 1024)
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "source run must have exactly one eligible Securefix artifact"
    );
    let artifact_id = matches[0]["id"].as_u64().context("artifact ID missing")?;
    let archive = api.download(
        &format!("/repos/{source_repo}/actions/artifacts/{artifact_id}/zip"),
        64 * 1024 * 1024,
    )?;
    let (source_files, source_metadata) = artifact_files(&archive, &label)?;
    ensure!(
        source_metadata["context"]["payload"]["repository"]["full_name"] == source_repo,
        "Securefix metadata belongs to a different client repository"
    );
    let pull_request_number = if source_branch != source_default {
        let number = source_metadata["context"]["payload"]["pull_request"]["number"]
            .as_u64()
            .context("CI artifact metadata has no pull request number")?;
        let pr: Value = api.get(&format!("/repos/{source_repo}/pulls/{number}"))?;
        ensure!(
            source_pr_matches(
                &pr,
                &source_repo,
                source_default,
                source_branch,
                run["head_sha"]
                    .as_str()
                    .context("source run has no head SHA")?,
            ),
            "metadata pull request is no longer a matching open same-repository PR"
        );
        Some(number)
    } else {
        None
    };
    validate_securefix_metadata(&source_metadata, source_default)?;
    let (_, destination_repository, destination_branch) =
        metadata_destination(&source_metadata, &source_repo, source_branch)?;
    ensure!(
        destination_repository.eq_ignore_ascii_case(&source_repo)
            && destination_allowed(source_branch, source_default, destination_branch),
        "Securefix destination is outside the source repository or allowed branch"
    );
    ensure!(
        destination_branch != source_default,
        "Securefix may not directly update a default branch"
    );
    let destination_head = branch_head(&api, &source_repo, destination_branch)?;
    let source_sha = run["head_sha"].as_str().context("source run SHA missing")?;
    let (expected_destination_head, destination_was_absent) = if source_branch == source_default {
        match destination_head {
            Some(head) => (head, false),
            None => (source_sha.to_owned(), true),
        }
    } else {
        let head = destination_head.context("source branch does not exist")?;
        ensure!(
            head == source_sha,
            "source branch has advanced beyond this workflow run"
        );
        (head, false)
    };
    let archive_sha256 = format!("{:x}", Sha256::digest(&archive));
    let plan = ValidatedSource {
        repository: source_repo.clone(),
        run_id,
        label: label.clone(),
        run_sha: source_sha.to_owned(),
        source_branch: source_branch.to_owned(),
        default_branch: source_default.to_owned(),
        destination_branch: destination_branch.to_owned(),
        expected_destination_head,
        destination_was_absent,
        artifact_id,
        archive_sha256,
        files: source_files,
        metadata: source_metadata,
        pull_request_number,
    };
    fs::write(SOURCE_ARCHIVE, &archive)?;
    fs::write(SOURCE_PLAN, serde_json::to_vec(&plan)?)?;
    output("source_sha", sha)?;
    output("source_artifact_id", artifact_id.to_string())?;
    output("source_workflow", run["name"].as_str().unwrap_or_default())?;
    Ok(())
}

fn apply() -> Result<()> {
    let read_api = GitHub::from_env("SECUREFIX_READ_TOKEN")?;
    let p = policy(&GitHub::from_env("GITHUB_TOKEN")?)?;
    let plan: ValidatedSource =
        serde_json::from_slice(&fs::read(SOURCE_PLAN)?).context("invalid Securefix source plan")?;
    ensure!(
        plan.repository == std::env::var("SOURCE_REPOSITORY")?
            && plan.run_id == std::env::var("SOURCE_RUN_ID")?.parse::<u64>()?
            && plan.label == std::env::var("SOURCE_LABEL")?,
        "Securefix source plan does not match the triggering label"
    );
    p.repository(&plan.repository)?
        .require(Capability::Securefix)?;

    let archive = fs::read(SOURCE_ARCHIVE)?;
    ensure!(
        format!("{:x}", Sha256::digest(&archive)) == plan.archive_sha256,
        "staged Securefix artifact changed after validation"
    );
    let (files, metadata) = artifact_files(&archive, &plan.label)?;
    ensure!(
        files == plan.files && metadata == plan.metadata,
        "staged Securefix artifact differs from validated plan"
    );
    validate_securefix_metadata(&metadata, &plan.default_branch)?;
    let (_, destination_repository, destination_branch) =
        metadata_destination(&metadata, &plan.repository, &plan.source_branch)?;
    ensure!(
        destination_repository.eq_ignore_ascii_case(&plan.repository)
            && destination_branch == plan.destination_branch
            && destination_allowed(
                &plan.source_branch,
                &plan.default_branch,
                &plan.destination_branch
            )
            && plan.destination_branch != plan.default_branch,
        "source plan destination differs from validated metadata"
    );
    let changes = artifact_changes(&archive, &plan.label, &files)?;

    revalidate_source(&read_api, &p, &plan)?;
    validate_artifact_id(&read_api, &plan)?;
    let write_api = GitHub::from_env("SECUREFIX_WRITE_TOKEN")?;
    validate_write_installation(&write_api, &plan.repository)?;

    let commit_sha = commit_validated_source(
        &read_api,
        &write_api,
        &plan,
        commit_headline(&metadata)?,
        format!(
            "Securefix source run: {}/{}/actions/runs/{}",
            std::env::var("GITHUB_SERVER_URL").unwrap_or_else(|_| "https://github.com".into()),
            plan.repository,
            plan.run_id
        ),
        changes.0,
        changes.1,
    )?;
    create_pull_request_if_requested(&write_api, &plan, &metadata)?;
    output("commit_sha", commit_sha)?;
    Ok(())
}

fn revalidate_source(api: &GitHub, policy: &Policy, plan: &ValidatedSource) -> Result<()> {
    let run = securefix::workflow::successful_source_run(api, &plan.repository, plan.run_id)?;
    ensure!(
        run["repository"]["full_name"] == plan.repository
            && run["head_sha"] == plan.run_sha
            && run["head_branch"] == plan.source_branch
            && run["path"].as_str().is_some_and(allowed_source_workflow),
        "source workflow run changed after validation"
    );
    let repo: Value = api.get(&format!("/repos/{}", plan.repository))?;
    ensure!(
        repo["default_branch"] == plan.default_branch,
        "client default branch changed after validation"
    );
    if plan.source_branch == plan.default_branch {
        ensure!(
            run["path"] == RELEASE_PR_WORKFLOW,
            "invalid release PR source workflow"
        );
        let current_default = branch_head(api, &plan.repository, &plan.default_branch)?;
        ensure!(
            current_default.as_deref() == Some(plan.run_sha.as_str()),
            "release run is no longer the current default-branch head"
        );
        let wrapper = api.content(&plan.repository, RELEASE_PR_WORKFLOW, &plan.run_sha)?;
        securefix::workflow::require_reusable_pin(&wrapper, REUSABLE_RELEASE_PR, &policy.revision)?;
        let referenced: Vec<securefix::workflow::ReferencedWorkflow> =
            serde_json::from_value(run["referenced_workflows"].clone())
                .context("release PR run lacks reusable workflow provenance")?;
        securefix::workflow::referenced_revision(
            &referenced,
            REUSABLE_RELEASE_PR,
            &policy.revision,
        )?;
    } else {
        ensure!(
            run["path"] == CLIENT_CI_WORKFLOW && run["event"] == "pull_request",
            "invalid Securefix CI source workflow"
        );
        let number = plan
            .pull_request_number
            .context("CI source plan has no pull request")?;
        let pr: Value = api.get(&format!("/repos/{}/pulls/{number}", plan.repository))?;
        ensure!(
            source_pr_matches(
                &pr,
                &plan.repository,
                &plan.default_branch,
                &plan.source_branch,
                &plan.run_sha
            ),
            "client pull request changed after validation"
        );
    }
    Ok(())
}

fn validate_artifact_id(api: &GitHub, plan: &ValidatedSource) -> Result<()> {
    let artifacts: Value = api.get(&format!(
        "/repos/{}/actions/runs/{}/artifacts",
        plan.repository, plan.run_id
    ))?;
    let artifacts = artifacts["artifacts"]
        .as_array()
        .context("source artifacts missing")?;
    let matches = artifacts
        .iter()
        .filter(|artifact| {
            artifact["id"].as_u64() == Some(plan.artifact_id)
                && artifact["name"] == plan.label
                && artifact["expired"] == false
                && artifact["size_in_bytes"]
                    .as_u64()
                    .is_some_and(|size| size <= 64 * 1024 * 1024)
        })
        .count();
    ensure!(
        matches == 1,
        "validated Securefix artifact is no longer available"
    );
    Ok(())
}

fn validate_write_installation(api: &GitHub, repository: &str) -> Result<()> {
    let installations: Value = api.get("/installation/repositories?per_page=100")?;
    let installed = installations["repositories"]
        .as_array()
        .context("write token has no repository scope")?;
    ensure!(
        installed.len() == 1
            && installed[0]["full_name"]
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(repository)),
        "Securefix write token must be scoped to exactly the source repository"
    );
    Ok(())
}

fn create_branch(api: &GitHub, plan: &ValidatedSource) -> Result<()> {
    let response: Value = api.post(
        &format!("/repos/{}/git/refs", plan.repository),
        &serde_json::json!({"ref":format!("refs/heads/{}", plan.destination_branch),"sha":plan.run_sha}),
    )?;
    ensure!(
        response["object"]["sha"] == plan.run_sha,
        "new release branch did not start at source run head"
    );
    Ok(())
}

fn commit_validated_source(
    read_api: &GitHub,
    write_api: &GitHub,
    plan: &ValidatedSource,
    headline: String,
    body: String,
    additions: Vec<CommitAddition>,
    deletions: Vec<String>,
) -> Result<String> {
    let current_destination = branch_head(read_api, &plan.repository, &plan.destination_branch)?;
    if plan.source_branch == plan.default_branch {
        ensure!(
            branch_head(read_api, &plan.repository, &plan.default_branch)?.as_deref()
                == Some(plan.run_sha.as_str()),
            "release source branch advanced after validation"
        );
    }
    if plan.destination_was_absent {
        ensure!(
            current_destination.is_none(),
            "destination branch appeared after source validation"
        );
        create_branch(write_api, plan)?;
    } else {
        ensure!(
            current_destination.as_deref() == Some(plan.expected_destination_head.as_str()),
            "destination branch advanced after source validation"
        );
    }
    write_api.create_commit_on_branch(&CommitOnBranch {
        repository: plan.repository.clone(),
        branch: plan.destination_branch.clone(),
        expected_head: plan.expected_destination_head.clone(),
        headline,
        body,
        additions,
        deletions,
    })
}

fn create_pull_request_if_requested(
    api: &GitHub,
    plan: &ValidatedSource,
    metadata: &Value,
) -> Result<()> {
    let Some(value) = pull_request_options(&metadata["inputs"]["pull_request"])? else {
        return Ok(());
    };
    let value = &value;
    let Some(request) = value.as_object() else {
        return Ok(());
    };
    let Some(title) = request
        .get("title")
        .and_then(Value::as_str)
        .filter(|title| !title.trim().is_empty())
    else {
        return Ok(());
    };
    let base = request["base"]
        .as_str()
        .context("pull request base missing")?;
    let head_query = encode_query_value(&format!("civitaspo:{}", plan.destination_branch));
    let base_query = encode_query_value(base);
    let existing: Vec<Value> = api.paginate(&format!(
        "/repos/{}/pulls?state=open&head={head_query}&base={base_query}",
        plan.repository
    ))?;
    ensure!(
        existing.iter().all(|pr| {
            pr["head"]["repo"]["full_name"] == plan.repository
                && pr["head"]["ref"] == plan.destination_branch
                && pr["base"]["ref"] == plan.default_branch
        }),
        "existing pull request does not match the validated destination"
    );
    if !existing.is_empty() {
        return Ok(());
    }
    let body = request
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let draft = request
        .get("draft")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let _: Value = api.post(
        &format!("/repos/{}/pulls", plan.repository),
        &serde_json::json!({"title":title,"body":body,"head":plan.destination_branch,"base":base,"draft":draft}),
    )?;
    Ok(())
}

fn pull_request_options(value: &Value) -> Result<Option<Value>> {
    if value.is_null() || value.as_str().is_some_and(str::is_empty) {
        return Ok(None);
    }
    let parsed = if let Some(text) = value.as_str() {
        serde_json::from_str::<Value>(text).context("invalid serialized pull request options")?
    } else {
        value.clone()
    };
    ensure!(parsed.is_object(), "invalid Securefix pull request options");
    Ok(Some(parsed))
}

fn validate_securefix_metadata(metadata: &Value, default_branch: &str) -> Result<()> {
    let inputs = metadata["inputs"]
        .as_object()
        .context("Securefix metadata inputs missing")?;
    let allowed = [
        "repository",
        "branch",
        "commit_message",
        "root_dir",
        "pull_request",
        "custom",
        "submodules",
    ];
    ensure!(
        inputs.keys().all(|key| allowed.contains(&key.as_str())),
        "Securefix metadata contains an unsupported input"
    );
    ensure!(
        metadata["context"]["payload"]["repository"]["full_name"]
            .as_str()
            .is_some(),
        "Securefix metadata repository missing"
    );
    if let Some(root) = inputs.get("root_dir") {
        ensure!(
            root.is_null() || root.as_str().is_some(),
            "invalid Securefix root directory metadata"
        );
    }
    if let Some(message) = inputs.get("commit_message") {
        ensure!(
            message
                .as_str()
                .is_some_and(|value| !value.trim().is_empty()
                    && value.len() <= 256
                    && !value.contains(['\r', '\n', '\0'])),
            "invalid Securefix commit message"
        );
    }
    ensure!(
        inputs
            .get("submodules")
            .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty)),
        "Securefix submodule changes are unsupported"
    );
    validate_pull_request(
        &metadata["inputs"]["pull_request"],
        default_branch,
        "release/next",
    )?;
    Ok(())
}

fn commit_headline(metadata: &Value) -> Result<String> {
    let headline = metadata["inputs"]["commit_message"]
        .as_str()
        .unwrap_or("Securefix");
    ensure!(
        !headline.trim().is_empty()
            && headline.len() <= 256
            && !headline.contains(['\r', '\n', '\0']),
        "invalid Securefix commit message"
    );
    Ok(headline.to_owned())
}

fn artifact_changes(
    bytes: &[u8],
    label: &str,
    files: &[String],
) -> Result<(Vec<CommitAddition>, Vec<String>)> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    let mut payloads = std::collections::BTreeMap::new();
    for index in 0..zip.len() {
        let entry = zip.by_index(index)?;
        let name = entry.name().to_owned();
        if name == format!("{label}_files.txt") || name == format!("{label}.json") {
            continue;
        }
        let declared_size = entry.size();
        ensure!(
            declared_size <= 16 * 1024 * 1024,
            "Securefix payload is too large"
        );
        let mut contents = Vec::new();
        entry
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut contents)?;
        ensure!(
            contents.len() as u64 == declared_size,
            "truncated Securefix payload"
        );
        ensure!(
            payloads.insert(name, contents).is_none(),
            "duplicate Securefix payload entry"
        );
    }
    let mut additions = Vec::new();
    let mut deletions = Vec::new();
    for path in files {
        if let Some(contents) = payloads.remove(path) {
            additions.push(CommitAddition {
                path: path.clone(),
                contents: base64::engine::general_purpose::STANDARD.encode(contents),
            });
        } else {
            deletions.push(path.clone());
        }
    }
    ensure!(
        payloads.is_empty(),
        "Securefix artifact has unlisted payload files"
    );
    Ok((additions, deletions))
}

fn branch_head(api: &GitHub, repository: &str, branch: &str) -> Result<Option<String>> {
    let path = format!(
        "/repos/{repository}/git/ref/heads{}",
        encode_path_value(branch)
    );
    match api.get::<Value>(&path) {
        Ok(reference) => {
            let sha = reference["object"]["sha"]
                .as_str()
                .context("branch ref has no target SHA")?
                .to_owned();
            validate_sha(&sha)?;
            Ok(Some(sha))
        }
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|e| e.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn encode_path_value(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    format!("%2F{encoded}")
}

fn encode_query_value(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !path.starts_with('/')
        && !path.contains(['\\', '\0'])
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn validate_pull_request(value: &Value, default_branch: &str, source_branch: &str) -> Result<()> {
    if value.is_null() || value.as_str().is_some_and(str::is_empty) {
        ensure!(!source_branch.is_empty(), "invalid source branch");
        return Ok(());
    }
    let parsed;
    let request = match value {
        Value::String(text) => {
            parsed = serde_json::from_str::<Value>(text)
                .context("invalid serialized pull request options")?;
            &parsed
        }
        value => value,
    };
    ensure!(
        request.is_object(),
        "invalid Securefix pull request options"
    );
    let map = request
        .as_object()
        .context("pull request options missing")?;
    let allowed = [
        "title",
        "body",
        "base",
        "draft",
        "labels",
        "assignees",
        "reviewers",
        "team_reviewers",
        "comment",
        "automerge_method",
        "project",
        "milestone_number",
    ];
    ensure!(
        map.keys().all(|key| allowed.contains(&key.as_str())),
        "Securefix pull request contains an unknown option"
    );
    if let Some(base) = request.get("base") {
        ensure!(
            base == default_branch,
            "Securefix pull request must target the default branch"
        );
    }
    for field in ["labels", "assignees", "reviewers", "team_reviewers"] {
        if let Some(values) = request.get(field) {
            ensure!(
                values.as_array().is_some_and(Vec::is_empty),
                "Securefix pull request cannot add {field}"
            );
        }
    }
    for field in ["comment", "automerge_method", "project", "milestone_number"] {
        if let Some(value) = request.get(field) {
            ensure!(
                value.is_null() || value.as_str() == Some(""),
                "Securefix pull request cannot set {field}"
            );
        }
    }
    if let Some(title) = request.get("title") {
        ensure!(
            title.as_str().is_some_and(|s| !s.trim().is_empty()),
            "invalid pull request title"
        );
    }
    if let Some(draft) = request.get("draft") {
        ensure!(draft.is_boolean(), "invalid pull request draft option");
    }
    ensure!(
        request.get("base").is_some(),
        "created pull request must specify its base branch"
    );
    ensure!(!source_branch.is_empty(), "invalid source branch");
    Ok(())
}

fn source_pr_matches(
    pull_request: &Value,
    repository: &str,
    default_branch: &str,
    run_branch: &str,
    run_sha: &str,
) -> bool {
    pull_request["state"] == "open"
        && pull_request["base"]["ref"] == default_branch
        && pull_request["base"]["repo"]["full_name"] == repository
        && pull_request["head"]["repo"]["full_name"] == repository
        && pull_request["head"]["ref"] == run_branch
        && pull_request["head"]["sha"] == run_sha
}

fn allowed_source_workflow(path: &str) -> bool {
    matches!(path, CLIENT_CI_WORKFLOW | RELEASE_PR_WORKFLOW)
}

fn destination_allowed(source_branch: &str, default_branch: &str, destination: &str) -> bool {
    if source_branch == default_branch {
        destination == "release/next"
    } else {
        destination == source_branch
    }
}

fn metadata_destination<'a>(
    metadata: &'a Value,
    source_repository: &str,
    source_branch: &'a str,
) -> Result<(&'a str, &'a str, &'a str)> {
    let client_repository = metadata["context"]["payload"]["repository"]["full_name"]
        .as_str()
        .context("artifact client repository missing")?;
    ensure!(
        client_repository.eq_ignore_ascii_case(source_repository),
        "artifact client repository mismatch"
    );
    let destination_repository = metadata["inputs"]["repository"]
        .as_str()
        .unwrap_or(client_repository);
    validate_repository(destination_repository)?;
    ensure!(
        destination_repository.eq_ignore_ascii_case(source_repository),
        "cross-repository pushes are disabled"
    );
    let destination_branch = metadata["inputs"]["branch"]
        .as_str()
        .unwrap_or(source_branch);
    ensure!(
        !destination_branch.is_empty()
            && destination_branch.len() <= 255
            && !destination_branch.starts_with('/')
            && !destination_branch.contains(['\\', '\0']),
        "invalid Securefix destination branch"
    );
    Ok((
        client_repository,
        destination_repository,
        destination_branch,
    ))
}

fn artifact_files(bytes: &[u8], label: &str) -> Result<(Vec<String>, Value)> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    ensure!(
        zip.len() <= 502,
        "Securefix artifact contains too many entries"
    );
    let mut file_list = None;
    let mut metadata = None;
    let mut payload_entries = BTreeSet::new();
    let mut uncompressed_size = 0u64;
    for index in 0..zip.len() {
        let file = zip.by_index(index)?;
        let name = file.name().to_owned();
        ensure!(
            !file.is_dir()
                && !name.starts_with('/')
                && !name.split('/').any(|s| s == "..")
                && file
                    .unix_mode()
                    .is_none_or(|mode| mode & 0o170000 != 0o120000),
            "unsafe entry in Securefix artifact"
        );
        ensure!(
            file.size() <= 16 * 1024 * 1024,
            "Securefix artifact entry is too large"
        );
        uncompressed_size = uncompressed_size
            .checked_add(file.size())
            .context("Securefix artifact size overflow")?;
        ensure!(
            uncompressed_size <= 64 * 1024 * 1024,
            "Securefix artifact expands beyond its size limit"
        );
        if name == format!("{label}_files.txt") {
            ensure!(file_list.is_none(), "duplicate Securefix file manifest");
            let size = file.size();
            ensure!(size <= 128 * 1024, "Securefix file manifest is too large");
            let mut contents = Vec::new();
            file.take(128 * 1024).read_to_end(&mut contents)?;
            ensure!(
                contents.len() as u64 == size,
                "truncated Securefix file manifest"
            );
            file_list = Some(String::from_utf8(contents)?);
        } else if name == format!("{label}.json") {
            ensure!(metadata.is_none(), "duplicate Securefix metadata");
            let size = file.size();
            ensure!(size <= 128 * 1024, "Securefix metadata is too large");
            let mut contents = Vec::new();
            file.take(128 * 1024).read_to_end(&mut contents)?;
            ensure!(
                contents.len() as u64 == size,
                "truncated Securefix metadata"
            );
            metadata =
                Some(serde_json::from_slice(&contents).context("invalid Securefix metadata JSON")?);
        } else {
            ensure!(valid_path(&name), "unsafe Securefix payload path");
            ensure!(
                !name.split('/').any(|part| part == ".git"),
                "Securefix payload cannot write into git metadata"
            );
            ensure!(
                payload_entries.insert(name),
                "duplicate Securefix payload entry"
            );
        }
    }
    let manifest = file_list.context("Securefix artifact file manifest missing")?;
    let files = manifest
        .lines()
        .map(|line| line.trim_end_matches('\r').to_owned())
        .collect::<Vec<_>>();
    ensure!(
        !files.is_empty()
            && files.len() <= 500
            && files
                .iter()
                .all(|p| valid_path(p) && !p.split('/').any(|part| part == ".git")),
        "invalid paths in Securefix file manifest"
    );
    let unique = files.iter().collect::<BTreeSet<_>>();
    ensure!(
        unique.len() == files.len(),
        "duplicate paths in Securefix file manifest"
    );
    ensure!(
        payload_entries.iter().all(|path| unique.contains(path)),
        "Securefix artifact contains an unlisted payload entry"
    );
    Ok((
        files,
        metadata.context("Securefix artifact metadata missing")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fixed_path_validation_rejects_traversal() {
        for bad in ["../secret", "/absolute", "a//b", "a/./b", "a\\b"] {
            assert!(!valid_path(bad), "accepted {bad}");
        }
        assert!(valid_path("src/main.rs"));
        assert!(!valid_path("../secret"));
    }

    #[test]
    fn pull_request_options_are_constrained() {
        assert_eq!(
            pull_request_options(&serde_json::json!(r#"{"title":"release","base":"main"}"#))
                .unwrap(),
            Some(serde_json::json!({"title":"release","base":"main"}))
        );
        assert!(
            validate_pull_request(
                &serde_json::json!({"base":"main","labels":["x"]}),
                "main",
                "feature"
            )
            .is_err()
        );
        assert!(
            validate_pull_request(&serde_json::json!({"base":"other"}), "main", "feature").is_err()
        );
        assert!(validate_pull_request(&serde_json::json!(""), "main", "release/next").is_ok());
        assert!(
            validate_pull_request(
                &serde_json::json!({"title":"Release v1","base":"main","draft":false}),
                "main",
                "release/next"
            )
            .is_ok()
        );
    }

    #[test]
    fn securefix_destination_is_confined_to_source_or_release_branch() {
        assert!(destination_allowed("feature", "main", "feature"));
        assert!(!destination_allowed("feature", "main", "main"));
        assert!(!destination_allowed("feature", "main", "release/next"));
        assert!(destination_allowed("main", "main", "release/next"));
        assert!(!destination_allowed("main", "main", "other"));
    }

    #[test]
    fn pinned_prepare_contract_uses_serialized_run_metadata_and_allows_release_pr() {
        let metadata = json!({
            "inputs": {
                "branch": "release/next",
                "pull_request": {"title":"chore(release): v1.2.3", "base":"main", "draft":false}
            },
            "context": {"payload": {"repository":{"full_name":"civitaspo/example"}}}
        });
        let (client, destination, branch) =
            metadata_destination(&metadata, "civitaspo/example", "main").unwrap();
        assert_eq!(client, "civitaspo/example");
        assert_eq!(destination, "civitaspo/example");
        assert_eq!(branch, "release/next");
        assert!(destination_allowed("main", "main", branch));
        assert!(validate_pull_request(&metadata["inputs"]["pull_request"], "main", branch).is_ok());

        assert!(validate_securefix_metadata(&metadata, "main").is_ok());
    }

    #[test]
    fn pull_request_run_head_sha_is_bound_to_the_live_pr() {
        let actual_head = "b".repeat(40);
        let run = json!({"head_sha":actual_head,"head_branch":"feature"});
        let pr = json!({
            "number":12,"state":"open",
            "base":{"ref":"main","repo":{"full_name":"civitaspo/example"}},
            "head":{"ref":"feature","sha":"b".repeat(40),"repo":{"full_name":"civitaspo/example"}}
        });
        assert_eq!(run["head_sha"], pr["head"]["sha"]);
        assert!(source_pr_matches(
            &pr,
            "civitaspo/example",
            "main",
            "feature",
            run["head_sha"].as_str().unwrap()
        ));

        let mut changed = pr.clone();
        changed["head"]["sha"] = json!("c".repeat(40));
        assert!(!source_pr_matches(
            &pr,
            "civitaspo/example",
            "main",
            "feature",
            "c".repeat(40).as_str()
        ));
        changed["base"]["ref"] = json!("release/next");
        assert!(!source_pr_matches(
            &changed,
            "civitaspo/example",
            "main",
            "feature",
            run["head_sha"].as_str().unwrap()
        ));
        changed["base"]["ref"] = json!("main");
        changed["head"]["repo"]["full_name"] = json!("attacker/fork");
        assert!(!source_pr_matches(
            &changed,
            "civitaspo/example",
            "main",
            "feature",
            run["head_sha"].as_str().unwrap()
        ));
    }

    #[test]
    fn actual_pinned_artifact_files_and_metadata_are_bound_and_safe() {
        let metadata = json!({
            "inputs":{"branch":"release/next"},
            "context":{"payload":{"repository":{"full_name":"civitaspo/example"}}}
        });
        let bytes = securefix_artifact_with_payload(
            "securefix-abc",
            "Cargo.toml\ndeleted.txt\n.github/workflows/ci.yml\n",
            &metadata,
            &[
                ("Cargo.toml", "[package]\n"),
                (".github/workflows/ci.yml", "name: CI\n"),
            ],
        );
        let (files, read_metadata) = artifact_files(&bytes, "securefix-abc").unwrap();
        assert_eq!(
            files,
            ["Cargo.toml", "deleted.txt", ".github/workflows/ci.yml"]
        );
        assert_eq!(read_metadata, metadata);
        let (additions, deletions) = artifact_changes(&bytes, "securefix-abc", &files).unwrap();
        assert_eq!(
            additions
                .iter()
                .map(|addition| addition.path.as_str())
                .collect::<Vec<_>>(),
            ["Cargo.toml", ".github/workflows/ci.yml"]
        );
        assert_eq!(deletions, ["deleted.txt"]);
        assert_eq!(
            String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(&additions[0].contents)
                    .unwrap()
            )
            .unwrap(),
            "[package]\n"
        );
        assert!(validate_securefix_metadata(&metadata, "main").is_ok());
        let wrong_repository = json!({"inputs":{"branch":"release/next","repository":"civitaspo/other"},"context":{"payload":{"repository":{"full_name":"civitaspo/example"}}}});
        assert!(metadata_destination(&wrong_repository, "civitaspo/example", "main").is_err());

        for (files, payload) in [
            ("../outside\n", vec![("../outside", "x")]),
            ("Cargo.toml\n", vec![("README.md", "unlisted")]),
            (".git/config\n", vec![(".git/config", "overwrite")]),
        ] {
            let unsafe_bytes =
                securefix_artifact_with_payload("securefix-abc", files, &metadata, &payload);
            assert!(artifact_files(&unsafe_bytes, "securefix-abc").is_err());
        }
        let deleted_git_path =
            securefix_artifact_with_payload("securefix-abc", ".git/config\n", &metadata, &[]);
        assert!(artifact_files(&deleted_git_path, "securefix-abc").is_err());
    }

    #[test]
    fn native_apply_uses_the_captured_head_as_a_cas_parent() {
        use crate::fixtures::{Fixture, Route};
        let head = "a".repeat(40);
        let commit = "b".repeat(40);
        let plan = source_plan(head.clone(), false);
        let expected_body = json!({
            "query":"mutation SecurefixCommit($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid signature{isValid state} parents(first:2){nodes{oid}}} ref{target{oid}}}}",
            "variables":{"input":{
                "branch":{"repositoryNameWithOwner":"civitaspo/example","branchName":"feature"},
                "expectedHeadOid":head,
                "message":{"headline":"Securefix","body":"validated run"},
                "fileChanges":{"additions":[{"path":"README.md","contents":"dGVzdAo="}],"deletions":[{"path":"old.txt"}]}
            }}
        });
        let fixture = Fixture::new(vec![
            Route::get(
                "/repos/civitaspo/example/git/ref/heads%2Ffeature",
                json!({"object":{"sha":head}}),
            ),
            Route::get(
                "/repos/civitaspo/securefix-server/commits/main",
                json!({"sha":"a".repeat(40)}),
            ),
            Route::request("POST", "/graphql", 200, json!({"data":{"createCommitOnBranch":{
                "commit":{"oid":commit,"signature":{"isValid":true,"state":"VALID"},"parents":{"nodes":[{"oid":head}]}},
                "ref":{"target":{"oid":commit}}
            }}})).with_request_body(expected_body),
        ]);
        let result = commit_validated_source(
            &fixture.api,
            &fixture.api,
            &plan,
            "Securefix".into(),
            "validated run".into(),
            vec![CommitAddition {
                path: "README.md".into(),
                contents: "dGVzdAo=".into(),
            }],
            vec!["old.txt".into()],
        )
        .unwrap();
        assert_eq!(result, commit);
        fixture.finish();
    }

    #[test]
    fn changed_destination_head_is_rejected_before_any_write() {
        use crate::fixtures::{Fixture, Route};
        let fixture = Fixture::new(vec![Route::get(
            "/repos/civitaspo/example/git/ref/heads%2Ffeature",
            json!({"object":{"sha":"c".repeat(40)}}),
        )]);
        let plan = source_plan("a".repeat(40), false);
        assert!(
            commit_validated_source(
                &fixture.api,
                &fixture.api,
                &plan,
                "Securefix".into(),
                String::new(),
                vec![],
                vec![],
            )
            .is_err()
        );
        fixture.finish();
    }

    #[test]
    fn missing_release_branch_is_created_at_run_head_before_the_cas_commit() {
        use crate::fixtures::{Fixture, Route};
        let head = "a".repeat(40);
        let commit = "b".repeat(40);
        let mut plan = source_plan(head.clone(), true);
        plan.source_branch = "main".into();
        plan.destination_branch = "release/next".into();
        let create_ref = json!({"ref":"refs/heads/release/next","sha":head});
        let commit_request = json!({
            "query":"mutation SecurefixCommit($input:CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid signature{isValid state} parents(first:2){nodes{oid}}} ref{target{oid}}}}",
            "variables":{"input":{
                "branch":{"repositoryNameWithOwner":"civitaspo/example","branchName":"release/next"},
                "expectedHeadOid":head,
                "message":{"headline":"Securefix","body":"release run"},
                "fileChanges":{"additions":[],"deletions":[]}
            }}
        });
        let fixture = Fixture::new(vec![
            Route::request("GET", "/repos/civitaspo/example/git/ref/heads%2Frelease%2Fnext", 404, json!({"message":"Not Found"})),
            Route::get("/repos/civitaspo/example/git/ref/heads%2Fmain", json!({"object":{"sha":head}})),
            Route::get("/repos/civitaspo/securefix-server/commits/main", json!({"sha":"a".repeat(40)})),
            Route::request("POST", "/repos/civitaspo/example/git/refs", 201, json!({"object":{"sha":head}})).with_request_body(create_ref),
            Route::get("/repos/civitaspo/securefix-server/commits/main", json!({"sha":"a".repeat(40)})),
            Route::request("POST", "/graphql", 200, json!({"data":{"createCommitOnBranch":{
                "commit":{"oid":commit,"signature":{"isValid":true,"state":"VALID"},"parents":{"nodes":[{"oid":head}]}},
                "ref":{"target":{"oid":commit}}
            }}})).with_request_body(commit_request),
        ]);
        let result = commit_validated_source(
            &fixture.api,
            &fixture.api,
            &plan,
            "Securefix".into(),
            "release run".into(),
            vec![],
            vec![],
        )
        .unwrap();
        assert_eq!(result, commit);
        fixture.finish();
    }

    #[test]
    fn changed_live_pr_head_is_rejected_before_any_write() {
        use crate::fixtures::{Fixture, Route};
        let sha = "a".repeat(40);
        let run = json!({"id":55,"run_attempt":1,"status":"completed","conclusion":"success",
            "repository":{"full_name":"civitaspo/example"},"head_sha":sha,"head_branch":"feature",
            "path":CLIENT_CI_WORKFLOW,"event":"pull_request"});
        let repo = json!({"default_branch":"main"});
        let pr = json!({"state":"open","base":{"ref":"main","repo":{"full_name":"civitaspo/example"}},
            "head":{"ref":"feature","sha":"c".repeat(40),"repo":{"full_name":"civitaspo/example"}}});
        let fixture = Fixture::new(vec![
            Route::get("/repos/civitaspo/example/actions/runs/55", run),
            Route::get("/repos/civitaspo/example", repo),
            Route::get("/repos/civitaspo/example/pulls/12", pr),
        ]);
        let plan = source_plan(sha, false);
        assert!(
            revalidate_source(&fixture.api, &Policy::load("policy.json").unwrap(), &plan).is_err()
        );
        fixture.finish();
    }

    fn source_plan(head: String, destination_was_absent: bool) -> ValidatedSource {
        ValidatedSource {
            repository: "civitaspo/example".into(),
            run_id: 55,
            label: "securefix-abc".into(),
            run_sha: head.clone(),
            source_branch: "feature".into(),
            default_branch: "main".into(),
            destination_branch: "feature".into(),
            expected_destination_head: head,
            destination_was_absent,
            artifact_id: 77,
            archive_sha256: "0".repeat(64),
            files: vec!["README.md".into()],
            metadata: json!({}),
            pull_request_number: Some(12),
        }
    }

    fn securefix_artifact_with_payload(
        label: &str,
        files: &str,
        metadata: &Value,
        payload: &[(&str, &str)],
    ) -> Vec<u8> {
        use std::io::Write;
        let cursor = std::io::Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file(format!("{label}_files.txt"), options)
            .unwrap();
        zip.write_all(files.as_bytes()).unwrap();
        zip.start_file(format!("{label}.json"), options).unwrap();
        zip.write_all(&serde_json::to_vec(metadata).unwrap())
            .unwrap();
        for (path, contents) in payload {
            zip.start_file(path, options).unwrap();
            zip.write_all(contents.as_bytes()).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn source_workflows_match_documented_client_contract() {
        assert!(allowed_source_workflow(CLIENT_CI_WORKFLOW));
        assert!(allowed_source_workflow(RELEASE_PR_WORKFLOW));
        assert!(!allowed_source_workflow(".github/workflows/ci.yml"));
        assert!(!allowed_source_workflow(".github/workflows/release.yml"));
    }
}
