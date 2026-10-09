use crate::{
    api::{ApiError, GitHub},
    output,
    policy::{Capability, Policy, SERVER, validate_repository, validate_sha},
    workflow,
};
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};

mod caller;
use caller::{prepare_caller, rendered_files, write_migration};

const UPDATE_BRANCH: &str = "automation/securefix-runtime";
const DISTRIBUTOR_WORKFLOW: &str = ".github/workflows/distribute-runtime.yml";
const PUBLISHER_WORKFLOW: &str = ".github/workflows/publish-runtime.yml";
const PUBLISHER_ACTOR: u64 = 4_525_500;
const RUNTIME_ASSET: &str = "securefix-runtime-linux-x86_64.tar.gz";

#[derive(Subcommand)]
pub enum Command {
    #[command(about = "Validate an owner-published runtime release")]
    ValidatePromotion { publisher_run_id: u64 },
    #[command(about = "Generate the fixed migration for one policy-approved caller")]
    PrepareCaller {
        repository: String,
        directory: String,
    },
    #[command(about = "Validate a Securefix runtime-distribution request")]
    ValidatePrepared,
    #[command(about = "Reconcile the bot-owned runtime migration pull request")]
    ReconcilePullRequest,
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::ValidatePromotion { publisher_run_id } => {
            let api = GitHub::from_env("GITHUB_TOKEN")?;
            let policy = active_policy(&api)?;
            validate_distributor_context(publisher_run_id)?;
            let promotion = validate_promotion(&api, &policy, publisher_run_id)?;
            output("source_sha", &promotion.source_sha)?;
            output("callers", &serde_json::to_string(&caller_names(&policy)?)?)
        }
        Command::PrepareCaller {
            repository,
            directory,
        } => {
            let api = GitHub::from_env("GITHUB_TOKEN")?;
            let policy = active_policy(&api)?;
            let source_sha = current_runtime(&api)?;
            let migration = prepare_caller(&api, &policy, &repository, &source_sha)?;
            write_migration(Path::new(&directory), &migration)?;
            output("already_current", migration.default_current.to_string())?;
            output_multiline(
                "files",
                &migration
                    .files
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n"),
            )?;
            output(
                "repository_name",
                repository.split('/').nth(1).context("invalid repository")?,
            )
        }
        Command::ValidatePrepared => {
            let api = GitHub::from_env("GITHUB_TOKEN")?;
            let policy = active_policy(&api)?;
            let prepared = PreparedDistribution::from_env()?;
            let migration = validate_prepared(&api, &policy, &prepared)?;
            output("distribution", "true")?;
            output("push_repository", &migration.repository)?;
            output("branch", UPDATE_BRANCH)?;
            output("default_branch", &migration.default_branch)?;
            output("already_current", migration.already_current.to_string())?;
            output("source_sha", &migration.source_sha)
        }
        Command::ReconcilePullRequest => {
            let api = GitHub::from_env("GITHUB_TOKEN")?;
            let policy = active_policy(&api)?;
            let prepared = PreparedDistribution::from_env()?;
            let migration = validate_prepared(&api, &policy, &prepared)?;
            workflow::successful_source_run(&api, SERVER, migration.source_run_id)?;
            let write = GitHub::from_env("SECUREFIX_DISTRIBUTION_TOKEN")?;
            let number = reconcile_pull_request(&write, &policy, &migration)?;
            output("pull_request_number", number.to_string())
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PublishedRuntime {
    pub(crate) publisher_run_id: u64,
    pub(crate) source_sha: String,
    release_id: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct CallerMigration {
    repository: String,
    default_branch: String,
    publisher_run_id: u64,
    source_run_id: u64,
    source_sha: String,
    files: BTreeMap<String, Vec<u8>>,
    default_current: bool,
    already_current: bool,
}

struct PreparedDistribution {
    source_repository: String,
    source_run_id: u64,
    source_run: Value,
    destination: String,
    branch: String,
    fixed_files: Vec<String>,
    metadata: Value,
}

impl PreparedDistribution {
    fn from_env() -> Result<Self> {
        let event = crate::event()?;
        let label = event["label"]["name"]
            .as_str()
            .context("missing label name")?;
        ensure!(
            label.starts_with("securefix-") && label.len() <= 50,
            "invalid Securefix label"
        );
        let (source_repository, source_run_id) = event["label"]["description"]
            .as_str()
            .context("missing label description")?
            .rsplit_once('/')
            .context("invalid Securefix label description")?;
        validate_repository(source_repository)?;
        let source_run_id = source_run_id.parse::<u64>()?;
        let source_run: Value = serde_json::from_str(&std::env::var("SECUREFIX_WORKFLOW_RUN")?)?;
        let metadata: Value = serde_json::from_str(&std::env::var("SECUREFIX_METADATA")?)?;
        let fixed_files = std::env::var("SECUREFIX_FIXED_FILES")?
            .lines()
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(str::to_owned)
            .collect();
        Ok(Self {
            source_repository: source_repository.to_owned(),
            source_run_id,
            source_run,
            destination: std::env::var("SECUREFIX_PUSH_REPOSITORY")?,
            branch: std::env::var("SECUREFIX_BRANCH")?,
            fixed_files,
            metadata,
        })
    }
}

fn active_policy(api: &GitHub) -> Result<Policy> {
    let policy = Policy::active(api)?;
    ensure!(
        std::env::var("SECUREFIX_SOURCE_SHA")? == policy.revision,
        "runtime revision is not current"
    );
    Ok(policy)
}

fn current_runtime(api: &GitHub) -> Result<String> {
    workflow::require_current_runtime(api, DISTRIBUTOR_WORKFLOW)
}

fn caller_names(policy: &Policy) -> Result<Vec<String>> {
    let mut callers: Vec<String> = policy
        .repositories
        .iter()
        .filter(|repository| {
            repository.repository != SERVER
                && repository.capabilities.contains(&Capability::Securefix)
                && repository.capabilities.contains(&Capability::Approve)
                && repository.capabilities.contains(&Capability::Merge)
        })
        .map(|repository| repository.repository.clone())
        .collect();
    callers.sort();
    ensure!(
        !callers.is_empty(),
        "no Securefix caller repositories are enabled"
    );
    Ok(callers)
}

pub(crate) fn validate_promotion(
    api: &GitHub,
    policy: &Policy,
    publisher_run_id: u64,
) -> Result<PublishedRuntime> {
    ensure!(publisher_run_id > 0, "invalid publisher run ID");
    let run: Value = api.get(&format!("/repos/{SERVER}/actions/runs/{publisher_run_id}"))?;
    ensure!(
        run["id"].as_u64() == Some(publisher_run_id)
            && run["repository"]["full_name"] == SERVER
            && run["repository"]["id"] == run["head_repository"]["id"]
            && run["head_repository"]["full_name"] == SERVER
            && workflow_path(&run["path"], PUBLISHER_WORKFLOW)
            && run["event"] == "workflow_dispatch"
            && run["head_branch"] == "main"
            && run["run_attempt"]
                .as_u64()
                .is_some_and(|attempt| attempt >= 1)
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && run["actor"]["id"].as_u64() == Some(PUBLISHER_ACTOR)
            && run["triggering_actor"]["id"].as_u64() == Some(PUBLISHER_ACTOR),
        "runtime publication is not a successful owner-dispatched run"
    );
    let source_sha = run["head_sha"]
        .as_str()
        .context("publisher source SHA missing")?;
    validate_sha(source_sha)?;
    let repository: Value = api.get(&format!("/repos/{SERVER}"))?;
    ensure!(
        repository["full_name"] == SERVER
            && repository["owner"]["id"] == policy.owner_id
            && repository["owner"]["id"].as_u64().is_some_and(|id| id > 0),
        "unexpected server owner"
    );
    let main: Value = api.get(&format!("/repos/{SERVER}/commits/main"))?;
    ensure!(
        main["sha"] == source_sha,
        "publisher is not the current server main revision"
    );
    let tag = format!("securefix-runtime-{source_sha}");
    let release: Value = api.get(&format!("/repos/{SERVER}/releases/tags/{tag}"))?;
    ensure!(
        release["tag_name"] == tag
            && release["target_commitish"] == source_sha
            && release["draft"] == false
            && release["prerelease"] == true,
        "exact runtime release is not published"
    );
    let assets = release["assets"]
        .as_array()
        .context("runtime assets missing")?;
    ensure!(assets.len() == 1, "runtime release has unexpected assets");
    ensure!(
        assets[0]["name"] == RUNTIME_ASSET
            && assets[0]["state"] == "uploaded"
            && assets[0]["size"].as_u64().is_some_and(|size| size > 0)
            && assets[0]["digest"]
                .as_str()
                .is_some_and(|digest| digest.starts_with("sha256:")),
        "published runtime asset is invalid"
    );
    Ok(PublishedRuntime {
        publisher_run_id,
        source_sha: source_sha.to_owned(),
        release_id: release["id"]
            .as_u64()
            .context("runtime release ID missing")?,
    })
}

fn validate_distributor_context(publisher_run_id: u64) -> Result<()> {
    ensure!(
        std::env::var("GITHUB_REPOSITORY")? == SERVER
            && std::env::var("GITHUB_REF")? == "refs/heads/main",
        "runtime distribution can run only from the server default branch"
    );
    match std::env::var("GITHUB_EVENT_NAME")?.as_str() {
        "workflow_run" => {
            let payload = crate::event()?;
            ensure!(
                payload["workflow_run"]["id"].as_u64() == Some(publisher_run_id),
                "workflow_run event does not match the requested publisher"
            );
        }
        "workflow_dispatch" => ensure!(
            std::env::var("GITHUB_ACTOR_ID")?.parse::<u64>()? == PUBLISHER_ACTOR,
            "runtime distribution retry requires the repository owner"
        ),
        _ => anyhow::bail!("unsupported runtime distribution trigger"),
    }
    Ok(())
}

fn workflow_path(actual: &Value, expected: &str) -> bool {
    actual.as_str().is_some_and(|path| {
        let (path, reference) = path.split_once('@').unwrap_or((path, ""));
        path == expected
            && (reference.is_empty() || reference == "main" || reference == "refs/heads/main")
    })
}

fn validate_prepared(
    api: &GitHub,
    policy: &Policy,
    prepared: &PreparedDistribution,
) -> Result<CallerMigration> {
    let source = std::env::var("SECUREFIX_SOURCE_SHA")?;
    ensure!(source == policy.revision, "runtime revision is not current");
    ensure!(
        prepared.source_repository == SERVER
            && std::env::var("GITHUB_REPOSITORY")? == SERVER
            && std::env::var("GITHUB_EVENT_NAME")? == "label"
            && std::env::var("GITHUB_RUN_ATTEMPT")? == "1",
        "runtime distribution must be received by a first-attempt server label workflow"
    );
    let event = crate::event()?;
    ensure!(
        event["action"] == "created"
            && event["sender"]["id"].as_u64() == Some(policy.client_bot_id)
            && event["sender"]["type"] == "Bot",
        "runtime distribution label was not created by Securefix Client"
    );
    ensure!(
        prepared.source_run["id"].as_u64() == Some(prepared.source_run_id)
            && prepared.source_run["repository"]["full_name"] == SERVER
            && prepared.source_run["head_repository"]["full_name"] == SERVER
            && workflow_path(&prepared.source_run["path"], DISTRIBUTOR_WORKFLOW)
            && prepared.source_run["head_branch"] == "main"
            && matches!(
                prepared.source_run["event"].as_str(),
                Some("workflow_run" | "workflow_dispatch")
            )
            && prepared.source_run["actor"]["id"].as_u64() == Some(PUBLISHER_ACTOR)
            && prepared.source_run["run_attempt"] == 1,
        "Securefix request is not from the runtime distributor workflow"
    );
    ensure!(
        prepared.metadata["context"]["payload"]["repository"]["full_name"] == SERVER
            && prepared.metadata["inputs"]["repository"] == prepared.destination
            && prepared.metadata["inputs"]["branch"] == UPDATE_BRANCH,
        "Securefix destination metadata mismatch"
    );
    ensure!(
        prepared.branch == UPDATE_BRANCH
            && caller_names(policy)?
                .iter()
                .any(|repository| repository == &prepared.destination),
        "Securefix destination is outside the fixed runtime migration registry"
    );
    let publisher_run_id = prepared.metadata["inputs"]["custom"]["publisher_run_id"]
        .as_u64()
        .context("Securefix request lacks publisher identity")?;
    let promotion = validate_promotion(api, policy, publisher_run_id)?;
    ensure!(
        prepared.source_run["head_sha"] == promotion.source_sha
            && std::env::var("SECUREFIX_SOURCE_SHA")? == promotion.source_sha,
        "runtime distributor does not match the published current main"
    );
    let successful = workflow::successful_source_run(api, SERVER, prepared.source_run_id)?;
    ensure!(
        workflow_path(&successful["path"], DISTRIBUTOR_WORKFLOW)
            && successful["head_sha"] == promotion.source_sha,
        "runtime distributor run identity changed"
    );
    let migration = prepare_caller(api, policy, &prepared.destination, &promotion.source_sha)?;
    let expected: Vec<_> = migration.files.keys().map(String::as_str).collect();
    let actual: Vec<_> = prepared.fixed_files.iter().map(String::as_str).collect();
    ensure!(
        actual == expected,
        "Securefix file list does not match the reviewed caller migration"
    );
    for (path, expected_contents) in &migration.files {
        let file = fs::symlink_metadata(path)
            .with_context(|| format!("missing prepared migration file {path}"))?;
        ensure!(
            file.is_file() && !file.file_type().is_symlink(),
            "prepared migration is not a regular file: {path}"
        );
        ensure!(
            fs::read(path).with_context(|| format!("missing prepared migration file {path}"))?
                == *expected_contents,
            "prepared migration content does not match the reviewed template: {path}"
        );
    }
    let repo: Value = api.get(&format!("/repos/{}", migration.repository))?;
    let default_branch = repo["default_branch"]
        .as_str()
        .context("caller default branch missing")?;
    ensure!(
        default_branch == migration.default_branch && default_branch != UPDATE_BRANCH,
        "caller default branch changed during validation"
    );
    let already_current = validate_automation_branch(api, policy, &migration)?;
    validate_existing_pull_request(api, policy, &migration)?;
    Ok(CallerMigration {
        repository: migration.repository,
        default_branch: migration.default_branch,
        publisher_run_id,
        source_run_id: prepared.source_run_id,
        source_sha: promotion.source_sha,
        files: migration.files,
        default_current: migration.default_current,
        already_current: already_current || migration.default_current,
    })
}

fn validate_previous_generation(files: &BTreeMap<String, Vec<u8>>, releases: bool) -> Result<()> {
    let path = ".github/workflows/approve-request.yml";
    let approve: serde_yaml::Value = serde_yaml::from_slice(
        files
            .get(path)
            .context("managed approval workflow is missing")?,
    )?;
    let job = approve["jobs"]
        .as_mapping()
        .and_then(|jobs| jobs.values().next())
        .context("managed approval job missing")?;
    let uses = job["uses"]
        .as_str()
        .context("automation branch approval is not canonical")?;
    let (_, sha) = uses
        .rsplit_once('@')
        .context("automation branch pin missing")?;
    validate_sha(sha)?;
    let check_path = ".github/workflows/policy-check.yml";
    let check: serde_yaml::Value = serde_yaml::from_slice(
        files
            .get(check_path)
            .context("managed policy-check workflow missing")?,
    )?;
    let event_key = serde_yaml::Value::Bool(true);
    let on = check
        .as_mapping()
        .and_then(|map| map.get("on").or_else(|| map.get(&event_key)))
        .context("managed policy event missing")?;
    let branches = &on["push"]["branches"];
    let branch = branches
        .as_sequence()
        .and_then(|values| (values.len() == 1).then(|| values[0].as_str()).flatten())
        .context("managed policy branch missing")?;
    validate_branch(branch)?;
    let expected = rendered_files(sha, branch, releases)?;
    for (path, contents) in &expected {
        let actual = files
            .get(path)
            .context("automation branch has an incomplete template generation")?;
        let actual_yaml: serde_yaml::Value = serde_yaml::from_slice(actual)?;
        let expected_yaml: serde_yaml::Value = serde_yaml::from_slice(contents)?;
        ensure!(
            actual_yaml == expected_yaml,
            "automation branch does not contain a previously generated canonical workflow: {path}"
        );
    }
    Ok(())
}

fn validate_automation_branch(
    api: &GitHub,
    policy: &Policy,
    migration: &CallerMigration,
) -> Result<bool> {
    let ref_path = format!(
        "/repos/{}/git/ref/heads/{}",
        migration.repository, UPDATE_BRANCH
    );
    let branch = match api.get::<Value>(&ref_path) {
        Ok(value) => value,
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|e| e.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let head = branch["object"]["sha"]
        .as_str()
        .context("automation branch has no commit")?;
    validate_sha(head)?;
    let base: Value = api.get(&format!(
        "/repos/{}/commits/{}",
        migration.repository, migration.default_branch
    ))?;
    let base_sha = base["sha"]
        .as_str()
        .context("default branch has no commit")?;
    let compare: Value = api.get(&format!(
        "/repos/{}/compare/{}...{}",
        migration.repository, base_sha, head
    ))?;
    ensure!(
        matches!(
            compare["status"].as_str(),
            Some("ahead" | "identical" | "diverged" | "behind")
        ),
        "runtime branch cannot be reconciled against caller default branch"
    );
    let files = compare["files"]
        .as_array()
        .context("automation branch diff missing")?;
    ensure!(
        files.len() < 300,
        "automation branch file diff may be truncated"
    );
    ensure!(
        files
            .iter()
            .all(|file| file["status"] != "renamed" && file.get("previous_filename").is_none()),
        "automation branch contains a rename"
    );
    let managed: std::collections::BTreeSet<_> =
        migration.files.keys().map(String::as_str).collect();
    ensure!(
        !files.is_empty() || matches!(compare["status"].as_str(), Some("identical" | "behind")),
        "automation branch has no reviewable change"
    );
    for file in files {
        let path = file["filename"]
            .as_str()
            .context("automation branch diff path missing")?;
        ensure!(
            managed.contains(path) && file["status"] != "removed",
            "automation branch contains an unmanaged or deleted file: {path}"
        );
    }
    let commits = compare["commits"]
        .as_array()
        .context("automation branch commits missing")?;
    ensure!(
        compare["total_commits"].as_u64() == Some(commits.len() as u64),
        "automation branch commit history is truncated"
    );
    ensure!(
        !commits.is_empty() || matches!(compare["status"].as_str(), Some("identical" | "behind")),
        "automation branch commit list is empty"
    );
    let mut commit_shas = commits
        .iter()
        .map(|commit| {
            commit["sha"]
                .as_str()
                .context("automation commit SHA missing")
        })
        .collect::<Result<Vec<_>>>()?;
    if !commit_shas.contains(&head) {
        commit_shas.push(head);
    }
    for sha in commit_shas {
        validate_sha(sha)?;
        let verified: Value = api.get(&format!("/repos/{}/commits/{sha}", migration.repository))?;
        ensure!(
            verified["commit"]["verification"]["verified"] == true
                && verified["author"]["id"].as_u64() == Some(policy.server_bot_id),
            "automation branch contains an unsigned or non-server commit"
        );
    }
    let commit: Value = api.get(&format!(
        "/repos/{}/git/commits/{head}",
        migration.repository
    ))?;
    let tree_sha = commit["tree"]["sha"]
        .as_str()
        .context("automation branch tree missing")?;
    let tree: Value = api.get(&format!(
        "/repos/{}/git/trees/{tree_sha}?recursive=1",
        migration.repository
    ))?;
    ensure!(
        tree["truncated"] == false,
        "automation branch tree is truncated"
    );
    let entries = tree["tree"]
        .as_array()
        .context("automation branch tree missing")?;
    let mut branch_files = BTreeMap::new();
    for path in migration.files.keys() {
        let entry = entries
            .iter()
            .find(|entry| entry["path"].as_str() == Some(path.as_str()))
            .context("automation branch lacks a managed workflow")?;
        ensure!(
            entry["type"] == "blob" && entry["mode"] == "100644",
            "automation branch managed file is not a regular blob: {path}"
        );
        branch_files.insert(
            path.clone(),
            api.content(&migration.repository, path, head)?,
        );
    }
    validate_previous_generation(
        &branch_files,
        migration
            .files
            .contains_key(".github/workflows/release-pr.yml"),
    )?;
    let desired = branch_files == migration.files;
    if !desired {
        ensure!(
            files.iter().all(|file| file["filename"]
                .as_str()
                .is_some_and(|path| migration.files.contains_key(path))),
            "automation branch changes unmanaged files"
        );
    }
    Ok(desired)
}

fn validate_existing_pull_request(
    api: &GitHub,
    policy: &Policy,
    migration: &CallerMigration,
) -> Result<()> {
    let head = format!("civitaspo:{UPDATE_BRANCH}");
    let pulls: Vec<Value> = api.paginate(&format!(
        "/repos/{}/pulls?state=open&head={head}",
        migration.repository
    ))?;
    ensure!(
        pulls.len() <= 1,
        "duplicate runtime migration pull requests"
    );
    if let Some(pr) = pulls.first() {
        ensure!(
            pr["user"]["id"].as_u64() == Some(policy.server_bot_id)
                && pr["head"]["repo"]["full_name"] == migration.repository
                && pr["head"]["ref"] == UPDATE_BRANCH
                && pr["base"]["repo"]["full_name"] == migration.repository
                && pr["base"]["ref"] == migration.default_branch,
            "existing runtime migration PR is not bot-owned with the fixed base and head"
        );
        let number = pr["number"]
            .as_u64()
            .context("runtime migration PR number missing")?;
        let changed: Vec<Value> = api.paginate(&format!(
            "/repos/{}/pulls/{number}/files?per_page=100",
            migration.repository
        ))?;
        let allowed: std::collections::BTreeSet<_> =
            migration.files.keys().map(String::as_str).collect();
        ensure!(
            !changed.is_empty()
                && changed.iter().all(|file| file["filename"]
                    .as_str()
                    .is_some_and(|path| allowed.contains(path))
                    && file["status"] != "removed"
                    && file["status"] != "renamed"),
            "existing runtime migration PR contains unmanaged, removed, or renamed files"
        );
    }
    Ok(())
}

fn reconcile_pull_request(
    api: &GitHub,
    policy: &Policy,
    migration: &CallerMigration,
) -> Result<u64> {
    if migration.default_current {
        return Ok(0);
    }
    let head = format!("civitaspo:{UPDATE_BRANCH}");
    let pulls: Vec<Value> = api.paginate(&format!(
        "/repos/{}/pulls?state=open&head={head}",
        migration.repository
    ))?;
    ensure!(
        pulls.len() <= 1,
        "duplicate runtime migration pull requests"
    );
    if let Some(pr) = pulls.first() {
        ensure!(
            pr["user"]["id"].as_u64() == Some(policy.server_bot_id)
                && pr["head"]["repo"]["full_name"] == migration.repository
                && pr["head"]["ref"] == UPDATE_BRANCH
                && pr["base"]["repo"]["full_name"] == migration.repository
                && pr["base"]["ref"] == migration.default_branch,
            "runtime migration pull request has an unexpected base or head"
        );
        let number = pr["number"]
            .as_u64()
            .context("runtime migration PR number missing")?;
        let changed: Vec<Value> = api.paginate(&format!(
            "/repos/{}/pulls/{number}/files?per_page=100",
            migration.repository
        ))?;
        let allowed: std::collections::BTreeSet<_> =
            migration.files.keys().map(String::as_str).collect();
        ensure!(
            !changed.is_empty()
                && changed.iter().all(|file| file["filename"]
                    .as_str()
                    .is_some_and(|path| allowed.contains(path))
                    && file["status"] != "removed"),
            "runtime migration PR contains unexpected changed files"
        );
        return Ok(number);
    }
    let pr: Value = api.post(
        &format!("/repos/{}/pulls", migration.repository),
        &json!({
            "head": UPDATE_BRANCH,
            "base": migration.default_branch,
            "title": "chore: update Securefix caller workflows",
            "body": "Update the server-owned Securefix caller workflows to the promoted runtime. Each changed reusable-workflow reference pins the full runtime revision.\n\nGenerated by the Securefix Runtime Distributor after successful runtime publication. Review the workflow diff before merging.",
            "draft": false
        }),
    )?;
    ensure!(
        pr["user"]["id"].as_u64() == Some(policy.server_bot_id)
            && pr["head"]["repo"]["full_name"] == migration.repository
            && pr["head"]["ref"] == UPDATE_BRANCH
            && pr["base"]["repo"]["full_name"] == migration.repository
            && pr["base"]["ref"] == migration.default_branch,
        "created runtime migration PR has an unexpected base or head"
    );
    let number = pr["number"]
        .as_u64()
        .context("created runtime migration PR number missing")?;
    validate_existing_pull_request(api, policy, migration)?;
    Ok(number)
}

fn validate_branch(branch: &str) -> Result<()> {
    ensure!(
        !branch.is_empty()
            && branch.len() <= 255
            && !branch.starts_with('/')
            && !branch.ends_with('/')
            && !branch.contains("..")
            && !branch.contains("//")
            && !branch.contains(['~', '^', ':', '?', '*', '[', '\\', '\0', ' ']),
        "invalid branch name"
    );
    Ok(())
}

fn output_multiline(name: &str, value: &str) -> Result<()> {
    use std::{fs::OpenOptions, io::Write};
    ensure!(
        !value.contains("SECUREFIX_OUTPUT_END"),
        "invalid multiline output"
    );
    if let Ok(path) = std::env::var("GITHUB_OUTPUT") {
        writeln!(
            OpenOptions::new().append(true).open(path)?,
            "{name}<<SECUREFIX_OUTPUT_END\n{value}\nSECUREFIX_OUTPUT_END"
        )?;
    } else {
        println!("{name}={value}");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
