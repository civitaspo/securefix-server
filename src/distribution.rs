use crate::{
    api::{ApiError, GitHub},
    output,
    policy::{Capability, Policy, validate_sha},
    workflow,
};
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use securefix::output_multiline;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

pub(crate) mod caller;
use caller::{prepare_caller, rendered_files, validate_migration_files, write_migration};

const DISTRIBUTOR_WORKFLOW: &str = ".github/workflows/distribute-runtime.yml";
const PUBLISHER_WORKFLOW: &str = ".github/workflows/publish-runtime.yml";
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
    #[command(about = "Apply and reconcile one policy-approved caller migration")]
    ApplyCaller {
        #[arg(long)]
        repository: String,
        #[arg(long)]
        directory: String,
        #[arg(long)]
        publisher_run_id: u64,
    },
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
        Command::ApplyCaller {
            repository,
            directory,
            publisher_run_id,
        } => {
            let api = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
            let policy = active_policy(&api)?;
            validate_distributor_context(publisher_run_id)?;
            let promotion = validate_promotion(&api, &policy, publisher_run_id)?;
            ensure!(
                std::env::var("SECUREFIX_SOURCE_SHA")? == promotion.source_sha,
                "runtime distributor does not match the published current main"
            );
            let migration = prepare_caller(&api, &policy, &repository, &promotion.source_sha)?;
            validate_migration_files(Path::new(&directory), &migration)?;
            let number = apply_caller_migration(&api, &policy, &migration)?;
            output("pull_request_number", number.to_string())
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PublishedRuntime {
    pub(crate) publisher_run_id: u64,
    pub(crate) source_sha: String,
}

#[derive(Debug, PartialEq, Eq)]
struct CallerMigration {
    repository: String,
    default_branch: String,
    source_sha: String,
    files: BTreeMap<String, Vec<u8>>,
    default_current: bool,
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
    let server_repository = &crate::config::trusted()?.deployment.server.repository;
    let mut callers: Vec<String> = policy
        .repositories
        .iter()
        .filter(|repository| {
            repository.repository != *server_repository
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
    _policy: &Policy,
    publisher_run_id: u64,
) -> Result<PublishedRuntime> {
    let trusted = crate::config::trusted()?;
    let server_repository = trusted.deployment.server.repository.as_str();
    let default_branch = trusted.deployment.server.default_branch.as_str();
    ensure!(publisher_run_id > 0, "invalid publisher run ID");
    let run: Value = api.get(&format!(
        "/repos/{server_repository}/actions/runs/{publisher_run_id}"
    ))?;
    ensure!(
        run["id"].as_u64() == Some(publisher_run_id)
            && run["repository"]["full_name"] == server_repository
            && run["repository"]["id"].as_u64() == Some(trusted.deployment.server.id)
            && run["head_repository"]["id"].as_u64() == Some(trusted.deployment.server.id)
            && run["head_repository"]["full_name"] == server_repository
            && workflow_path(&run["path"], PUBLISHER_WORKFLOW, default_branch)
            && run["event"] == "workflow_dispatch"
            && run["head_branch"] == default_branch
            && run["run_attempt"]
                .as_u64()
                .is_some_and(|attempt| attempt >= 1)
            && run["status"] == "completed"
            && run["conclusion"] == "success"
            && run["actor"]["id"].as_u64() == Some(trusted.owner_id)
            && run["triggering_actor"]["id"].as_u64() == Some(trusted.owner_id),
        "runtime publication is not a successful owner-dispatched run"
    );
    let source_sha = run["head_sha"]
        .as_str()
        .context("publisher source SHA missing")?;
    validate_sha(source_sha)?;
    let repository: Value = api.get(&format!("/repos/{server_repository}"))?;
    ensure!(
        repository["full_name"] == server_repository
            && repository["id"].as_u64() == Some(trusted.deployment.server.id)
            && repository["owner"]["id"].as_u64() == Some(trusted.deployment.repository_owner.id),
        "unexpected server owner"
    );
    let main: Value = api.get(&format!(
        "/repos/{server_repository}/commits/{default_branch}"
    ))?;
    ensure!(
        main["sha"] == source_sha,
        "publisher is not the current server main revision"
    );
    let version = crate::runtime::version_at_source(api, source_sha)?;
    let tag = version.tag();
    let release: Value = api.get(&format!("/repos/{server_repository}/releases/tags/{tag}"))?;
    ensure!(
        release["tag_name"] == tag
            && release["name"] == tag
            && release["target_commitish"] == source_sha
            && release["draft"] == false
            && release["prerelease"] == !version.as_semver().pre.is_empty(),
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
            && assets[0]["digest"].as_str().is_some_and(|digest| digest
                .strip_prefix("sha256:")
                .is_some_and(|hex| hex.len() == 64
                    && hex
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))),
        "published runtime asset is invalid"
    );
    let version_tag = tag;
    let version_ref: Value = api.get(&format!(
        "/repos/{server_repository}/git/ref/tags/{version_tag}"
    ))?;
    ensure!(
        version_ref["ref"] == format!("refs/tags/{version_tag}")
            && version_ref["object"]["type"] == "commit"
            && version_ref["object"]["sha"] == source_sha,
        "runtime version annotation does not resolve to the published source"
    );
    Ok(PublishedRuntime {
        publisher_run_id,
        source_sha: source_sha.to_owned(),
    })
}

fn validate_distributor_context(publisher_run_id: u64) -> Result<()> {
    let trusted = crate::config::trusted()?;
    let server_repository = &trusted.deployment.server.repository;
    let default_branch = &trusted.deployment.server.default_branch;
    ensure!(
        std::env::var("GITHUB_REPOSITORY")? == *server_repository
            && std::env::var("GITHUB_REF")? == format!("refs/heads/{default_branch}"),
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
            std::env::var("GITHUB_ACTOR_ID")?.parse::<u64>()? == trusted.owner_id,
            "runtime distribution retry requires the repository owner"
        ),
        _ => anyhow::bail!("unsupported runtime distribution trigger"),
    }
    Ok(())
}

fn workflow_path(actual: &Value, expected: &str, default_branch: &str) -> bool {
    actual.as_str().is_some_and(|path| {
        let (path, reference) = path.split_once('@').unwrap_or((path, ""));
        path == expected
            && (reference.is_empty()
                || reference == default_branch
                || reference == format!("refs/heads/{default_branch}"))
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
    let expected = rendered_files(sha, "v0.0.0", branch, releases)?;
    for (path, contents) in &expected {
        let actual = files
            .get(path)
            .context("automation branch has an incomplete template generation")?;
        let actual_yaml: serde_yaml::Value = serde_yaml::from_slice(actual)?;
        let expected_yaml: serde_yaml::Value = serde_yaml::from_slice(contents)?;
        ensure!(
            actual_yaml == expected_yaml
                || legacy_request_permission(path, expected_yaml.clone())
                    .is_some_and(|legacy| actual_yaml == legacy),
            "automation branch does not contain a previously generated canonical workflow: {path}"
        );
    }
    caller::validate_previous_client_generation(files, sha, branch)?;
    Ok(())
}

fn legacy_request_permission(
    path: &str,
    mut expected: serde_yaml::Value,
) -> Option<serde_yaml::Value> {
    let (job, permission) = match path {
        ".github/workflows/approve-request.yml" => ("approve", "issues"),
        ".github/workflows/merge-request.yml" => ("request", "issues"),
        _ => return None,
    };
    expected["jobs"][job]["permissions"][permission] = serde_yaml::Value::String("read".to_owned());
    Some(expected)
}

fn validate_automation_branch(
    api: &GitHub,
    policy: &Policy,
    migration: &CallerMigration,
) -> Result<(bool, Option<String>)> {
    let update_branch = crate::config::trusted()?
        .deployment
        .runtime_update_branch
        .as_str();
    let ref_path = format!(
        "/repos/{}/git/ref/heads/{}",
        migration.repository, update_branch
    );
    let branch = match api.get::<Value>(&ref_path) {
        Ok(value) => value,
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|e| e.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            return Ok((false, None));
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
    if head == base_sha {
        ensure!(
            compare["status"] == "identical",
            "runtime branch comparison is inconsistent"
        );
        return Ok((false, Some(head.to_owned())));
    }
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
    Ok((desired, Some(head.to_owned())))
}

fn validate_existing_pull_request(
    api: &GitHub,
    policy: &Policy,
    migration: &CallerMigration,
) -> Result<()> {
    let update_branch = crate::config::trusted()?
        .deployment
        .runtime_update_branch
        .as_str();
    let owner = migration
        .repository
        .split('/')
        .next()
        .context("invalid caller repository")?;
    let head = format!("{owner}:{update_branch}");
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
                && pr["head"]["ref"] == update_branch
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
    let update_branch = crate::config::trusted()?
        .deployment
        .runtime_update_branch
        .as_str();
    if migration.default_current {
        return Ok(0);
    }
    let owner = migration
        .repository
        .split('/')
        .next()
        .context("invalid caller repository")?;
    let head = format!("{owner}:{update_branch}");
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
                && pr["head"]["ref"] == update_branch
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
            "head": update_branch,
            "base": migration.default_branch,
            "title": "chore: update Securefix caller workflows",
            "body": "Update the server-owned Securefix caller workflows to the promoted runtime. Each changed reusable-workflow reference pins the full runtime revision.\n\nGenerated by the Securefix Runtime Distributor after successful runtime publication. Review the workflow diff before merging.",
            "draft": false
        }),
    )?;
    ensure!(
        pr["user"]["id"].as_u64() == Some(policy.server_bot_id)
            && pr["head"]["repo"]["full_name"] == migration.repository
            && pr["head"]["ref"] == update_branch
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

fn apply_caller_migration(
    api: &GitHub,
    policy: &Policy,
    migration: &CallerMigration,
) -> Result<u64> {
    let update_branch = crate::config::trusted()?
        .deployment
        .runtime_update_branch
        .as_str();
    if migration.default_current {
        return Ok(0);
    }
    let (desired, validated_head) = validate_automation_branch(api, policy, migration)?;
    validate_existing_pull_request(api, policy, migration)?;
    if !desired {
        let base: Value = api.get(&format!(
            "/repos/{}/commits/{}",
            migration.repository, migration.default_branch
        ))?;
        let base_sha = base["sha"]
            .as_str()
            .context("caller default branch SHA missing")?;
        validate_sha(base_sha)?;
        let expected_head = match validated_head {
            Some(head) => head,
            None => {
                let response: Result<Value> = api.post(
                    &format!("/repos/{}/git/refs", migration.repository),
                    &json!({"ref":format!("refs/heads/{update_branch}"),"sha":base_sha}),
                );
                match response {
                    Ok(value) => {
                        ensure!(
                            value["ref"] == format!("refs/heads/{update_branch}")
                                && value["object"]["sha"] == base_sha,
                            "created runtime migration branch has an unexpected head"
                        );
                        base_sha.to_owned()
                    }
                    Err(error)
                        if error.downcast_ref::<ApiError>().is_some_and(|error| {
                            matches!(
                                error.status,
                                reqwest::StatusCode::CONFLICT
                                    | reqwest::StatusCode::UNPROCESSABLE_ENTITY
                            )
                        }) =>
                    {
                        let head =
                            automation_branch_head(api, &migration.repository, update_branch)?
                                .context(
                                    "runtime migration branch creation raced but branch is missing",
                                )?;
                        ensure!(
                            head == base_sha,
                            "runtime migration branch changed during creation"
                        );
                        head
                    }
                    Err(error) => return Err(error),
                }
            }
        };
        api.create_commit(
            &migration.repository,
            update_branch,
            &expected_head,
            &format!(
                "chore: update Securefix workflows to {}",
                migration.source_sha
            ),
            migration.files.clone(),
            Vec::new(),
        )?;
    }
    reconcile_pull_request(api, policy, migration)
}

fn automation_branch_head(
    api: &GitHub,
    repository: &str,
    update_branch: &str,
) -> Result<Option<String>> {
    match api.get::<Value>(&format!(
        "/repos/{repository}/git/ref/heads/{update_branch}"
    )) {
        Ok(value) => {
            let head = value["object"]["sha"]
                .as_str()
                .context("automation branch has no commit")?;
            validate_sha(head)?;
            Ok(Some(head.to_owned()))
        }
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|error| error.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
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

#[cfg(test)]
mod tests;
