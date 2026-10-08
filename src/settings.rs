use crate::{
    api::{ApiError, GitHub},
    policy::{Capability, Policy, RepositoryPolicy, SERVER, validate_repository},
    workflow::require_current_runtime,
};
use anyhow::{Context, Result, bail, ensure};
use clap::Subcommand;
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs};

const RULESET_DIR: &str = "repo-settings/rulesets";
const CLIENT_WORKFLOWS: &[(&str, &str)] = &[
    (
        ".github/workflows/merge-request.yml",
        "reusable-merge-request.yml",
    ),
    (
        ".github/workflows/approve-request.yml",
        "reusable-approve-request.yml",
    ),
    (
        ".github/workflows/policy-check.yml",
        "reusable-policy-check.yml",
    ),
];
const STATUS_CHECK_APP: u64 = 15368;
const POLICY_CHECK_APP: u64 = 3872533;

#[derive(Subcommand)]
pub enum Command {
    Prepare,
    Reconcile {
        #[arg(long)]
        repository: String,
    },
    ActivationPreflight,
    ControlledMerges,
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Prepare => prepare(),
        Command::Reconcile { repository } => reconcile(&repository),
        Command::ActivationPreflight => activation_preflight(),
        Command::ControlledMerges => controlled_merges(),
    }
}

fn api() -> Result<GitHub> {
    GitHub::from_env("GH_TOKEN")
}

fn prepare() -> Result<()> {
    let api = api()?;
    require_current_runtime(&api, ".github/workflows/repo-settings.yml")?;
    let login: Value = api.get("/user")?;
    ensure!(
        login["login"] == "civitaspo",
        "settings token must authenticate as civitaspo"
    );
    let policy = Policy::active(&api)?;
    validate_desired_settings()?;
    let input_name = env_string("INPUT_REPOSITORY");
    let input_repo = if input_name.trim().is_empty() {
        String::new()
    } else {
        let full_name = format!("civitaspo/{input_name}");
        validate_repository(&full_name)?;
        full_name
    };
    let ready = env_bool("INPUT_MERGE_CONTROLS_READY")?;
    let event_name = std::env::var("GITHUB_EVENT_NAME").unwrap_or_default();
    let activation = activation_mode(
        &event_name,
        &input_repo,
        ready,
        policy.merge_controls_enabled,
    )?;
    let repositories = if input_repo.trim().is_empty() {
        settings_repositories(&policy)?
    } else {
        policy
            .repository(&input_repo)?
            .require(Capability::Settings)?;
        vec![input_repo]
    };
    if activation == ActivationMode::AttestedFullRollout {
        validate_approval_token_if_present(&repositories)?;
    }
    crate::output("repositories", serde_json::to_string(&repositories)?)?;
    crate::output(
        "repos_list",
        repositories
            .iter()
            .map(|r| r.split_once('/').unwrap().1)
            .collect::<Vec<_>>()
            .join(","),
    )?;
    crate::output(
        "activate_merge_controls",
        matches!(activation, ActivationMode::AttestedFullRollout).to_string(),
    )?;
    crate::output("bot_invite", token_present("BOT_TOKEN").to_string())?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivationMode {
    NoActivation,
    ScheduledReconcile,
    AttestedFullRollout,
}

fn activation_mode(
    event_name: &str,
    repository: &str,
    ready: bool,
    enabled: bool,
) -> Result<ActivationMode> {
    if ready {
        ensure!(
            event_name == "workflow_dispatch",
            "merge controls readiness is only valid for manual dispatch"
        );
        ensure!(
            repository.trim().is_empty(),
            "merge-control activation requires the full repository set"
        );
        ensure!(enabled, "merge controls are disabled by central policy");
        return Ok(ActivationMode::AttestedFullRollout);
    }
    if event_name == "schedule" && enabled {
        return Ok(ActivationMode::ScheduledReconcile);
    }
    Ok(ActivationMode::NoActivation)
}

fn settings_repositories(policy: &Policy) -> Result<Vec<String>> {
    let repositories = policy
        .repositories
        .iter()
        .filter(|repo| repo.capabilities.contains(&Capability::Settings))
        .map(|repo| repo.repository.clone())
        .collect::<Vec<_>>();
    ensure!(
        !repositories.is_empty(),
        "policy has no settings repositories"
    );
    Ok(repositories)
}

fn reconcile(repository: &str) -> Result<()> {
    validate_repository(repository)?;
    let api = api()?;
    require_current_runtime(&api, ".github/workflows/repo-settings.yml")?;
    let policy = Policy::active(&api)?;
    let repo_policy = policy.repository(repository)?;
    repo_policy.require(Capability::Settings)?;
    reconcile_one(&api, repo_policy, env_bool("INPUT_CREATE_IF_MISSING")?)
}

fn reconcile_one(
    api: &GitHub,
    repo_policy: &RepositoryPolicy,
    create_if_missing: bool,
) -> Result<()> {
    let repository = &repo_policy.repository;
    let existing: Option<Value> = match api.get(&format!("/repos/{repository}")) {
        Ok(value) => Some(value),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|e| e.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    if let Some(existing) = &existing {
        ensure_owner(existing, repository)?;
    } else {
        ensure!(create_if_missing, "repository does not exist: {repository}");
        ensure!(
            std::env::var("GITHUB_EVENT_NAME").as_deref() == Ok("workflow_dispatch"),
            "repository creation is manual-dispatch only"
        );
        api.post::<Value>(
            "/user/repos",
            &json!({"name":repository_name(repository)?,"private":false}),
        )?;
    }
    let merge_settings = read_json("repo-settings/repository.json")?;
    api.patch::<Value>(&format!("/repos/{repository}"), &merge_settings)?;

    upsert_ruleset(
        api,
        repository,
        &read_json(&format!("{RULESET_DIR}/default-branch.json"))?,
    )?;
    if repo_policy.protect_tags {
        let tag_ruleset = read_json(&format!("{RULESET_DIR}/all-tags.json"))?;
        upsert_ruleset(api, repository, &tag_ruleset)?;
        delete_legacy_tag_rulesets(api, repository)?;
    }
    ensure_immutable_releases(api, repo_policy)?;
    invite_collaborator(api, repository)?;
    if token_present("BOT_TOKEN") {
        accept_invitation(api, repository)?;
    }
    Ok(())
}

fn ensure_immutable_releases(api: &GitHub, repo_policy: &RepositoryPolicy) -> Result<()> {
    if !repo_policy.capabilities.contains(&Capability::Release) {
        return Ok(());
    }
    let path = format!("/repos/{}/immutable-releases", repo_policy.repository);
    match api.get::<Value>(&path) {
        Ok(state) if state["enabled"] == true => return Ok(()),
        Ok(state) => ensure!(
            state["enabled"] == false,
            "immutable release status is invalid"
        ),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|e| e.status == reqwest::StatusCode::NOT_FOUND) => {}
        Err(error) => return Err(error),
    }
    api.request(reqwest::Method::PUT, &path, None)?;
    let state: Value = api.get(&path)?;
    ensure!(
        state["enabled"] == true,
        "immutable releases did not become enabled"
    );
    Ok(())
}

fn controlled_merges() -> Result<()> {
    let api = api()?;
    require_current_runtime(&api, ".github/workflows/repo-settings.yml")?;
    let policy = Policy::active(&api)?;
    let event_name = std::env::var("GITHUB_EVENT_NAME").unwrap_or_default();
    let ready = env_bool("INPUT_MERGE_CONTROLS_READY")?;
    let input_repo = env_string("INPUT_REPOSITORY");
    let mode = activation_mode(
        &event_name,
        &input_repo,
        ready,
        policy.merge_controls_enabled,
    )?;
    match mode {
        ActivationMode::AttestedFullRollout => {
            preflight(&api, &policy)?;
            activate_controls(&api, &policy)?;
        }
        ActivationMode::ScheduledReconcile => reconcile_active_controls(&api, &policy)?,
        ActivationMode::NoActivation => {}
    }
    Ok(())
}

fn activation_preflight() -> Result<()> {
    let api = api()?;
    require_current_runtime(&api, ".github/workflows/repo-settings.yml")?;
    let policy = Policy::active(&api)?;
    ensure!(
        activation_mode(
            &std::env::var("GITHUB_EVENT_NAME").unwrap_or_default(),
            &env_string("INPUT_REPOSITORY"),
            env_bool("INPUT_MERGE_CONTROLS_READY")?,
            policy.merge_controls_enabled,
        )? == ActivationMode::AttestedFullRollout,
        "full attested rollout was not requested"
    );
    preflight(&api, &policy)
}

fn preflight(api: &GitHub, policy: &Policy) -> Result<()> {
    let repositories = merge_repositories(policy)?;
    let expected_sha = &policy.revision;
    ensure!(!expected_sha.is_empty(), "policy revision is missing");
    validate_server_app_installation(&repositories)?;
    for repository in &repositories {
        validate_repo_identity(api, repository)?;
        validate_default_branch_ruleset(api, repository)?;
        validate_current_policy_check(api, repository)?;
        validate_collaborator(api, repository)?;
        if repository != SERVER {
            for (wrapper, reusable) in CLIENT_WORKFLOWS {
                validate_wrapper_pin(api, repository, wrapper, reusable, expected_sha)?;
            }
        }
    }
    Ok(())
}

fn merge_repositories(policy: &Policy) -> Result<Vec<String>> {
    let mut clients = policy
        .repositories
        .iter()
        .filter(|r| r.capabilities.contains(&Capability::Merge) && r.repository != SERVER)
        .map(|r| r.repository.clone())
        .collect::<Vec<_>>();
    clients.sort();
    ensure!(
        policy
            .repository(SERVER)?
            .capabilities
            .contains(&Capability::Merge),
        "server merge capability is not enabled"
    );
    clients.push(SERVER.to_string());
    Ok(clients)
}

fn reconcile_existing_controlled_merges(ruleset: &Value) -> bool {
    ruleset["enforcement"] == "active"
}

fn activate_controls(api: &GitHub, policy: &Policy) -> Result<()> {
    let ruleset = read_json(&format!("{RULESET_DIR}/controlled-merges.json"))?;
    for repository in merge_repositories(policy)? {
        validate_repo_identity(api, &repository)?;
        upsert_ruleset(api, &repository, &ruleset)?;
    }
    Ok(())
}

fn reconcile_active_controls(api: &GitHub, policy: &Policy) -> Result<()> {
    let ruleset = read_json(&format!("{RULESET_DIR}/controlled-merges.json"))?;
    for repository in merge_repositories(policy)? {
        let matches = repository_rulesets(api, &repository, "controlled-merges")?;
        ensure!(
            matches.len() <= 1,
            "multiple controlled-merges rulesets on {repository}"
        );
        let Some(existing) = matches.first() else {
            continue;
        };
        if !reconcile_existing_controlled_merges(existing) {
            continue;
        }
        let id = existing["id"].as_u64().context("ruleset ID missing")?;
        api.put::<Value>(&format!("/repos/{repository}/rulesets/{id}"), &ruleset)?;
    }
    Ok(())
}

fn validate_repo_identity(api: &GitHub, repository: &str) -> Result<()> {
    let value: Value = api.get(&format!("/repos/{repository}"))?;
    ensure_owner(&value, repository)
}

fn ensure_owner(repo: &Value, expected: &str) -> Result<()> {
    ensure!(
        repo["full_name"] == expected,
        "repository identity mismatch"
    );
    ensure!(
        repo["owner"]["id"].as_u64() == Some(4525500),
        "repository is not owned by the configured organization"
    );
    Ok(())
}

fn validate_wrapper_pin(
    api: &GitHub,
    repository: &str,
    path: &str,
    reusable: &str,
    expected_sha: &str,
) -> Result<()> {
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    let branch = repo["default_branch"]
        .as_str()
        .context("default branch missing")?;
    let bytes = api.content(repository, path, branch)?;
    let yaml: Value = serde_yaml::from_slice(&bytes)
        .with_context(|| format!("invalid workflow {repository}/{path}"))?;
    let uses = find_uses(&yaml);
    let expected =
        format!("civitaspo/securefix-server/.github/workflows/{reusable}@{expected_sha}");
    ensure!(
        uses.iter().filter(|value| **value == expected).count() == 1 && uses.len() == 1,
        "{repository}/{path} must call {reusable} at the current server revision"
    );
    Ok(())
}

fn find_uses(value: &Value) -> Vec<&str> {
    let mut found = Vec::new();
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "uses"
                    && let Some(value) = child.as_str()
                {
                    found.push(value);
                }
                found.extend(find_uses(child));
            }
        }
        Value::Array(items) => {
            for item in items {
                found.extend(find_uses(item));
            }
        }
        _ => {}
    }
    found
}

fn validate_current_policy_check(api: &GitHub, repository: &str) -> Result<()> {
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    let branch = repo["default_branch"]
        .as_str()
        .context("default branch missing")?;
    let reference: Value = api.get(&format!("/repos/{repository}/git/ref/heads/{branch}"))?;
    let sha = reference["object"]["sha"]
        .as_str()
        .context("default branch SHA missing")?;
    let checks: Value = api.get(&format!(
        "/repos/{repository}/commits/{sha}/check-runs?per_page=100"
    ))?;
    let check_runs = checks["check_runs"]
        .as_array()
        .context("check-runs missing")?;
    for (name, app_id) in [
        ("status-check", STATUS_CHECK_APP),
        ("securefix-policy-check", POLICY_CHECK_APP),
    ] {
        ensure!(
            check_runs.iter().any(|check| check["name"] == name
                && check["status"] == "completed"
                && check["conclusion"] == "success"
                && check["app"]["id"].as_u64() == Some(app_id)),
            "{repository} default-branch head lacks successful {name} from app {app_id}"
        );
    }
    Ok(())
}

fn validate_default_branch_ruleset(api: &GitHub, repository: &str) -> Result<()> {
    let matches = repository_rulesets(api, repository, "default-branch")?;
    ensure!(
        matches.len() == 1,
        "{repository} must have exactly one default-branch ruleset"
    );
    validate_default_ruleset(&matches[0], repository)
}

fn validate_default_ruleset(ruleset: &Value, repository: &str) -> Result<()> {
    ensure!(
        ruleset["enforcement"] == "active"
            && ruleset["bypass_actors"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "{repository} default-branch protections are not active and bypass-free"
    );
    let rules = ruleset["rules"]
        .as_array()
        .context("default-branch rules missing")?;
    ensure!(
        rules
            .iter()
            .any(|rule| rule["type"] == "required_signatures"),
        "{repository} requires signed commits"
    );
    let pull_request = rules
        .iter()
        .find(|rule| rule["type"] == "pull_request")
        .context("{repository} lacks pull-request rules")?;
    ensure!(
        pull_request["parameters"]["required_approving_review_count"] == 1
            && pull_request["parameters"]["dismiss_stale_reviews_on_push"] == true,
        "{repository} review rules must require one approval and dismiss stale approvals"
    );
    let checks = rules
        .iter()
        .find(|rule| rule["type"] == "required_status_checks")
        .context("{repository} lacks required status checks")?;
    let statuses = checks["parameters"]["required_status_checks"]
        .as_array()
        .context("required status checks missing")?;
    for (name, integration_id) in [
        ("status-check", STATUS_CHECK_APP),
        ("securefix-policy-check", POLICY_CHECK_APP),
    ] {
        ensure!(
            statuses.iter().any(|check| check["context"] == name
                && check["integration_id"].as_u64() == Some(integration_id)),
            "{repository} ruleset does not bind {name} to app {integration_id}"
        );
    }
    Ok(())
}

fn validate_server_app_installation(repositories: &[String]) -> Result<()> {
    let api = GitHub::from_env("SECUREFIX_APP_TOKEN")?;
    let mut installed = BTreeSet::new();
    for page in 1..=100 {
        let response: Value = api.get(&format!(
            "/installation/repositories?per_page=100&page={page}"
        ))?;
        let values = response["repositories"]
            .as_array()
            .context("installation repositories missing")?;
        for repository in values {
            ensure!(
                repository["owner"]["id"].as_u64() == Some(4525500),
                "Securefix Server App installation contains a repository outside civitaspo"
            );
            if let Some(name) = repository["full_name"].as_str() {
                installed.insert(name.to_string());
            }
        }
        if values.len() < 100 {
            break;
        }
        ensure!(
            page < 100,
            "Securefix Server App installation repository list exceeded limit"
        );
    }
    for repository in repositories {
        ensure!(
            installed.contains(repository),
            "Securefix Server App is not installed on {repository}"
        );
    }
    ensure!(
        installed == repositories.iter().cloned().collect(),
        "Securefix Server App token scope differs from the full configured repository set"
    );
    Ok(())
}

fn validate_approval_token_if_present(repositories: &[String]) -> Result<()> {
    ensure!(
        token_present("CIVITASPO_BOT_PR_APPROVE_TOKEN"),
        "CIVITASPO_BOT_PR_APPROVE_TOKEN is required for full activation readiness"
    );
    let api = GitHub::from_env("CIVITASPO_BOT_PR_APPROVE_TOKEN")?;
    let user: Value = api.get("/user")?;
    ensure!(
        user["login"] == "civitaspo-bot",
        "approval token must authenticate as civitaspo-bot"
    );
    for repository in repositories {
        validate_collaborator(&api, repository)?;
    }
    Ok(())
}

fn validate_collaborator(api: &GitHub, repository: &str) -> Result<()> {
    let collaborator: Value = api.get(&format!(
        "/repos/{repository}/collaborators/civitaspo-bot/permission"
    ))?;
    ensure!(
        matches!(
            collaborator["permission"].as_str(),
            Some("push" | "maintain" | "admin")
        ),
        "civitaspo-bot lacks effective write permission on {repository}"
    );
    Ok(())
}

fn repository_rulesets(api: &GitHub, repository: &str, name: &str) -> Result<Vec<Value>> {
    Ok(api
        .paginate(&format!(
            "/repos/{repository}/rulesets?includes_parents=false"
        ))?
        .into_iter()
        .filter(|value| value["name"] == name && value["source_type"] == "Repository")
        .collect())
}

fn upsert_ruleset(api: &GitHub, repository: &str, body: &Value) -> Result<()> {
    let name = body["name"].as_str().context("ruleset name missing")?;
    let matches = repository_rulesets(api, repository, name)?;
    ensure!(
        matches.len() <= 1,
        "multiple {name} rulesets on {repository}"
    );
    if let Some(existing) = matches.first() {
        let id = existing["id"].as_u64().context("ruleset ID missing")?;
        api.put::<Value>(&format!("/repos/{repository}/rulesets/{id}"), body)?;
    } else {
        api.post::<Value>(&format!("/repos/{repository}/rulesets"), body)?;
    }
    Ok(())
}

fn delete_legacy_tag_rulesets(api: &GitHub, repository: &str) -> Result<()> {
    let existing = api.paginate(&format!(
        "/repos/{repository}/rulesets?includes_parents=false"
    ))?;
    for ruleset in existing.into_iter().filter(|value| {
        value["name"] == "Protect tags"
            && value["source_type"] == "Repository"
            && value["target"] == "tag"
    }) {
        let id = ruleset["id"]
            .as_u64()
            .context("legacy ruleset ID missing")?;
        api.delete(&format!("/repos/{repository}/rulesets/{id}"))?;
    }
    Ok(())
}

fn invite_collaborator(api: &GitHub, repository: &str) -> Result<()> {
    let collaborator = read_json("repo-settings/collaborator.json")?;
    let username = collaborator["username"]
        .as_str()
        .context("collaborator username missing")?;
    let permission = collaborator["permission"]
        .as_str()
        .context("collaborator permission missing")?;
    api.put::<Value>(
        &format!("/repos/{repository}/collaborators/{username}"),
        &json!({"permission":permission}),
    )?;
    Ok(())
}

fn accept_invitation(_api: &GitHub, repository: &str) -> Result<()> {
    let api = GitHub::from_env("BOT_TOKEN")?;
    let username = read_json("repo-settings/collaborator.json")?["username"]
        .as_str()
        .context("collaborator username missing")?
        .to_string();
    let invitations: Vec<Value> = api.paginate("/user/repository_invitations")?;
    let full_name = repository.to_lowercase();
    if let Some(invitation) = invitations.iter().find(|item| {
        item["repository"]["full_name"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(&full_name))
    }) {
        let id = invitation["id"].as_u64().context("invitation ID missing")?;
        api.patch::<Value>(&format!("/user/repository_invitations/{id}"), &json!({}))?;
        return Ok(());
    }
    let status: Value = api.get(&format!(
        "/repos/{repository}/collaborators/{username}/permission"
    ))?;
    ensure!(
        matches!(
            status["permission"].as_str(),
            Some("push" | "maintain" | "admin")
        ),
        "no pending invitation or effective permission for {username} on {repository}"
    );
    Ok(())
}

fn validate_desired_settings() -> Result<()> {
    let repository = read_json("repo-settings/repository.json")?;
    ensure!(
        repository["allow_squash_merge"] == true
            && repository["allow_merge_commit"] == false
            && repository["allow_rebase_merge"] == false,
        "repository.json must enforce squash-only merges"
    );
    let collaborator = read_json("repo-settings/collaborator.json")?;
    ensure!(
        collaborator["username"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
            && collaborator["permission"] == "push",
        "collaborator.json must grant push access to a named collaborator"
    );
    let default = read_json(&format!("{RULESET_DIR}/default-branch.json"))?;
    ensure!(
        default["name"] == "default-branch"
            && default["target"] == "branch"
            && default["bypass_actors"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "invalid default-branch ruleset"
    );
    let controlled = read_json(&format!("{RULESET_DIR}/controlled-merges.json"))?;
    ensure!(
        controlled["name"] == "controlled-merges" && controlled["target"] == "branch",
        "invalid controlled-merges ruleset"
    );
    let tags = read_json(&format!("{RULESET_DIR}/all-tags.json"))?;
    ensure!(
        tags["name"] == "all-tags"
            && tags["target"] == "tag"
            && tags["bypass_actors"].as_array().is_some_and(Vec::is_empty),
        "invalid all-tags ruleset"
    );
    Ok(())
}

fn read_json(path: &str) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("read {path}"))?;
    ensure!(bytes.len() <= 256 * 1024, "{path} exceeds size limit");
    serde_json::from_slice(&bytes).with_context(|| format!("parse {path}"))
}

fn repository_name(repository: &str) -> Result<&str> {
    repository
        .split_once('/')
        .map(|(_, name)| name)
        .context("invalid repository name")
}

fn env_string(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}
fn token_present(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| !value.trim().is_empty())
}
fn env_bool(name: &str) -> Result<bool> {
    match env_string(name).as_str() {
        "" | "false" | "0" => Ok(false),
        "true" | "1" => Ok(true),
        _ => bail!("{name} must be true or false"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Fixture, Route};

    #[test]
    fn scheduled_runs_reconcile_without_activating() {
        assert_eq!(
            activation_mode("schedule", "", false, true).unwrap(),
            ActivationMode::ScheduledReconcile
        );
        assert_eq!(
            activation_mode("workflow_dispatch", "", false, true).unwrap(),
            ActivationMode::NoActivation
        );
        assert_eq!(
            activation_mode("workflow_dispatch", "", true, true).unwrap(),
            ActivationMode::AttestedFullRollout
        );
        assert!(activation_mode("workflow_dispatch", "civitaspo/repo", true, true).is_err());
        assert!(activation_mode("workflow_dispatch", "", true, false).is_err());
        assert!(reconcile_existing_controlled_merges(
            &json!({"enforcement":"active"})
        ));
        assert!(!reconcile_existing_controlled_merges(
            &json!({"enforcement":"disabled"})
        ));
        assert!(!reconcile_existing_controlled_merges(
            &json!({"enforcement":"evaluate"})
        ));
    }

    #[test]
    fn activation_readiness_covers_the_full_merge_set_and_keeps_server_last() {
        let policy = Policy::load("policy.json").unwrap();
        let expected = policy
            .repositories
            .iter()
            .filter(|repo| repo.capabilities.contains(&Capability::Merge))
            .map(|repo| repo.repository.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let activation = merge_repositories(&policy).unwrap();
        let actual = activation
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual, expected);
        assert_eq!(activation.last().map(String::as_str), Some(SERVER));
        assert!(
            activation[..activation.len() - 1]
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }

    #[test]
    fn default_ruleset_requires_all_review_and_check_sources() {
        let valid = json!({
            "enforcement":"active", "bypass_actors":[], "rules":[
                {"type":"required_signatures"},
                {"type":"pull_request","parameters":{"required_approving_review_count":1,"dismiss_stale_reviews_on_push":true}},
                {"type":"required_status_checks","parameters":{"required_status_checks":[
                    {"context":"status-check","integration_id":15368},
                    {"context":"securefix-policy-check","integration_id":3872533}
                ]}}
            ]
        });
        assert!(validate_default_ruleset(&valid, "civitaspo/example").is_ok());
        let mut wrong_source = valid.clone();
        wrong_source["rules"][2]["parameters"]["required_status_checks"][1]["integration_id"] =
            json!(15368);
        assert!(validate_default_ruleset(&wrong_source, "civitaspo/example").is_err());
        let mut stale_reviews = valid;
        stale_reviews["rules"][1]["parameters"]["dismiss_stale_reviews_on_push"] = json!(false);
        assert!(validate_default_ruleset(&stale_reviews, "civitaspo/example").is_err());
    }

    #[test]
    fn workflow_pin_parser_rejects_unexpected_callers() {
        let workflow: Value = serde_yaml::from_str("on: workflow_dispatch\njobs:\n  call:\n    uses: civitaspo/securefix-server/.github/workflows/reusable-policy-check.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n").unwrap();
        assert_eq!(
            find_uses(&workflow),
            vec![
                "civitaspo/securefix-server/.github/workflows/reusable-policy-check.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ]
        );
        let additional: Value = serde_yaml::from_str("jobs:\n  call:\n    uses: civitaspo/securefix-server/.github/workflows/reusable-policy-check.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  extra:\n    uses: attacker/workflow@main\n").unwrap();
        assert_eq!(find_uses(&additional).len(), 2);
    }

    #[test]
    fn immutable_release_reconciliation_is_release_scoped_and_non_disabling() {
        let repository = RepositoryPolicy {
            repository: "civitaspo/example".into(),
            capabilities: vec![Capability::Settings],
            release: None,
            sensitive_paths: vec![".github/**".into()],
            protect_tags: false,
        };
        let fixture = Fixture::new(vec![]);
        ensure_immutable_releases(&fixture.api, &repository).unwrap();
        fixture.finish();

        let repository = RepositoryPolicy {
            capabilities: vec![Capability::Settings, Capability::Release],
            release: Some(crate::policy::ReleaseStrategy::GithubRelease),
            ..repository
        };
        let path = "/repos/civitaspo/example/immutable-releases";
        let fixture = Fixture::new(vec![Route::get(
            path,
            json!({"enabled":true,"enforced_by_owner":false}),
        )]);
        ensure_immutable_releases(&fixture.api, &repository).unwrap();
        fixture.finish();
    }

    #[test]
    fn disabled_immutable_releases_are_enabled_then_verified() {
        let repository = RepositoryPolicy {
            repository: "civitaspo/example".into(),
            capabilities: vec![Capability::Release],
            release: Some(crate::policy::ReleaseStrategy::GithubRelease),
            sensitive_paths: vec![".github/**".into()],
            protect_tags: false,
        };
        let path = "/repos/civitaspo/example/immutable-releases";
        let fixture = Fixture::new(vec![
            Route::request("GET", path, 404, json!({"message":"Not Found"})),
            Route::get(
                "/repos/civitaspo/securefix-server/commits/main",
                json!({"sha":"a".repeat(40)}),
            ),
            Route::request("PUT", path, 204, Value::Null),
            Route::get(path, json!({"enabled":true,"enforced_by_owner":false})),
        ]);
        ensure_immutable_releases(&fixture.api, &repository).unwrap();
        fixture.finish();
    }
}
