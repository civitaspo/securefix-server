use crate::{
    api::{ApiError, GitHub},
    config::{self, Checks},
    policy::{Capability, Policy, RepositoryPolicy, validate_repository},
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
    let trusted = config::trusted()?;
    let deployment = &trusted.deployment;
    let api = api()?;
    require_current_runtime(&api, ".github/workflows/repo-settings.yml")?;
    let login: Value = api.get("/user")?;
    ensure!(
        login["login"] == deployment.owner_login && login["id"].as_u64() == Some(trusted.owner_id),
        "settings token must authenticate as the configured owner"
    );
    let policy = Policy::active(&api)?;
    validate_desired_settings()?;
    let input_name = env_string("INPUT_REPOSITORY");
    let input_repo = if input_name.trim().is_empty() {
        String::new()
    } else {
        let full_name = format!("{}/{input_name}", deployment.repository_owner.login);
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
        validate_approval_token_if_present(&api, &repositories)?;
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
    crate::output(
        "bot_invite",
        token_present("SECUREFIX_REVIEWER_INVITE_TOKEN").to_string(),
    )?;
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
        ensure_owner(
            existing,
            repository,
            config::trusted()?.deployment.repository_owner.id,
        )?;
    } else {
        ensure!(create_if_missing, "repository does not exist: {repository}");
        ensure!(
            std::env::var("GITHUB_EVENT_NAME").as_deref() == Ok("workflow_dispatch"),
            "repository creation is manual-dispatch only"
        );
        let trusted = config::trusted()?;
        let repository_owner = &trusted.deployment.repository_owner;
        let account: Value = api.get(&format!("/users/{}", repository_owner.login))?;
        ensure!(
            account["id"].as_u64() == Some(repository_owner.id),
            "configured repository owner identity changed"
        );
        let maintainer = config::Principal {
            login: trusted.deployment.owner_login.clone(),
            id: trusted.owner_id,
        };
        let create_path = repository_creation_path(
            account["type"]
                .as_str()
                .context("repository owner type is missing")?,
            repository_owner,
            &maintainer,
        )?;
        api.post::<Value>(
            &create_path,
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
    let reviewer = &config::trusted()?.deployment.approval_reviewer.login;
    invite_collaborator(api, repository, reviewer)?;
    if token_present("SECUREFIX_REVIEWER_INVITE_TOKEN") {
        accept_invitation(api, repository, reviewer)?;
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
    let trusted = config::trusted()?;
    let deployment = &trusted.deployment;
    let repositories = merge_repositories(policy, &deployment.server.repository)?;
    let expected_sha = &policy.revision;
    ensure!(!expected_sha.is_empty(), "policy revision is missing");
    validate_server_app_installation(
        &repositories,
        deployment.repository_owner.id,
        deployment.server_app_id,
    )?;
    for repository in &repositories {
        validate_repo_identity(api, repository)?;
        validate_default_branch_ruleset(api, repository, &deployment.checks)?;
        validate_current_policy_check(api, repository, &deployment.checks)?;
        validate_collaborator(api, repository, &deployment.approval_reviewer.login)?;
        if repository != &deployment.server.repository {
            for (wrapper, reusable) in CLIENT_WORKFLOWS {
                validate_wrapper_pin(
                    api,
                    repository,
                    wrapper,
                    reusable,
                    expected_sha,
                    &deployment.server.repository,
                )?;
            }
        }
    }
    Ok(())
}

fn merge_repositories(policy: &Policy, server: &str) -> Result<Vec<String>> {
    let mut clients = policy
        .repositories
        .iter()
        .filter(|r| r.capabilities.contains(&Capability::Merge) && r.repository != server)
        .map(|r| r.repository.clone())
        .collect::<Vec<_>>();
    clients.sort();
    ensure!(
        policy
            .repository(server)?
            .capabilities
            .contains(&Capability::Merge),
        "server merge capability is not enabled"
    );
    clients.push(server.to_owned());
    Ok(clients)
}

fn reconcile_existing_controlled_merges(ruleset: &Value) -> bool {
    ruleset["enforcement"] == "active"
}

fn activate_controls(api: &GitHub, policy: &Policy) -> Result<()> {
    let ruleset = read_json(&format!("{RULESET_DIR}/controlled-merges.json"))?;
    let server = &config::trusted()?.deployment.server.repository;
    for repository in merge_repositories(policy, server)? {
        validate_repo_identity(api, &repository)?;
        upsert_ruleset(api, &repository, &ruleset)?;
    }
    Ok(())
}

fn reconcile_active_controls(api: &GitHub, policy: &Policy) -> Result<()> {
    let ruleset = read_json(&format!("{RULESET_DIR}/controlled-merges.json"))?;
    let server = &config::trusted()?.deployment.server.repository;
    for repository in merge_repositories(policy, server)? {
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
    let trusted = config::trusted()?;
    ensure_owner(&value, repository, trusted.deployment.repository_owner.id)?;
    let server = &trusted.deployment.server;
    if repository == server.repository {
        ensure!(
            value["id"].as_u64() == Some(server.id)
                && value["default_branch"] == server.default_branch,
            "configured server repository identity or default branch changed"
        );
    }
    Ok(())
}

fn ensure_owner(repo: &Value, expected: &str, owner_id: u64) -> Result<()> {
    ensure!(
        repo["full_name"] == expected,
        "repository identity mismatch"
    );
    ensure!(
        repo["owner"]["id"].as_u64() == Some(owner_id),
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
    server_repository: &str,
) -> Result<()> {
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    let branch = repo["default_branch"]
        .as_str()
        .context("default branch missing")?;
    let bytes = api.content(repository, path, branch)?;
    let yaml: Value = serde_yaml::from_slice(&bytes)
        .with_context(|| format!("invalid workflow {repository}/{path}"))?;
    let uses = find_uses(&yaml);
    let expected = wrapper_pin(server_repository, reusable, expected_sha);
    ensure!(
        uses.iter().filter(|value| **value == expected).count() == 1 && uses.len() == 1,
        "{repository}/{path} must call {reusable} at the current server revision"
    );
    Ok(())
}

fn wrapper_pin(server_repository: &str, reusable: &str, expected_sha: &str) -> String {
    format!("{server_repository}/.github/workflows/{reusable}@{expected_sha}")
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

fn validate_current_policy_check(api: &GitHub, repository: &str, checks: &Checks) -> Result<()> {
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    let branch = repo["default_branch"]
        .as_str()
        .context("default branch missing")?;
    let reference: Value = api.get(&format!("/repos/{repository}/git/ref/heads/{branch}"))?;
    let sha = reference["object"]["sha"]
        .as_str()
        .context("default branch SHA missing")?;
    for (name, app_id) in [
        ("status-check", checks.status_app_id),
        ("securefix-policy-check", checks.policy_app_id),
    ] {
        let response: Value = api.get(&format!(
            "/repos/{repository}/commits/{sha}/check-runs?per_page=100&filter=latest&check_name={name}&app_id={app_id}"
        ))?;
        let check_runs = response["check_runs"]
            .as_array()
            .context("check-runs missing")?;
        ensure!(
            response["total_count"].as_u64() == Some(check_runs.len() as u64),
            "{repository} named check response is incomplete"
        );
        let latest = check_runs
            .iter()
            .filter(|check| check["name"] == name && check["app"]["id"].as_u64() == Some(app_id))
            .max_by_key(|check| check["id"].as_u64().unwrap_or_default());
        ensure!(
            latest.is_some_and(
                |check| check["status"] == "completed" && check["conclusion"] == "success"
            ),
            "{repository} default-branch head lacks successful {name} from app {app_id}"
        );
    }
    Ok(())
}

fn validate_default_branch_ruleset(api: &GitHub, repository: &str, checks: &Checks) -> Result<()> {
    let matches = repository_rulesets(api, repository, "default-branch")?;
    ensure!(
        matches.len() == 1,
        "{repository} must have exactly one default-branch ruleset"
    );
    validate_default_ruleset(&matches[0], repository, checks)
}

fn validate_default_ruleset(ruleset: &Value, repository: &str, checks: &Checks) -> Result<()> {
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
    let required_checks = rules
        .iter()
        .find(|rule| rule["type"] == "required_status_checks")
        .context("{repository} lacks required status checks")?;
    let statuses = required_checks["parameters"]["required_status_checks"]
        .as_array()
        .context("required status checks missing")?;
    for (name, integration_id) in [
        ("status-check", checks.status_app_id),
        ("securefix-policy-check", checks.policy_app_id),
    ] {
        ensure!(
            statuses.iter().any(|check| check["context"] == name
                && check["integration_id"].as_u64() == Some(integration_id)),
            "{repository} ruleset does not bind {name} to app {integration_id}"
        );
    }
    Ok(())
}

fn validate_server_app_installation(
    repositories: &[String],
    owner_id: u64,
    server_app_id: u64,
) -> Result<()> {
    let api = GitHub::from_env("SECUREFIX_SERVER_APP_TOKEN")?;
    let installation: Value = api.get("/installation")?;
    ensure!(
        installation["app_id"].as_u64() == Some(server_app_id),
        "configured Securefix Server App token has the wrong App identity"
    );
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
                repository["owner"]["id"].as_u64() == Some(owner_id),
                "Securefix Server App installation contains a repository outside the configured owner"
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

fn validate_approval_token_if_present(owner_api: &GitHub, repositories: &[String]) -> Result<()> {
    let reviewer = &config::trusted()?.deployment.approval_reviewer;
    ensure!(
        token_present("SECUREFIX_APPROVAL_REVIEWER_TOKEN"),
        "SECUREFIX_APPROVAL_REVIEWER_TOKEN is required for full activation readiness"
    );
    let api = GitHub::from_env("SECUREFIX_APPROVAL_REVIEWER_TOKEN")?;
    validate_reviewer_access(owner_api, &api, repositories, reviewer)
}

fn validate_reviewer_access(
    owner_api: &GitHub,
    reviewer_api: &GitHub,
    repositories: &[String],
    reviewer: &config::Principal,
) -> Result<()> {
    let user: Value = reviewer_api.get("/user")?;
    validate_reviewer_identity(&user, reviewer)?;
    for repository in repositories {
        validate_collaborator(owner_api, repository, &reviewer.login)?;
    }
    Ok(())
}

fn validate_collaborator(api: &GitHub, repository: &str, reviewer: &str) -> Result<()> {
    let collaborator: Value = api.get(&format!(
        "/repos/{repository}/collaborators/{reviewer}/permission"
    ))?;
    ensure!(
        matches!(collaborator["permission"].as_str(), Some("write" | "admin")),
        "configured approval reviewer lacks effective write permission on {repository}"
    );
    Ok(())
}

fn validate_reviewer_identity(identity: &Value, reviewer: &config::Principal) -> Result<()> {
    ensure!(
        identity["login"] == reviewer.login && identity["id"].as_u64() == Some(reviewer.id),
        "token must authenticate as the configured approval reviewer"
    );
    Ok(())
}

fn repository_creation_path(
    account_type: &str,
    repository_owner: &config::Principal,
    maintainer: &config::Principal,
) -> Result<String> {
    match account_type {
        "Organization" => Ok(format!("/orgs/{}/repos", repository_owner.login)),
        "User" => {
            ensure!(
                repository_owner.id == maintainer.id && repository_owner.login == maintainer.login,
                "the configured human settings token cannot create a repository for a different user"
            );
            Ok("/user/repos".to_owned())
        }
        _ => anyhow::bail!("configured repository owner has an unknown account type"),
    }
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

fn invite_collaborator(api: &GitHub, repository: &str, username: &str) -> Result<()> {
    let collaborator = read_json("repo-settings/collaborator.json")?;
    let permission = collaborator["permission"]
        .as_str()
        .context("collaborator permission missing")?;
    api.put::<Value>(
        &format!("/repos/{repository}/collaborators/{username}"),
        &json!({"permission":permission}),
    )?;
    Ok(())
}

fn accept_invitation(owner_api: &GitHub, repository: &str, username: &str) -> Result<()> {
    let api = GitHub::from_env("SECUREFIX_REVIEWER_INVITE_TOKEN")?;
    let trusted = config::trusted()?;
    ensure!(
        username == trusted.deployment.approval_reviewer.login,
        "invitation target differs from the configured approval reviewer"
    );
    accept_reviewer_invitation(
        owner_api,
        &api,
        repository,
        &trusted.deployment.approval_reviewer,
    )
}

fn accept_reviewer_invitation(
    owner_api: &GitHub,
    invitation_api: &GitHub,
    repository: &str,
    reviewer: &config::Principal,
) -> Result<()> {
    let identity: Value = invitation_api.get("/user")?;
    validate_reviewer_identity(&identity, reviewer)?;
    let invitations: Vec<Value> = invitation_api.paginate("/user/repository_invitations")?;
    let full_name = repository.to_lowercase();
    if let Some(invitation) = invitations.iter().find(|item| {
        item["repository"]["full_name"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(&full_name))
    }) {
        let id = invitation["id"].as_u64().context("invitation ID missing")?;
        invitation_api.patch::<Value>(&format!("/user/repository_invitations/{id}"), &json!({}))?;
    }
    validate_collaborator(owner_api, repository, &reviewer.login)
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
        collaborator["permission"] == "push",
        "collaborator.json must grant push access"
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
    fn collaborator_readback_uses_github_effective_roles() {
        for (permission, accepted) in [
            ("write", true),
            ("admin", true),
            ("read", false),
            ("none", false),
            ("push", false),
            ("maintain", false),
        ] {
            let fixture = Fixture::new(vec![Route::get(
                "/repos/forge/example/collaborators/reviewer/permission",
                json!({"permission":permission}),
            )]);
            assert_eq!(
                validate_collaborator(&fixture.api, "forge/example", "reviewer").is_ok(),
                accepted
            );
            fixture.finish();
        }
    }

    #[test]
    fn reviewer_token_authenticates_identity_and_owner_checks_access() {
        let reviewer = config::Principal {
            login: "reviewer".into(),
            id: 100,
        };
        let owner = Fixture::new(vec![Route::get(
            "/repos/forge/example/collaborators/reviewer/permission",
            json!({"permission":"write"}),
        )]);
        let token = Fixture::new(vec![Route::get(
            "/user",
            json!({"login":"reviewer","id":100}),
        )]);
        validate_reviewer_access(&owner.api, &token.api, &["forge/example".into()], &reviewer)
            .unwrap();
        token.finish();
        owner.finish();
    }

    #[test]
    fn invitation_only_token_does_not_query_repository_permissions() {
        let reviewer = config::Principal {
            login: "reviewer".into(),
            id: 100,
        };
        for (permission, accepted) in [("write", true), ("read", false)] {
            let owner = Fixture::new(vec![Route::get(
                "/repos/forge/example/collaborators/reviewer/permission",
                json!({"permission":permission}),
            )]);
            let token = Fixture::new(vec![
                Route::get("/user", json!({"login":"reviewer","id":100})),
                Route::get(
                    "/user/repository_invitations?per_page=100&page=1",
                    json!([]),
                ),
            ]);
            assert_eq!(
                accept_reviewer_invitation(&owner.api, &token.api, "forge/example", &reviewer)
                    .is_ok(),
                accepted
            );
            token.finish();
            owner.finish();
        }
    }

    #[test]
    fn matching_invitation_is_accepted_before_owner_access_readback() {
        let reviewer = config::Principal {
            login: "reviewer".into(),
            id: 100,
        };
        let server = &config::trusted().unwrap().deployment.server;
        let owner = Fixture::new(vec![Route::get(
            "/repos/forge/example/collaborators/reviewer/permission",
            json!({"permission":"write"}),
        )]);
        let token = Fixture::new(vec![
            Route::get("/user", json!({"login":"reviewer","id":100})),
            Route::get(
                "/user/repository_invitations?per_page=100&page=1",
                json!([
                    {"id":1,"repository":{"full_name":"forge/other"}},
                    {"id":2,"repository":{"full_name":"forge/example"}}
                ]),
            ),
            Route::get(
                format!(
                    "/repos/{}/commits/{}",
                    server.repository, server.default_branch
                ),
                json!({"sha":"a".repeat(40)}),
            ),
            Route::request("PATCH", "/user/repository_invitations/2", 204, Value::Null),
        ]);
        accept_reviewer_invitation(&owner.api, &token.api, "forge/example", &reviewer).unwrap();
        token.finish();
        owner.finish();
    }

    #[test]
    fn default_readiness_uses_named_checks_and_rejects_newer_failure() {
        let sha = "a".repeat(40);
        let checks = Checks {
            status_app_id: 11,
            policy_app_id: 22,
        };
        for (latest_app, conclusion, accepted) in [
            (11, "success", true),
            (11, "failure", false),
            (99, "success", false),
            (11, "skipped", false),
        ] {
            let mut routes = vec![
                Route::get("/repos/forge/example", json!({"default_branch":"main"})),
                Route::get(
                    "/repos/forge/example/git/ref/heads/main",
                    json!({"object":{"sha":sha}}),
                ),
                Route::get(
                    format!(
                        "/repos/forge/example/commits/{sha}/check-runs?per_page=100&filter=latest&check_name=status-check&app_id=11"
                    ),
                    json!({"total_count":2,"check_runs":[
                        {"id":1,"name":"status-check","status":"completed","conclusion":"success","app":{"id":latest_app}},
                        {"id":2,"name":"status-check","status":"completed","conclusion":conclusion,"app":{"id":latest_app}}
                    ]}),
                ),
            ];
            if accepted {
                routes.push(Route::get(format!("/repos/forge/example/commits/{sha}/check-runs?per_page=100&filter=latest&check_name=securefix-policy-check&app_id=22"),
                    json!({"total_count":1,"check_runs":[{"id":3,"name":"securefix-policy-check","status":"completed","conclusion":"success","app":{"id":22}}]})));
            }
            let fixture = Fixture::new(routes);
            assert_eq!(
                validate_current_policy_check(&fixture.api, "forge/example", &checks).is_ok(),
                accepted
            );
            fixture.finish();
        }
    }

    #[test]
    fn default_readiness_rejects_incomplete_named_response() {
        let sha = "a".repeat(40);
        let fixture = Fixture::new(vec![
            Route::get("/repos/forge/example", json!({"default_branch":"main"})),
            Route::get(
                "/repos/forge/example/git/ref/heads/main",
                json!({"object":{"sha":sha}}),
            ),
            Route::get(
                format!(
                    "/repos/forge/example/commits/{sha}/check-runs?per_page=100&filter=latest&check_name=status-check&app_id=11"
                ),
                json!({"total_count":101,"check_runs":[{"id":1,"name":"status-check","status":"completed","conclusion":"success","app":{"id":11}}]}),
            ),
        ]);
        assert!(
            validate_current_policy_check(
                &fixture.api,
                "forge/example",
                &Checks {
                    status_app_id: 11,
                    policy_app_id: 22
                }
            )
            .is_err()
        );
        fixture.finish();
    }

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
    fn repository_creation_uses_org_endpoint_and_only_creates_user_repos_for_maintainer() {
        let org = config::Principal {
            login: "forge-org".into(),
            id: 200,
        };
        let maintainer = config::Principal {
            login: "alice".into(),
            id: 100,
        };
        assert_eq!(
            repository_creation_path("Organization", &org, &maintainer).unwrap(),
            "/orgs/forge-org/repos"
        );
        assert_eq!(
            repository_creation_path("User", &maintainer, &maintainer).unwrap(),
            "/user/repos"
        );
        assert!(repository_creation_path("User", &org, &maintainer).is_err());
    }

    #[test]
    fn reviewer_invitation_identity_is_not_the_client_app_bot() {
        let reviewer = config::Principal {
            login: "approval-reviewer".into(),
            id: 100,
        };
        assert!(
            validate_reviewer_identity(&json!({"login":"approval-reviewer","id":100}), &reviewer)
                .is_ok()
        );
        assert!(
            validate_reviewer_identity(&json!({"login":"client-bot[bot]","id":200}), &reviewer)
                .is_err()
        );
    }

    #[test]
    fn activation_readiness_covers_the_full_merge_set_and_keeps_server_last() {
        let policy = Policy::load("tests/fixtures/policy.json").unwrap();
        let expected = policy
            .repositories
            .iter()
            .filter(|repo| repo.capabilities.contains(&Capability::Merge))
            .map(|repo| repo.repository.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let activation = merge_repositories(
            &policy,
            &config::trusted().unwrap().deployment.server.repository,
        )
        .unwrap();
        let actual = activation
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual, expected);
        assert_eq!(
            activation.last().map(String::as_str),
            Some(
                config::trusted()
                    .unwrap()
                    .deployment
                    .server
                    .repository
                    .as_str()
            )
        );
        assert!(
            activation[..activation.len() - 1]
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }

    #[test]
    fn default_ruleset_requires_all_review_and_check_sources() {
        let checks = config::Checks {
            status_app_id: 17,
            policy_app_id: 23,
        };
        let valid = json!({
            "enforcement":"active", "bypass_actors":[], "rules":[
                {"type":"required_signatures"},
                {"type":"pull_request","parameters":{"required_approving_review_count":1,"dismiss_stale_reviews_on_push":true}},
                {"type":"required_status_checks","parameters":{"required_status_checks":[
                    {"context":"status-check","integration_id":17},
                    {"context":"securefix-policy-check","integration_id":23}
                ]}}
            ]
        });
        assert!(validate_default_ruleset(&valid, "forge/example", &checks).is_ok());
        let mut wrong_source = valid.clone();
        wrong_source["rules"][2]["parameters"]["required_status_checks"][1]["integration_id"] =
            json!(15368);
        assert!(validate_default_ruleset(&wrong_source, "forge/example", &checks).is_err());
        let mut stale_reviews = valid;
        stale_reviews["rules"][1]["parameters"]["dismiss_stale_reviews_on_push"] = json!(false);
        assert!(validate_default_ruleset(&stale_reviews, "forge/example", &checks).is_err());
    }

    #[test]
    fn server_wrapper_pin_uses_the_trusted_deployment_repository() {
        assert_eq!(
            wrapper_pin(
                "forge/securefix",
                "reusable-approve-request.yml",
                &"a".repeat(40)
            ),
            format!(
                "forge/securefix/.github/workflows/reusable-approve-request.yml@{}",
                "a".repeat(40)
            )
        );
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
