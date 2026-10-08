use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use securefix::{
    api::GitHub,
    event, output,
    policy::{Capability, Policy, SERVER, validate_repository, validate_sha},
};
use serde_json::Value;

const CLIENT_BOT_ID: u64 = 288_068_203;
const OWNER_ID: u64 = 4_525_500;
const LABEL_PREFIX: &str = "securefix-";
const CLIENT_CI_WORKFLOW: &str = ".github/workflows/pull_request.yml";
const RELEASE_PR_WORKFLOW: &str = ".github/workflows/release-pr.yml";
const REUSABLE_RELEASE_PR: &str = ".github/workflows/reusable-release-pr.yml";

#[derive(Debug)]
struct PreparedFix {
    client_repository: String,
    push_repository: String,
    branch: String,
    workflow_run: String,
    pull_request: Option<String>,
    create_pull_request: Option<String>,
}

#[derive(Subcommand)]
pub enum Command {
    ValidateEvent,
    ValidatePrepared,
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::ValidateEvent => validate_event(),
        Command::ValidatePrepared => validate_prepared(),
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
    p.repository(source_repo)?.require(Capability::Securefix)?;
    Ok((source_repo.to_owned(), run_id, label.to_owned()))
}

fn validate_prepared() -> Result<()> {
    let api = GitHub::from_env("GITHUB_TOKEN")?;
    let p = policy(&api)?;
    let payload = event()?;
    let server = std::env::var("GITHUB_REPOSITORY")?;
    let (source_repository, source_run_id, _) = parse_label_event(&p, &payload, &server)?;
    let prepared = PreparedFix {
        client_repository: std::env::var("SECUREFIX_CLIENT_REPOSITORY")?,
        push_repository: std::env::var("SECUREFIX_PUSH_REPOSITORY")?,
        branch: std::env::var("SECUREFIX_BRANCH")?,
        workflow_run: std::env::var("SECUREFIX_WORKFLOW_RUN")?,
        pull_request: optional_env("SECUREFIX_PULL_REQUEST"),
        create_pull_request: optional_env("SECUREFIX_CREATE_PULL_REQUEST"),
    };

    let (source_sha, source_workflow) =
        validate_prepared_source(&api, &p, &source_repository, source_run_id, &prepared)?;
    output("source_sha", source_sha)?;
    output("source_workflow", source_workflow)?;
    Ok(())
}

fn validate_prepared_source(
    api: &GitHub,
    p: &Policy,
    source_repository: &str,
    source_run_id: u64,
    prepared: &PreparedFix,
) -> Result<(String, String)> {
    let workflow_run: Value = serde_json::from_str(&prepared.workflow_run)
        .context("invalid source workflow run output")?;
    validate_run_identity(&workflow_run, source_run_id, source_repository)?;
    let source_sha = workflow_run["head_sha"]
        .as_str()
        .context("source workflow run SHA missing")?;
    validate_sha(source_sha)?;
    let source_branch = workflow_run["head_branch"]
        .as_str()
        .context("source workflow run branch missing")?;
    ensure!(
        !source_branch.is_empty() && source_branch.len() <= 255,
        "invalid source workflow branch"
    );
    let workflow_path = workflow_run["path"]
        .as_str()
        .context("source workflow path missing")?;
    let workflow_file = normalize_source_workflow(workflow_path)
        .context("source run is not an approved workflow")?;

    let repo: Value = api.get(&format!("/repos/{source_repository}"))?;
    let default_branch = repo["default_branch"]
        .as_str()
        .context("client default branch missing")?;
    let is_release = source_branch == default_branch;
    validate_destination(
        &prepared.client_repository,
        &prepared.push_repository,
        &prepared.branch,
        source_repository,
        source_branch,
        default_branch,
    )?;
    ensure!(
        !is_release || workflow_file == RELEASE_PR_WORKFLOW,
        "default-branch Securefix runs are limited to the release PR workflow"
    );
    if is_release {
        p.repository(source_repository)?
            .require(Capability::Release)?;
        validate_release_provenance(api, p, &workflow_run, source_repository, source_sha)?;
        if let Some(options) = nonempty(prepared.create_pull_request.as_deref()) {
            validate_pull_request_options(options, default_branch)?;
        }
    } else {
        ensure!(
            workflow_file == CLIENT_CI_WORKFLOW && workflow_run["event"] == "pull_request",
            "client PR fixes must come from the pull-request CI workflow"
        );
        ensure!(
            prepared.branch == source_branch,
            "client PR fixes may only update their source branch"
        );
        let number = workflow_run["pull_requests"][0]["number"]
            .as_u64()
            .context("source run has no pull request")?;
        let pr: Value = api.get(&format!("/repos/{source_repository}/pulls/{number}"))?;
        ensure!(
            source_pr_matches(&pr, source_repository, default_branch, source_branch),
            "source workflow no longer belongs to an open same-repository pull request"
        );
        let prepared_pr: Value = serde_json::from_str(
            nonempty(prepared.pull_request.as_deref())
                .context("prepare output lacks pull request")?,
        )
        .context("invalid prepared pull request")?;
        ensure!(
            prepared_pr["number"].as_u64() == Some(number)
                && prepared_pr["head"]["repo"]["full_name"] == source_repository
                && prepared_pr["head"]["ref"] == source_branch
                && prepared_pr["base"]["ref"] == default_branch,
            "prepared pull request does not match the source workflow"
        );
        ensure!(
            nonempty(prepared.create_pull_request.as_deref()).is_none(),
            "client PR fixes cannot create additional pull requests"
        );
    }

    Ok((
        source_sha.to_owned(),
        workflow_run["name"].as_str().unwrap_or_default().to_owned(),
    ))
}

fn validate_release_provenance(
    api: &GitHub,
    policy: &Policy,
    run: &Value,
    repository: &str,
    source_sha: &str,
) -> Result<()> {
    let current: Value = api.get(&format!(
        "/repos/{repository}/commits/{}",
        run["head_branch"].as_str().unwrap_or_default()
    ))?;
    let current_sha = current["sha"]
        .as_str()
        .context("client default branch has no SHA")?;
    let ancestry: Value = api.get(&format!(
        "/repos/{repository}/compare/{source_sha}...{current_sha}"
    ))?;
    ensure!(
        matches!(ancestry["status"].as_str(), Some("ahead" | "identical")),
        "release PR caller is not on default-branch history"
    );
    let wrapper = api.content(repository, RELEASE_PR_WORKFLOW, source_sha)?;
    securefix::workflow::require_reusable_pin(&wrapper, REUSABLE_RELEASE_PR, &policy.revision)?;
    let referenced: Vec<securefix::workflow::ReferencedWorkflow> =
        serde_json::from_value(run["referenced_workflows"].clone())
            .context("release PR run lacks reusable workflow provenance")?;
    securefix::workflow::referenced_revision(&referenced, REUSABLE_RELEASE_PR, &policy.revision)?;
    Ok(())
}

fn validate_pull_request_options(value: &str, default_branch: &str) -> Result<()> {
    let value: Value =
        serde_json::from_str(value).context("invalid prepared pull request creation options")?;
    let options = value
        .as_object()
        .context("prepared pull request options must be an object")?;
    let allowed = [
        "title",
        "body",
        "base",
        "labels",
        "assignees",
        "reviewers",
        "team_reviewers",
        "draft",
        "automerge_method",
        "comment",
        "project",
        "milestone_number",
    ];
    ensure!(
        options.keys().all(|key| allowed.contains(&key.as_str())),
        "prepared pull request options contain an unknown field"
    );
    let title = options
        .get("title")
        .and_then(Value::as_str)
        .context("release pull request title missing")?;
    let base = options
        .get("base")
        .and_then(Value::as_str)
        .context("release pull request base missing")?;
    ensure!(
        !title.trim().is_empty() && title.len() <= 256,
        "invalid release pull request title"
    );
    ensure!(
        base == default_branch,
        "release pull request must target the default branch"
    );
    ensure!(
        options
            .get("body")
            .is_none_or(|body| body.as_str().is_some_and(|body| body.len() <= 64 * 1024))
            && options.get("draft").is_none_or(Value::is_boolean),
        "invalid release pull request body or draft option"
    );
    ensure!(
        ["labels", "assignees", "reviewers", "team_reviewers"]
            .iter()
            .all(|key| options
                .get(*key)
                .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty)))
            && options
                .get("automerge_method")
                .is_none_or(|value| value.as_str() == Some(""))
            && options
                .get("comment")
                .is_none_or(|value| value.as_str() == Some(""))
            && options.get("project").is_none_or(Value::is_null)
            && options.get("milestone_number").is_none_or(Value::is_null),
        "release pull request options contain unsupported side effects"
    );
    Ok(())
}

fn source_pr_matches(pr: &Value, repository: &str, default_branch: &str, branch: &str) -> bool {
    pr["state"] == "open"
        && pr["base"]["ref"] == default_branch
        && pr["base"]["repo"]["full_name"] == repository
        && pr["head"]["repo"]["full_name"] == repository
        && pr["head"]["ref"] == branch
}

fn normalize_source_workflow(path: &str) -> Option<&str> {
    if path == CLIENT_CI_WORKFLOW || path == RELEASE_PR_WORKFLOW {
        return Some(path);
    }
    let (workflow, reference) = path.split_once('@')?;
    (!reference.is_empty()
        && !reference.contains('@')
        && (workflow == CLIENT_CI_WORKFLOW || workflow == RELEASE_PR_WORKFLOW))
        .then_some(workflow)
}

fn validate_destination(
    client_repository: &str,
    push_repository: &str,
    destination: &str,
    source_repository: &str,
    source_branch: &str,
    default_branch: &str,
) -> Result<()> {
    validate_repository(client_repository)?;
    validate_repository(push_repository)?;
    ensure!(
        client_repository.eq_ignore_ascii_case(source_repository)
            && push_repository.eq_ignore_ascii_case(source_repository),
        "Securefix may only update its source repository"
    );
    ensure!(
        !destination.is_empty()
            && destination.len() <= 255
            && !destination.starts_with('/')
            && !destination.contains(['\\', '\0']),
        "invalid Securefix destination branch"
    );
    ensure!(
        destination != default_branch,
        "Securefix may not directly update a default branch"
    );
    ensure!(
        source_branch == default_branch || destination == source_branch,
        "Securefix destination branch is outside the allowed scope"
    );
    Ok(())
}

fn validate_run_identity(run: &Value, run_id: u64, repository: &str) -> Result<()> {
    ensure!(
        run["id"].as_u64() == Some(run_id)
            && run["repository"]["full_name"] == repository
            && run["head_repository"]["full_name"] == repository
            && run["run_attempt"].as_u64() == Some(1),
        "source workflow run identity or repository mismatch"
    );
    Ok(())
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn source_pull_request_can_advance_after_the_fix_run() {
        let pull_request = json!({
            "state":"open",
            "base":{"ref":"main","repo":{"full_name":"civitaspo/example"}},
            "head":{"ref":"feature","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","repo":{"full_name":"civitaspo/example"}}
        });
        assert!(source_pr_matches(
            &pull_request,
            "civitaspo/example",
            "main",
            "feature"
        ));
        assert_eq!(nonempty(Some("")), None);
        assert_eq!(nonempty(Some("{}")), Some("{}"));
    }

    #[test]
    fn source_pull_request_must_be_open_same_repo_and_target_default_branch() {
        let valid = json!({"state":"open","base":{"ref":"main","repo":{"full_name":"civitaspo/example"}},"head":{"ref":"feature","repo":{"full_name":"civitaspo/example"}}});
        assert!(source_pr_matches(
            &valid,
            "civitaspo/example",
            "main",
            "feature"
        ));
        for invalid in [
            json!({"state":"closed","base":{"ref":"main","repo":{"full_name":"civitaspo/example"}},"head":{"ref":"feature","repo":{"full_name":"civitaspo/example"}}}),
            json!({"state":"open","base":{"ref":"main","repo":{"full_name":"civitaspo/example"}},"head":{"ref":"feature","repo":{"full_name":"attacker/fork"}}}),
            json!({"state":"open","base":{"ref":"other","repo":{"full_name":"civitaspo/example"}},"head":{"ref":"feature","repo":{"full_name":"civitaspo/example"}}}),
        ] {
            assert!(!source_pr_matches(
                &invalid,
                "civitaspo/example",
                "main",
                "feature"
            ));
        }
    }

    #[test]
    fn workflow_path_accepts_github_ref_suffix_only_for_exact_allowed_files() {
        assert_eq!(
            normalize_source_workflow(CLIENT_CI_WORKFLOW),
            Some(CLIENT_CI_WORKFLOW)
        );
        assert_eq!(
            normalize_source_workflow(".github/workflows/pull_request.yml@refs/heads/feature"),
            Some(CLIENT_CI_WORKFLOW)
        );
        assert_eq!(
            normalize_source_workflow(".github/workflows/release-pr.yml@main"),
            Some(RELEASE_PR_WORKFLOW)
        );
        for invalid in [
            ".github/workflows/other.yml@main",
            ".github/workflows/pull_request.yml@",
            ".github/workflows/pull_request.yml@main@extra",
        ] {
            assert_eq!(normalize_source_workflow(invalid), None);
        }
    }

    #[test]
    fn release_pull_request_options_reject_extra_side_effects() {
        let valid = r#"{"title":"Release","base":"main","body":"release","draft":true}"#;
        assert!(validate_pull_request_options(valid, "main").is_ok());
        let with_label = r#"{"title":"Release","base":"main","labels":["release"]}"#;
        assert!(validate_pull_request_options(with_label, "main").is_err());
        let wrong_base = r#"{"title":"Release","base":"other"}"#;
        assert!(validate_pull_request_options(wrong_base, "main").is_err());
        assert!(
            validate_pull_request_options(r#"{"body":"missing required fields"}"#, "main").is_err()
        );
    }

    #[test]
    fn source_run_identity_accepts_running_or_failed_client_ci() {
        for (status, conclusion) in [
            ("in_progress", Value::Null),
            ("completed", json!("failure")),
        ] {
            let run = json!({
                "id":123,
                "repository":{"full_name":"civitaspo/example"},
                "head_repository":{"full_name":"civitaspo/example"},
                "run_attempt":1,
                "status":status,
                "conclusion":conclusion
            });
            assert!(validate_run_identity(&run, 123, "civitaspo/example").is_ok());
        }
        let fork = json!({
            "id":123,
            "repository":{"full_name":"civitaspo/example"},
            "head_repository":{"full_name":"attacker/example"},
            "run_attempt":1
        });
        assert!(validate_run_identity(&fork, 123, "civitaspo/example").is_err());
    }

    #[test]
    fn prepared_ci_run_accepts_in_progress_and_failed_runs_after_pr_head_advances() {
        use crate::fixtures::{Fixture, Route};

        let policy = Policy::load("policy.json").unwrap();
        for (status, conclusion) in [
            ("in_progress", Value::Null),
            ("completed", json!("failure")),
        ] {
            let run = json!({
                "id":17,
                "run_attempt":1,
                "status":status,
                "conclusion":conclusion,
                "repository":{"full_name":"civitaspo/dotfiles"},
                "head_repository":{"full_name":"civitaspo/dotfiles"},
                "head_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "head_branch":"ai/fix",
                "path":format!("{CLIENT_CI_WORKFLOW}@refs/heads/ai/fix"),
                "event":"pull_request",
                "pull_requests":[{"number":8}],
                "name":"Pull Request"
            });
            let current_pr = json!({
                "number":8,
                "state":"open",
                "base":{"ref":"main","repo":{"full_name":"civitaspo/dotfiles"}},
                "head":{"ref":"ai/fix","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","repo":{"full_name":"civitaspo/dotfiles"}}
            });
            let prepared = PreparedFix {
                client_repository: "civitaspo/dotfiles".into(),
                push_repository: "civitaspo/dotfiles".into(),
                branch: "ai/fix".into(),
                workflow_run: run.to_string(),
                pull_request: Some(current_pr.to_string()),
                create_pull_request: Some(String::new()),
            };
            let fixture = Fixture::new(vec![
                Route::get(
                    "/repos/civitaspo/dotfiles",
                    json!({"default_branch":"main"}),
                ),
                Route::get("/repos/civitaspo/dotfiles/pulls/8", current_pr),
            ]);
            assert_eq!(
                validate_prepared_source(
                    &fixture.api,
                    &policy,
                    "civitaspo/dotfiles",
                    17,
                    &prepared
                )
                .unwrap()
                .0,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            );
            fixture.finish();
        }
    }

    #[test]
    fn prepared_release_run_accepts_pending_or_failed_run_with_pinned_provenance() {
        use crate::fixtures::{Fixture, Route};
        use base64::Engine;

        let repository = "civitaspo/dbt-authorized-models";
        let mut policy = Policy::load("policy.json").unwrap();
        policy.revision = "a".repeat(40);
        let source_sha = "b".repeat(40);
        let current_sha = "c".repeat(40);
        let caller = format!(
            "jobs:\n  release:\n    uses: {SERVER}/{REUSABLE_RELEASE_PR}@{}\n",
            policy.revision
        );
        for (status, conclusion) in [
            ("in_progress", Value::Null),
            ("completed", json!("failure")),
        ] {
            let run = json!({
                "id":18,
                "run_attempt":1,
                "status":status,
                "conclusion":conclusion,
                "repository":{"full_name":repository},
                "head_repository":{"full_name":repository},
                "head_sha":source_sha,
                "head_branch":"main",
                "path":format!("{RELEASE_PR_WORKFLOW}@main"),
                "event":"push",
                "name":"Release PR",
                "referenced_workflows":[{
                    "path":format!("{SERVER}/{REUSABLE_RELEASE_PR}@{}", policy.revision),
                    "sha":policy.revision
                }]
            });
            let prepared = PreparedFix {
                client_repository: repository.into(),
                push_repository: repository.into(),
                branch: "release/feature/2026-10".into(),
                workflow_run: run.to_string(),
                pull_request: Some(String::new()),
                create_pull_request: Some(
                    json!({
                        "title":"chore(release): v1.2.3",
                        "body":"Release notes",
                        "base":"main",
                        "draft":false,
                        "labels":[],"assignees":[],"reviewers":[],"team_reviewers":[],
                        "automerge_method":"","comment":"","project":null
                    })
                    .to_string(),
                ),
            };
            let fixture = Fixture::new(vec![
                Route::get(
                    format!("/repos/{repository}"),
                    json!({"default_branch":"main"}),
                ),
                Route::get(
                    format!("/repos/{repository}/commits/main"),
                    json!({"sha":current_sha}),
                ),
                Route::get(
                    format!("/repos/{repository}/compare/{source_sha}...{current_sha}"),
                    json!({"status":"ahead"}),
                ),
                Route::get(
                    format!("/repos/{repository}/contents/{RELEASE_PR_WORKFLOW}?ref={source_sha}"),
                    json!({
                        "content":base64::engine::general_purpose::STANDARD.encode(&caller),
                        "encoding":"base64"
                    }),
                ),
            ]);
            assert_eq!(
                validate_prepared_source(&fixture.api, &policy, repository, 18, &prepared)
                    .unwrap()
                    .0,
                source_sha
            );
            fixture.finish();
        }
    }

    #[test]
    fn destination_must_be_same_repo_non_default_and_source_branch_for_prs() {
        assert!(
            validate_destination(
                "civitaspo/example",
                "civitaspo/example",
                "feature",
                "civitaspo/example",
                "feature",
                "main"
            )
            .is_ok()
        );
        assert!(
            validate_destination(
                "civitaspo/example",
                "attacker/example",
                "feature",
                "civitaspo/example",
                "feature",
                "main"
            )
            .is_err()
        );
        assert!(
            validate_destination(
                "civitaspo/example",
                "civitaspo/example",
                "main",
                "civitaspo/example",
                "feature",
                "main"
            )
            .is_err()
        );
        for destination in ["feature/ai-fix", "release/next", "release/2026-q4"] {
            assert!(
                validate_destination(
                    "civitaspo/example",
                    "civitaspo/example",
                    destination,
                    "civitaspo/example",
                    "main",
                    "main"
                )
                .is_ok()
            );
        }
        assert!(
            validate_destination(
                "civitaspo/example",
                "civitaspo/example",
                "main",
                "civitaspo/example",
                "main",
                "main"
            )
            .is_err()
        );
        assert!(
            validate_destination(
                "civitaspo/example",
                "civitaspo/example",
                "other",
                "civitaspo/example",
                "feature/source",
                "main"
            )
            .is_err()
        );
    }
}
