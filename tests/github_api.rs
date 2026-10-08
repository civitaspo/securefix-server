use anyhow::{Context, Result, ensure};
use securefix::api::{ApiError, GitHub};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

const SCRATCH_REPOSITORY: &str = "civitaspo/testing-securefix-server";

#[test]
#[ignore = "requires SECUREFIX_LIVE_TEST_TOKEN and the dedicated scratch repository"]
fn stale_pull_request_merge_is_rejected_without_changing_the_pr() -> Result<()> {
    let repository = std::env::var("SECUREFIX_LIVE_TEST_REPOSITORY")
        .context("SECUREFIX_LIVE_TEST_REPOSITORY must name the dedicated scratch repository")?;
    ensure!(
        repository == SCRATCH_REPOSITORY,
        "live test is restricted to {SCRATCH_REPOSITORY}"
    );
    let token = std::env::var("SECUREFIX_LIVE_TEST_TOKEN")
        .context("SECUREFIX_LIVE_TEST_TOKEN is required")?;
    ensure!(!token.is_empty(), "SECUREFIX_LIVE_TEST_TOKEN is empty");

    let read_api = GitHub::new("https://api.github.com", token)?;
    let runtime: Value = read_api.get("/repos/civitaspo/securefix-server/commits/main")?;
    let runtime_sha = runtime["sha"]
        .as_str()
        .context("securefix-server main response has no SHA")?;
    let api = read_api.with_runtime_revision(runtime_sha)?;
    let repo: Value = api.get(&format!("/repos/{repository}"))?;
    ensure!(
        repo["full_name"] == SCRATCH_REPOSITORY,
        "scratch repository identity changed"
    );
    let base = repo["default_branch"]
        .as_str()
        .context("scratch repository has no default branch")?;
    let base_commit: Value = api.get(&format!("/repos/{repository}/commits/{base}"))?;
    let base_sha = base_commit["sha"]
        .as_str()
        .context("default branch has no SHA")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let branch = format!("securefix-stale-merge-{nonce}");
    let path = format!("securefix-stale-merge/{nonce}.txt");

    let first = create_commit(&api, &repository, base_sha, &path, "head A\n")?;
    let _: Value = api.post(
        &format!("/repos/{repository}/git/refs"),
        &json!({"ref":format!("refs/heads/{branch}"),"sha":first}),
    )?;
    let pull_request: Value = api.post(
        &format!("/repos/{repository}/pulls"),
        &json!({"title":format!("test: reject stale merge {nonce}"),"head":branch,"base":base}),
    )?;
    let number = pull_request["number"]
        .as_u64()
        .context("created PR has no number")?;

    let second = create_commit(&api, &repository, &first, &path, "head B\n")?;
    let _: Value = api.patch(
        &format!("/repos/{repository}/git/refs/heads/{branch}"),
        &json!({"sha":second,"force":false}),
    )?;
    let mut current: Value = api.get(&format!("/repos/{repository}/pulls/{number}"))?;
    for _ in 0..30 {
        ensure!(current["state"] == "open", "scratch PR is no longer open");
        if current["head"]["sha"] == second {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        current = api.get(&format!("/repos/{repository}/pulls/{number}"))?;
    }
    ensure!(
        current["head"]["sha"] == second,
        "scratch PR did not reflect its advanced head within 30 attempts"
    );
    let stale_merge = api.put::<Value>(
        &format!("/repos/{repository}/pulls/{number}/merge"),
        &json!({"sha":first,"merge_method":"squash"}),
    );
    ensure!(
        stale_merge
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<ApiError>())
            .is_some_and(|error| error.status == reqwest::StatusCode::CONFLICT),
        "merge API did not reject the stale head SHA with HTTP 409"
    );
    let current: Value = api.get(&format!("/repos/{repository}/pulls/{number}"))?;
    ensure!(
        current["state"] == "open" && current["head"]["sha"] == second,
        "stale merge changed the PR"
    );
    eprintln!(
        "Scratch stale-merge evidence: {repository} PR={} headB={}",
        current["html_url"].as_str().unwrap_or_default(),
        second
    );
    Ok(())
}

fn create_commit(
    api: &GitHub,
    repository: &str,
    parent: &str,
    path: &str,
    contents: &str,
) -> Result<String> {
    let blob: Value = api.post(
        &format!("/repos/{repository}/git/blobs"),
        &json!({"content":contents,"encoding":"utf-8"}),
    )?;
    let tree: Value = api.post(
        &format!("/repos/{repository}/git/trees"),
        &json!({"base_tree":parent,"tree":[{"path":path,"mode":"100644","type":"blob","sha":blob["sha"]}]}),
    )?;
    let commit: Value = api.post(
        &format!("/repos/{repository}/git/commits"),
        &json!({"message":"test: advance scratch fixture head","tree":tree["sha"],"parents":[parent]}),
    )?;
    commit["sha"]
        .as_str()
        .map(str::to_owned)
        .context("created commit has no SHA")
}

#[test]
#[ignore = "requires the dedicated scratch repository and a read-only Client App installation token"]
fn client_app_token_is_scoped_to_scratch_repository() -> Result<()> {
    let repository = std::env::var("SECUREFIX_LIVE_TEST_REPOSITORY")
        .context("SECUREFIX_LIVE_TEST_REPOSITORY is required")?;
    ensure!(
        repository == SCRATCH_REPOSITORY,
        "live test is restricted to {SCRATCH_REPOSITORY}"
    );
    let token = std::env::var("SECUREFIX_CLIENT_INSTALLATION_TOKEN")
        .context("SECUREFIX_CLIENT_INSTALLATION_TOKEN is required")?;
    ensure!(
        !token.is_empty(),
        "SECUREFIX_CLIENT_INSTALLATION_TOKEN is empty"
    );

    let api = GitHub::new("https://api.github.com", token)?;
    let installation: Value = api.get("/installation/repositories")?;
    let repositories = installation["repositories"]
        .as_array()
        .context("installation response has no repositories array")?;
    ensure!(
        installation["total_count"].as_u64() == Some(1)
            && repositories.len() == 1
            && repositories[0]["full_name"] == SCRATCH_REPOSITORY,
        "Client App token must be scoped to exactly the scratch repository"
    );
    let repo: Value = api.get(&format!("/repos/{SCRATCH_REPOSITORY}"))?;
    ensure!(
        repo["full_name"] == SCRATCH_REPOSITORY && repo["id"].as_u64().is_some_and(|id| id > 0),
        "scratch repository identity is missing or unexpected"
    );
    Ok(())
}
