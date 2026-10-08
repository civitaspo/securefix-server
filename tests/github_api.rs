use anyhow::{Context, Result, ensure};
use base64::Engine;
use securefix::api::{ApiError, CommitAddition, CommitOnBranch, GitHub};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

const SCRATCH_REPOSITORY: &str = "civitaspo/testing-securefix-server";

#[test]
#[ignore = "requires SECUREFIX_LIVE_TEST_TOKEN and the dedicated scratch repository"]
fn live_commit_api_guard_cas_signature_and_stale_merge() -> Result<()> {
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
    let default_branch = repo["default_branch"]
        .as_str()
        .context("scratch repository has no default branch")?;
    let default_head = branch_head(&api, &repository, default_branch)?;

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let branch = format!("securefix-live-{}-{nonce}", std::process::id());
    let first_path = format!("securefix-live/{nonce}-initial.txt");
    let deleted_path = format!("securefix-live/{nonce}-deleted.txt");
    let final_path = format!("securefix-live/{nonce}-final.txt");

    let created_ref: Value = api.post(
        &format!("/repos/{repository}/git/refs"),
        &json!({"ref":format!("refs/heads/{branch}"),"sha":default_head}),
    )?;
    ensure!(
        created_ref["object"]["sha"] == default_head,
        "scratch branch did not start at the captured default head"
    );

    let first_commit = api.create_commit_on_branch(&CommitOnBranch {
        repository: repository.clone(),
        branch: branch.clone(),
        expected_head: default_head.clone(),
        headline: "test: create Securefix live API fixture".into(),
        body: "Ignored live API boundary test fixture.".into(),
        additions: vec![
            addition(&first_path, b"initial fixture content\n"),
            addition(&deleted_path, b"delete this fixture file\n"),
        ],
        deletions: vec![],
    })?;
    ensure!(
        branch_head(&api, &repository, &branch)? == first_commit,
        "first commit is not at branch head"
    );

    let stale_result = api.create_commit_on_branch(&CommitOnBranch {
        repository: repository.clone(),
        branch: branch.clone(),
        expected_head: default_head,
        headline: "test: reject stale Securefix head".into(),
        body: "This commit must not be created.".into(),
        additions: vec![addition(
            &format!("securefix-live/{nonce}-stale.txt"),
            b"must not appear\n",
        )],
        deletions: vec![],
    });
    ensure!(
        stale_result.is_err(),
        "stale expectedHeadOid unexpectedly committed"
    );
    ensure!(
        branch_head(&api, &repository, &branch)? == first_commit,
        "stale attempt changed the branch ref"
    );

    let final_commit = api.create_commit_on_branch(&CommitOnBranch {
        repository: repository.clone(),
        branch: branch.clone(),
        expected_head: first_commit.clone(),
        headline: "test: verify Securefix additions and deletions".into(),
        body: "Apply one exact addition and one exact deletion.".into(),
        additions: vec![addition(&final_path, b"final fixture content\n")],
        deletions: vec![deleted_path.clone()],
    })?;
    ensure!(
        branch_head(&api, &repository, &branch)? == final_commit,
        "final commit is not at branch head"
    );

    let final_file: Value = api.get(&format!(
        "/repos/{repository}/contents/{}?ref={branch}",
        encode_path(&final_path)
    ))?;
    let encoded = final_file["content"]
        .as_str()
        .context("added fixture file has no contents")?
        .replace('\n', "");
    let contents = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    ensure!(
        contents == b"final fixture content\n",
        "added fixture bytes differ"
    );
    let deleted = api.get::<Value>(&format!(
        "/repos/{repository}/contents/{}?ref={branch}",
        encode_path(&deleted_path)
    ));
    ensure!(
        deleted
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<ApiError>())
            .is_some_and(|error| error.status == reqwest::StatusCode::NOT_FOUND),
        "deleted fixture file still exists or lookup failed unexpectedly"
    );

    let pull_request: Value = api.post(
        &format!("/repos/{repository}/pulls"),
        &json!({
            "title": format!("test: Securefix live API fixture {nonce}"),
            "body": format!("Preserved API boundary fixture branch `{branch}` at `{final_commit}`."),
            "head": branch,
            "base": default_branch,
            "draft": false
        }),
    )?;
    let number = pull_request["number"]
        .as_u64()
        .context("created fixture PR has no number")?;
    let stale_merge = api.put::<Value>(
        &format!("/repos/{repository}/pulls/{number}/merge"),
        &json!({"sha":first_commit,"merge_method":"squash"}),
    );
    ensure!(
        stale_merge
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<ApiError>())
            .is_some_and(|error| error.status == reqwest::StatusCode::CONFLICT),
        "merge API did not reject the stale head SHA with HTTP 409"
    );
    let current_pr: Value = api.get(&format!("/repos/{repository}/pulls/{number}"))?;
    ensure!(
        current_pr["state"] == "open",
        "stale merge attempt changed PR state"
    );

    eprintln!(
        "Scratch evidence: {} branch={} first_commit={} final_commit={} signature=VALID (verified by createCommitOnBranch) PR={}",
        SCRATCH_REPOSITORY,
        branch,
        first_commit,
        final_commit,
        current_pr["html_url"].as_str().unwrap_or_default()
    );
    Ok(())
}

fn addition(path: &str, bytes: &[u8]) -> CommitAddition {
    CommitAddition {
        path: path.to_owned(),
        contents: base64::engine::general_purpose::STANDARD.encode(bytes),
    }
}

fn branch_head(api: &GitHub, repository: &str, branch: &str) -> Result<String> {
    let value: Value = api.get(&format!("/repos/{repository}/git/ref/heads/{branch}"))?;
    value["object"]["sha"]
        .as_str()
        .map(str::to_owned)
        .context("branch ref has no SHA")
}

fn encode_path(path: &str) -> String {
    path.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}
