//! Independent readback of one workflow fixture; no GitHub mutations.
use anyhow::{Context, Result, ensure};
use clap::ValueEnum;
use securefix::{api::GitHub, config, policy::validate_sha};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

#[derive(Clone, Copy, ValueEnum)]
pub enum Protection {
    All,
    BranchAndPull,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    repository: String,
    repository_id: u64,
    default_branch: String,
    default_head: String,
    pull_request: u64,
    head: String,
    state: String,
    merged: bool,
    reviews: BTreeMap<u64, String>,
    checks: BTreeMap<u64, String>,
    statuses: BTreeMap<u64, String>,
    comments: BTreeMap<u64, String>,
}

pub(super) fn capture(pull_request: u64, path: &Path) -> Result<()> {
    ensure!(pull_request > 0, "invalid workflow fixture PR number");
    let token = std::env::var("GITHUB_TOKEN").context("missing readback GITHUB_TOKEN")?;
    ensure!(!token.is_empty(), "readback GITHUB_TOKEN is empty");
    let api = GitHub::new("https://api.github.com", token)?;
    let target = &config::trusted()?.deployment.integration;
    crate::workflow::write_json(path, &read(&api, target, pull_request)?)
}

fn read(api: &GitHub, target: &config::Repository, number: u64) -> Result<Snapshot> {
    let root = format!("/repos/{}", target.repository);
    let repository: Value = api.get(&root)?;
    ensure!(
        repository["id"].as_u64() == Some(target.id)
            && repository["full_name"] == target.repository
            && repository["default_branch"] == target.default_branch,
        "workflow fixture repository identity changed"
    );
    let branch_path = format!("{root}/commits/{}", target.default_branch);
    let pull_path = format!("{root}/pulls/{number}");
    let branch: Value = api.get(&branch_path)?;
    let pull: Value = api.get(&pull_path)?;
    ensure!(
        pull["number"].as_u64() == Some(number)
            && pull["base"]["repo"]["id"].as_u64() == Some(target.id)
            && pull["head"]["repo"]["id"].as_u64() == Some(target.id)
            && pull["base"]["ref"] == target.default_branch,
        "workflow fixture PR identity changed"
    );
    let default_head = required_string(&branch, "sha")?;
    let head = required_string(&pull["head"], "sha")?;
    validate_sha(&default_head)?;
    validate_sha(&head)?;
    let state = required_string(&pull, "state")?;
    ensure!(
        matches!(state.as_str(), "open" | "closed"),
        "invalid workflow fixture PR state"
    );
    let merged = pull["merged"]
        .as_bool()
        .context("workflow fixture merged state missing")?;
    let reviews = fingerprints(
        api.paginate(&format!("{pull_path}/reviews"))?,
        &["state", "body", "commit_id", "submitted_at", "user"],
    )?;
    let comments = fingerprints(
        api.paginate(&format!("{root}/issues/{number}/comments"))?,
        &["body", "created_at", "updated_at", "user"],
    )?;
    let statuses = fingerprints(
        api.paginate(&format!("{root}/commits/{head}/statuses"))?,
        &[
            "state",
            "context",
            "description",
            "target_url",
            "created_at",
            "updated_at",
            "creator",
        ],
    )?;
    let mut checks = Vec::new();
    for page in 1..=100 {
        let response: Value = api.get(&format!(
            "{root}/commits/{head}/check-runs?per_page=100&page={page}&filter=all"
        ))?;
        let rows = response["check_runs"]
            .as_array()
            .context("workflow fixture checks missing")?;
        checks.extend(rows.iter().cloned());
        if rows.len() < 100 {
            ensure!(
                response["total_count"].as_u64() == Some(checks.len() as u64),
                "workflow fixture check list changed or was truncated"
            );
            break;
        }
        ensure!(
            page < 100,
            "workflow fixture check pagination exceeded bound"
        );
    }
    let checks = fingerprints(
        checks,
        &[
            "name",
            "head_sha",
            "status",
            "conclusion",
            "external_id",
            "app",
            "started_at",
            "completed_at",
            "output",
        ],
    )?;
    let current_branch: Value = api.get(&branch_path)?;
    let current_pull: Value = api.get(&pull_path)?;
    ensure!(
        current_branch["sha"] == default_head
            && current_pull["head"]["sha"] == head
            && current_pull["state"] == state
            && current_pull["merged"] == merged,
        "workflow fixture moved during state readback"
    );
    Ok(Snapshot {
        version: 1,
        repository: target.repository.clone(),
        repository_id: target.id,
        default_branch: target.default_branch.clone(),
        default_head,
        pull_request: number,
        head,
        state,
        merged,
        reviews,
        checks,
        statuses,
        comments,
    })
}

fn required_string(value: &Value, key: &str) -> Result<String> {
    Ok(value[key]
        .as_str()
        .filter(|value| !value.is_empty())
        .context("workflow fixture string field missing")?
        .to_owned())
}

fn fingerprints(rows: Vec<Value>, fields: &[&str]) -> Result<BTreeMap<u64, String>> {
    let mut result = BTreeMap::new();
    for row in rows {
        let id = row["id"]
            .as_u64()
            .filter(|id| *id > 0)
            .context("workflow fixture row ID missing")?;
        let mut selected = serde_json::Map::new();
        for field in fields {
            let value = row
                .get(*field)
                .context("workflow fixture row field missing")?;
            let value = if matches!(*field, "user" | "creator") {
                json!({"id":value["id"], "login":value["login"], "type":value["type"]})
            } else {
                value.clone()
            };
            selected.insert((*field).into(), value);
        }
        let digest = securefix::hex_encode(Sha256::digest(serde_json::to_vec(&selected)?));
        ensure!(
            result.insert(id, digest).is_none(),
            "workflow fixture has duplicate row IDs"
        );
    }
    Ok(result)
}

pub(super) fn compare(before: &Path, after: &Path, protection: Protection) -> Result<()> {
    let workspace = std::env::current_dir()?;
    let parse = |path| -> Result<Snapshot> {
        Ok(serde_json::from_slice(&super::read_output_file(
            &workspace, path,
        )?)?)
    };
    unchanged(&parse(before)?, &parse(after)?, protection)
}

fn unchanged(before: &Snapshot, after: &Snapshot, protection: Protection) -> Result<()> {
    let target = &config::trusted()?.deployment.integration;
    for snapshot in [before, after] {
        ensure!(
            snapshot.version == 1
                && snapshot.repository == target.repository
                && snapshot.repository_id == target.id
                && snapshot.default_branch == target.default_branch
                && snapshot.pull_request > 0,
            "snapshot is not bound to the configured test fixture"
        );
        validate_sha(&snapshot.default_head)?;
        validate_sha(&snapshot.head)?;
        for (id, digest) in snapshot
            .reviews
            .iter()
            .chain(snapshot.checks.iter())
            .chain(snapshot.statuses.iter())
            .chain(snapshot.comments.iter())
        {
            ensure!(
                *id > 0
                    && digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "invalid workflow snapshot digest"
            );
        }
    }
    ensure!(
        before.pull_request == after.pull_request && before.state == "open" && !before.merged,
        "rejection snapshot must name the same open, unmerged fixture"
    );
    ensure!(
        before.default_head == after.default_head
            && before.head == after.head
            && before.state == after.state
            && before.merged == after.merged,
        "rejected workflow changed protected branch or PR state"
    );
    if matches!(protection, Protection::All) {
        ensure!(
            before == after,
            "rejected workflow changed protected reviews, checks, statuses or comments"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn readback_uses_fixed_repository_and_rejects_a_moving_default_head() {
        use crate::fixtures::{Fixture, Route};
        let target = &config::trusted().unwrap().deployment.integration;
        let root = format!("/repos/{}", target.repository);
        let head = "b".repeat(40);
        let default_head = "a".repeat(40);
        let pull = json!({"number":17,"state":"open","merged":false,
            "base":{"ref":target.default_branch,"repo":{"id":target.id}},
            "head":{"sha":head,"repo":{"id":target.id}}});
        for moving in [false, true] {
            let fixture = Fixture::new(vec![
                Route::get(
                    &root,
                    json!({"id":target.id,"full_name":target.repository,"default_branch":target.default_branch}),
                ),
                Route::get(
                    format!("{root}/commits/{}", target.default_branch),
                    json!({"sha":default_head}),
                ),
                Route::get(format!("{root}/pulls/17"), pull.clone()),
                Route::get(
                    format!("{root}/pulls/17/reviews?per_page=100&page=1"),
                    json!([]),
                ),
                Route::get(
                    format!("{root}/issues/17/comments?per_page=100&page=1"),
                    json!([]),
                ),
                Route::get(
                    format!("{root}/commits/{head}/statuses?per_page=100&page=1"),
                    json!([]),
                ),
                Route::get(
                    format!("{root}/commits/{head}/check-runs?per_page=100&page=1&filter=all"),
                    json!({"total_count":0,"check_runs":[]}),
                ),
                Route::get(
                    format!("{root}/commits/{}", target.default_branch),
                    json!({"sha":if moving {"c".repeat(40)} else {default_head.clone()}}),
                ),
                Route::get(format!("{root}/pulls/17"), pull.clone()),
            ]);
            let result = read(&fixture.api, target, 17);
            if moving {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("moved during state readback")
                );
            } else {
                let snapshot = result.unwrap();
                assert_eq!(snapshot.default_head, default_head);
                assert_eq!(snapshot.head, head);
                unchanged(&snapshot, &snapshot, Protection::All).unwrap();
            }
            fixture.finish();
        }
    }

    #[test]
    fn rejection_readback_requires_exact_fixture_and_selected_protected_state() {
        let target = &config::trusted().unwrap().deployment.integration;
        let before = Snapshot {
            version: 1,
            repository: target.repository.clone(),
            repository_id: target.id,
            default_branch: target.default_branch.clone(),
            default_head: "a".repeat(40),
            pull_request: 17,
            head: "b".repeat(40),
            state: "open".into(),
            merged: false,
            reviews: BTreeMap::new(),
            checks: BTreeMap::new(),
            statuses: BTreeMap::new(),
            comments: BTreeMap::new(),
        };
        let bytes = serde_json::to_vec(&before).unwrap();
        let copy = || serde_json::from_slice::<Snapshot>(&bytes).unwrap();
        unchanged(&before, &copy(), Protection::All).unwrap();
        let mut after = copy();
        after.comments.insert(3, "c".repeat(64));
        assert!(unchanged(&before, &after, Protection::All).is_err());
        unchanged(&before, &after, Protection::BranchAndPull).unwrap();
        for change in [
            "default_head",
            "head",
            "merged",
            "pull_request",
            "repository_id",
        ] {
            let mut after = serde_json::to_value(copy()).unwrap();
            after[change] = match change {
                "merged" => json!(true),
                "pull_request" | "repository_id" => json!(123),
                _ => json!("c".repeat(40)),
            };
            assert!(
                unchanged(
                    &before,
                    &serde_json::from_value(after).unwrap(),
                    Protection::BranchAndPull
                )
                .is_err()
            );
        }
        let rows = vec![json!({"id":1, "state":"APPROVED"})];
        assert!(fingerprints(rows.clone(), &["commit_id"]).is_err());
        assert!(fingerprints([rows.clone(), rows].concat(), &["state"]).is_err());
    }
}
