//! Deliberately invalid, test-only migration inputs. Never an activation or merge lane.
use anyhow::{Context, Result, ensure};
use securefix::{api::GitHub, config, policy::Policy};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Case {
    UnmanagedFile,
    ManagedBytes,
    AdvanceHead,
    NonownerDispatch,
    Cleanup,
}

pub(super) fn run(case: Case, number: u64, head: &str, main: &str, control: &str) -> Result<()> {
    super::testing_processor::require_context(
        super::testing_processor::HostKind::MigrationFixture,
    )?;
    securefix::policy::validate_sha(head)?;
    ensure!(number > 0, "invalid migration fixture PR number");
    let source = std::env::var("SECUREFIX_TEST_BASELINE_SHA")?;
    let api = GitHub::scratch_from_env("SECUREFIX_TEST_FIXTURE_TOKEN", &source)?;
    let trusted = config::trusted()?;
    let fixture = &trusted.deployment.integration;
    let isolated = Policy::parse(super::testing_publication::POLICY)?;
    let branch = &isolated.deployment.runtime_update_branch;
    let root = format!("/repos/{}", fixture.repository);
    let fence = || -> Result<()> {
        super::testing_control::fence(&api, main, control)?
            .context("migration fixture requires initialized isolated control")?;
        let pull: Value = api.get(&format!("{root}/pulls/{number}"))?;
        validate_pull(&pull, number, head, main, trusted, branch)
    };
    fence()?;
    if matches!(case, Case::NonownerDispatch) {
        let reviewer = &trusted.deployment.approval_reviewer;
        let token = std::env::var("SECUREFIX_TEST_NONOWNER_TOKEN")?;
        let user: Value = GitHub::new("https://api.github.com", token)?.get("/user")?;
        ensure!(
            reviewer.id != trusted.owner_id
                && crate::request::matches_principal(&user, reviewer.id, &reviewer.login, "User"),
            "non-owner fixture requires the existing configured User reviewer"
        );
        let event = securefix::event()?;
        let number_input = |key: &str| -> Result<u64> {
            let n = event["inputs"][key]
                .as_str()
                .context("missing fixture dispatch input")?
                .parse::<u64>()?;
            ensure!(n > 0, "fixture dispatch input must be nonzero");
            Ok(n)
        };
        let approve = number_input("approve_comment_id")?;
        let merge = number_input("merge_comment_id")?;
        let publisher = number_input("publisher_run_id")?;
        let active = super::testing_control::fence(&api, main, control)?
            .context("missing fixture control")?;
        ensure!(
            approve != merge && publisher == active.publisher_run_id,
            "fixture dispatch bindings changed"
        );
        return securefix::workflow::write_json(
            "migration-nonowner-dispatch.json",
            &json!({
                "ref":trusted.deployment.server.default_branch,
                "inputs":{"repository":fixture.repository,"pull_request":number.to_string(),
                    "expected_head_sha":head,"control_id":control,"approve_comment_id":approve.to_string(),
                    "merge_comment_id":merge.to_string(),"publisher_run_id":publisher.to_string()}
            }),
        );
    }
    if matches!(case, Case::Cleanup) {
        fence()?;
        let _: Value = api.patch(
            &format!("{root}/pulls/{number}"),
            &json!({"state":"closed"}),
        )?;
        let pull: Value = api.get(&format!("{root}/pulls/{number}"))?;
        ensure!(
            pull["state"] == "closed" && pull["merged"] == false && pull["head"]["sha"] == head,
            "migration fixture changed during cleanup"
        );
        super::testing_control::fence(&api, main, control)?;
        let reference: Value = api.get(&format!("{root}/git/ref/heads/{branch}"))?;
        ensure!(
            reference["object"]["sha"] == head,
            "fixture branch changed before deletion"
        );
        api.delete(&format!("{root}/git/refs/heads/{branch}"))?;
        super::testing_control::fence(&api, main, control)?;
        return Ok(());
    }
    let path = match case {
        Case::UnmanagedFile => ".securefix-testing/migration-unmanaged.txt".to_owned(),
        Case::ManagedBytes | Case::AdvanceHead => isolated
            .deployment
            .workflow_path(".github/workflows/merge-request.yml")?,
        Case::NonownerDispatch | Case::Cleanup => unreachable!(),
    };
    let bytes = match case {
        Case::UnmanagedFile => b"This file must never be merged by the migration lane.\n".to_vec(),
        _ => {
            let mut bytes = api.content(&fixture.repository, &path, head)?;
            ensure!(
                bytes.len() <= 64 * 1024,
                "managed fixture workflow is oversized"
            );
            bytes.extend_from_slice(b"\n# testing: deliberately non-canonical migration fixture\n");
            bytes
        }
    };
    fence()?;
    let next = api.create_commit(
        &fixture.repository,
        branch,
        head,
        "test: create deliberately invalid migration fixture",
        BTreeMap::from([(path, bytes)]),
        Vec::new(),
    )?;
    ensure!(next != head, "fixture mutation did not advance the head");
    super::testing_control::fence(&api, main, control)?;
    let pull: Value = api.get(&format!("{root}/pulls/{number}"))?;
    validate_pull(&pull, number, &next, main, trusted, branch)?;
    securefix::workflow::write_json(
        "migration-fixture.json",
        &json!({"repository":fixture.repository,"pull_request":number,"before_head":head,
            "after_head":next,"protected_main":main,"control_id":control}),
    )?;
    securefix::output("head_sha", next)
}

fn validate_pull(
    pull: &Value,
    number: u64,
    head: &str,
    main: &str,
    trusted: &config::TrustedConfig,
    branch: &str,
) -> Result<()> {
    let fixture = &trusted.deployment.integration;
    ensure!(
        pull["number"] == number
            && pull["state"] == "open"
            && pull["draft"] == false
            && pull["merged"] == false
            && pull["head"]["sha"] == head
            && pull["head"]["ref"] == branch
            && pull["base"]["sha"] == main
            && pull["base"]["ref"] == fixture.default_branch
            && crate::request::matches_principal(
                &pull["user"],
                trusted.server_bot_id,
                &trusted.deployment.server_bot_login,
                "Bot"
            )
            && [&pull["head"]["repo"], &pull["base"]["repo"]]
                .iter()
                .all(|r| r["id"] == fixture.id && r["full_name"] == fixture.repository),
        "fixture is not the exact open Server App migration PR on the fixed test repository: number={} state={} draft={} merged={} head={} expected_head={} branch={} expected_branch={} base={} expected_base={} base_ref={} author_id={} author_type={} head_repo={} base_repo={}",
        pull["number"],
        pull["state"],
        pull["draft"],
        pull["merged"],
        pull["head"]["sha"],
        head,
        pull["head"]["ref"],
        branch,
        pull["base"]["sha"],
        main,
        pull["base"]["ref"],
        pull["user"]["id"],
        pull["user"]["type"],
        pull["head"]["repo"]["full_name"],
        pull["base"]["repo"]["full_name"]
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_fixture_cannot_target_another_pr_head_branch_author_or_repository() {
        let trusted = config::trusted().unwrap();
        let target = &trusted.deployment.integration;
        let head = "a".repeat(40);
        let main = "b".repeat(40);
        let branch = "automation/testing-securefix-runtime";
        let repository = json!({"id":target.id,"full_name":target.repository});
        let pull = json!({"number":7,"state":"open","draft":false,"merged":false,
            "head":{"sha":head,"ref":branch,"repo":repository},
            "base":{"sha":main,"ref":target.default_branch,"repo":repository},
            "user":{"id":trusted.server_bot_id,"login":trusted.deployment.server_bot_login,"type":"Bot"}});
        validate_pull(&pull, 7, &head, &main, trusted, branch).unwrap();
        for pointer in [
            "/number",
            "/state",
            "/draft",
            "/merged",
            "/head/sha",
            "/head/ref",
            "/head/repo/id",
            "/base/sha",
            "/base/ref",
            "/base/repo/full_name",
            "/user/id",
            "/user/type",
        ] {
            let mut wrong = pull.clone();
            *wrong.pointer_mut(pointer).unwrap() = json!("wrong");
            assert!(
                validate_pull(&wrong, 7, &head, &main, trusted, branch).is_err(),
                "{pointer}"
            );
        }
    }
}
