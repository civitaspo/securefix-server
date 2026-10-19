//! Reviewed fixture descriptors on the test client; never production activation.
use super::testing_publication::{POLICY, POLICY_PATH, require_prerelease, validate_policy};
use anyhow::{Context, Result, ensure};
use securefix::{
    api::{ApiError, GitHub},
    config,
    control::ControlRevision,
    policy::Policy,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const WORKFLOW: &str = ".github/workflows/testing-control-fixture.yml";
const ACTIVE: &str = "control/active.json";

#[derive(clap::Subcommand)]
pub enum Command {
    Validate,
    Propose {
        #[arg(long)]
        source_sha: String,
        #[arg(long)]
        publisher_run_id: u64,
        #[arg(long)]
        verification_run_id: u64,
        #[arg(long)]
        expected_main_sha: String,
        /// Zero digest means an absent initial fixture, not a production bootstrap.
        #[arg(long)]
        expected_control_id: String,
    },
    Merge {
        #[arg(long)]
        pull_request: u64,
        #[arg(long)]
        expected_head_sha: String,
        #[arg(long)]
        expected_main_sha: String,
        #[arg(long)]
        expected_control_id: String,
        #[arg(long)]
        approve_comment_id: u64,
        #[arg(long)]
        merge_comment_id: u64,
    },
}

fn context() -> Result<GitHub> {
    let trusted = config::trusted()?;
    ensure!(
        trusted.deployment.workflow_prefix.is_empty()
            && trusted.deployment.control_repository.is_none(),
        "fixture controller requires the production-configured trusted host"
    );
    validate_policy(trusted)?;
    let server = &trusted.deployment.server;
    let source = std::env::var("SECUREFIX_TEST_BASELINE_SHA")?;
    ensure!(
        std::env::var("GITHUB_REPOSITORY").is_ok_and(|v| v == server.repository)
            && std::env::var("GITHUB_REF")
                .is_ok_and(|v| v == format!("refs/heads/{}", server.default_branch))
            && std::env::var("GITHUB_SHA").is_ok_and(|v| v == source)
            && std::env::var("GITHUB_EVENT_NAME").is_ok_and(|v| v == "workflow_dispatch")
            && std::env::var("GITHUB_WORKFLOW_REF").is_ok_and(|v| v
                == format!(
                    "{}/{WORKFLOW}@refs/heads/{}",
                    server.repository, server.default_branch
                ))
            && std::env::var("GITHUB_ACTOR_ID").is_ok_and(|v| v == trusted.owner_id.to_string())
            && std::env::var("GITHUB_RUN_ATTEMPT").is_ok_and(|v| v == "1"),
        "fixture control requires its exact first-attempt owner dispatch on captured main"
    );
    let api = super::integration_read_api()?;
    let id: u64 = std::env::var("GITHUB_RUN_ID")?.parse()?;
    let run: Value = api.get(&format!("/repos/{}/actions/runs/{id}", server.repository))?;
    validate_run(&run, id, &source, trusted)?;
    Ok(api)
}

fn validate_run(run: &Value, id: u64, source: &str, trusted: &config::TrustedConfig) -> Result<()> {
    let server = &trusted.deployment.server;
    ensure!(
        id > 0
            && run["id"] == id
            && run["path"] == WORKFLOW
            && run["head_sha"] == source
            && run["head_branch"] == server.default_branch
            && run["run_attempt"] == 1
            && run["event"] == "workflow_dispatch"
            && run["status"] == "in_progress"
            && run["actor"]["id"] == trusted.owner_id
            && run["triggering_actor"]["id"] == trusted.owner_id
            && [&run["repository"], &run["head_repository"]]
                .iter()
                .all(|r| r["id"] == server.id && r["full_name"] == server.repository),
        "fixture controller run provenance mismatch"
    );
    Ok(())
}

fn current(api: &GitHub, main: &str, expected: &str) -> Result<Option<ControlRevision>> {
    securefix::policy::validate_sha(main)?;
    ensure!(
        expected.len() == 64
            && expected
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)),
        "invalid fixture control identity"
    );
    let fixture = &config::trusted()?.deployment.integration;
    let repository: Value = api.get(&format!("/repos/{}", fixture.repository))?;
    ensure!(
        repository["id"] == fixture.id
            && repository["full_name"] == fixture.repository
            && repository["default_branch"] == fixture.default_branch,
        "fixture repository identity changed"
    );
    let branch: Value = api.get(&format!(
        "/repos/{}/commits/{}",
        fixture.repository, fixture.default_branch
    ))?;
    ensure!(branch["sha"] == main, "fixture protected main changed");
    let bytes = match api.content(&fixture.repository, ACTIVE, main) {
        Ok(bytes) => bytes,
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|e| e.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            ensure!(expected == "0".repeat(64), "fixture descriptor disappeared");
            let history: Value = api.get(&format!(
                "/repos/{}/commits?path={ACTIVE}&sha={main}&per_page=1",
                fixture.repository
            ))?;
            ensure!(
                history.as_array().is_some_and(|v| v.is_empty()),
                "fixture descriptor was previously initialized; refusing reinitialization"
            );
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let descriptor = parse(&bytes)?;
    ensure!(
        descriptor.identity()? == expected,
        "fixture active control changed"
    );
    Ok(Some(descriptor))
}

fn fence(api: &GitHub, main: &str, expected: &str) -> Result<Option<ControlRevision>> {
    super::integration_read_api()?;
    current(api, main, expected)
}

fn parse(bytes: &[u8]) -> Result<ControlRevision> {
    ensure!(bytes.len() <= 16 * 1024, "fixture descriptor is oversized");
    let descriptor: ControlRevision = serde_json::from_slice(bytes)?;
    descriptor.validate()?;
    Ok(descriptor)
}

fn qualify(
    api: &GitHub,
    source: &str,
    publisher: u64,
    verification: u64,
) -> Result<ControlRevision> {
    securefix::policy::validate_sha(source)?;
    let server = &config::trusted()?.deployment.server;
    let baseline = std::env::var("SECUREFIX_TEST_BASELINE_SHA")?;
    crate::control_commands::require_ancestor(api, &server.repository, source, &baseline)?;
    crate::control_commands::verify_source_commit(api, &server.repository, source)?;
    crate::control_commands::verify_ci_status(api, &server.repository, source)?;
    require_prerelease(&crate::runtime::version_at_source(api, source)?)?;
    ensure!(
        api.content(&server.repository, POLICY_PATH, source)? == POLICY,
        "fixture source testing policy changed"
    );
    let (publication, archive) = crate::control_commands::verify_testing_publisher(
        api,
        &server.repository,
        source,
        publisher,
    )?;
    ensure!(
        securefix::runtime_archive::policy(&std::fs::read(archive.path())?)? == POLICY,
        "fixture archive testing policy changed"
    );
    crate::control_commands::verify_candidate_test(api, &server.repository, source, verification)?;
    Ok(ControlRevision {
        version: 1,
        generation: 1,
        source_sha: source.into(),
        policy_sha256: securefix::hex_encode(Sha256::digest(POLICY)),
        archive_sha256: publication.archive_sha256,
        release_id: publication.release_id,
        asset_id: publication.asset_id,
        publisher_run_id: publisher,
        verification_run_id: verification,
        previous: "0".repeat(64),
    })
}

fn successor(
    current: Option<&ControlRevision>,
    mut next: ControlRevision,
) -> Result<ControlRevision> {
    if let Some(current) = current {
        next.generation = current
            .generation
            .checked_add(1)
            .context("fixture generation overflow")?;
        next.previous = current.identity()?;
        current.validate_successor(&next)?;
    } else {
        ensure!(
            next.generation == 1 && next.previous == "0".repeat(64),
            "invalid initial fixture"
        );
        next.validate()?;
    }
    Ok(next)
}

fn branch(next: &ControlRevision) -> Result<String> {
    Ok(format!(
        "testing-control/{}/{}",
        next.generation,
        &next.identity()?[..12]
    ))
}

pub(super) fn run(command: Command) -> Result<()> {
    let public = context()?;
    if matches!(command, Command::Validate) {
        return Ok(());
    }
    let source = std::env::var("SECUREFIX_TEST_BASELINE_SHA")?;
    let write = GitHub::scratch_from_env("SECUREFIX_TEST_WRITE_TOKEN", &source)?;
    let fixture = &config::trusted()?.deployment.integration;
    let root = format!("/repos/{}", fixture.repository);
    match command {
        Command::Validate => unreachable!(),
        Command::Propose {
            source_sha,
            publisher_run_id,
            verification_run_id,
            expected_main_sha,
            expected_control_id,
        } => {
            let before = fence(&write, &expected_main_sha, &expected_control_id)?;
            let next = successor(
                before.as_ref(),
                qualify(&public, &source_sha, publisher_run_id, verification_run_id)?,
            )?;
            let branch = branch(&next)?;
            let existing: Value = write.get(&format!(
                "{root}/pulls?state=open&head={}:{}",
                config::trusted()?.deployment.repository_owner.login,
                branch
            ))?;
            ensure!(
                existing.as_array().is_some_and(|v| v.is_empty()),
                "fixture proposal already exists"
            );
            fence(&write, &expected_main_sha, &expected_control_id)?;
            let _: Value = write.post(
                &format!("{root}/git/refs"),
                &json!({"ref":format!("refs/heads/{branch}"),"sha":expected_main_sha}),
            )?;
            fence(&write, &expected_main_sha, &expected_control_id)?;
            let head = write.create_commit(
                &fixture.repository,
                &branch,
                &expected_main_sha,
                "test: propose reviewed isolated control fixture",
                BTreeMap::from([(ACTIVE.into(), serde_json::to_vec_pretty(&next)?)]),
                Vec::new(),
            )?;
            fence(&write, &expected_main_sha, &expected_control_id)?;
            let pull: Value = write.post(&format!("{root}/pulls"), &json!({"head":branch,"base":fixture.default_branch,
                "title":format!("testing-control: generation {}",next.generation),"body":format!("Test-only descriptor; production control unchanged.\n\nProposed control: {}\nReview control: {}\nExpected main: {expected_main_sha}\nReview this exact head, then post separate /approve and /merge commands.",next.identity()?,before.as_ref().unwrap_or(&next).identity()?)}))?;
            ensure!(
                pull["head"]["sha"] == head
                    && pull["user"]["id"] == config::trusted()?.server_bot_id,
                "fixture proposal response mismatch"
            );
            securefix::output(
                "pull_request",
                pull["number"]
                    .as_u64()
                    .context("missing fixture PR number")?
                    .to_string(),
            )?;
            securefix::output("head_sha", head)?;
            securefix::output("control_id", next.identity()?)
        }
        Command::Merge {
            pull_request,
            expected_head_sha,
            expected_main_sha,
            expected_control_id,
            approve_comment_id,
            merge_comment_id,
        } => {
            securefix::policy::validate_sha(&expected_head_sha)?;
            ensure!(pull_request > 0, "invalid fixture PR number");
            let before = fence(&write, &expected_main_sha, &expected_control_id)?;
            ensure!(
                if before.is_some() {
                    approve_comment_id > 0
                        && merge_comment_id > 0
                        && approve_comment_id != merge_comment_id
                } else {
                    approve_comment_id == 0 && merge_comment_id == 0
                },
                "initial fixture uses owner review; successors require separate fresh owner commands"
            );
            let next = parse(&write.content(&fixture.repository, ACTIVE, &expected_head_sha)?)?;
            let qualified = successor(
                before.as_ref(),
                qualify(
                    &public,
                    &next.source_sha,
                    next.publisher_run_id,
                    next.verification_run_id,
                )?,
            )?;
            ensure!(
                next == qualified,
                "fixture descriptor differs from qualified successor evidence"
            );
            let binding = before.as_ref().unwrap_or(&next);
            let validate = || -> Result<()> {
                fence(&write, &expected_main_sha, &expected_control_id)?;
                let pull: Value = write.get(&format!("{root}/pulls/{pull_request}"))?;
                validate_pull(
                    &pull,
                    pull_request,
                    &expected_head_sha,
                    &expected_main_sha,
                    &next,
                )?;
                let files = write.paginate(&format!("{root}/pulls/{pull_request}/files"))?;
                ensure!(
                    files.len() == 1
                        && files[0]["filename"] == ACTIVE
                        && matches!(files[0]["status"].as_str(), Some("added" | "modified")),
                    "fixture PR changes files outside descriptor"
                );
                let policy = Policy::parse(POLICY)?;
                crate::request::validate_pr_authorization(
                    &write,
                    &policy,
                    &fixture.repository,
                    pull_request,
                    &expected_head_sha,
                    true,
                )?;
                let (_, review_at) = crate::distribution::reviewed::owner_review(
                    &write,
                    &fixture.repository,
                    pull_request,
                    &expected_head_sha,
                    binding,
                )?;
                if before.is_some() {
                    let history: Value = write.get(&format!(
                        "{root}/commits?path={ACTIVE}&sha={expected_main_sha}&per_page=1"
                    ))?;
                    let activation = history
                        .as_array()
                        .and_then(|v| v.first())
                        .context("fixture activation history missing")?;
                    let activated_at = chrono::DateTime::parse_from_rfc3339(
                        activation["commit"]["committer"]["date"]
                            .as_str()
                            .context("fixture activation time missing")?,
                    )?;
                    ensure!(
                        review_at > activated_at,
                        "fixture owner review predates active generation"
                    );
                }
                let mut times = Vec::new();
                for (id, kind) in [
                    (approve_comment_id, crate::request::RequestKind::Approve),
                    (merge_comment_id, crate::request::RequestKind::Merge),
                ]
                .into_iter()
                .filter(|(id, _)| *id > 0)
                {
                    let comment: Value = write.get(&format!("{root}/issues/comments/{id}"))?;
                    times.push(crate::distribution::reviewed::validate_comment(
                        &comment,
                        &fixture.repository,
                        pull_request,
                        id,
                        kind,
                        review_at,
                    )?);
                }
                ensure!(
                    times.is_empty() || times[0] <= times[1],
                    "fixture owner commands are out of order"
                );
                crate::control_commands::verify_ci_status(
                    &write,
                    &fixture.repository,
                    &expected_head_sha,
                )
            };
            validate()?;
            let comments = write.paginate(&format!("{root}/issues/{pull_request}/comments"))?;
            let trusted = config::trusted()?;
            for id in [approve_comment_id, merge_comment_id]
                .into_iter()
                .filter(|id| *id > 0)
            {
                let marker = format!(
                    "<!-- securefix:v3:owner:{expected_head_sha}:{}:{id} -->",
                    binding.identity()?
                );
                ensure!(
                    !comments.iter().any(|c| crate::request::matches_principal(
                        &c["user"],
                        trusted.server_bot_id,
                        &trusted.deployment.server_bot_login,
                        "Bot"
                    ) && c["body"]
                        .as_str()
                        .is_some_and(|b| b.lines().any(|l| l == marker))),
                    "fixture owner command already consumed"
                );
            }
            for id in [approve_comment_id, merge_comment_id]
                .into_iter()
                .filter(|id| *id > 0)
            {
                validate()?;
                crate::request::post_owner_marker(
                    &write,
                    &fixture.repository,
                    pull_request,
                    &expected_head_sha,
                    id,
                    binding,
                )?;
            }
            validate()?;
            crate::policy_check::publish(
                &write,
                &fixture.repository,
                &expected_head_sha,
                true,
                "Exact test-only descriptor, qualified publication and scratch evidence, owner review and required CI verified by trusted fixture controller.",
                binding,
            )?;
            validate()?;
            let merged: Value = write.put(
                &format!("{root}/pulls/{pull_request}/merge"),
                &json!({"sha":expected_head_sha,"merge_method":"squash"}),
            )?;
            ensure!(merged["merged"] == true, "fixture reviewed merge failed");
            let actual = ControlRevision::load_from_repository(&write, fixture)?;
            ensure!(
                actual == next,
                "fixture merge did not activate the exact reviewed descriptor"
            );
            securefix::output("control_id", actual.identity()?)
        }
    }
}

fn validate_pull(
    pull: &Value,
    number: u64,
    head: &str,
    main: &str,
    next: &ControlRevision,
) -> Result<()> {
    let trusted = config::trusted()?;
    let fixture = &trusted.deployment.integration;
    ensure!(
        pull["number"] == number
            && pull["state"] == "open"
            && pull["draft"] == false
            && pull["head"]["sha"] == head
            && pull["base"]["sha"] == main
            && pull["head"]["ref"] == branch(next)?
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
        "fixture PR ownership, branch, base or accepted head changed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Fixture, Route};

    #[test]
    fn fixture_absence_requires_empty_history_and_current_expected_main() {
        let fixture = &config::trusted().unwrap().deployment.integration;
        let main = "a".repeat(40);
        let root = format!("/repos/{}", fixture.repository);
        for initialized in [false, true] {
            let api = Fixture::new(vec![
                Route::get(
                    &root,
                    json!({"id":fixture.id,"full_name":fixture.repository,"default_branch":fixture.default_branch}),
                ),
                Route::get(
                    format!("{root}/commits/{}", fixture.default_branch),
                    json!({"sha":main}),
                ),
                Route::request(
                    "GET",
                    format!("{root}/contents/{ACTIVE}?ref={main}"),
                    404,
                    json!({"message":"Not Found"}),
                ),
                Route::get(
                    format!("{root}/commits?path={ACTIVE}&sha={main}&per_page=1"),
                    if initialized {
                        json!([{"sha":main}])
                    } else {
                        json!([])
                    },
                ),
            ]);
            assert_eq!(
                current(&api.api, &main, &"0".repeat(64)).is_ok(),
                !initialized
            );
            api.finish();
        }
        let api = Fixture::new(vec![
            Route::get(
                &root,
                json!({"id":fixture.id,"full_name":fixture.repository,"default_branch":fixture.default_branch}),
            ),
            Route::get(
                format!("{root}/commits/{}", fixture.default_branch),
                json!({"sha":"b".repeat(40)}),
            ),
        ]);
        assert!(
            current(&api.api, &main, &"0".repeat(64))
                .unwrap_err()
                .to_string()
                .contains("main changed")
        );
        api.finish();
    }

    #[test]
    fn fixture_generation_reuses_successor_and_rejects_repeated_payload() {
        let before = crate::fixtures::Fixture::control_revision();
        assert!(successor(Some(&before), before.clone()).is_err());
        let mut payload = before.clone();
        payload.verification_run_id += 1;
        let next = successor(Some(&before), payload).unwrap();
        assert_eq!(next.generation, 2);
        assert_eq!(next.previous, before.identity().unwrap());
        assert!(parse(&vec![b' '; 16385]).is_err());
    }
    #[test]
    fn fixture_controller_provenance_rejects_other_workflows_and_actors() {
        let t = config::trusted().unwrap();
        let source = "a".repeat(40);
        let run = json!({"id":7,"path":WORKFLOW,"head_sha":source,"head_branch":t.deployment.server.default_branch,
            "run_attempt":1,"event":"workflow_dispatch","status":"in_progress","actor":{"id":t.owner_id},"triggering_actor":{"id":t.owner_id},
            "repository":{"id":t.deployment.server.id,"full_name":t.deployment.server.repository},"head_repository":{"id":t.deployment.server.id,"full_name":t.deployment.server.repository}});
        validate_run(&run, 7, &source, t).unwrap();
        for (field, value) in [
            ("path", json!(".github/workflows/control-activation.yml")),
            ("run_attempt", json!(2)),
            ("triggering_actor", json!({"id":1})),
        ] {
            let mut bad = run.clone();
            bad[field] = value;
            assert!(validate_run(&bad, 7, &source, t).is_err());
        }
    }
}
