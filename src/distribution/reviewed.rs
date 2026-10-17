use super::*;
use crate::{config, merge, policy_check, request};
use chrono::{DateTime, Utc};
use request::{Authorization, PullRequestRef, RepositoryRef, RequestKind, RequestManifest};
use serde::{Deserialize, Serialize};

const WORKFLOW: &str = ".github/workflows/merge-caller-migration.yml";
const PLAN: &str = "caller-migration/plan.json";

#[derive(Subcommand)]
pub(crate) enum Command {
    Target {
        repository: String,
    },
    Prepare {
        repository: String,
        pull_request: u64,
        expected_head_sha: String,
        control_id: String,
        approve_comment_id: u64,
        merge_comment_id: u64,
        publisher_run_id: u64,
    },
    Authorize,
    Ready,
    Merge,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u32,
    request: RequestManifest,
    approve_comment_id: u64,
    approve_updated_at: DateTime<Utc>,
    owner_review_id: u64,
    owner_review_at: DateTime<Utc>,
    base_sha: String,
    publisher_run_id: u64,
    processor_sha: String,
}

pub(crate) fn run(command: Command) -> Result<()> {
    let api = GitHub::from_env(if matches!(command, Command::Target { .. }) {
        "GITHUB_TOKEN"
    } else {
        "SECUREFIX_SERVER_TOKEN"
    })?;
    let policy = Policy::active(&api)?;
    let processor_sha = require_context(&api)?;
    match command {
        Command::Target { repository } => {
            ensure!(
                caller_names(&policy)?.contains(&repository),
                "caller is not in the fixed policy registry"
            );
            ensure!(
                crate::event()?["inputs"]["repository"] == repository,
                "caller differs from owner dispatch"
            );
            output(
                "repository_name",
                repository
                    .split('/')
                    .nth(1)
                    .context("caller name missing")?,
            )
        }
        Command::Prepare {
            repository,
            pull_request,
            expected_head_sha,
            control_id,
            approve_comment_id,
            merge_comment_id,
            publisher_run_id,
        } => {
            let control = policy.control.clone().context("active control missing")?;
            ensure!(
                control.identity()? == control_id,
                "requested control identity changed"
            );
            let migration = prepare_caller(&api, &policy, &repository, &policy.revision)?;
            let pull: Value = api.get(&format!("/repos/{repository}/pulls/{pull_request}"))?;
            validate_runtime_update_pull_request(
                &policy,
                &migration,
                pull_request,
                &pull,
                &expected_head_sha,
            )?;
            let (review_id, review_at) = owner_review(
                &api,
                &repository,
                pull_request,
                &expected_head_sha,
                &control,
            )?;
            let approve = owner_comment(
                &api,
                &repository,
                pull_request,
                approve_comment_id,
                RequestKind::Approve,
                review_at,
            )?;
            let merge = owner_comment(
                &api,
                &repository,
                pull_request,
                merge_comment_id,
                RequestKind::Merge,
                review_at,
            )?;
            ensure!(
                approve_comment_id != merge_comment_id && approve <= merge,
                "owner commands are not separate and ordered"
            );
            let plan = Plan {
                version: 1,
                request: RequestManifest {
                    version: 1,
                    kind: RequestKind::Merge,
                    repository: RepositoryRef {
                        id: pull["head"]["repo"]["id"]
                            .as_u64()
                            .context("caller ID missing")?,
                        full_name: repository,
                    },
                    pull_request: PullRequestRef {
                        number: pull_request,
                        head_sha: expected_head_sha,
                        base_ref: migration.default_branch,
                    },
                    authorization: Authorization::OwnerComment {
                        comment_id: merge_comment_id,
                        updated_at: Some(merge),
                    },
                    accepted_at: Utc::now(),
                    run_id: std::env::var("GITHUB_RUN_ID")?.parse()?,
                    run_attempt: 1,
                    workflow_sha: policy.revision.clone(),
                    caller_workflow_sha: pull["base"]["sha"]
                        .as_str()
                        .context("caller base missing")?
                        .to_owned(),
                    control,
                },
                approve_comment_id,
                approve_updated_at: approve,
                owner_review_id: review_id,
                owner_review_at: review_at,
                base_sha: pull["base"]["sha"]
                    .as_str()
                    .context("caller base missing")?
                    .to_owned(),
                publisher_run_id,
                processor_sha,
            };
            verify(&api, &policy, &plan)?;
            require_unconsumed(&api, &plan)?;
            workflow::write_json(PLAN, &plan)
        }
        Command::Authorize => {
            let plan = read_plan()?;
            verify(&api, &policy, &plan)?;
            require_unconsumed(&api, &plan)?;
            let write = GitHub::from_env("SECUREFIX_AUTHORIZATION_TOKEN")?;
            let Authorization::OwnerComment { comment_id, .. } = plan.request.authorization else {
                anyhow::bail!("migration lacks owner merge command")
            };
            request::post_owner_marker(
                &write,
                &plan.request.repository.full_name,
                plan.request.pull_request.number,
                &plan.request.pull_request.head_sha,
                comment_id,
                &plan.request.control,
            )?;
            request::post_owner_marker(
                &write,
                &plan.request.repository.full_name,
                plan.request.pull_request.number,
                &plan.request.pull_request.head_sha,
                plan.approve_comment_id,
                &plan.request.control,
            )?;
            policy_check::publish(
                &write,
                &plan.request.repository.full_name,
                &plan.request.pull_request.head_sha,
                true,
                "Canonical caller migration passed owner review, current-head authorization and signature checks.",
                &plan.request.control,
            )
        }
        Command::Ready => {
            let plan = read_plan()?;
            verify_ready(&api, &policy, &plan)?;
            output("ready", "true")
        }
        Command::Merge => {
            let plan = read_plan()?;
            let migration = verify_ready(&api, &policy, &plan)?;
            let write = GitHub::from_env("SECUREFIX_MERGE_TOKEN")?;
            let sha = merge_runtime_update(
                &write,
                &policy,
                &migration,
                plan.request.pull_request.number,
                &plan.request.pull_request.head_sha,
                || verify_ready(&api, &policy, &plan).map(|_| ()),
            )?;
            output("merge_sha", sha)
        }
    }
}

fn require_context(api: &GitHub) -> Result<String> {
    let config = config::trusted()?;
    let server = &config.deployment.server;
    ensure!(
        std::env::var("GITHUB_REPOSITORY")? == server.repository
            && std::env::var("GITHUB_REF")? == format!("refs/heads/{}", server.default_branch)
            && std::env::var("GITHUB_EVENT_NAME")? == "workflow_dispatch"
            && std::env::var("GITHUB_WORKFLOW_REF")?
                == format!(
                    "{}/{WORKFLOW}@refs/heads/{}",
                    server.repository, server.default_branch
                )
            && std::env::var("GITHUB_ACTOR_ID")?.parse::<u64>()? == config.owner_id
            && std::env::var("GITHUB_RUN_ATTEMPT")? == "1",
        "caller migration requires a first-attempt owner dispatch from protected main"
    );
    let source = std::env::var("GITHUB_SHA")?;
    validate_sha(&source)?;
    let id = std::env::var("GITHUB_RUN_ID")?.parse::<u64>()?;
    let run: Value = api.get(&format!("/repos/{}/actions/runs/{id}", server.repository))?;
    validate_producer(&run, id, &source)?;
    let main: Value = api.get(&format!(
        "/repos/{}/commits/{}",
        server.repository, server.default_branch
    ))?;
    ensure!(
        main["sha"] == source && main["commit"]["verification"]["verified"] == true,
        "protected processor source changed or lacks a verified signature"
    );
    Ok(source)
}

fn validate_producer(run: &Value, id: u64, source: &str) -> Result<()> {
    let trusted = config::trusted()?;
    let server = &trusted.deployment.server;
    ensure!(
        run["id"] == id
            && run["repository"]["id"] == server.id
            && run["repository"]["full_name"] == server.repository
            && run["head_repository"]["id"] == server.id
            && run["head_repository"]["full_name"] == server.repository
            && run["head_sha"] == source
            && run["head_branch"] == server.default_branch
            && run["path"] == WORKFLOW
            && run["event"] == "workflow_dispatch"
            && run["run_attempt"] == 1
            && run["status"] == "in_progress"
            && run["actor"]["id"] == trusted.owner_id
            && run["triggering_actor"]["id"] == trusted.owner_id,
        "caller migration producer is not the exact owner-dispatched server workflow"
    );
    Ok(())
}

fn verify(api: &GitHub, policy: &Policy, plan: &Plan) -> Result<CallerMigration> {
    plan.request.validate()?;
    ensure!(
        plan.version == 1
            && plan.request.run_id == std::env::var("GITHUB_RUN_ID")?.parse::<u64>()?
            && plan.processor_sha == require_context(api)?
            && policy.control.as_ref() == Some(&plan.request.control),
        "migration plan producer or control changed"
    );
    let request = &plan.request;
    let repository = &request.repository.full_name;
    let number = request.pull_request.number;
    let head = &request.pull_request.head_sha;
    let Authorization::OwnerComment {
        comment_id,
        updated_at,
    } = request.authorization
    else {
        anyhow::bail!("migration lacks owner merge command")
    };
    let inputs = crate::event()?["inputs"].clone();
    ensure!(
        inputs["repository"] == *repository
            && inputs["pull_request"].as_str() == Some(number.to_string().as_str())
            && inputs["expected_head_sha"] == *head
            && inputs["control_id"] == request.control.identity()?
            && inputs["approve_comment_id"].as_str()
                == Some(plan.approve_comment_id.to_string().as_str())
            && inputs["merge_comment_id"].as_str() == Some(comment_id.to_string().as_str())
            && inputs["publisher_run_id"].as_str()
                == Some(plan.publisher_run_id.to_string().as_str()),
        "migration plan differs from owner dispatch inputs"
    );
    securefix::control::ControlRevision::require_current(api, &request.control)?;
    ensure!(
        plan.owner_review_at > request::control_activated_at(api, &request.control)?,
        "owner review predates the active control generation"
    );
    validate_promotion(api, policy, plan.publisher_run_id)?;
    let migration = prepare_caller(api, policy, repository, &policy.revision)?;
    ensure!(
        caller_names(policy)?.contains(repository),
        "caller is not in the fixed policy registry"
    );
    ensure!(
        !migration.default_current,
        "caller already contains the activated migration"
    );
    let pull: Value = api.get(&format!("/repos/{repository}/pulls/{number}"))?;
    validate_runtime_update_pull_request(policy, &migration, number, &pull, head)?;
    ensure!(
        pull["base"]["sha"] == plan.base_sha && pull["head"]["repo"]["id"] == request.repository.id,
        "caller base or repository identity changed"
    );
    let (desired, current) = validate_automation_branch(api, policy, &migration)?;
    ensure!(
        desired && current.as_deref() == Some(head),
        "PR is not the exact canonical signed migration"
    );
    validate_existing_pull_request(api, policy, &migration)?;
    request::validate_pr_authorization(api, policy, repository, number, head, true)?;
    ensure!(
        owner_review(api, repository, number, head, &request.control)?
            == (plan.owner_review_id, plan.owner_review_at),
        "owner review changed after acceptance"
    );
    let approve = owner_comment(
        api,
        repository,
        number,
        plan.approve_comment_id,
        RequestKind::Approve,
        plan.owner_review_at,
    )?;
    let merge = owner_comment(
        api,
        repository,
        number,
        comment_id,
        RequestKind::Merge,
        plan.owner_review_at,
    )?;
    ensure!(
        Some(merge) == updated_at
            && approve == plan.approve_updated_at
            && approve <= merge
            && plan.approve_comment_id != comment_id,
        "owner commands changed after acceptance"
    );
    merge::validate_state(api, policy, request)?;
    Ok(migration)
}

fn verify_ready(api: &GitHub, policy: &Policy, plan: &Plan) -> Result<CallerMigration> {
    let migration = verify(api, policy, plan)?;
    let request = &plan.request;
    request::validate_pr_policy(
        api,
        policy,
        &request.repository.full_name,
        request.pull_request.number,
        &request.pull_request.head_sha,
    )?;
    let owner = config::Principal {
        id: config::trusted()?.owner_id,
        login: config::trusted()?.deployment.owner_login.clone(),
    };
    ensure!(
        merge::ready_with_reviewer(api, request, (&owner, "User"))?,
        "required CI, control-bound policy check and current-head owner review are not ready"
    );
    securefix::control::ControlRevision::require_current(api, &request.control)?;
    Ok(migration)
}

pub(crate) fn owner_review(
    api: &GitHub,
    repository: &str,
    number: u64,
    head: &str,
    control: &securefix::control::ControlRevision,
) -> Result<(u64, DateTime<Utc>)> {
    let trusted = config::trusted()?;
    let owner = config::Principal {
        id: trusted.owner_id,
        login: trusted.deployment.owner_login.clone(),
    };
    ensure!(
        request::has_current_head_approval_for_reviewer(
            api, repository, number, head, control, &owner, "User"
        )?,
        "current-head owner review for the active control is missing"
    );
    let reviews = api.paginate(&format!("/repos/{repository}/pulls/{number}/reviews"))?;
    let latest = reviews
        .iter()
        .filter(|r| {
            request::matches_principal(&r["user"], owner.id, &owner.login, "User")
                && matches!(
                    r["state"].as_str(),
                    Some("APPROVED" | "CHANGES_REQUESTED" | "DISMISSED")
                )
        })
        .map(|r| {
            Ok((
                request::review_order(r).context("owner review order missing")?,
                r,
            ))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max_by_key(|(order, _)| *order)
        .context("owner review missing")?
        .1;
    let marker = format!("<!-- securefix:control-review:{} -->", control.identity()?);
    ensure!(
        latest["state"] == "APPROVED"
            && latest["commit_id"] == head
            && latest["body"]
                .as_str()
                .is_some_and(|body| body.lines().any(|line| line == marker)),
        "latest owner review is not an approval of this head and control"
    );
    Ok((
        latest["id"].as_u64().context("owner review ID missing")?,
        timestamp(&latest["submitted_at"])?,
    ))
}

fn timestamp(value: &Value) -> Result<DateTime<Utc>> {
    Ok(
        DateTime::parse_from_rfc3339(value.as_str().context("timestamp missing")?)?
            .with_timezone(&Utc),
    )
}

fn owner_comment(
    api: &GitHub,
    repository: &str,
    number: u64,
    id: u64,
    kind: RequestKind,
    after: DateTime<Utc>,
) -> Result<DateTime<Utc>> {
    ensure!(id > 0, "owner command ID missing");
    let comment: Value = api.get(&format!("/repos/{repository}/issues/comments/{id}"))?;
    validate_comment(&comment, repository, number, id, kind, after)
}

pub(crate) fn validate_comment(
    comment: &Value,
    repository: &str,
    number: u64,
    id: u64,
    kind: RequestKind,
    after: DateTime<Utc>,
) -> Result<DateTime<Utc>> {
    let trusted = config::trusted()?;
    let created = timestamp(&comment["created_at"])?;
    let updated = timestamp(&comment["updated_at"])?;
    let age = Utc::now().signed_duration_since(created);
    ensure!(
        comment["id"] == id
            && kind.matches_comment_body(&comment["body"])
            && request::matches_principal(
                &comment["user"],
                trusted.owner_id,
                &trusted.deployment.owner_login,
                "User"
            )
            && comment["issue_url"]
                == format!("https://api.github.com/repos/{repository}/issues/{number}")
            && created == updated
            && created >= after
            && age.num_seconds() >= 0
            && age.num_minutes() < 60,
        "owner command is edited, expired, pre-review or bound to another owner/PR"
    );
    Ok(updated)
}

fn require_unconsumed(api: &GitHub, plan: &Plan) -> Result<()> {
    let r = &plan.request;
    let trusted = config::trusted()?;
    let Authorization::OwnerComment { comment_id, .. } = r.authorization else {
        anyhow::bail!("migration lacks owner merge command")
    };
    let prefixes = [plan.approve_comment_id, comment_id]
        .into_iter()
        .map(|id| {
            Ok(format!(
                "<!-- securefix:v3:owner:{}:{}:{id} -->",
                r.pull_request.head_sha,
                r.control.identity()?
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let comments = api.paginate(&format!(
        "/repos/{}/issues/{}/comments",
        r.repository.full_name, r.pull_request.number
    ))?;
    ensure!(
        !comments.iter().any(|c| request::matches_principal(
            &c["user"],
            trusted.server_bot_id,
            &trusted.deployment.server_bot_login,
            "Bot"
        ) && c["body"].as_str().is_some_and(|body| body
            .lines()
            .any(|line| prefixes.iter().any(|prefix| line == prefix)))),
        "owner approval or merge command was already consumed; issue new commands"
    );
    Ok(())
}

fn read_plan() -> Result<Plan> {
    let metadata = std::fs::symlink_metadata(PLAN)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 16384,
        "migration plan must be a bounded regular file"
    );
    Ok(serde_json::from_slice(&std::fs::read(PLAN)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Fixture, Route};

    const TEST_CALLER: &str = "civitaspo/dotfiles";
    const TEST_PR: u64 = 41;
    const TEST_RUN: u64 = 88;
    const TEST_PUBLISHER: u64 = 5;
    fn sha(ch: char) -> String {
        ch.to_string().repeat(40)
    }

    fn migration_plan(control: &securefix::control::ControlRevision) -> Plan {
        let review_at = Utc::now() - chrono::Duration::minutes(3);
        let approve_at = Utc::now() - chrono::Duration::minutes(2);
        let merge_at = Utc::now() - chrono::Duration::minutes(1);
        Plan {
            version: 1,
            request: RequestManifest {
                version: 1,
                kind: RequestKind::Merge,
                repository: RepositoryRef {
                    id: 123,
                    full_name: TEST_CALLER.into(),
                },
                pull_request: PullRequestRef {
                    number: TEST_PR,
                    head_sha: sha('d'),
                    base_ref: "main".into(),
                },
                authorization: Authorization::OwnerComment {
                    comment_id: 302,
                    updated_at: Some(merge_at),
                },
                accepted_at: Utc::now() - chrono::Duration::seconds(10),
                run_id: TEST_RUN,
                run_attempt: 1,
                workflow_sha: control.source_sha.clone(),
                caller_workflow_sha: sha('c'),
                control: control.clone(),
            },
            approve_comment_id: 301,
            approve_updated_at: approve_at,
            owner_review_id: 201,
            owner_review_at: review_at,
            base_sha: sha('c'),
            publisher_run_id: TEST_PUBLISHER,
            processor_sha: sha('f'),
        }
    }

    fn migration_routes(
        control: &securefix::control::ControlRevision,
        processor_sha: &str,
        review_at: DateTime<Utc>,
        approve_at: DateTime<Utc>,
        merge_at: DateTime<Utc>,
    ) -> Vec<Route> {
        use base64::Engine;
        let trusted = config::trusted().unwrap();
        let server = &trusted.deployment.server;
        let repository_id = 123;
        let base = sha('c');
        let head = sha('d');
        let activation_sha = sha('e');
        let update_branch = trusted.deployment.runtime_update_branch.as_str();
        let policy = Policy::load("tests/fixtures/policy.json").unwrap();
        let generated =
            super::super::caller::rendered_files(&control.source_sha, "v0.2.23", "main", false)
                .unwrap();
        let mut files = generated.clone();
        files.insert(
            ".github/workflows/push.yml".into(),
            super::super::caller::rendered_push_fixture("main").unwrap(),
        );
        let content = |bytes: &[u8]| json!({"encoding":"base64","content":base64::engine::general_purpose::STANDARD.encode(bytes)});
        let content_route = |repository: &str, path: &str, revision: &str, bytes: &[u8]| {
            let mut value = content(bytes);
            value["path"] = json!(path);
            value["type"] = json!("file");
            value["size"] = json!(bytes.len());
            Route::get(
                format!("/repos/{repository}/contents/{path}?ref={revision}"),
                value,
            )
        };
        let server_repo = json!({"id":server.id,"full_name":server.repository,
            "default_branch":server.default_branch,"owner":{"id":trusted.deployment.repository_owner.id}});
        let caller_repo = json!({"id":repository_id,"full_name":TEST_CALLER,
            "default_branch":"main","owner":{"id":trusted.deployment.repository_owner.id}});
        let processor_run = json!({"id":TEST_RUN,"repository":{"id":server.id,"full_name":server.repository},
            "head_repository":{"id":server.id,"full_name":server.repository},
            "head_sha":processor_sha,"head_branch":server.default_branch,"path":WORKFLOW,
            "event":"workflow_dispatch","run_attempt":1,"status":"in_progress",
            "actor":{"id":trusted.owner_id},"triggering_actor":{"id":trusted.owner_id}});
        let publisher_run = json!({"id":TEST_PUBLISHER,"repository":{"id":server.id,"full_name":server.repository},
            "head_repository":{"id":server.id,"full_name":server.repository},
            "head_sha":control.source_sha,"head_branch":server.default_branch,
            "path":format!(".github/workflows/publish-runtime.yml@refs/heads/{}",server.default_branch),
            "event":"workflow_dispatch","run_attempt":1,"status":"completed","conclusion":"success",
            "actor":{"id":trusted.owner_id},"triggering_actor":{"id":trusted.owner_id}});
        let control_bytes = serde_json::to_vec(control).unwrap();
        let mut routes = vec![
            Route::get(
                format!("/repos/{}/actions/runs/{TEST_RUN}", server.repository),
                processor_run,
            ),
            Route::get(
                format!(
                    "/repos/{}/commits/{}",
                    server.repository, server.default_branch
                ),
                json!({"sha":processor_sha,"commit":{"verification":{"verified":true}}}),
            ),
            Route::get(format!("/repos/{}", server.repository), server_repo.clone()),
            Route::get(
                format!(
                    "/repos/{}/commits/{}",
                    server.repository, server.default_branch
                ),
                json!({"sha":processor_sha}),
            ),
            content_route(
                &server.repository,
                "control/active.json",
                processor_sha,
                &control_bytes,
            ),
            Route::get(
                format!(
                    "/repos/{}/commits?path=control/active.json&per_page=1",
                    server.repository
                ),
                json!([{"sha":activation_sha,"commit":{"committer":{"date":(review_at-chrono::Duration::minutes(1)).to_rfc3339()}}}]),
            ),
            content_route(
                &server.repository,
                "control/active.json",
                &activation_sha,
                &control_bytes,
            ),
            Route::get(
                format!("/repos/{}/actions/runs/{TEST_PUBLISHER}", server.repository),
                publisher_run,
            ),
            Route::get(format!("/repos/{}", server.repository), server_repo),
        ];
        let manifest = b"[package]\nname = \"securefix\"\nversion = \"0.2.23\"\n";
        let mut source_manifest = content(manifest);
        source_manifest["path"] = json!("Cargo.toml");
        source_manifest["type"] = json!("file");
        source_manifest["size"] = json!(manifest.len());
        routes.push(Route::get(
            format!(
                "/repos/{}/contents/Cargo.toml?ref={}",
                server.repository, control.source_sha
            ),
            source_manifest.clone(),
        ));
        let release = json!({"id":control.release_id,"tag_name":"v0.2.23","name":"v0.2.23",
            "target_commitish":control.source_sha,"draft":false,"immutable":true,"prerelease":false,
            "assets":[{"id":control.asset_id,"name":"securefix-runtime-linux-x86_64.tar.gz","state":"uploaded",
                "size":100,"digest":format!("sha256:{}",control.archive_sha256)}]});
        routes.extend([
            Route::get(format!("/repos/{}/releases/tags/v0.2.23", server.repository), release),
            Route::get(format!("/repos/{}/git/ref/tags/v0.2.23", server.repository),
                json!({"ref":"refs/tags/v0.2.23","object":{"type":"commit","sha":control.source_sha}})),
            Route::get(format!("/repos/{TEST_CALLER}"), caller_repo.clone()),
            Route::get(format!("/repos/{TEST_CALLER}/commits/main"), json!({"sha":base})),
        ]);
        routes.push(Route::get(
            format!(
                "/repos/{}/contents/Cargo.toml?ref={}",
                server.repository, control.source_sha
            ),
            source_manifest,
        ));
        routes.push(content_route(
            TEST_CALLER,
            ".github/workflows/push.yml",
            &base,
            &files[".github/workflows/push.yml"],
        ));
        routes.push(Route::request(
            "GET",
            format!("/repos/{TEST_CALLER}/contents/.github/workflows/wc-autofix.yml?ref={base}"),
            404,
            json!({"message":"Not Found"}),
        ));
        for (path, bytes) in &files {
            if path == ".github/workflows/policy-check.yml" {
                routes.push(Route::request(
                    "GET",
                    format!("/repos/{TEST_CALLER}/contents/{path}?ref={base}"),
                    404,
                    json!({"message":"Not Found"}),
                ));
            } else {
                routes.push(content_route(TEST_CALLER, path, &base, bytes));
            }
        }
        let pr = json!({"number":TEST_PR,"state":"open","draft":false,
            "user":{"id":policy.server_bot_id,"type":"Bot"},
            "head":{"repo":{"id":repository_id,"full_name":TEST_CALLER},"ref":update_branch,"sha":head},
            "base":{"repo":{"full_name":TEST_CALLER},"ref":"main","sha":base}});
        routes.push(Route::get(
            format!("/repos/{TEST_CALLER}/pulls/{TEST_PR}"),
            pr.clone(),
        ));
        routes.extend([
            Route::get(format!("/repos/{TEST_CALLER}/git/ref/heads/{update_branch}"), json!({"object":{"sha":head}})),
            Route::get(format!("/repos/{TEST_CALLER}/commits/main"), json!({"sha":base})),
            Route::get(format!("/repos/{TEST_CALLER}/compare/{base}...{head}"), json!({
                "status":"ahead","total_commits":1,"commits":[{"sha":head}],
                "files":[{"filename":".github/workflows/policy-check.yml","status":"added"}]})),
            Route::get(format!("/repos/{TEST_CALLER}/commits/{head}"), json!({"sha":head,
                "commit":{"verification":{"verified":true}},"author":{"id":policy.server_bot_id,"login":trusted.deployment.server_bot_login}})),
            Route::get(format!("/repos/{TEST_CALLER}/git/commits/{head}"), json!({"tree":{"sha":sha('g')}})),
            Route::get(format!("/repos/{TEST_CALLER}/git/trees/{}?recursive=1", sha('g')), json!({"truncated":false,
                "tree":files.keys().map(|path| json!({"path":path,"type":"blob","mode":"100644"})).collect::<Vec<_>>()})),
        ]);
        for (path, bytes) in &files {
            routes.push(content_route(TEST_CALLER, path, &head, bytes));
        }
        let changed_files =
            json!([{"filename":".github/workflows/policy-check.yml","status":"added"}]);
        routes.extend([
            Route::get(format!("/repos/{TEST_CALLER}/pulls?state=open&head=civitaspo:{update_branch}&per_page=100&page=1"), json!([pr.clone()])),
            Route::get(format!("/repos/{TEST_CALLER}/pulls/{TEST_PR}/files?per_page=100&per_page=100&page=1"), changed_files.clone()),
            Route::get(format!("/repos/{TEST_CALLER}/pulls/{TEST_PR}"), pr.clone()),
            Route::get(format!("/repos/{TEST_CALLER}/pulls/{TEST_PR}/commits?per_page=100&page=1"), json!([{
                "sha":head,"commit":{"verification":{"verified":true}},
                "author":{"id":policy.server_bot_id,"login":trusted.deployment.server_bot_login},
                "committer":{"id":policy.server_bot_id,"login":trusted.deployment.server_bot_login}}])),
            Route::get(format!("/repos/{TEST_CALLER}/pulls/{TEST_PR}/files?per_page=100&page=1"), changed_files),
            Route::get(format!("/repos/{TEST_CALLER}/pulls/{TEST_PR}"), pr.clone()),
        ]);
        let review = json!({"id":201,"state":"APPROVED","commit_id":head,
            "body":format!("<!-- securefix:control-review:{} -->",control.identity().unwrap()),
            "submitted_at":review_at.to_rfc3339(),"user":{"id":trusted.owner_id,"login":trusted.deployment.owner_login,"type":"User"}});
        for _ in 0..2 {
            routes.extend([Route::get(
                format!("/repos/{TEST_CALLER}/pulls/{TEST_PR}/reviews?per_page=100&page=1"),
                json!([review.clone()]),
            )]);
        }
        for (id, body, at) in [(301, "/approve", approve_at), (302, "/merge", merge_at)] {
            routes.push(Route::get(format!("/repos/{TEST_CALLER}/issues/comments/{id}"), json!({
                "id":id,"body":body,"created_at":at.to_rfc3339(),"updated_at":at.to_rfc3339(),
                "issue_url":format!("https://api.github.com/repos/{TEST_CALLER}/issues/{TEST_PR}"),
                "user":{"id":trusted.owner_id,"login":trusted.deployment.owner_login,"type":"User"}})));
        }
        routes.extend([
            Route::get(format!("/repos/{TEST_CALLER}"), caller_repo),
            Route::get(format!("/repos/{TEST_CALLER}/pulls/{TEST_PR}"), pr),
            Route::get(format!("/repos/{TEST_CALLER}/issues/comments/302"), json!({
                "id":302,"body":"/merge","updated_at":merge_at.to_rfc3339(),
                "issue_url":format!("https://api.github.com/repos/{TEST_CALLER}/issues/{TEST_PR}"),
                "user":{"id":trusted.owner_id,"login":trusted.deployment.owner_login,"type":"User"}})),
            Route::get(format!("/repos/{TEST_CALLER}/issues/{TEST_PR}/timeline?per_page=100&page=1"), json!([])),
        ]);
        routes
    }

    #[test]
    fn verify_binds_the_canonical_migration_to_owner_review_commands_and_control() {
        use std::process::Command as ProcessCommand;
        if std::env::var_os("SECUREFIX_REVIEWED_VERIFY_CHILD").is_some() {
            let control = Fixture::control_revision();
            let plan = migration_plan(&control);
            let mut policy = Policy::load("tests/fixtures/policy.json").unwrap();
            policy.revision = control.source_sha.clone();
            policy.control = Some(control.clone());
            let fixture = Fixture::new(migration_routes(
                &control,
                &plan.processor_sha,
                plan.owner_review_at,
                plan.approve_updated_at,
                match plan.request.authorization {
                    Authorization::OwnerComment {
                        updated_at: Some(at),
                        ..
                    } => at,
                    _ => unreachable!("migration plan uses an owner merge comment"),
                },
            ));
            let migration = verify(&fixture.api, &policy, &plan).unwrap();
            assert_eq!(migration.source_sha, control.source_sha);
            assert!(!migration.default_current);
            assert!(
                migration
                    .files
                    .contains_key(".github/workflows/policy-check.yml")
            );
            fixture.finish();

            for (mut rejected, expected_routes) in [
                (
                    {
                        let mut plan = migration_plan(&control);
                        plan.request.pull_request.head_sha = sha('e');
                        plan
                    },
                    2,
                ),
                (
                    {
                        let mut plan = migration_plan(&control);
                        plan.request.control.generation += 1;
                        plan.request.control.previous = control.identity().unwrap();
                        plan
                    },
                    2,
                ),
            ] {
                rejected.request.workflow_sha = rejected.request.control.source_sha.clone();
                let trusted = config::trusted().unwrap();
                let server = &trusted.deployment.server;
                let run = json!({"id":TEST_RUN,"repository":{"id":server.id,"full_name":server.repository},
                    "head_repository":{"id":server.id,"full_name":server.repository},"head_sha":sha('f'),
                    "head_branch":server.default_branch,"path":WORKFLOW,"event":"workflow_dispatch",
                    "run_attempt":1,"status":"in_progress","actor":{"id":trusted.owner_id},"triggering_actor":{"id":trusted.owner_id}});
                let routes = vec![
                    Route::get(
                        format!("/repos/{}/actions/runs/{TEST_RUN}", server.repository),
                        run,
                    ),
                    Route::get(
                        format!(
                            "/repos/{}/commits/{}",
                            server.repository, server.default_branch
                        ),
                        json!({"sha":sha('f'),"commit":{"verification":{"verified":true}}}),
                    ),
                ];
                assert_eq!(expected_routes, routes.len());
                let fixture = Fixture::new(routes);
                assert!(verify(&fixture.api, &policy, &rejected).is_err());
                fixture.finish();
            }
        } else {
            let trusted = config::trusted().unwrap();
            let control = Fixture::control_revision();
            let event = json!({"inputs":{"repository":TEST_CALLER,"pull_request":TEST_PR.to_string(),
                "expected_head_sha":sha('d'),"control_id":control.identity().unwrap(),
                "approve_comment_id":"301","merge_comment_id":"302","publisher_run_id":TEST_PUBLISHER.to_string()}});
            let directory = tempfile::tempdir().unwrap();
            let event_path = directory.path().join("event.json");
            std::fs::write(&event_path, serde_json::to_vec(&event).unwrap()).unwrap();
            let status = ProcessCommand::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("distribution::reviewed::tests::verify_binds_the_canonical_migration_to_owner_review_commands_and_control")
                .arg("--nocapture")
                .env("SECUREFIX_REVIEWED_VERIFY_CHILD","1")
                .env("GITHUB_EVENT_PATH",event_path)
                .env("GITHUB_REPOSITORY",&trusted.deployment.server.repository)
                .env("GITHUB_REF",format!("refs/heads/{}",trusted.deployment.server.default_branch))
                .env("GITHUB_EVENT_NAME","workflow_dispatch")
                .env("GITHUB_WORKFLOW_REF",format!("{}/{}@refs/heads/{}",trusted.deployment.server.repository,WORKFLOW,trusted.deployment.server.default_branch))
                .env("GITHUB_ACTOR_ID",trusted.owner_id.to_string())
                .env("GITHUB_RUN_ID",TEST_RUN.to_string())
                .env("GITHUB_RUN_ATTEMPT","1")
                .env("GITHUB_SHA",sha('f'))
                .status()
                .unwrap();
            assert!(
                status.success(),
                "isolated reviewed-route test process failed"
            );
        }
    }

    #[test]
    fn producer_requires_exact_owner_first_attempt_main_workflow() {
        let config = config::trusted().unwrap();
        let server = &config.deployment.server;
        let source = "a".repeat(40);
        let run = json!({"id":7,"repository":{"id":server.id,"full_name":server.repository},
            "head_repository":{"id":server.id,"full_name":server.repository},
            "head_sha":source,"head_branch":server.default_branch,"path":WORKFLOW,
            "event":"workflow_dispatch","run_attempt":1,"status":"in_progress",
            "actor":{"id":config.owner_id},"triggering_actor":{"id":config.owner_id}});
        validate_producer(&run, 7, &source).unwrap();
        for (path, value) in [
            ("/actor/id", json!(1)),
            ("/triggering_actor/id", json!(1)),
            ("/repository/id", json!(1)),
            ("/head_repository/id", json!(1)),
            ("/run_attempt", json!(2)),
            ("/path", json!(".github/workflows/distribute-runtime.yml")),
            ("/event", json!("issue_comment")),
            ("/head_sha", json!("b".repeat(40))),
            ("/head_branch", json!("unreviewed")),
            ("/status", json!("completed")),
        ] {
            let mut changed = run.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(validate_producer(&changed, 7, &source).is_err(), "{path}");
        }
    }

    #[test]
    fn commands_are_fresh_unedited_owner_comments_after_the_review_on_this_pr() {
        let trusted = config::trusted().unwrap();
        let reviewed = Utc::now() - chrono::Duration::minutes(2);
        let command_at = Utc::now() - chrono::Duration::minutes(1);
        let comment = json!({"id":8,"user":{"id":trusted.owner_id,"login":trusted.deployment.owner_login,"type":"User"},
            "body":"/merge","issue_url":"https://api.github.com/repos/owner/caller/issues/2",
            "created_at":command_at.to_rfc3339(),"updated_at":command_at.to_rfc3339()});
        validate_comment(&comment, "owner/caller", 2, 8, RequestKind::Merge, reviewed).unwrap();
        for (path, value) in [
            ("/user/id", json!(1)),
            ("/user/type", json!("Bot")),
            ("/body", json!("/approve")),
            ("/id", json!(9)),
            (
                "/issue_url",
                json!("https://api.github.com/repos/owner/caller/issues/3"),
            ),
            ("/updated_at", json!(Utc::now().to_rfc3339())),
        ] {
            let mut changed = comment.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(
                validate_comment(&changed, "owner/caller", 2, 8, RequestKind::Merge, reviewed)
                    .is_err(),
                "{path}"
            );
        }
        assert!(
            validate_comment(
                &comment,
                "owner/caller",
                2,
                8,
                RequestKind::Merge,
                Utc::now()
            )
            .is_err()
        );
        let mut expired = comment;
        let old = (Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        expired["created_at"] = json!(old);
        expired["updated_at"] = json!(old);
        assert!(
            validate_comment(
                &expired,
                "owner/caller",
                2,
                8,
                RequestKind::Merge,
                reviewed - chrono::Duration::hours(3)
            )
            .is_err()
        );
    }

    #[test]
    fn consumed_owner_commands_cannot_be_replayed_in_another_dispatch() {
        let trusted = config::trusted().unwrap();
        let control = Fixture::control_revision();
        let now = Utc::now();
        let plan = Plan {
            version: 1,
            request: RequestManifest {
                version: 1,
                kind: RequestKind::Merge,
                repository: RepositoryRef {
                    id: 1,
                    full_name: "owner/caller".into(),
                },
                pull_request: PullRequestRef {
                    number: 2,
                    head_sha: "b".repeat(40),
                    base_ref: "main".into(),
                },
                authorization: Authorization::OwnerComment {
                    comment_id: 4,
                    updated_at: Some(now),
                },
                accepted_at: now,
                run_id: 7,
                run_attempt: 1,
                workflow_sha: control.source_sha.clone(),
                caller_workflow_sha: "c".repeat(40),
                control: control.clone(),
            },
            approve_comment_id: 3,
            approve_updated_at: now,
            owner_review_id: 5,
            owner_review_at: now,
            base_sha: "c".repeat(40),
            publisher_run_id: control.publisher_run_id,
            processor_sha: "a".repeat(40),
        };
        for id in [3, 4] {
            let marker = format!(
                "<!-- securefix:v3:owner:{}:{}:{id} -->",
                "b".repeat(40),
                control.identity().unwrap()
            );
            let fixture = Fixture::new(vec![Route::get(
                "/repos/owner/caller/issues/2/comments?per_page=100&page=1",
                json!([{"user":{"id":trusted.server_bot_id,"login":trusted.deployment.server_bot_login,"type":"Bot"},"body":marker}]),
            )]);
            assert!(require_unconsumed(&fixture.api, &plan).is_err());
            fixture.finish();
        }
        let fixture = Fixture::new(vec![Route::get(
            "/repos/owner/caller/issues/2/comments?per_page=100&page=1",
            json!([]),
        )]);
        require_unconsumed(&fixture.api, &plan).unwrap();
        fixture.finish();
    }
}
