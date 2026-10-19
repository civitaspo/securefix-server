//! Native label ingress and the dedicated owner migration lane. Candidate data grants no authority.
use super::testing_runtime::CaptureKind;
use anyhow::{Context, Result, ensure};
use securefix::{api::GitHub, config, policy::Policy};
use serde_json::Value;

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum HostKind {
    Request,
    CallerMigration,
}

impl HostKind {
    fn path(self) -> &'static str {
        match self {
            Self::Request => ".github/workflows/testing-process-request.yml",
            Self::CallerMigration => ".github/workflows/testing-merge-caller-migration.yml",
        }
    }

    fn workflow_ref(self, server: &config::Repository) -> String {
        format!(
            "{}/{}@refs/heads/{}",
            server.repository,
            self.path(),
            server.default_branch
        )
    }
}

fn label_prefix(kind: CaptureKind, refresh: bool) -> &'static str {
    match kind {
        CaptureKind::Approve if refresh => "testing-approve-request-renovate-",
        CaptureKind::Approve => "testing-approve-request-",
        CaptureKind::Merge => "testing-merge-request-",
        CaptureKind::Policy => "testing-policy-request-",
    }
}

pub(super) fn label_name(kind: CaptureKind, run_id: u64, refresh: bool) -> String {
    format!("{}{run_id}", label_prefix(kind, refresh))
}

fn label_request(
    payload: &Value,
    trusted: &config::TrustedConfig,
) -> Result<(CaptureKind, u64, bool)> {
    let server = &trusted.deployment.server;
    ensure!(
        payload["action"] == "created"
            && payload["repository"]["id"].as_u64() == Some(server.id)
            && payload["repository"]["full_name"] == server.repository
            && crate::request::matches_principal(
                &payload["sender"],
                trusted.client_bot_id,
                &trusted.deployment.client_bot_login,
                "Bot"
            ),
        "testing label must be created on the fixed server by the Client App"
    );
    let name = payload["label"]["name"]
        .as_str()
        .context("missing testing request label")?;
    for (kind, refresh) in [
        (CaptureKind::Approve, true),
        (CaptureKind::Approve, false),
        (CaptureKind::Merge, false),
        (CaptureKind::Policy, false),
    ] {
        if let Some(suffix) = name.strip_prefix(label_prefix(kind, refresh)) {
            let run_id: u64 = suffix.parse().context("invalid testing request run ID")?;
            ensure!(
                run_id > 0 && name == label_name(kind, run_id, refresh),
                "testing request label has a noncanonical run ID"
            );
            ensure!(
                payload["label"]["description"].as_str()
                    == Some(
                        format!("{}/{run_id}", trusted.deployment.integration.repository).as_str()
                    ),
                "testing request label locator differs from the fixed test client or run"
            );
            return Ok((kind, run_id, refresh));
        }
    }
    anyhow::bail!("unexpected testing request label")
}

pub(super) fn require_context(kind: HostKind) -> Result<()> {
    let trusted = config::trusted()?;
    let server = &trusted.deployment.server;
    let source = std::env::var("SECUREFIX_TEST_BASELINE_SHA")?;
    let (event, actor) = match kind {
        HostKind::Request => ("label", trusted.client_bot_id),
        HostKind::CallerMigration => ("workflow_dispatch", trusted.owner_id),
    };
    ensure!(
        std::env::var("GITHUB_EVENT_NAME").is_ok_and(|v| v == event)
            && std::env::var("GITHUB_REPOSITORY").is_ok_and(|v| v == server.repository)
            && std::env::var("GITHUB_REF")
                .is_ok_and(|v| v == format!("refs/heads/{}", server.default_branch))
            && std::env::var("GITHUB_SHA").is_ok_and(|v| v == source)
            && std::env::var("GITHUB_WORKFLOW_REF").is_ok_and(|v| v == kind.workflow_ref(server))
            && std::env::var("GITHUB_ACTOR_ID").is_ok_and(|v| v == actor.to_string())
            && std::env::var("GITHUB_RUN_ATTEMPT").is_ok_and(|v| v == "1"),
        "testing processor requires its exact first-attempt event, actor and captured protected-main source"
    );
    let request = if matches!(kind, HostKind::Request) {
        Some(label_request(&securefix::event()?, trusted)?)
    } else {
        None
    };
    let api = super::integration_read_api()?;
    let run_id: u64 = std::env::var("GITHUB_RUN_ID")?.parse()?;
    let run: Value = api.get(&format!(
        "/repos/{}/actions/runs/{run_id}",
        server.repository
    ))?;
    validate_run(&run, run_id, &source, trusted, kind)?;
    if let Some((kind, source_run, _)) = request {
        securefix::output(
            "kind",
            match kind {
                CaptureKind::Approve => "approve",
                CaptureKind::Merge => "merge",
                CaptureKind::Policy => "policy",
            },
        )?;
        securefix::output("source_run_id", source_run.to_string())?;
    }
    Ok(())
}

fn validate_run(
    run: &Value,
    id: u64,
    source: &str,
    trusted: &config::TrustedConfig,
    kind: HostKind,
) -> Result<()> {
    let server = &trusted.deployment.server;
    let (event, actor) = match kind {
        HostKind::Request => ("label", trusted.client_bot_id),
        HostKind::CallerMigration => ("workflow_dispatch", trusted.owner_id),
    };
    ensure!(
        id > 0
            && run["id"].as_u64() == Some(id)
            && run["path"] == kind.path()
            && run["event"] == event
            && run["status"] == "in_progress"
            && run["run_attempt"] == 1
            && run["head_sha"] == source
            && run["head_branch"] == server.default_branch
            && run["repository"]["id"].as_u64() == Some(server.id)
            && run["repository"]["full_name"] == server.repository
            && run["head_repository"]["id"].as_u64() == Some(server.id)
            && run["head_repository"]["full_name"] == server.repository
            && run["actor"]["id"].as_u64() == Some(actor)
            && run["triggering_actor"]["id"].as_u64() == Some(actor),
        "testing processor run differs from the exact workflow, event, actor, source or first attempt"
    );
    Ok(())
}

pub(super) fn cleanup() -> Result<()> {
    require_context(HostKind::Request)?;
    let payload = securefix::event()?;
    let label = payload["label"]["name"]
        .as_str()
        .context("missing testing request label")?;
    let api = GitHub::testing_label_cleanup_from_env("GITHUB_TOKEN", label)?;
    let server = &config::trusted()?.deployment.server.repository;
    match api.delete(&format!("/repos/{server}/labels/{label}")) {
        Ok(()) => Ok(()),
        Err(error)
            if error
                .downcast_ref::<securefix::api::ApiError>()
                .is_some_and(|error| error.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

pub(super) fn prepare(kind: CaptureKind, source_run_id: u64) -> Result<()> {
    require_context(HostKind::Request)?;
    let trusted = config::trusted()?;
    ensure!(
        trusted.deployment.workflow_prefix == "testing-"
            && trusted.deployment.control_repository.as_ref()
                == Some(&trusted.deployment.integration),
        "testing request relay requires the isolated testing policy"
    );
    let (label_kind, label_run, refresh) = label_request(&securefix::event()?, trusted)?;
    ensure!(
        kind == label_kind && source_run_id == label_run,
        "testing request differs from the Client App label"
    );
    let read = GitHub::from_env("SECUREFIX_SERVER_TOKEN")?;
    let policy = Policy::active(&read)?;
    let repository = &trusted.deployment.integration.repository;
    if matches!(kind, CaptureKind::Policy) {
        return crate::policy_check::prepare_testing_request(
            &read,
            &policy,
            repository,
            source_run_id,
        );
    }
    let kind = match kind {
        CaptureKind::Approve if !refresh => crate::request::RequestKind::Approve,
        _ => crate::request::RequestKind::Merge,
    };
    let manifest =
        crate::request::load_source_request(&read, &policy, repository, source_run_id, kind)?;
    if label_kind == CaptureKind::Approve {
        crate::approval::validate_approval_policy(&read, &policy, &manifest)?;
        securefix::workflow::write_json("approval/manifest.json", &manifest)
    } else {
        crate::merge::validate_state(&read, &policy, &manifest)?;
        crate::request::validate_merge_policy(&read, &policy, &manifest, true)?;
        securefix::workflow::write_json("merge/manifest.json", &manifest)
    }
}

pub(super) fn continue_request(kind: CaptureKind, source_run_id: u64) -> Result<()> {
    let trusted = config::trusted()?;
    ensure!(
        trusted.deployment.workflow_prefix == "testing-"
            && trusted.deployment.control_repository.as_ref()
                == Some(&trusted.deployment.integration),
        "candidate continuation requires the isolated testing policy"
    );
    match kind {
        CaptureKind::Approve => {
            let manifest: crate::request::RequestManifest =
                serde_json::from_slice(&std::fs::read("approval/manifest.json")?)?;
            ensure!(
                manifest.run_id == source_run_id,
                "approval continuation source run differs from host request"
            );
            crate::approval::run(crate::approval::Command::ApplyReviewedForTesting)
        }
        CaptureKind::Policy => {
            crate::policy_check::run(crate::policy_check::Command::ApplyForTesting {
                source_run_id,
            })
        }
        CaptureKind::Merge => {
            let manifest: crate::request::RequestManifest =
                serde_json::from_slice(&std::fs::read("merge/manifest.json")?)?;
            ensure!(
                manifest.run_id == source_run_id,
                "merge continuation source run differs from host request"
            );
            crate::merge::run(crate::merge::Command::Authorize)?;
            crate::merge::run(crate::merge::Command::Wait)?;
            crate::merge::run(crate::merge::Command::Apply)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn native_labels_bind_exact_client_sender_repository_run_and_namespace() {
        let trusted = config::trusted().unwrap();
        let server = &trusted.deployment.server;
        let event = json!({"action":"created",
            "repository":{"id":server.id,"full_name":server.repository},
            "sender":{"id":trusted.client_bot_id,"login":trusted.deployment.client_bot_login,"type":"Bot"},
            "label":{"name":"testing-approve-request-7", "description":format!("{}/7",trusted.deployment.integration.repository)}});
        for (kind, refresh) in [
            (CaptureKind::Approve, false),
            (CaptureKind::Approve, true),
            (CaptureKind::Merge, false),
            (CaptureKind::Policy, false),
        ] {
            let mut valid = event.clone();
            valid["label"]["name"] = json!(label_name(kind, 7, refresh));
            assert_eq!(label_request(&valid, trusted).unwrap(), (kind, 7, refresh));
        }
        for name in [
            "approve-request-7",
            "testing-approve-request-0",
            "testing-approve-request-07",
            "testing-approve-request-+7",
            "testing-approve-request-7-extra",
            "testing-policy-request-8",
            "testing-merge-request-renovate-7",
            "testing-securefix-request-7",
        ] {
            let mut wrong = event.clone();
            wrong["label"]["name"] = json!(name);
            assert!(label_request(&wrong, trusted).is_err(), "{name}");
        }
        for (key, value) in [
            ("action", json!("edited")),
            (
                "sender",
                json!({"id":trusted.owner_id,"login":"civitaspo","type":"User"}),
            ),
            (
                "sender",
                json!({"id":trusted.client_bot_id,"login":"wrong[bot]","type":"Bot"}),
            ),
            (
                "sender",
                json!({"id":trusted.client_bot_id,"login":trusted.deployment.client_bot_login,"type":"User"}),
            ),
            (
                "repository",
                json!({"id":server.id+1,"full_name":server.repository}),
            ),
            (
                "repository",
                json!({"id":server.id,"full_name":"other/server"}),
            ),
            (
                "label",
                json!({"name":"testing-approve-request-7","description":format!("{}/7",server.repository)}),
            ),
        ] {
            let mut wrong = event.clone();
            wrong[key] = value;
            assert!(label_request(&wrong, trusted).is_err(), "{key}");
        }
    }

    #[test]
    fn processor_run_rejects_wrong_actor_event_rerun_source_path_and_repository() {
        let trusted = config::trusted().unwrap();
        let server = &trusted.deployment.server;
        let source = "a".repeat(40);
        let run = json!({"id":7,"path":HostKind::Request.path(),"event":"label","status":"in_progress",
            "run_attempt":1,"head_sha":source,"head_branch":server.default_branch,
            "repository":{"id":server.id,"full_name":server.repository},
            "head_repository":{"id":server.id,"full_name":server.repository},
            "actor":{"id":trusted.client_bot_id},"triggering_actor":{"id":trusted.client_bot_id}});
        validate_run(&run, 7, &source, trusted, HostKind::Request).unwrap();
        assert_eq!(
            HostKind::Request.workflow_ref(server),
            format!(
                "{}/.github/workflows/testing-process-request.yml@refs/heads/{}",
                server.repository, server.default_branch
            )
        );
        assert!(validate_run(&run, 7, &source, trusted, HostKind::CallerMigration).is_err());
        let mut migration = run.clone();
        migration["path"] = json!(HostKind::CallerMigration.path());
        migration["event"] = json!("workflow_dispatch");
        migration["actor"] = json!({"id":trusted.owner_id});
        migration["triggering_actor"] = json!({"id":trusted.owner_id});
        validate_run(&migration, 7, &source, trusted, HostKind::CallerMigration).unwrap();
        assert!(validate_run(&migration, 7, &source, trusted, HostKind::Request).is_err());
        let mut wrong_migration = migration.clone();
        wrong_migration["actor"] = json!({"id":trusted.client_bot_id});
        assert!(
            validate_run(
                &wrong_migration,
                7,
                &source,
                trusted,
                HostKind::CallerMigration
            )
            .is_err()
        );
        for (key, value) in [
            ("actor", json!({"id":1})),
            ("triggering_actor", json!({"id":1})),
            ("event", json!("workflow_dispatch")),
            ("run_attempt", json!(2)),
            ("head_sha", json!("b".repeat(40))),
            ("path", json!(".github/workflows/process-request.yml")),
            (
                "repository",
                json!({"id":server.id + 1,"full_name":server.repository}),
            ),
        ] {
            let mut wrong = run.clone();
            wrong[key] = value;
            assert!(
                validate_run(&wrong, 7, &source, trusted, HostKind::Request).is_err(),
                "{key}"
            );
        }
    }
}
