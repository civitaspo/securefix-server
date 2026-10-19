//! Exact owner-dispatched fixture and migration authorities. Native requests use normal commands.
use anyhow::{Result, ensure};
use securefix::config;
use serde_json::Value;

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum HostKind {
    CallerMigration,
    CallerDistribution,
    MigrationFixture,
}

impl HostKind {
    fn path(self) -> &'static str {
        match self {
            Self::CallerMigration => ".github/workflows/testing-merge-caller-migration.yml",
            Self::CallerDistribution => ".github/workflows/testing-distribute-runtime.yml",
            Self::MigrationFixture => ".github/workflows/testing-migration-fixture.yml",
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

pub(super) fn require_context(kind: HostKind) -> Result<()> {
    let trusted = config::trusted()?;
    let server = &trusted.deployment.server;
    let source = std::env::var("SECUREFIX_TEST_BASELINE_SHA")?;
    let (event, actor) = ("workflow_dispatch", trusted.owner_id);
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
    let api = super::integration_read_api()?;
    let run_id: u64 = std::env::var("GITHUB_RUN_ID")?.parse()?;
    let run: Value = api.get(&format!(
        "/repos/{}/actions/runs/{run_id}",
        server.repository
    ))?;
    validate_run(&run, run_id, &source, trusted, kind)?;
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
    let (event, actor) = ("workflow_dispatch", trusted.owner_id);
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fixture_authority_binds_exact_owner_source_run_and_workflow() {
        let trusted = config::trusted().unwrap();
        let server = &trusted.deployment.server;
        let source = "a".repeat(40);
        for kind in [
            HostKind::CallerMigration,
            HostKind::CallerDistribution,
            HostKind::MigrationFixture,
        ] {
            let run = json!({"id":7,"path":kind.path(),"event":"workflow_dispatch","status":"in_progress",
                "run_attempt":1,"head_sha":source,"head_branch":server.default_branch,
                "repository":{"id":server.id,"full_name":server.repository},
                "head_repository":{"id":server.id,"full_name":server.repository},
                "actor":{"id":trusted.owner_id},"triggering_actor":{"id":trusted.owner_id}});
            validate_run(&run, 7, &source, trusted, kind).unwrap();
            for (key, value) in [
                ("actor", json!({"id":trusted.client_bot_id})),
                ("triggering_actor", json!({"id":1})),
                ("event", json!("label")),
                ("run_attempt", json!(2)),
                ("head_sha", json!("b".repeat(40))),
                ("path", json!(".github/workflows/untrusted.yml")),
                (
                    "repository",
                    json!({"id":server.id+1,"full_name":server.repository}),
                ),
            ] {
                let mut wrong = run.clone();
                wrong[key] = value;
                assert!(
                    validate_run(&wrong, 7, &source, trusted, kind).is_err(),
                    "{key}"
                );
            }
        }
    }
}
