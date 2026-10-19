//! Read-only qualification by the captured, reviewed host validator.
use anyhow::{Context, Result, ensure};
use securefix::{config, policy::Policy};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

const WORKFLOW: &str = ".github/workflows/testing-publish-runtime.yml";
pub(super) const POLICY_PATH: &str = ".github/testing-policy.json";
pub(super) const POLICY: &[u8] = include_bytes!("../../.github/testing-policy.json");

fn workflow_ref(server: &config::Repository) -> String {
    format!(
        "{}/{WORKFLOW}@refs/heads/{}",
        server.repository, server.default_branch
    )
}

pub(super) fn validate(source: &str, archive: &Path) -> Result<()> {
    securefix::policy::validate_sha(source)?;
    let trusted = config::trusted()?;
    ensure!(
        trusted.deployment.workflow_prefix.is_empty()
            && trusted.deployment.control_repository.is_none(),
        "testing publication requires the production-configured trusted host validator"
    );
    let server = &trusted.deployment.server;
    ensure!(
        std::env::var("GITHUB_EVENT_NAME").is_ok_and(|v| v == "workflow_dispatch")
            && std::env::var("GITHUB_REF")
                .is_ok_and(|v| v == format!("refs/heads/{}", server.default_branch))
            && std::env::var("GITHUB_WORKFLOW_REF").is_ok_and(|v| v == workflow_ref(server))
            && std::env::var("GITHUB_SHA").is_ok_and(|v| v == source)
            && std::env::var("SECUREFIX_TEST_BASELINE_SHA").is_ok_and(|v| v == source),
        "testing publication must use its captured protected-main workflow source"
    );
    let api = super::integration_read_api()?;
    let run_id: u64 = std::env::var("GITHUB_RUN_ID")?.parse()?;
    let run: Value = api.get(&format!(
        "/repos/{}/actions/runs/{run_id}",
        server.repository
    ))?;
    validate_run(&run, run_id, source, trusted)?;
    let version = crate::runtime::version_at_source(&api, source)?;
    require_prerelease(&version)?;
    ensure!(
        api.content(&server.repository, POLICY_PATH, source)? == POLICY,
        "testing policy differs from the captured trusted source"
    );
    validate_policy(trusted)?;
    let (bytes, digest) = crate::runtime::read_archive(archive)?;
    ensure!(
        securefix::runtime_archive::policy(&bytes)? == POLICY,
        "testing archive policy differs from the captured trusted source"
    );
    securefix::output("runtime_tag", version.tag())?;
    securefix::output("archive_sha256", digest)?;
    securefix::output(
        "policy_sha256",
        securefix::hex_encode(Sha256::digest(POLICY)),
    )
}

pub(super) fn require_prerelease(version: &crate::runtime::RuntimeVersion) -> Result<()> {
    let number = version
        .as_semver()
        .pre
        .as_str()
        .strip_prefix("pre.")
        .context("testing publication requires a pre.N runtime version")?;
    ensure!(
        number.parse::<u64>().is_ok_and(|n| n > 0),
        "invalid testing pre-release number"
    );
    Ok(())
}

pub(super) fn validate_policy(trusted: &config::TrustedConfig) -> Result<()> {
    let policy = Policy::parse(POLICY)?;
    let mut expected = trusted.deployment.clone();
    expected.workflow_prefix = "testing-".into();
    expected.control_repository = Some(expected.integration.clone());
    // These two reviewed test branch names are not credential/source authority.
    expected.release_branch = policy.deployment.release_branch.clone();
    expected.runtime_update_branch = policy.deployment.runtime_update_branch.clone();
    ensure!(
        policy.deployment == expected
            && policy.owner_id == trusted.owner_id
            && policy.client_bot_id == trusted.client_bot_id
            && policy.server_bot_id == trusted.server_bot_id,
        "testing policy changes trusted workflow, App or User identities"
    );
    Ok(())
}

fn validate_run(run: &Value, id: u64, source: &str, trusted: &config::TrustedConfig) -> Result<()> {
    let server = &trusted.deployment.server;
    ensure!(
        id > 0
            && run["id"].as_u64() == Some(id)
            && run["run_attempt"] == 1
            && run["event"] == "workflow_dispatch"
            && run["status"] == "in_progress"
            && run["head_sha"] == source
            && run["head_branch"] == server.default_branch
            && run["repository"]["id"].as_u64() == Some(server.id)
            && run["repository"]["full_name"] == server.repository
            && run["head_repository"]["id"].as_u64() == Some(server.id)
            && run["head_repository"]["full_name"] == server.repository
            && run["actor"]["id"].as_u64() == Some(trusted.owner_id)
            && run["triggering_actor"]["id"].as_u64() == Some(trusted.owner_id)
            && (run["path"] == WORKFLOW
                || run["path"] == format!("{WORKFLOW}@refs/heads/{}", server.default_branch)),
        "testing publisher is not the exact first-attempt owner workflow on protected main"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn testing_publication_keeps_production_identities_and_requires_pre_n() {
        let production = Policy::parse(include_bytes!("../../policy.json")).unwrap();
        let mut trusted = config::TrustedConfig {
            owner_id: production.owner_id,
            client_bot_id: production.client_bot_id,
            server_bot_id: production.server_bot_id,
            renovate_merge_bot: None,
            deployment: production.deployment,
        };
        validate_policy(&trusted).unwrap();
        trusted.deployment.approval_reviewer.id += 1;
        assert!(validate_policy(&trusted).is_err());
        for (version, accepted) in [
            ("0.2.34-pre.1", true),
            ("0.2.34", false),
            ("0.2.34-rc.1", false),
            ("0.2.34-pre.0", false),
            ("0.2.34-pre.1.2", false),
        ] {
            assert_eq!(
                require_prerelease(&crate::runtime::RuntimeVersion::parse(version).unwrap())
                    .is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn testing_publisher_identity_rejects_wrong_namespace_source_actor_and_attempt() {
        let trusted = config::trusted().unwrap();
        let server = &trusted.deployment.server;
        assert_eq!(
            workflow_ref(server),
            format!(
                "{}/.github/workflows/testing-publish-runtime.yml@refs/heads/{}",
                server.repository, server.default_branch
            )
        );
        let source = "a".repeat(40);
        let run = json!({"id":7,"run_attempt":1,"event":"workflow_dispatch","status":"in_progress",
            "head_sha":source,"head_branch":server.default_branch,
            "repository":{"id":server.id,"full_name":server.repository},
            "head_repository":{"id":server.id,"full_name":server.repository},
            "actor":{"id":trusted.owner_id},"triggering_actor":{"id":trusted.owner_id},"path":WORKFLOW});
        validate_run(&run, 7, &source, trusted).unwrap();
        for (key, value) in [
            ("path", json!(".github/workflows/publish-runtime.yml")),
            ("run_attempt", json!(2)),
            ("head_sha", json!("b".repeat(40))),
            ("head_branch", json!("integration/native-test")),
            ("triggering_actor", json!({"id":1})),
            (
                "repository",
                json!({"id":server.id,"full_name":"another/repository"}),
            ),
        ] {
            let mut wrong = run.clone();
            wrong[key] = value;
            assert!(validate_run(&wrong, 7, &source, trusted).is_err(), "{key}");
        }
    }
}
