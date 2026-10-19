//! Qualify the test control and its source-bound pre-release before returning it to a caller.
use super::testing_publication::{POLICY, POLICY_PATH, require_prerelease, validate_policy};
use anyhow::{Context, Result, ensure};
use securefix::{api::GitHub, config, control::ControlRevision, policy::Policy};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;

pub(super) fn load_for_caller(workflow_sha: &str) -> Result<()> {
    let trusted = config::trusted()?;
    let fixture = &trusted.deployment.integration;
    let running_repository = std::env::var("GITHUB_REPOSITORY")?;
    let client = if running_repository == fixture.repository {
        let token = std::env::var("GITHUB_TOKEN").context("missing test client GITHUB_TOKEN")?;
        ensure!(!token.is_empty(), "test client GITHUB_TOKEN is empty");
        GitHub::new("https://api.github.com", token)?
    } else {
        ensure!(
            running_repository == trusted.deployment.server.repository,
            "testing runtime must load in the fixed test client or server"
        );
        let baseline = std::env::var("SECUREFIX_TEST_BASELINE_SHA")?;
        ensure!(
            baseline == workflow_sha,
            "server testing workflow is not pinned to the captured protected-main revision"
        );
        let token = std::env::var("GITHUB_TOKEN").context("missing server GITHUB_TOKEN")?;
        ensure!(!token.is_empty(), "server GITHUB_TOKEN is empty");
        GitHub::new("https://api.github.com", token)?
    };
    let policy = Policy::parse(POLICY)?;
    let control =
        ControlRevision::load_from_repository(&client, policy.deployment.control_repository())?;
    if running_repository == fixture.repository {
        qualify(workflow_sha, &client)
    } else {
        // Server event workflows are current protected-main code; the runtime source remains
        // independently selected by the isolated test control.
        qualify(&control.source_sha, &client)
    }
}

pub(super) fn load_for_host() -> Result<()> {
    let token = std::env::var("SECUREFIX_TEST_READ_TOKEN")?;
    ensure!(!token.is_empty(), "test client read token is empty");
    let client = GitHub::new("https://api.github.com", token)?;
    let policy = Policy::parse(POLICY)?;
    let control =
        ControlRevision::load_from_repository(&client, policy.deployment.control_repository())?;
    qualify(&control.source_sha, &client)
}

fn qualify(workflow_sha: &str, client: &GitHub) -> Result<()> {
    securefix::policy::validate_sha(workflow_sha)?;
    let trusted = config::trusted()?;
    ensure!(
        (trusted.deployment.workflow_prefix.is_empty()
            && trusted.deployment.control_repository.is_none())
            || (trusted.deployment.workflow_prefix == "testing-"
                && trusted.deployment.control_repository.as_ref()
                    == Some(&trusted.deployment.integration)),
        "testing runtime qualification requires the production or isolated testing deployment"
    );
    validate_policy(trusted)?;
    let policy = Policy::parse(POLICY)?;
    let fixture = policy.deployment.control_repository();
    // Server hosts keep the test installation token separate from server metadata reads.
    // Callers reuse their read-only GITHUB_TOKEN for public server metadata.
    let server = &trusted.deployment.server;
    let public = if std::env::var("GITHUB_REPOSITORY")
        .is_ok_and(|repository| repository == server.repository)
    {
        super::integration_read_api()?
    } else {
        client.clone()
    };
    let baseline = std::env::var("SECUREFIX_TEST_BASELINE_SHA")?;
    let main = || -> Result<Value> {
        public.get(&format!(
            "/repos/{}/commits/{}",
            server.repository, server.default_branch
        ))
    };
    super::validate_test_baseline(&baseline, &main()?)?;
    ensure!(
        public.content(&server.repository, POLICY_PATH, &baseline)? == POLICY,
        "testing runtime policy differs from the captured protected-main policy"
    );
    let repository: Value = public.get(&format!("/repos/{}", server.repository))?;
    ensure!(
        repository["id"].as_u64() == Some(server.id)
            && repository["full_name"] == server.repository
            && repository["default_branch"] == server.default_branch,
        "testing workflow host repository identity changed"
    );
    let control = ControlRevision::load_from_repository(client, fixture)?;
    ensure!(
        control.source_sha == workflow_sha,
        "testing caller workflow source differs from active test control"
    );
    crate::control_commands::require_ancestor(
        &public,
        &server.repository,
        workflow_sha,
        &baseline,
    )?;
    crate::control_commands::verify_source_commit(&public, &server.repository, workflow_sha)?;
    crate::control_commands::verify_ci_status(&public, &server.repository, workflow_sha)?;
    require_prerelease(&crate::runtime::version_at_source(&public, workflow_sha)?)?;
    ensure!(
        public.content(&server.repository, POLICY_PATH, workflow_sha)? == POLICY,
        "testing runtime policy differs from the captured trusted policy"
    );
    let (publication, archive) = crate::control_commands::verify_testing_publisher(
        &public,
        &server.repository,
        workflow_sha,
        control.publisher_run_id,
    )?;
    let bytes = fs::read(archive.path())?;
    let contents = securefix::runtime_archive::contents(&bytes)?;
    validate_binding(&control, &publication, &contents.policy)?;
    let binary = contents
        .binary
        .context("testing archive is missing securefix")?;
    ensure!(
        ControlRevision::load_from_repository(client, fixture)? == control,
        "test control moved during runtime qualification"
    );
    super::validate_test_baseline(&baseline, &main()?)?;
    // Never extract arbitrary archive members, install on PATH, or execute the binary.
    // Artifact uploads exclude files below dot-prefixed directories by default.
    let directory = tempfile::Builder::new()
        .prefix("securefix-testing-runtime-")
        .tempdir()?;
    fs::write(directory.path().join("securefix"), binary)?;
    fs::write(directory.path().join("policy.json"), contents.policy)?;
    fs::write(
        directory.path().join("control.json"),
        serde_json::to_vec(&control)?,
    )?;
    securefix::output("source_sha", workflow_sha)?;
    securefix::output("control_id", control.identity()?)?;
    securefix::output("directory", directory.keep().to_string_lossy())
}

fn validate_binding(
    control: &ControlRevision,
    publication: &crate::runtime::Publication,
    policy: &[u8],
) -> Result<()> {
    control.validate()?;
    ensure!(
        control.source_sha == publication.source_sha
            && control.archive_sha256 == publication.archive_sha256
            && control.release_id == publication.release_id
            && control.asset_id == publication.asset_id,
        "testing publication differs from the full active test descriptor"
    );
    ensure!(
        policy == POLICY && control.policy_sha256 == securefix::hex_encode(Sha256::digest(policy)),
        "testing archive policy differs from active test control or trusted source"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testing_runtime_binds_archive_policy_and_publication_to_fixture_control() {
        let control = ControlRevision {
            version: 1,
            generation: 1,
            source_sha: "a".repeat(40),
            policy_sha256: securefix::hex_encode(Sha256::digest(POLICY)),
            archive_sha256: "b".repeat(64),
            release_id: 1,
            asset_id: 2,
            publisher_run_id: 3,
            verification_run_id: 4,
            previous: "0".repeat(64),
        };
        let publication = crate::runtime::Publication {
            source_sha: control.source_sha.clone(),
            archive_sha256: control.archive_sha256.clone(),
            release_id: 1,
            asset_id: 2,
        };
        validate_binding(&control, &publication, POLICY).unwrap();
        for field in [
            "source_sha",
            "archive_sha256",
            "policy_sha256",
            "release_id",
            "asset_id",
        ] {
            let mut changed = serde_json::to_value(&control).unwrap();
            changed[field] = match field {
                "source_sha" => serde_json::json!("c".repeat(40)),
                "archive_sha256" | "policy_sha256" => serde_json::json!("c".repeat(64)),
                _ => serde_json::json!(9),
            };
            assert!(
                validate_binding(
                    &serde_json::from_value(changed).unwrap(),
                    &publication,
                    POLICY
                )
                .is_err(),
                "{field}"
            );
        }
        assert!(validate_binding(&control, &publication, b"{}").is_err());
    }
}
