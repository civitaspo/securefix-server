//! A candidate is data on this host. Only the test client's read token is needed.
use super::testing_publication::{POLICY, POLICY_PATH, require_prerelease, validate_policy};
use anyhow::{Context, Result, ensure};
use clap::ValueEnum;
use securefix::{api::GitHub, config, control::ControlRevision, policy::Policy};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CaptureKind {
    Approve,
    Merge,
    Policy,
}

pub(super) fn validate_capture(
    kind: CaptureKind,
    directory: &Path,
    source: &str,
    control: &str,
) -> Result<()> {
    securefix::policy::validate_sha(source)?;
    let fixture = &config::trusted()?.deployment.integration;
    ensure!(
        std::env::var("GITHUB_REPOSITORY").is_ok_and(|v| v == fixture.repository),
        "testing capture must belong to the fixed test client"
    );
    ensure!(
        std::env::var("GITHUB_RUN_ATTEMPT").is_ok_and(|v| v == "1"),
        "testing capture must be a first-attempt run"
    );
    let run_id: u64 = std::env::var("GITHUB_RUN_ID")?.parse()?;
    let bytes = capture_file(directory)?;
    match kind {
        CaptureKind::Policy => crate::policy_check::validate_testing_capture(
            &bytes,
            &fixture.repository,
            fixture.id,
            source,
            control,
            run_id,
        ),
        CaptureKind::Approve | CaptureKind::Merge => {
            let manifest: crate::request::RequestManifest = serde_json::from_slice(&bytes)?;
            manifest.validate()?;
            let expected = match kind {
                CaptureKind::Approve => crate::request::RequestKind::Approve,
                _ => crate::request::RequestKind::Merge,
            };
            ensure!(
                manifest.repository.full_name == fixture.repository
                    && manifest.repository.id == fixture.id
                    && manifest.workflow_sha == source
                    && manifest.control.identity()? == control
                    && manifest.run_id == run_id
                    && manifest.kind == expected,
                "testing request capture differs from the qualified runtime or client run"
            );
            Ok(())
        }
    }
}

pub(super) fn dispatch(
    kind: CaptureKind,
    directory: &Path,
    source: &str,
    control: &str,
) -> Result<()> {
    validate_capture(kind, directory, source, control)?;
    let policy = Policy::parse(POLICY)?;
    let token = std::env::var("GITHUB_TOKEN")?;
    ensure!(!token.is_empty(), "missing client read token");
    let read = GitHub::new("https://api.github.com", token)?;
    let active =
        ControlRevision::load_from_repository(&read, policy.deployment.control_repository())?;
    ensure!(
        active.source_sha == source && active.identity()? == control,
        "testing dispatch control is no longer current"
    );
    let run_id: u64 = std::env::var("GITHUB_RUN_ID")?.parse()?;
    ensure!(run_id > 0, "invalid testing dispatch run");
    let path = format!("/repos/{}/labels", policy.deployment.server.repository);
    let description = format!("{}/{run_id}", policy.deployment.integration.repository);
    let label = super::testing_processor::label_name(kind, run_id, false);
    let refresh_label = super::testing_processor::label_name(CaptureKind::Approve, run_id, true);
    ensure!(
        label.len() <= 50 && refresh_label.len() <= 50 && description.len() <= 100,
        "testing request label exceeds GitHub limits"
    );
    let api = GitHub::client_from_env("SECUREFIX_APP_TOKEN")?;
    // The host chooses the endpoint, label and locator. Candidate output never supplies them.
    if kind == CaptureKind::Merge {
        let manifest: crate::request::RequestManifest =
            serde_json::from_slice(&capture_file(directory)?)?;
        if matches!(
            manifest.authorization,
            crate::request::Authorization::RenovateComment { .. }
        ) {
            let _: Value = api.post(
                &path,
                &json!({"name":refresh_label,
                "description":description,"color":"1f6feb"}),
            )?;
        }
    }
    let _: Value = api.post(
        &path,
        &json!({"name":label,"description":description,"color":"1f6feb"}),
    )?;
    securefix::output("label", label)
}

fn capture_file(directory: &Path) -> Result<Vec<u8>> {
    ensure!(
        fs::symlink_metadata(directory)?.file_type().is_dir(),
        "capture directory is not regular"
    );
    let entries: Vec<_> = fs::read_dir(directory)?.collect::<std::io::Result<_>>()?;
    ensure!(
        entries.len() == 1 && entries[0].file_name() == "manifest.json",
        "capture must contain only manifest.json"
    );
    let entry = &entries[0];
    let metadata = fs::symlink_metadata(entry.path())?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() > 0 && metadata.len() <= 16 * 1024,
        "capture manifest is not a bounded regular file"
    );
    let bytes = fs::read(entry.path())?;
    ensure!(
        bytes.len() as u64 == metadata.len(),
        "capture file size changed"
    );
    Ok(bytes)
}

pub(super) fn load(workflow_sha: &str) -> Result<()> {
    let fixture = &config::trusted()?.deployment.integration;
    ensure!(
        std::env::var("GITHUB_REPOSITORY").is_ok_and(|v| v == fixture.repository),
        "testing runtime must load in the fixed test client"
    );
    let token = std::env::var("GITHUB_TOKEN").context("missing test client GITHUB_TOKEN")?;
    ensure!(!token.is_empty(), "test client GITHUB_TOKEN is empty");
    qualify(workflow_sha, &GitHub::new("https://api.github.com", token)?)
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
        trusted.deployment.workflow_prefix.is_empty()
            && trusted.deployment.control_repository.is_none(),
        "testing runtime qualification requires the production-configured host validator"
    );
    validate_policy(trusted)?;
    let policy = Policy::parse(POLICY)?;
    let fixture = policy.deployment.control_repository();
    // This token is never used to query the production repository.
    let public = GitHub::anonymous()?;
    let server = &trusted.deployment.server;
    let baseline = std::env::var("SECUREFIX_TEST_BASELINE_SHA")?;
    let main = || -> Result<Value> {
        public.get(&format!(
            "/repos/{}/commits/{}",
            server.repository, server.default_branch
        ))
    };
    super::validate_test_baseline(&baseline, &main()?)?;
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
    let directory = tempfile::tempdir()?;
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
    fn testing_capture_rejects_symlinks_extra_files_and_oversize_before_upload() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("manifest.json");
        fs::write(&path, b"{}").unwrap();
        assert_eq!(capture_file(directory.path()).unwrap(), b"{}");
        fs::write(directory.path().join("extra"), b"secret").unwrap();
        assert!(capture_file(directory.path()).is_err());
        fs::remove_file(directory.path().join("extra")).unwrap();
        fs::write(&path, vec![0; 16385]).unwrap();
        assert!(capture_file(directory.path()).is_err());
        fs::remove_file(&path).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/passwd", &path).unwrap();
            assert!(capture_file(directory.path()).is_err());
        }
    }

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
