//! Shared host-side wrapper around GitHub's official Sigstore attestation verifier.
//!
//! This module only accepts local subjects and bundles. It never resolves a
//! mutable release or chooses a trust identity; callers must supply those from
//! authenticated deployment or fixed source configuration.

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    fs::{self, OpenOptions},
    io::Read,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const SLSA_PREDICATE: &str = "https://slsa.dev/provenance/v1";
const OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
const MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SUBJECT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_VERIFIER_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_VERIFIER_TIME: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
pub struct VerifyRequest<'a> {
    /// Repository whose subject is being verified.
    pub repository: &'a str,
    /// Repository that owns the exact workflow signer.
    pub signer_repository: &'a str,
    /// Canonical workflow path, relative to the signer repository root.
    pub signer_workflow: &'a str,
    /// Full SHA of the signer workflow source.
    pub signer_sha: &'a str,
    /// Optional exact source identity required by the caller.
    pub source: Option<(&'a str, &'a str)>,
}

/// Verify a local subject against a local Sigstore bundle with the official
/// `gh attestation verify` implementation and isolated CLI credentials/config.
pub fn verify_with_gh(subject: &Path, bundle: &Path, request: VerifyRequest<'_>) -> Result<Value> {
    crate::policy::validate_repository(request.repository)?;
    crate::policy::validate_repository(request.signer_repository)?;
    crate::policy::validate_sha(request.signer_sha)?;
    ensure!(
        request.signer_workflow.starts_with(".github/workflows/")
            && !request.signer_workflow.contains("..")
            && !request.signer_workflow.contains(['\\', '%', '?', '#'])
            && (request.signer_workflow.ends_with(".yml")
                || request.signer_workflow.ends_with(".yaml")),
        "attestation signer workflow path is invalid"
    );
    if let Some((source_sha, source_ref)) = request.source {
        crate::policy::validate_sha(source_sha)?;
        ensure!(
            source_ref
                .strip_prefix("refs/heads/")
                .is_some_and(|branch| crate::config::validate_branch(branch).is_ok()),
            "attestation source ref is invalid"
        );
    }

    for (path, max, label) in [
        (subject, MAX_SUBJECT_BYTES, "attestation subject"),
        (bundle, MAX_BUNDLE_BYTES, "attestation bundle"),
    ] {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.file_type().is_file() && metadata.len() > 0 && metadata.len() <= max,
            "{label} is not a bounded regular file"
        );
    }

    let signer = format!("{}/{}", request.signer_repository, request.signer_workflow);
    let isolation = tempfile::tempdir()?;
    let output_path = isolation.path().join("verifier-output.json");
    let output_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)?;
    let mut command = Command::new("gh");
    command
        .arg("attestation")
        .arg("verify")
        .arg(subject)
        .arg("--bundle")
        .arg(bundle)
        .args(["--repo", request.repository, "--signer-workflow", &signer])
        .args(["--signer-digest", request.signer_sha])
        .args(["--cert-oidc-issuer", OIDC_ISSUER])
        .args(["--predicate-type", SLSA_PREDICATE])
        .arg("--deny-self-hosted-runners")
        .args(["--format", "json"]);
    if let Some((source_sha, source_ref)) = request.source {
        command
            .args(["--source-digest", source_sha])
            .args(["--source-ref", source_ref]);
    }
    let mut child = command
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .env_remove("GH_ENTERPRISE_TOKEN")
        .env_remove("GITHUB_ENTERPRISE_TOKEN")
        .env("GH_CONFIG_DIR", isolation.path())
        .env("HOME", isolation.path())
        .env("XDG_CACHE_HOME", isolation.path().join("cache"))
        .stdin(Stdio::null())
        .stdout(output_file)
        .stderr(Stdio::null())
        .spawn()
        .context("start GitHub attestation verifier")?;
    let deadline = Instant::now() + MAX_VERIFIER_TIME;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if fs::metadata(&output_path)?.len() > MAX_VERIFIER_OUTPUT_BYTES
            || Instant::now() >= deadline
        {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&output_path);
            anyhow::bail!("GitHub attestation verification exceeded its bounds");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let output = read_bounded(&output_path, MAX_VERIFIER_OUTPUT_BYTES as usize)?;
    let _ = fs::remove_file(&output_path);
    ensure!(status.success(), "GitHub attestation verification failed");
    serde_json::from_slice(&output).context("parse GitHub attestation verifier result")
}

/// Serialize the inline public attestation bundles into the JSONL format
/// consumed by `gh attestation verify`, bound to the repository identity.
pub fn public_bundles(response: &Value, repository_id: u64) -> Result<Vec<u8>> {
    let attestations = response["attestations"]
        .as_array()
        .context("public attestation list is missing")?;
    ensure!(
        !attestations.is_empty() && attestations.len() < 100,
        "public attestations are absent or truncated"
    );
    let mut bytes = Vec::new();
    for attestation in attestations {
        ensure!(
            attestation["repository_id"].as_u64() == Some(repository_id)
                && attestation["bundle"].is_object(),
            "public attestation repository or inline bundle is invalid"
        );
        serde_json::to_writer(&mut bytes, &attestation["bundle"])?;
        bytes.push(b'\n');
        ensure!(
            bytes.len() as u64 <= MAX_BUNDLE_BYTES,
            "public attestation bundles exceed size limit"
        );
    }
    Ok(bytes)
}

fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file(),
        "verifier output is not a regular file"
    );
    ensure!(
        metadata.len() <= max as u64,
        "verifier output exceeds size limit"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max, "verifier output exceeds size limit");
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn public_bundles_require_complete_repository_bound_inline_data() {
        let valid = json!({"attestations": [
            {"repository_id": 7, "bundle": {"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1", "dsseEnvelope": {}}}
        ]});
        assert_eq!(public_bundles(&valid, 7).unwrap().last(), Some(&b'\n'));
        for invalid in [
            json!({"attestations": []}),
            json!({"attestations": [{"repository_id": 8, "bundle": {}}]}),
            json!({"attestations": [{"repository_id": 7, "bundle_url": "https://example.invalid/bundle"}]}),
            json!({"attestations": vec![json!({"repository_id": 7, "bundle": {}}); 100]}),
        ] {
            assert!(public_bundles(&invalid, 7).is_err());
        }
    }

    #[test]
    fn verifier_inputs_require_exact_sha_repository_and_workflow_path() {
        for request in [
            VerifyRequest {
                repository: "bad name/repo",
                signer_repository: "owner/repo",
                signer_workflow: ".github/workflows/release.yml",
                signer_sha: &"a".repeat(40),
                source: None,
            },
            VerifyRequest {
                repository: "owner/repo",
                signer_repository: "owner/repo",
                signer_workflow: ".github/workflows/../release.yml",
                signer_sha: &"a".repeat(40),
                source: None,
            },
            VerifyRequest {
                repository: "owner/repo",
                signer_repository: "owner/repo",
                signer_workflow: ".github/workflows/release.yml",
                signer_sha: &"A".repeat(40),
                source: None,
            },
        ] {
            assert!(verify_with_gh(Path::new("subject"), Path::new("bundle"), request).is_err());
        }
        assert!(
            verify_with_gh(
                Path::new("subject"),
                Path::new("bundle"),
                VerifyRequest {
                    repository: "owner/repo",
                    signer_repository: "owner/repo",
                    signer_workflow: ".github/workflows/release.yml",
                    signer_sha: &"a".repeat(40),
                    source: Some((&"b".repeat(40), "refs/tags/v1.2.3")),
                }
            )
            .is_err()
        );
    }
}
