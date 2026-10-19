use crate::api::GitHub;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    fs,
    io::Read,
    path::Path,
    thread,
    time::{Duration, Instant},
};

pub fn successful_source_run(
    api: &GitHub,
    repository: &str,
    run_id: u64,
) -> Result<serde_json::Value> {
    ensure!(run_id > 0, "invalid source run ID");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let run: serde_json::Value =
            api.get(&format!("/repos/{repository}/actions/runs/{run_id}"))?;
        ensure!(
            run["id"].as_u64() == Some(run_id),
            "source run identity mismatch"
        );
        ensure!(
            run["run_attempt"].as_u64() == Some(1),
            "source workflow run is not its first attempt"
        );
        match run["status"].as_str() {
            Some("completed") => {
                ensure!(
                    run["conclusion"] == "success",
                    "source workflow run did not succeed"
                );
                return Ok(run);
            }
            Some("queued" | "in_progress" | "requested" | "waiting" | "pending") => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                ensure!(
                    !remaining.is_zero(),
                    "source workflow run did not complete within 120 seconds"
                );
                thread::sleep(remaining.min(Duration::from_secs(5)));
            }
            _ => anyhow::bail!("source workflow run has an invalid status"),
        }
    }
}

pub fn require_current_runtime(api: &GitHub, workflow_path: &str) -> Result<String> {
    let _ = workflow_path;
    Ok(crate::control::ControlRevision::require_runtime(api)?.source_sha)
}

pub fn write_json(path: impl AsRef<Path>, value: &impl serde::Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    ensure!(bytes.len() <= 16384, "manifest exceeds size limit");
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

pub fn manifest_from_zip<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    ensure!(
        archive.len() == 1,
        "manifest artifact must contain exactly one file"
    );
    let mut file = archive.by_index(0)?;
    ensure!(
        file.name() == "manifest.json"
            && file.is_file()
            && file.size() <= 16384
            && file.unix_mode().is_none_or(|m| m & 0o170000 != 0o120000),
        "invalid manifest entry"
    );
    let mut contents = Vec::new();
    let declared_size = file.size();
    (&mut file).take(16385).read_to_end(&mut contents)?;
    ensure!(
        contents.len() <= 16384 && contents.len() as u64 == declared_size,
        "manifest size mismatch or exceeds limit"
    );
    Ok(serde_json::from_slice(&contents)?)
}

#[derive(Deserialize)]
pub struct ReferencedWorkflow {
    pub path: String,
    pub sha: String,
}

pub fn referenced_revision(
    workflows: &[ReferencedWorkflow],
    path: &str,
    expected: &str,
) -> Result<()> {
    referenced_revision_for(
        &crate::config::trusted()?.deployment,
        workflows,
        path,
        expected,
    )
}

fn referenced_revision_for(
    deployment: &crate::config::Deployment,
    workflows: &[ReferencedWorkflow],
    path: &str,
    expected: &str,
) -> Result<()> {
    let path = deployment.workflow_path(path)?;
    let prefix = format!("{}/{path}@", deployment.server.repository);
    let matching: Vec<_> = workflows
        .iter()
        .filter(|w| w.path.starts_with(&prefix))
        .collect();
    ensure!(
        matching.len() == 1
            && matching[0].sha == expected
            && matching[0].path == format!("{prefix}{expected}"),
        "source reusable workflow is not the single current revision"
    );
    Ok(())
}

pub fn require_reusable_pin(bytes: &[u8], path: &str, revision: &str) -> Result<()> {
    require_reusable_pin_for(&crate::config::trusted()?.deployment, bytes, path, revision)
}

fn require_reusable_pin_for(
    deployment: &crate::config::Deployment,
    bytes: &[u8],
    path: &str,
    revision: &str,
) -> Result<()> {
    let path = deployment.workflow_path(path)?;
    let yaml: serde_yaml::Value = serde_yaml::from_slice(bytes)?;
    let jobs = yaml["jobs"]
        .as_mapping()
        .context("caller workflow has no jobs")?;
    let prefix = format!("{}/{path}@", deployment.server.repository);
    let calls: Vec<_> = jobs
        .values()
        .filter_map(|job| job["uses"].as_str())
        .filter(|uses| uses.starts_with(&prefix))
        .collect();
    ensure!(
        calls.len() == 1 && calls[0] == format!("{prefix}{revision}"),
        "caller must pin one current reusable workflow"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn testing_provenance_rejects_production_paths_wrong_revisions_and_duplicates() {
        let mut deployment = crate::config::trusted().unwrap().deployment.clone();
        deployment.workflow_prefix = "testing-".into();
        deployment.server.repository = "civitaspo/testing-securefix-control".into();
        let path = ".github/workflows/reusable-merge-request.yml";
        let sha = "a".repeat(40);
        let expected = format!(
            "{}/{}@{sha}",
            deployment.server.repository,
            deployment.workflow_path(path).unwrap()
        );
        let reference = |value: &str| ReferencedWorkflow {
            path: value.into(),
            sha: sha.clone(),
        };
        assert!(referenced_revision_for(&deployment, &[reference(&expected)], path, &sha).is_ok());
        let wrapper = |value: &str| format!("jobs:\n  request:\n    uses: {value}\n");
        assert!(
            require_reusable_pin_for(&deployment, wrapper(&expected).as_bytes(), path, &sha)
                .is_ok()
        );
        for invalid in [
            expected.replace("testing-reusable", "reusable"),
            expected.replace(&sha, "main"),
            expected.replace("testing-securefix-control", "securefix-server"),
            expected.replace(&sha, &"b".repeat(40)),
        ] {
            assert!(
                referenced_revision_for(&deployment, &[reference(&invalid)], path, &sha).is_err(),
                "{invalid}"
            );
            assert!(
                require_reusable_pin_for(&deployment, wrapper(&invalid).as_bytes(), path, &sha)
                    .is_err(),
                "{invalid}"
            );
        }
        assert!(
            referenced_revision_for(
                &deployment,
                &[reference(&expected), reference(&expected)],
                path,
                &sha
            )
            .is_err()
        );
        let duplicate = format!("{}  second:\n    uses: {expected}\n", wrapper(&expected));
        assert!(require_reusable_pin_for(&deployment, duplicate.as_bytes(), path, &sha).is_err());
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct FixtureManifest {
        version: u8,
    }

    fn manifest_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, contents) in entries {
            archive
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            archive.write_all(contents).unwrap();
        }
        archive.finish().unwrap().into_inner()
    }

    #[test]
    fn manifest_artifacts_parse_one_strict_bounded_json_file() {
        let bytes = manifest_archive(&[("manifest.json", br#"{"version":1}"#)]);
        assert_eq!(
            manifest_from_zip::<FixtureManifest>(&bytes).unwrap(),
            FixtureManifest { version: 1 }
        );
        let unknown = manifest_archive(&[("manifest.json", br#"{"version":1,"extra":true}"#)]);
        assert!(manifest_from_zip::<FixtureManifest>(&unknown).is_err());
        let malformed = manifest_archive(&[("manifest.json", b"{")]);
        assert!(manifest_from_zip::<FixtureManifest>(&malformed).is_err());
    }

    #[test]
    fn manifest_artifacts_reject_extra_files_unsafe_names_symlinks_and_oversize() {
        let json = br#"{"version":1}"#;
        let oversized = vec![b' '; 16385];
        for entries in [
            vec![],
            vec![
                ("manifest.json", json.as_slice()),
                ("extra", b"x".as_slice()),
            ],
            vec![("../manifest.json", json.as_slice())],
            vec![("nested/manifest.json", json.as_slice())],
            vec![("manifest.json", oversized.as_slice())],
        ] {
            assert!(manifest_from_zip::<FixtureManifest>(&manifest_archive(&entries)).is_err());
        }
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        archive
            .add_symlink(
                "manifest.json",
                "target",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        assert!(
            manifest_from_zip::<FixtureManifest>(&archive.finish().unwrap().into_inner()).is_err()
        );
        assert!(manifest_from_zip::<FixtureManifest>(b"not a zip").is_err());
    }

    #[test]
    fn reusable_caller_must_pin_the_exact_current_server_revision_once() {
        let path = ".github/workflows/reusable-approve-request.yml";
        let sha = "a".repeat(40);
        let exact =
            format!("jobs:\n  approve:\n    uses: civitaspo/securefix-server/{path}@{sha}\n");
        assert!(require_reusable_pin(exact.as_bytes(), path, &sha).is_ok());

        let branch =
            format!("jobs:\n  approve:\n    uses: civitaspo/securefix-server/{path}@main\n");
        assert!(require_reusable_pin(branch.as_bytes(), path, &sha).is_err());

        let duplicate = format!(
            "jobs:\n  approve:\n    uses: civitaspo/securefix-server/{path}@{sha}\n  second:\n    uses: civitaspo/securefix-server/{path}@{sha}\n"
        );
        assert!(require_reusable_pin(duplicate.as_bytes(), path, &sha).is_err());
    }
}
