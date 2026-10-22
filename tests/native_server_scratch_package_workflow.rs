use std::{fs, os::unix::fs::PermissionsExt, process::Command};

use tempfile::tempdir;

const SERVER: &str = "civitaspo/securefix-server";
const SCRATCH: &str = "civitaspo/testing-securefix-server";
const CALLER: &str =
    "civitaspo/testing-securefix-server/.github/workflows/server-policy-check.yml@refs/heads/main";

fn run_loader(
    caller_repository: &str,
    repository_id: &str,
    workflow_ref: &str,
    event: &str,
    attempt: &str,
) -> (std::process::Output, std::path::PathBuf, tempfile::TempDir) {
    let temp = tempdir().unwrap();
    let bin = temp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let curl_marker = temp.path().join("curl-called");
    let curl = bin.join("curl");
    fs::write(
        &curl,
        format!(
            "#!/bin/sh\nprintf called > '{}'\nexit 19\n",
            curl_marker.display()
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&curl).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&curl, permissions).unwrap();

    let script = format!(
        "{}/.github/actions/load-package/load.sh",
        env!("CARGO_MANIFEST_DIR")
    );
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let output = Command::new("bash")
        .arg(script)
        .env("PATH", path)
        .env("RUNNER_TEMP", temp.path())
        .env("ACTION_SHA", "fa40fc15f4ac79ad97282b83a44d26f6c747311c")
        .env("SOURCE_REPOSITORY", SERVER)
        .env("SOURCE_REPOSITORY_ID", "1250079425")
        .env("DESTINATION_REPOSITORY", SCRATCH)
        .env("DESTINATION_REPOSITORY_ID", "1410312556")
        .env("SOURCE_DEFAULT_BRANCH", "main")
        .env("OWNER_ID", "4525500")
        .env("CHANNEL", "scratch")
        .env(
            "MANIFEST_SOURCE_SHA",
            "fa40fc15f4ac79ad97282b83a44d26f6c747311c",
        )
        .env(
            "PUBLICATION_SOURCE_SHA",
            "fa40fc15f4ac79ad97282b83a44d26f6c747311c",
        )
        .env("GH_TOKEN", "test-token")
        .env("CALLER_REPOSITORY", caller_repository)
        .env("CALLER_REPOSITORY_ID", repository_id)
        .env("CALLER_WORKFLOW_REF", workflow_ref)
        .env("EVENT_NAME", event)
        .env("ACTOR_ID", "4525500")
        .env("RUN_ATTEMPT", attempt)
        .output()
        .unwrap();
    (output, curl_marker, temp)
}

#[test]
fn scratch_server_policy_receiver_admits_only_its_exact_label_context_before_network() {
    let (accepted, marker, _temp) = run_loader(SCRATCH, "1410312556", CALLER, "label", "1");
    assert!(!accepted.status.success());
    assert!(
        marker.exists(),
        "the exact tuple should pass caller admission: {}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&accepted.stderr)
            .contains("scratch package loading is restricted")
    );

    for (repository, id, workflow_ref, event, attempt) in [
        ("civitaspo/other", "1410312556", CALLER, "label", "1"),
        (SCRATCH, "1250079425", CALLER, "label", "1"),
        (
            SCRATCH,
            "1410312556",
            "civitaspo/testing-securefix-server/.github/workflows/server-approve.yml@refs/heads/main",
            "label",
            "1",
        ),
        (SCRATCH, "1410312556", CALLER, "workflow_dispatch", "1"),
        (SCRATCH, "1410312556", CALLER, "label", "2"),
    ] {
        let (rejected, marker, _temp) = run_loader(repository, id, workflow_ref, event, attempt);
        assert!(!rejected.status.success());
        assert!(
            !marker.exists(),
            "altered context unexpectedly reached curl"
        );
        assert!(
            String::from_utf8_lossy(&rejected.stderr)
                .contains("scratch package loading is restricted")
        );
    }
}

#[test]
fn server_policy_receiver_uses_pre35_only_for_its_exact_scratch_label_workflow() {
    let workflow: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(format!(
            "{}/.github/workflows/reusable-server-policy-check.yml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let steps = workflow["jobs"]["receive"]["steps"].as_sequence().unwrap();
    let scratch_context = "github.repository == 'civitaspo/testing-securefix-server' && github.repository_id == '1410312556' && github.workflow_ref == 'civitaspo/testing-securefix-server/.github/workflows/server-policy-check.yml@refs/heads/main' && github.event_name == 'label' && github.run_attempt == 1";
    let stable = steps
        .iter()
        .find(|step| step["id"] == "package-stable")
        .unwrap();
    let scratch = steps
        .iter()
        .find(|step| step["id"] == "package-scratch")
        .unwrap();
    assert!(
        stable["if"]
            .as_str()
            .unwrap()
            .contains(&format!("!({scratch_context})"))
    );
    assert_eq!(
        stable["uses"],
        "civitaspo/securefix-server/.github/actions/load-package@c6aa3110bb31d5ca5bae452d291870066f0147ef"
    );
    assert_eq!(stable["with"]["channel"], "stable");
    assert_eq!(scratch["if"], format!("${{{{ {scratch_context} }}}}"));
    assert_eq!(
        scratch["uses"],
        "civitaspo/securefix-server/.github/actions/load-package@7d04df0755f857d45897c4df53ce51d2c14fe0a4"
    );
    assert_eq!(
        scratch["with"]["action-sha"],
        "7d04df0755f857d45897c4df53ce51d2c14fe0a4"
    );
    for (key, expected) in [
        ("channel", "scratch"),
        (
            "manifest-source-sha",
            "fa40fc15f4ac79ad97282b83a44d26f6c747311c",
        ),
        (
            "publication-source-sha",
            "fa40fc15f4ac79ad97282b83a44d26f6c747311c",
        ),
        (
            "publication-source-branch",
            "integration/native-consumer-pre35-20261023",
        ),
        ("publication-tag", "v0.2.45-pre.35"),
        ("publication-release-id", "421283713"),
        ("publication-asset-id", "667334470"),
        (
            "publication-asset-sha256",
            "589ca95c11671707213b124299d28954bd56957345bbfb637ac2d68d48a9212d",
        ),
        ("publication-asset-size", "12173384"),
        ("publication-producer-run-id", "39866598474"),
        ("publication-producer-run-attempt", "1"),
    ] {
        assert_eq!(scratch["with"][key], expected, "{key}");
    }
    for name in [
        "Resolve the authenticated Client request label",
        "Validate the exact-head policy check without a writer token",
        "Revalidate and publish the exact-head policy check",
    ] {
        let step = steps.iter().find(|step| step["name"] == name).unwrap();
        assert_eq!(
            step["env"]["CLI_BINARY"],
            "${{ steps.package-scratch.outputs.binary || steps.package-stable.outputs.binary }}"
        );
    }
}
