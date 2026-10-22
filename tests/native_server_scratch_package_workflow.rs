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
