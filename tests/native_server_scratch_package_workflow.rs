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
    run_loader_as(
        caller_repository,
        repository_id,
        workflow_ref,
        event,
        attempt,
        "4525500",
    )
}

fn run_loader_as(
    caller_repository: &str,
    repository_id: &str,
    workflow_ref: &str,
    event: &str,
    attempt: &str,
    actor_id: &str,
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
        .env("ACTOR_ID", actor_id)
        .env("RUN_ATTEMPT", attempt)
        .output()
        .unwrap();
    (output, curl_marker, temp)
}

#[test]
fn securefix_client_request_loader_admits_only_the_exact_owner_context_before_network() {
    let caller = "civitaspo/testing-securefix-server/.github/workflows/securefix-request.yml@refs/heads/main";
    let (accepted, marker, _temp) = run_loader_as(
        SCRATCH,
        "1410312556",
        caller,
        "pull_request_target",
        "1",
        "4525500",
    );
    assert!(!accepted.status.success());
    assert!(
        marker.exists(),
        "the exact tuple should pass caller admission"
    );
    assert!(
        !String::from_utf8_lossy(&accepted.stderr)
            .contains("scratch package loading is restricted")
    );

    for (repository, id, workflow_ref, event, attempt, actor) in [
        (
            "civitaspo/other",
            "1410312556",
            caller,
            "pull_request_target",
            "1",
            "4525500",
        ),
        (
            SCRATCH,
            "1250079425",
            caller,
            "pull_request_target",
            "1",
            "4525500",
        ),
        (
            SCRATCH,
            "1410312556",
            "civitaspo/testing-securefix-server/.github/workflows/securefix-request.yml@refs/heads/release",
            "pull_request_target",
            "1",
            "4525500",
        ),
        (
            SCRATCH,
            "1410312556",
            caller,
            "workflow_dispatch",
            "1",
            "4525500",
        ),
        (
            SCRATCH,
            "1410312556",
            caller,
            "pull_request_target",
            "2",
            "4525500",
        ),
        (
            SCRATCH,
            "1410312556",
            caller,
            "pull_request_target",
            "1",
            "42",
        ),
    ] {
        let (rejected, marker, _temp) =
            run_loader_as(repository, id, workflow_ref, event, attempt, actor);
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
            "civitaspo/testing-securefix-server/.github/workflows/server-policy-check.yml@refs/heads/release",
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

#[test]
fn scratch_server_role_receivers_admit_only_their_exact_label_context_before_network() {
    for role in ["approve", "merge", "securefix", "release"] {
        let caller = format!("{SCRATCH}/.github/workflows/server-{role}.yml@refs/heads/main");
        let (accepted, marker, _temp) = run_loader(SCRATCH, "1410312556", &caller, "label", "1");
        assert!(
            marker.exists(),
            "the exact {role} tuple should pass caller admission: {}",
            String::from_utf8_lossy(&accepted.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&accepted.stderr)
                .contains("scratch package loading is restricted")
        );

        for (repository, id, workflow_ref, event, attempt) in [
            (
                "civitaspo/other",
                "1410312556",
                caller.as_str(),
                "label",
                "1",
            ),
            (SCRATCH, "1250079425", caller.as_str(), "label", "1"),
            (
                SCRATCH,
                "1410312556",
                "civitaspo/testing-securefix-server/.github/workflows/server-other.yml@refs/heads/main",
                "label",
                "1",
            ),
            (
                SCRATCH,
                "1410312556",
                caller.as_str(),
                "workflow_dispatch",
                "1",
            ),
            (SCRATCH, "1410312556", caller.as_str(), "label", "2"),
        ] {
            let (rejected, marker, _temp) =
                run_loader(repository, id, workflow_ref, event, attempt);
            assert!(!rejected.status.success());
            assert!(
                !marker.exists(),
                "altered {role} context unexpectedly reached curl"
            );
            assert!(
                String::from_utf8_lossy(&rejected.stderr)
                    .contains("scratch package loading is restricted")
            );
        }
    }
}

#[test]
fn server_approval_receiver_uses_pre35_only_for_its_exact_scratch_label_workflow() {
    let workflow: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(format!(
            "{}/.github/workflows/reusable-server-approve.yml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let steps = workflow["jobs"]["receive"]["steps"].as_sequence().unwrap();
    let scratch_context = "github.repository == 'civitaspo/testing-securefix-server' && github.repository_id == '1410312556' && github.workflow_ref == 'civitaspo/testing-securefix-server/.github/workflows/server-approve.yml@refs/heads/main' && github.event_name == 'label' && github.run_attempt == 1";
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
    assert_eq!(stable["with"]["channel"], "stable");
    assert_eq!(scratch["if"], format!("${{{{ {scratch_context} }}}}"));
    assert_eq!(
        scratch["uses"],
        "civitaspo/securefix-server/.github/actions/load-package@119643d5407f97b3589059246d43bd05590a248e"
    );
    assert_eq!(
        scratch["with"]["action-sha"],
        "119643d5407f97b3589059246d43bd05590a248e"
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
        "Validate the owner approval without a write credential",
        "Apply the owner approval after revalidation",
    ] {
        let step = steps.iter().find(|step| step["name"] == name).unwrap();
        assert_eq!(
            step["env"]["CLI_BINARY"],
            "${{ steps.package-scratch.outputs.binary || steps.package-stable.outputs.binary }}"
        );
    }
    let validate = steps
        .iter()
        .find(|step| step["name"] == "Validate the owner approval without a write credential")
        .unwrap();
    let apply = steps
        .iter()
        .find(|step| step["name"] == "Apply the owner approval after revalidation")
        .unwrap();
    assert!(validate["env"]["SECUREFIX_APPROVE_TOKEN"].is_null());
    assert_eq!(
        apply["env"]["SECUREFIX_APPROVE_TOKEN"],
        "${{ secrets.APPROVAL_TOKEN }}"
    );
    assert_eq!(
        steps
            .iter()
            .filter(|step| step["env"]["SECUREFIX_APPROVE_TOKEN"]
                == "${{ secrets.APPROVAL_TOKEN }}")
            .count(),
        1
    );
}

#[test]
fn server_merge_receiver_uses_pre35_only_for_its_exact_scratch_label_workflow() {
    let workflow: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(format!(
            "{}/.github/workflows/reusable-server-merge.yml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let steps = workflow["jobs"]["receive"]["steps"].as_sequence().unwrap();
    let scratch_context = "github.repository == 'civitaspo/testing-securefix-server' && github.repository_id == '1410312556' && github.workflow_ref == 'civitaspo/testing-securefix-server/.github/workflows/server-merge.yml@refs/heads/main' && github.event_name == 'label' && github.run_attempt == 1";
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
    assert_eq!(stable["with"]["channel"], "stable");
    assert_eq!(scratch["if"], format!("${{{{ {scratch_context} }}}}"));
    assert_eq!(
        scratch["uses"],
        "civitaspo/securefix-server/.github/actions/load-package@119643d5407f97b3589059246d43bd05590a248e"
    );
    assert_eq!(
        scratch["with"]["action-sha"],
        "119643d5407f97b3589059246d43bd05590a248e"
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
        "Validate the merge request and paired approval without a writer token",
        "Revalidate and merge the exact Client head",
    ] {
        let step = steps.iter().find(|step| step["name"] == name).unwrap();
        assert_eq!(
            step["env"]["CLI_BINARY"],
            "${{ steps.package-scratch.outputs.binary || steps.package-stable.outputs.binary }}"
        );
    }
    let validate = steps
        .iter()
        .find(|step| {
            step["name"] == "Validate the merge request and paired approval without a writer token"
        })
        .unwrap();
    let apply = steps
        .iter()
        .find(|step| step["name"] == "Revalidate and merge the exact Client head")
        .unwrap();
    assert!(validate["env"]["SECUREFIX_NATIVE_MERGE_TOKEN"].is_null());
    assert_eq!(
        apply["env"]["SECUREFIX_NATIVE_MERGE_TOKEN"],
        "${{ steps.merge-writer.outputs.token }}"
    );
    let writer = steps
        .iter()
        .find(|step| step["id"] == "merge-writer")
        .unwrap();
    assert_eq!(writer["with"]["permission-contents"], "write");
    assert_eq!(writer["with"]["permission-pull-requests"], "write");
    assert_eq!(
        writer["with"]["permission-administration"],
        serde_yaml::Value::Null
    );
}

#[test]
fn server_securefix_receiver_uses_pre38_only_for_its_exact_scratch_label_workflow() {
    let workflow: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(format!(
            "{}/.github/workflows/reusable-server-securefix.yml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let steps = workflow["jobs"]["receive"]["steps"].as_sequence().unwrap();
    let scratch_context = "github.repository == 'civitaspo/testing-securefix-server' && github.repository_id == '1410312556' && github.workflow_ref == 'civitaspo/testing-securefix-server/.github/workflows/server-securefix.yml@refs/heads/main' && github.event_name == 'label' && github.run_attempt == 1";
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
    assert_eq!(stable["with"]["channel"], "stable");
    assert_eq!(scratch["if"], format!("${{{{ {scratch_context} }}}}"));
    assert_eq!(
        scratch["uses"],
        "civitaspo/securefix-server/.github/actions/load-package@119643d5407f97b3589059246d43bd05590a248e"
    );
    assert_eq!(
        scratch["with"]["action-sha"],
        "119643d5407f97b3589059246d43bd05590a248e"
    );
    for (key, expected) in [
        ("channel", "scratch"),
        (
            "manifest-source-sha",
            "95520b982c915e8a7c20d6a8464aa9d926216573",
        ),
        (
            "publication-source-sha",
            "95520b982c915e8a7c20d6a8464aa9d926216573",
        ),
        (
            "publication-source-branch",
            "integration/native-server-approve-pre35-20261023",
        ),
        ("publication-tag", "v0.2.45-pre.38"),
        ("publication-release-id", "421371928"),
        ("publication-asset-id", "667664206"),
        (
            "publication-asset-sha256",
            "b06fc4c5dc4062c8ab7c49d35052407823c38d297c9ad31767fc574468e01daa",
        ),
        ("publication-asset-size", "12147624"),
        ("publication-producer-run-id", "39885673712"),
        ("publication-producer-run-attempt", "1"),
    ] {
        assert_eq!(scratch["with"][key], expected, "{key}");
    }
    for name in [
        "Resolve the authenticated Client request label",
        "Revalidate and apply the exact Securefix request",
    ] {
        let step = steps.iter().find(|step| step["name"] == name).unwrap();
        assert_eq!(
            step["env"]["CLI_BINARY"],
            "${{ steps.package-scratch.outputs.binary || steps.package-stable.outputs.binary }}"
        );
    }
    let writer = steps
        .iter()
        .find(|step| step["id"] == "client-writer")
        .unwrap();
    assert_eq!(writer["with"]["permission-contents"], "write");
    assert_eq!(
        writer["with"]["permission-pull-requests"],
        serde_yaml::Value::Null
    );
    assert_eq!(
        writer["with"]["permission-administration"],
        serde_yaml::Value::Null
    );
    let apply = steps
        .iter()
        .find(|step| step["name"] == "Revalidate and apply the exact Securefix request")
        .unwrap();
    assert_eq!(
        apply["env"]["SECUREFIX_WRITE_TOKEN"],
        "${{ steps.client-writer.outputs.token }}"
    );
}

#[test]
fn server_release_receiver_selects_pre35_only_for_its_exact_scratch_label_workflow() {
    let workflow: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(format!(
            "{}/.github/workflows/reusable-server-release.yml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let scratch_context = "github.repository == 'civitaspo/testing-securefix-server' && github.repository_id == '1410312556' && github.workflow_ref == 'civitaspo/testing-securefix-server/.github/workflows/server-release.yml@refs/heads/main' && github.event_name == 'label' && github.run_attempt == 1";
    let jobs = workflow["jobs"].as_mapping().unwrap();
    assert_eq!(jobs.len(), 5);
    for (job_id, job) in jobs {
        let steps = job["steps"].as_sequence().unwrap();
        let stable = steps
            .iter()
            .find(|step| step["id"] == "package-stable")
            .unwrap_or_else(|| panic!("{job_id:?} lacks stable package loader"));
        let scratch = steps
            .iter()
            .find(|step| step["id"] == "package-scratch")
            .unwrap_or_else(|| panic!("{job_id:?} lacks scratch package loader"));
        assert!(
            stable["if"]
                .as_str()
                .unwrap()
                .contains(&format!("!({scratch_context})"))
        );
        assert_eq!(stable["with"]["channel"], "stable");
        assert_eq!(scratch["if"], format!("${{{{ {scratch_context} }}}}"));
        assert_eq!(
            scratch["uses"],
            "civitaspo/securefix-server/.github/actions/load-package@119643d5407f97b3589059246d43bd05590a248e"
        );
        assert_eq!(
            scratch["with"]["action-sha"],
            "119643d5407f97b3589059246d43bd05590a248e"
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
            assert_eq!(scratch["with"][key], expected, "{job_id:?} {key}");
        }
        for step in steps {
            if step["env"]["CLI_BINARY"].is_string() {
                assert_eq!(
                    step["env"]["CLI_BINARY"],
                    "${{ steps.package-scratch.outputs.binary || steps.package-stable.outputs.binary }}",
                    "{job_id:?} {:?}",
                    step["name"]
                );
            }
        }
    }
}

#[test]
fn scratch_client_signer_uses_one_helper_pin_and_the_fixed_pre35_package_record() {
    let workflow: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(format!(
            "{}/.github/workflows/reusable-client-request-scratch.yml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let jobs = workflow["jobs"].as_mapping().unwrap();
    let mut helper_sha = None;
    let mut package_steps = 0;
    for job_id in ["prepare-source", "capture", "dispatch"] {
        let steps = jobs[job_id]["steps"].as_sequence().unwrap();
        let package = steps
            .iter()
            .find(|step| step["id"] == "package")
            .unwrap_or_else(|| panic!("{job_id} has no package loader"));
        package_steps += 1;

        let uses = package["uses"].as_str().unwrap();
        let (action, sha) = uses
            .rsplit_once('@')
            .unwrap_or_else(|| panic!("{job_id} package loader is not pinned"));
        assert_eq!(
            action,
            "civitaspo/securefix-server/.github/actions/load-package"
        );
        assert_eq!(sha.len(), 40, "{job_id} helper pin is not a full SHA");
        assert!(sha.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(package["with"]["action-sha"], sha, "{job_id}");
        if let Some(expected) = helper_sha {
            assert_eq!(
                sha, expected,
                "all signer package loads must share a helper"
            );
        } else {
            helper_sha = Some(sha);
        }

        for (key, expected) in [
            ("source-repository", "civitaspo/securefix-server"),
            ("source-repository-id", "1250079425"),
            (
                "destination-repository",
                "civitaspo/testing-securefix-server",
            ),
            ("destination-repository-id", "1410312556"),
            ("source-default-branch", "main"),
            ("owner-id", "4525500"),
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
            assert_eq!(package["with"][key], expected, "{job_id} {key}");
        }
        assert_eq!(package["with"]["token"], "${{ github.token }}", "{job_id}");
    }
    assert_eq!(package_steps, 3);
}
