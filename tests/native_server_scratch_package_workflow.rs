use std::fs;

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
fn server_securefix_receiver_uses_a_fixed_package_with_scoped_writer() {
    let workflow: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(format!(
            "{}/.github/workflows/reusable-server-securefix.yml",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let steps = workflow["jobs"]["receive"]["steps"].as_sequence().unwrap();
    let package = steps.iter().find(|step| step["id"] == "package").unwrap();
    assert_eq!(package["with"].as_mapping().unwrap().len(), 1);
    assert_eq!(package["with"]["token"], "${{ github.token }}");
    assert_eq!(
        package["uses"],
        "civitaspo/securefix-server/.github/actions/load-package@9a3a92d53c2ca5116fbe652a2ad7a6a4785e8d97"
    );
    assert!(package["if"].is_null());
    for name in [
        "Resolve the authenticated Client request label",
        "Revalidate and apply the exact Securefix request",
    ] {
        let step = steps.iter().find(|step| step["name"] == name).unwrap();
        assert_eq!(
            step["env"]["CLI_BINARY"],
            "${{ steps.package.outputs.binary }}"
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
fn scratch_client_signer_uses_one_fixed_action_across_isolated_jobs() {
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
        assert_eq!(package["with"].as_mapping().unwrap().len(), 1, "{job_id}");
        if let Some(expected) = helper_sha {
            assert_eq!(
                sha, expected,
                "all signer package loads must share a helper"
            );
        } else {
            helper_sha = Some(sha);
        }

        assert_eq!(package["with"]["token"], "${{ github.token }}", "{job_id}");
    }
    assert_eq!(package_steps, 3);
    let prepare = jobs["prepare-source"]["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "source")
        .unwrap();
    let script = prepare["run"].as_str().unwrap();
    assert!(script.contains("new-client securefix prepare"));
    assert!(!script.contains("securefix client-prepare"));
}
