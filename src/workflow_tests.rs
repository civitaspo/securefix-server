use serde_json::Value;
use std::fs;

fn workflows() -> Vec<(String, Value)> {
    fs::read_dir(".github/workflows")
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            matches!(
                path.extension().and_then(|s| s.to_str()),
                Some("yml" | "yaml")
            )
        })
        .map(|path| {
            let value: Value = serde_yaml::from_slice(&fs::read(&path).unwrap()).unwrap();
            (path.display().to_string(), value)
        })
        .collect()
}

fn workflow(name: &str) -> Value {
    let mut yaml: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(format!(".github/workflows/{name}"))
            .unwrap_or_else(|error| panic!("cannot read {name}: {error}")),
    )
    .unwrap_or_else(|error| panic!("cannot parse {name}: {error}"));
    // serde_yaml follows YAML 1.1 and parses GitHub Actions' `on` key as true.
    if let Some(mapping) = yaml.as_mapping_mut()
        && let Some(on) = mapping.remove(serde_yaml::Value::Bool(true))
    {
        mapping.insert(serde_yaml::Value::String("on".into()), on);
    }
    serde_json::to_value(yaml).unwrap()
}

#[test]
fn testing_workflows_have_testing_file_and_display_names() {
    for (path, value) in workflows() {
        if path.starts_with(".github/workflows/testing-") {
            assert!(
                value["name"].as_str().unwrap().starts_with("testing-"),
                "{path}"
            );
        }
    }
}

#[test]
fn managed_files_scratch_probe_validates_before_scoped_writer_token() {
    let value = workflow("testing-securefix-server.yml");
    let inputs = &value["on"]["workflow_dispatch"]["inputs"];
    assert!(
        inputs["phase"]["options"]
            .as_array()
            .unwrap()
            .iter()
            .any(|phase| phase == "managed-files")
    );
    for name in [
        "client_repository",
        "client_implementation_sha",
        "client_version",
    ] {
        assert_eq!(inputs[name]["default"], "");
    }

    let job = &value["jobs"]["managed-files-probe"];
    assert_eq!(job["needs"], serde_json::json!(["baseline", "build"]));
    assert_eq!(job["environment"], "main");
    assert_eq!(
        job["permissions"],
        serde_json::json!({"actions":"read", "contents":"read"})
    );
    let steps = job["steps"].as_array().unwrap();
    let validate = steps
        .iter()
        .position(|step| {
            step["name"] == "Validate the exact selected candidate before minting a writer token"
        })
        .unwrap();
    let mint = steps
        .iter()
        .position(|step| step["id"] == "managed-writer")
        .unwrap();
    let write = steps
        .iter()
        .position(|step| {
            step["name"] == "Create the reviewable managed-file PR from the selected source"
        })
        .unwrap();
    assert!(validate < mint && mint < write);
    assert_eq!(
        steps[mint]["with"]["repositories"],
        "testing-securefix-server"
    );
    assert_eq!(steps[mint]["with"]["permission-contents"], "write");
    assert_eq!(steps[mint]["with"]["permission-pull-requests"], "write");
    assert_eq!(steps[mint]["with"]["permission-workflows"], "write");
    let serialized = serde_json::to_string(job).unwrap();
    assert!(!serialized.contains("permission-administration"));
    assert!(!serialized.contains("SECUREFIX_ADMIN"));
    assert!(
        steps[write]["run"]
            .as_str()
            .unwrap()
            .contains("securefix settings managed-reconcile-scratch --source-sha")
    );
}

#[test]
fn candidate_artifact_phase_only_builds_source_bound_runtime() {
    let value = workflow("testing-securefix-server.yml");
    let options = value["on"]["workflow_dispatch"]["inputs"]["phase"]["options"]
        .as_array()
        .unwrap();
    assert!(options.iter().any(|phase| phase == "candidate-artifact"));

    let build = &value["jobs"]["build"];
    assert!(
        build["if"]
            .as_str()
            .unwrap()
            .contains("inputs.phase == 'candidate-artifact'")
    );
    assert_eq!(
        build["permissions"],
        serde_json::json!({"actions":"read", "contents":"read"})
    );
    let build_steps = build["steps"].as_array().unwrap();
    let source_checkout = build_steps
        .iter()
        .find(|step| step["uses"] == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1")
        .unwrap();
    assert_eq!(
        source_checkout["with"]["ref"],
        "${{ inputs.candidate_sha || job.workflow_sha }}"
    );
    let assemble = build_steps
        .iter()
        .find(|step| step["name"] == "Assemble source-bound candidate runtime")
        .unwrap();
    let assemble_script = assemble["run"].as_str().unwrap();
    assert!(assemble_script.contains("\"$SOURCE_SHA\" \"$WORKFLOW_SHA\""));
    let artifact = build_steps
        .iter()
        .find(|step| step["with"]["name"] == "candidate-runtime")
        .unwrap();
    assert!(
        artifact["with"]["path"]
            .as_str()
            .unwrap()
            .contains("candidate-runtime/")
    );

    let scratch = &value["jobs"]["scratch"];
    let scratch_condition = scratch["if"].as_str().unwrap();
    assert!(scratch_condition.contains("inputs.phase == 'prepare' || inputs.phase == 'verify'"));
    assert!(!scratch_condition.contains("candidate-artifact"));
    assert!(
        scratch["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| { step["id"] == "server" || step["id"] == "client" })
    );

    for (job_id, phase) in [
        ("bootstrap-host", "bootstrap"),
        ("bootstrap-legacy-runtime", "bootstrap"),
        ("bootstrap-scratch", "bootstrap"),
        ("managed-files-probe", "managed-files"),
        ("provider-release-probe", "provider"),
    ] {
        let condition = value["jobs"][job_id]["if"].as_str().unwrap();
        assert!(
            condition.contains(&format!("inputs.phase == '{phase}'")),
            "{job_id} must be limited to the {phase} phase"
        );
        assert!(
            !condition.contains("candidate-artifact"),
            "{job_id} must not run during candidate-artifact"
        );
    }

    for job_id in ["baseline", "build"] {
        assert_eq!(
            value["jobs"][job_id]["permissions"],
            serde_json::json!({"actions":"read", "contents":"read"}),
            "candidate-artifact's only shared jobs must remain read-only"
        );
    }
}

#[test]
fn testing_native_release_assets_publish_is_source_bound_and_scratch_scoped() {
    let value = workflow("testing-native-release-assets-publish.yml");
    assert_eq!(value["permissions"], serde_json::json!({}));
    assert_eq!(
        value["on"]["workflow_dispatch"]["inputs"]["harness_sha"]["required"],
        true
    );
    assert_eq!(
        value["on"]["workflow_dispatch"]["inputs"]["producer_source_sha"]["required"],
        true
    );
    assert_eq!(
        value["on"]["workflow_dispatch"]["inputs"]["producer_run_id"]["required"],
        true
    );
    assert_eq!(
        value["on"]["workflow_dispatch"]["inputs"]["producer_run_attempt"]["required"],
        true
    );

    let host = &value["jobs"]["host-build"];
    assert_eq!(host["permissions"], serde_json::json!({"contents":"read"}));
    assert!(!serde_json::to_string(host).unwrap().contains("secrets."));
    let host_steps = host["steps"].as_array().unwrap();
    let checkout = host_steps
        .iter()
        .find(|step| step["uses"] == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1")
        .unwrap();
    assert_eq!(checkout["with"]["ref"], "${{ inputs.harness_sha }}");
    assert_eq!(checkout["with"]["persist-credentials"], false);
    let build = host_steps
        .iter()
        .find(|step| step["name"] == "Build the selected-source native release probe harness")
        .unwrap();
    assert!(
        build["run"]
            .as_str()
            .unwrap()
            .contains("cargo +1.99.0 test --locked --bin securefix --no-run")
    );

    let qualify = &value["jobs"]["qualify"];
    assert_eq!(
        qualify["permissions"],
        serde_json::json!({"actions":"read","contents":"read"})
    );
    assert!(!serde_json::to_string(qualify).unwrap().contains("secrets."));
    let qualify_run = qualify["steps"][0]["run"].as_str().unwrap();
    assert_eq!(
        qualify["steps"][0]["env"]["HARNESS_SHA"],
        "${{ inputs.harness_sha }}"
    );
    assert_eq!(
        qualify["steps"][0]["env"]["PRODUCER_SOURCE_SHA"],
        "${{ inputs.producer_source_sha }}"
    );
    for binding in [
        "93e16ba0c8b41617889cff557ee20fb19d9ce5ef",
        "39728542160",
        "native-release-assets-probe / verify-native-targets",
        "runner_name == \"\"",
        "12403514103",
        "sha256:7f1e66b5a7deb48d92cda66ab0ced18249bb50476b758ee6f63ee001492e5c9e",
        "12403799531",
        "sha256:50a73ccbb088427af0010f680e3514d3e0ba489b90eb79da77ed4563690cbae4",
        "12404720358",
        "sha256:8e6f33e6d8560872a2c907035bd76d98f496f83c98c06db6a5f793c63ff21a71",
        "12403759658",
        "sha256:c633c557e2df699a548e8ab4b56db53d524b10b0a4dc39c49da34315136ba8c5",
        "12404825172",
        "sha256:0f770a876d04a161a8eba43c34ffc32fbbd13b296221ed8d7ae330a4d3a1991a",
        "12403594699",
        "sha256:8b0c1849fb88d348017342fd75c7fe00a59367df726ba662353f096f20b89531",
        "ancestry",
        "merge_base_commit.sha",
        "\"$source_policy\" == \"$harness_policy\"",
    ] {
        assert!(
            qualify_run.contains(binding),
            "missing producer binding: {binding}"
        );
    }
    let publish_source_recheck = value["jobs"]["publish-scratch"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| {
            step["name"] == "Recheck the selected source and target before minting a scratch token"
        })
        .unwrap();
    let publish_source_recheck_run = publish_source_recheck["run"].as_str().unwrap();
    assert!(publish_source_recheck_run.contains("\"$source_policy\" == \"$harness_policy\""));
    assert!(publish_source_recheck_run.contains("\"$source_control\" == \"$main_control\""));
    assert!(publish_source_recheck_run.contains("\"$harness_control\" == \"$main_control\""));
    assert!(publish_source_recheck_run.contains("active_source_sha"));
    assert!(publish_source_recheck_run.contains("active_policy_sha"));
    assert!(publish_source_recheck_run.contains("policy.json?ref=$active_source_sha"));
    assert!(publish_source_recheck_run.contains("sha256sum --check"));
    assert!(!publish_source_recheck_run.contains("main_policy"));
    assert!(!publish_source_recheck_run.contains("policy.json?ref=$WORKFLOW_SHA"));

    let publish = &value["jobs"]["publish-scratch"];
    assert_eq!(publish["environment"], "main");
    assert_eq!(
        publish["permissions"],
        serde_json::json!({"actions":"read","contents":"read"})
    );
    let steps = publish["steps"].as_array().unwrap();
    let downloads: Vec<_> = steps
        .iter()
        .filter(|step| {
            step["uses"] == "actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0"
        })
        .collect();
    assert_eq!(downloads.len(), 3);
    assert_eq!(
        downloads[1]["with"]["artifact-ids"],
        "${{ needs.qualify.outputs.artifact-ids }}"
    );
    assert_eq!(
        downloads[1]["with"]["run-id"],
        "${{ inputs.producer_run_id }}"
    );
    assert_eq!(
        downloads[2]["with"]["artifact-ids"],
        "${{ needs.qualify.outputs.verification-artifact-id }}"
    );
    let prewrite = steps
        .iter()
        .position(|step| {
            step["name"] == "Revalidate the exact native artifacts before minting a scratch token"
        })
        .unwrap();
    let prewrite_run = steps[prewrite]["run"].as_str().unwrap();
    assert!(prewrite_run.contains("release::tests::native_release_assets_validate_probe_inputs"));
    assert!(!prewrite_run.contains("GITHUB_SHA=") && !prewrite_run.contains("GITHUB_RUN_ID="));
    assert_eq!(
        steps[prewrite]["env"]["SECUREFIX_POLICY_PATH"],
        "probe/active-policy.json"
    );
    assert_eq!(
        steps[prewrite]["env"]["SECUREFIX_NATIVE_RELEASE_PROBE_TARGET_POLICY_PATH"],
        "probe/policy.json"
    );
    let token = steps
        .iter()
        .position(|step| step["id"] == "scratch-token")
        .unwrap();
    let writer = steps
        .iter()
        .position(|step| step["name"] == "Run the source-bound native scratch release probe")
        .unwrap();
    assert!(prewrite < token && token < writer);
    let app = &steps[token];
    assert_eq!(app["with"]["owner"], "civitaspo");
    assert_eq!(app["with"]["repositories"], "testing-securefix-server");
    assert_eq!(app["with"]["app-id"], "3872533");
    assert_eq!(app["with"]["permission-contents"], "write");
    assert!(app["with"].get("permission-administration").is_none());
    assert!(app["with"].get("permission-workflows").is_none());
    let writer_run = steps[writer]["run"].as_str().unwrap();
    assert!(writer_run.contains("release::tests::native_release_assets_scratch_publish_probe"));
    assert!(!writer_run.contains("GITHUB_SHA=") && !writer_run.contains("GITHUB_RUN_ID="));
    assert_eq!(
        steps[writer]["env"]["SECUREFIX_NATIVE_RELEASE_PROBE_HARNESS_SHA"],
        "${{ inputs.harness_sha }}"
    );
    assert_eq!(
        steps[writer]["env"]["SECUREFIX_NATIVE_RELEASE_PROBE_SERVER_SHA"],
        "${{ inputs.producer_source_sha }}"
    );
    assert_eq!(
        steps[writer]["env"]["SECUREFIX_NATIVE_RELEASE_PROBE_PRODUCER_RUN_ID"],
        "${{ inputs.producer_run_id }}"
    );
    assert_eq!(
        steps[writer]["env"]["SECUREFIX_NATIVE_RELEASE_PROBE_PRODUCER_RUN_ATTEMPT"],
        "${{ inputs.producer_run_attempt }}"
    );
    assert_eq!(
        steps[writer]["env"]["SECUREFIX_POLICY_PATH"],
        "probe/active-policy.json"
    );
    assert_eq!(
        steps[writer]["env"]["SECUREFIX_NATIVE_RELEASE_PROBE_TARGET_POLICY_PATH"],
        "probe/policy.json"
    );
    assert_eq!(
        steps[prewrite]["env"]["SECUREFIX_NATIVE_RELEASE_PROBE_HARNESS_SHA"],
        "${{ inputs.harness_sha }}"
    );
    assert_eq!(
        steps[prewrite]["env"]["SECUREFIX_NATIVE_RELEASE_PROBE_SERVER_SHA"],
        "${{ inputs.producer_source_sha }}"
    );
    assert_eq!(
        steps[prewrite]["env"]["SECUREFIX_NATIVE_RELEASE_PROBE_PRODUCER_RUN_ID"],
        "${{ inputs.producer_run_id }}"
    );
    assert_eq!(
        steps[prewrite]["env"]["SECUREFIX_NATIVE_RELEASE_PROBE_PRODUCER_RUN_ATTEMPT"],
        "${{ inputs.producer_run_attempt }}"
    );
    assert!(steps.iter().any(|step| {
        step["uses"] == "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
            && step["if"] == "always()"
    }));
    assert!(
        !serde_json::to_string(publish)
            .unwrap()
            .contains("Administration")
    );
}

#[test]
fn testing_publication_executes_only_trusted_qualification_and_stable_publisher() {
    let value = workflow("testing-publish-runtime.yml");
    for job in value["jobs"].as_object().unwrap().values() {
        let guard = job["if"].as_str().unwrap();
        for condition in [
            "github.repository == 'civitaspo/securefix-server'",
            "github.ref == 'refs/heads/main'",
            "github.actor_id == '4525500'",
            "github.run_attempt == 1",
        ] {
            assert!(guard.contains(condition), "{condition}");
        }
    }
    let build = &value["jobs"]["build"];
    assert_eq!(
        build["outputs"]["validator-artifact-id"],
        "${{ steps.validator.outputs.artifact-id }}"
    );
    assert_eq!(
        build["steps"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|step| step["uses"] == "$/.github/actions/setup-cli")
            .count(),
        1
    );
    let publish = &value["jobs"]["publish"];
    assert_eq!(publish["needs"], serde_json::json!(["build", "controller"]));
    assert_eq!(
        publish["env"]["SECUREFIX_TEST_BASELINE_SHA"],
        "${{ needs.build.outputs.source-sha }}"
    );
    assert!(publish["steps"].as_array().unwrap().iter().any(|step| {
        step["uses"]
            .as_str()
            .is_some_and(|uses| uses.starts_with("actions/download-artifact@"))
            && step["with"]["artifact-ids"] == "${{ needs.build.outputs.validator-artifact-id }}"
            && step["with"]["path"] == "${{ runner.temp }}/testing-validator"
    }));
    assert_eq!(publish["environment"], "main");
    assert_eq!(publish["concurrency"]["group"], "securefix-control");
    let steps = publish["steps"].as_array().unwrap();
    let attestation = steps
        .iter()
        .position(|s| s["name"] == "Verify exact testing publisher attestation")
        .unwrap();
    let qualify = steps
        .iter()
        .position(|s| {
            s["run"]
                .as_str()
                .is_some_and(|s| s.contains("integration validate-testing-publication"))
        })
        .unwrap();
    let stable = steps
        .iter()
        .position(|s| {
            s["uses"] == "$/.github/actions/install-cli"
                && s["with"]["binary"] == "${{ runner.temp }}/active-controller/securefix"
        })
        .unwrap();
    let publish_archive = steps
        .iter()
        .position(|s| {
            s["run"]
                .as_str()
                .is_some_and(|s| s.starts_with("securefix runtime publish "))
        })
        .unwrap();
    assert!(attestation < qualify && qualify < stable && stable < publish_archive);
    assert_eq!(
        steps[stable]["with"]["binary"],
        "${{ runner.temp }}/active-controller/securefix"
    );
    let text = serde_json::to_string(publish).unwrap();
    assert!(text.contains(".github/workflows/testing-publish-runtime.yml"));
    for forbidden in [
        "secrets.",
        "tar -x",
        "candidate-runtime/securefix",
        "./runtime/securefix",
        "control activate",
    ] {
        assert!(!text.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn testing_fixture_controller_scopes_credentials_and_retires_legacy_client_smoke() {
    let value = workflow("testing-control-fixture.yml");
    let host = &value["jobs"]["host"];
    assert!(!serde_json::to_string(host).unwrap().contains("secrets."));
    let fixture = &value["jobs"]["fixture"];
    assert_eq!(fixture["concurrency"]["group"], "securefix-control");
    for id in ["host", "fixture"] {
        let guard = value["jobs"][id]["if"].as_str().unwrap();
        for clause in [
            "github.actor_id == '4525500'",
            "github.run_attempt == 1",
            "refs/heads/main",
        ] {
            assert!(guard.contains(clause));
        }
    }
    let steps = fixture["steps"].as_array().unwrap();
    let check = steps
        .iter()
        .position(|s| s["run"] == "securefix integration testing-control validate")
        .unwrap();
    let mint = steps.iter().position(|s| s["id"] == "test-token").unwrap();
    assert!(check < mint);
    assert_eq!(
        steps[mint]["with"]["repositories"],
        "testing-securefix-server"
    );
    let candidate = workflow("testing-securefix-server.yml");
    assert!(candidate["jobs"].get("client-smoke").is_none());
    assert!(candidate["jobs"].get("client-baseline").is_none());
    assert!(
        candidate["on"]["workflow_dispatch"]["inputs"]
            .get("client_runtime")
            .is_none()
    );
}

#[test]
fn testing_loader_qualifies_selected_runtime_without_operational_secrets() {
    let value = workflow("testing-load-cli.yml");
    assert!(value["on"]["workflow_call"].get("secrets").is_none());
    for output in ["artifact-id", "source-sha", "control-id", "workflow-sha"] {
        assert!(
            value["on"]["workflow_call"]["outputs"]
                .get(output)
                .is_some()
        );
    }
    let load = &value["jobs"]["load"];
    let text = serde_json::to_string(load).unwrap();
    assert!(text.contains("load-testing-runtime --workflow-sha"));
    assert!(text.contains("job.workflow_sha"));
    assert!(text.contains("load-runtime"));
    assert!(text.contains("install-cli"));
    assert!(text.contains("control-repository"));
    assert!(text.contains("testing-"));
    for forbidden in [
        "setup-cli",
        "secrets.",
        "create-github-app-token",
        "validator-artifact-id",
        "docker run",
    ] {
        assert!(!text.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn testing_reusables_share_production_jobs_and_commands() {
    for feature in ["release-pr", "release-pr-sync"] {
        let production = workflow(&format!("reusable-{feature}.yml"));
        let testing = workflow(&format!("testing-reusable-{feature}.yml"));
        let expected = serde_json::to_string(&production["jobs"])
            .unwrap()
            .replace(
                ".github/workflows/load-cli.yml",
                ".github/workflows/testing-load-cli.yml",
            )
            .replace("release/next", "release/testing-next");
        assert_eq!(
            serde_json::to_string(&testing["jobs"]).unwrap(),
            expected,
            "{feature}"
        );
        assert_eq!(testing["on"], production["on"], "{feature}");
        assert_eq!(testing["permissions"], production["permissions"]);
    }

    let production = workflow("reusable-release-tag.yml");
    let testing = workflow("testing-reusable-release-tag.yml");
    assert_eq!(
        production["on"]["workflow_call"]["inputs"],
        testing["on"]["workflow_call"]["inputs"]
    );
    assert_eq!(production["permissions"], serde_json::json!({}));
    assert_eq!(testing["permissions"], serde_json::json!({}));
    let production_jobs = serde_json::to_string(&production["jobs"]).unwrap();
    assert!(production_jobs.contains(".github/actions/load-package@"));
    assert!(!production_jobs.contains("testing-load-cli.yml"));
    let testing_jobs = serde_json::to_string(&testing["jobs"]).unwrap();
    assert!(testing_jobs.contains("testing-load-cli.yml"));

    for feature in ["approve-request", "merge-request"] {
        let production = workflow(&format!("reusable-{feature}.yml"));
        assert_eq!(production["permissions"], serde_json::json!({}));
        assert_eq!(
            production["jobs"]["request"]["uses"],
            "./.github/workflows/reusable-client-request.yml"
        );
        assert_eq!(
            production["jobs"]["request"]["with"]["operation"],
            if feature == "approve-request" {
                "approval"
            } else {
                "merge"
            }
        );
        let testing = workflow(&format!("testing-reusable-{feature}.yml"));
        assert_eq!(testing["permissions"], serde_json::json!({}));
        assert!(
            serde_json::to_string(&testing["jobs"])
                .unwrap()
                .contains("testing-load-cli.yml"),
            "{feature} must retain the explicit test runtime"
        );
    }
}

#[test]
fn testing_migration_reuses_normal_commands_with_test_only_tokens() {
    let value = workflow("testing-merge-caller-migration.yml");
    for job in value["jobs"].as_object().unwrap().values() {
        let guard = job["if"].as_str().unwrap();
        for required in [
            "github.actor_id == '4525500'",
            "github.run_attempt == 1",
            "github.ref == 'refs/heads/main'",
        ] {
            assert!(guard.contains(required));
        }
    }
    let merge = &value["jobs"]["merge"];
    assert_eq!(merge["environment"], "main");
    assert_eq!(merge["concurrency"]["group"], "securefix-control");
    let steps = merge["steps"].as_array().unwrap();
    let position = |needle: &str| {
        steps
            .iter()
            .position(|step| step["run"].as_str().is_some_and(|s| s.contains(needle)))
            .unwrap()
    };
    let preflight = position("validate-testing-processor --kind caller-migration");
    let read = steps.iter().position(|s| s["id"] == "read").unwrap();
    let qualify = position("load-testing-control --kind caller-migration");
    let prepare = position("securefix caller-migration prepare");
    let authorize = position("securefix caller-migration authorize");
    let ready = position("securefix caller-migration ready");
    let mint = steps.iter().position(|s| s["id"] == "write").unwrap();
    let apply = position("securefix caller-migration merge");
    assert!(
        preflight < read
            && read < qualify
            && qualify < prepare
            && prepare < authorize
            && authorize < ready
            && ready < mint
            && mint < apply
    );
    assert!(!serde_json::to_string(merge).unwrap().contains("docker run"));
    let install = steps
        .iter()
        .position(|s| s["with"]["binary"] == "${{ steps.runtime.outputs.directory }}/securefix")
        .unwrap();
    assert!(qualify < install && install < prepare);
    for step in steps {
        if step["uses"]
            .as_str()
            .is_some_and(|s| s.starts_with("actions/create-github-app-token@"))
        {
            assert_eq!(step["with"]["repositories"], "testing-securefix-server");
            assert!(step["with"].get("permission-workflows").is_none());
        }
    }
}

#[test]
fn testing_server_uses_normal_commands_and_restricts_app_targets() {
    for (file, normal_commands) in [
        (
            "testing-approve.yml",
            vec!["securefix approve validate", "securefix approve apply"],
        ),
        (
            "testing-merge.yml",
            vec![
                "securefix merge validate",
                "securefix merge authorize",
                "securefix merge wait",
                "securefix merge apply",
            ],
        ),
        (
            "testing-policy-check.yml",
            vec!["securefix check validate", "securefix check apply"],
        ),
        (
            "testing-securefix.yml",
            vec!["securefix securefix prepare", "securefix securefix apply"],
        ),
        (
            "testing-release.yml",
            vec![
                "securefix release preflight",
                "securefix release sign",
                "securefix release publish",
            ],
        ),
    ] {
        let value = workflow(file);
        let text = serde_json::to_string(&value).unwrap();
        for command in normal_commands {
            assert!(text.contains(command), "{file}: {command}");
        }
        for forbidden in [
            "review-for-testing",
            "apply-reviewed-for-testing",
            "continue-testing-request",
            "docker run",
            "testing-notification",
        ] {
            assert!(!text.contains(forbidden), "{file}: {forbidden}");
        }
        for job in value["jobs"].as_object().unwrap().values() {
            if let Some(steps) = job["steps"].as_array() {
                for step in steps {
                    if step["uses"].as_str().is_some_and(|action| {
                        action.starts_with("actions/create-github-app-token@")
                    }) {
                        assert_eq!(
                            step["with"]["repositories"], "testing-securefix-server",
                            "{file}"
                        );
                    }
                }
            }
        }
    }
    let approve = workflow("testing-approve.yml");
    let steps = approve["jobs"]["approve"]["steps"].as_array().unwrap();
    let apply = steps
        .iter()
        .find(|step| step["run"] == "securefix approve apply")
        .unwrap();
    assert_eq!(
        apply["env"]["SECUREFIX_APPROVE_TOKEN"],
        "${{ secrets.CIVITASPO_BOT_PR_APPROVE_TOKEN }}"
    );
    assert!(!std::path::Path::new(".github/workflows/testing-process-request.yml").exists());
}

#[test]
#[cfg(unix)]
fn runtime_loader_stops_before_extraction_or_export_when_a_gate_fails() {
    use std::{os::unix::fs::PermissionsExt, process::Command};

    let script = include_str!("../.github/actions/load-runtime/load.sh");
    let source_sha = "a".repeat(40);
    let policy_sha = "b".repeat(64);
    let archive_sha = "c".repeat(64);
    let control_id = "d".repeat(64);
    for (scenario, testing) in [
        "success",
        "success-no-pin",
        "success-unsuffixed-publisher",
        "success-bootstrap",
        "success-unsuffixed-bootstrap",
        "success-publisher-later-generation",
        "wrong-publisher-source",
        "wrong-publisher-path",
        "wrong-publisher-suffix",
        "wrong-publisher-ref",
        "wrong-publisher-actor",
        "wrong-publisher-repository",
        "bootstrap-rerun",
        "bootstrap-later-generation",
        "missing",
        "wrong-source",
        "malformed-pin",
        "ambiguous",
        "bad-id",
        "api-error",
        "wrong-immutable",
        "oversized",
        "bad-digest",
        "bad-attestation",
        "bad-metadata",
        "wrong-workflow-namespace",
        "wrong-policy-namespace",
        "wrong-control-policy",
        "invalid-workflow-prefix",
    ]
    .into_iter()
    .flat_map(|scenario| [(scenario, false), (scenario, true)])
    {
        let prefix = if testing { "testing-" } else { "" };
        let temp = tempfile::tempdir().unwrap();
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        for (name, body) in [
            (
                "gh",
                r#"#!/bin/bash
set -euo pipefail
case "$1" in
  api)
    [[ "$SCENARIO" != api-error ]] || exit 1
    case "$2" in
      repos/example/runtime) cat "$REPOSITORY_JSON" ;;
      repos/example/control) cat "$CONTROL_REPOSITORY_JSON" ;;
      repos/example/runtime/commits/main|repos/example/control/commits/control-main) printf '%s\n' "$ACTIVE_SOURCE_SHA" ;;
      repos/example/runtime/contents/control/active.json\?ref=*|repos/example/control/contents/control/active.json\?ref=*)
        [[ "$SCENARIO" != missing ]] || exit 1
        cat "$CONTENT_RESPONSE" ;;
      repos/example/runtime/actions/runs/9) cat "$PUBLISHER_RUN_JSON" ;;
      repos/example/runtime/releases/7) cat "$RELEASE_JSON" ;;
      repos/example/runtime/releases/assets/8)
      echo download >> "$TRACE"
        printf archive ;;
      *) exit 1 ;;
    esac ;;
  attestation)
    echo attestation >> "$TRACE"
    printf '%s\n' "$@" > "$ATTESTATION_ARGS"
    [[ "$SCENARIO" != bad-attestation && "$SCENARIO" != wrong-source ]] ;;
  *) exit 1 ;;
esac
"#,
            ),
            (
                "stat",
                r#"#!/bin/bash
if [[ "$SCENARIO" == oversized && "$3" == *runtime-archive* ]]; then echo 134217729; else wc -c < "$3"; fi
"#,
            ),
            (
                "sha256sum",
                r#"#!/bin/bash
if [[ "$1" == *policy.json ]]; then digest="$POLICY_SHA"; else digest="$ARCHIVE_SHA"; fi
printf '%s  %s\n' "$digest" "$1"
"#,
            ),
            (
                "tar",
                r#"#!/bin/bash
set -euo pipefail
echo extraction >> "$TRACE"
cp "$VERIFIER" "$4/securefix"
if [[ "$CONTROL_REPOSITORY" != "$REPOSITORY" || -n "${MOCK_CONTROL_REPOSITORY:-}" ]]; then
  printf '{"deployment":{"workflow_prefix":"%s","server":{"repository":"example/runtime","id":1,"default_branch":"main"},"control_repository":{"repository":"%s","id":%s,"default_branch":"control-main"}}}\n' "$MOCK_POLICY_PREFIX" "${MOCK_CONTROL_REPOSITORY:-$CONTROL_REPOSITORY}" "${MOCK_CONTROL_ID:-2}" > "$4/policy.json"
else
  printf '{"deployment":{"workflow_prefix":"%s","server":{"repository":"example/runtime","id":1,"default_branch":"main"}}}\n' "$MOCK_POLICY_PREFIX" > "$4/policy.json"
fi
"#,
            ),
            (
                "securefix-mock",
                r#"#!/bin/bash
set -euo pipefail
if [[ "$1 $2" == "runtime verify" ]]; then
  echo runtime-verify >> "$TRACE"
elif [[ "$1 $2" == "control identify" ]]; then
  echo control-identify >> "$TRACE"
  source_sha="$ACTIVE_SOURCE_SHA"
  [[ "$SCENARIO" != bad-metadata ]] || source_sha="$(printf 'e%.0s' {1..40})"
  generation=1
  [[ "$SCENARIO" != bootstrap-later-generation && "$SCENARIO" != success-publisher-later-generation ]] || generation=2
  printf 'source-sha=%s\ngeneration=%s\npolicy-sha256=%s\narchive-sha256=%s\nrelease-id=7\nasset-id=8\n' "$source_sha" "$generation" "$POLICY_SHA" "$ARCHIVE_SHA"
  printf 'control-id=%s\n' "$CONTROL_ID"
else
  exit 1
fi
"#,
            ),
        ] {
            let path = bin.join(name);
            fs::write(&path, body).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut descriptor = serde_json::json!({
            "version": 1,
            "generation": if scenario == "bootstrap-later-generation" || scenario == "success-publisher-later-generation" { 2 } else { 1 },
            "source_sha": source_sha,
            "policy_sha256": policy_sha,
            "archive_sha256": archive_sha,
            "release_id": 7,
            "asset_id": 8,
            "publisher_run_id": 9,
            "verification_run_id": 10,
            "previous": "0".repeat(64)
        });
        if scenario == "bad-id" {
            descriptor["asset_id"] = 0.into();
        }
        let descriptor_bytes = serde_json::to_vec(&descriptor).unwrap();
        use base64::Engine;
        let content_response = serde_json::json!({
            "encoding":"base64",
            "content":base64::engine::general_purpose::STANDARD.encode(descriptor_bytes)
        });
        let content_path = temp.path().join("content.json");
        fs::write(
            &content_path,
            serde_json::to_vec(&content_response).unwrap(),
        )
        .unwrap();
        let repository_path = temp.path().join("repository.json");
        fs::write(
            &repository_path,
            serde_json::to_vec(&serde_json::json!({
                "id":1,"full_name":"example/runtime","default_branch":"main","owner":{"id":2}
            }))
            .unwrap(),
        )
        .unwrap();
        let control_repository_path = temp.path().join("control-repository.json");
        fs::write(
            &control_repository_path,
            serde_json::to_vec(&serde_json::json!({
                "id":2,"full_name":"example/control","default_branch":"control-main","owner":{"id":2}
            }))
            .unwrap(),
        )
        .unwrap();
        let publisher_run_path = if scenario == "success-bootstrap"
            || scenario == "success-unsuffixed-bootstrap"
            || scenario == "bootstrap-rerun"
            || scenario == "bootstrap-later-generation"
        {
            if scenario == "success-unsuffixed-bootstrap" {
                ".github/workflows/control-bootstrap.yml"
            } else {
                ".github/workflows/control-bootstrap.yml@refs/heads/main"
            }
        } else if scenario == "wrong-publisher-path" {
            ".github/workflows/other.yml@refs/heads/main"
        } else if scenario == "wrong-publisher-suffix" {
            ".github/workflows/publish-runtime.yml@refs/heads/other"
        } else if scenario == "success-unsuffixed-publisher" {
            ".github/workflows/publish-runtime.yml"
        } else {
            ".github/workflows/publish-runtime.yml@refs/heads/main"
        };
        let publisher_run_path_file = temp.path().join("publisher-run.json");
        let publisher_prefix = if scenario == "wrong-workflow-namespace" {
            if testing { "" } else { "testing-" }
        } else {
            prefix
        };
        let publisher_run_path = publisher_run_path.replace(
            ".github/workflows/",
            &format!(".github/workflows/{publisher_prefix}"),
        );
        fs::write(
            &publisher_run_path_file,
            serde_json::to_vec(&serde_json::json!({
                "id":9,
                "path":publisher_run_path,
                "run_attempt": if scenario == "bootstrap-rerun" { 2 } else { 1 },
                "status":"completed",
                "conclusion":"success",
                "event":"workflow_dispatch",
                "head_branch": if scenario == "wrong-publisher-ref" { "other" } else { "main" },
                "head_sha": if scenario == "wrong-publisher-source" { "f".repeat(40) } else { source_sha.clone() },
                "repository": if scenario == "wrong-publisher-repository" { serde_json::json!({"id":7,"full_name":"example/other"}) } else { serde_json::json!({"id":1,"full_name":"example/runtime"}) },
                "head_repository":{"id":1,"full_name":"example/runtime"},
                "actor":{"id": if scenario == "wrong-publisher-actor" { 3 } else { 4525500 }},
                "triggering_actor":{"id":4525500}
            })).unwrap(),
        ).unwrap();
        let mut release = serde_json::json!({
            "id":7,"draft":false,"immutable":true,
            "assets":[{"id":8,"name":"securefix-runtime-linux-x86_64.tar.gz"}]
        });
        if scenario == "ambiguous" {
            let asset = release["assets"][0].clone();
            release["assets"].as_array_mut().unwrap().push(asset);
        }
        if scenario == "wrong-immutable" {
            release["immutable"] = false.into();
        }
        let release_path = temp.path().join("release.json");
        fs::write(&release_path, serde_json::to_vec(&release).unwrap()).unwrap();
        let trace = temp.path().join("trace");
        let output = temp.path().join("output");
        fs::write(&trace, "").unwrap();
        fs::write(&output, "").unwrap();
        let mut command = Command::new("bash");
        command
            .args(["-euo", "pipefail", "-c", script])
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            )
            .env("RUNNER_TEMP", temp.path())
            .env("GITHUB_OUTPUT", &output)
            .env("ACTIVE_SOURCE_SHA", &source_sha)
            .env("POLICY_SHA", &policy_sha)
            .env(
                "ARCHIVE_SHA",
                if scenario == "bad-digest" {
                    "f".repeat(64)
                } else {
                    archive_sha.clone()
                },
            )
            .env("CONTROL_ID", &control_id)
            .env("REPOSITORY", "example/runtime")
            .env(
                "CONTROL_REPOSITORY",
                if testing {
                    "example/control"
                } else {
                    "example/runtime"
                },
            )
            .env("DEFAULT_BRANCH", "main")
            .env(
                "WORKFLOW_PREFIX",
                if scenario == "invalid-workflow-prefix" {
                    "test-"
                } else {
                    prefix
                },
            )
            .env(
                "MOCK_POLICY_PREFIX",
                if scenario == "wrong-policy-namespace" {
                    if testing { "" } else { "testing-" }
                } else {
                    prefix
                },
            )
            .env("SCENARIO", scenario)
            .env("CONTENT_RESPONSE", content_path)
            .env("REPOSITORY_JSON", repository_path)
            .env("CONTROL_REPOSITORY_JSON", control_repository_path)
            .env(
                "MOCK_CONTROL_REPOSITORY",
                if scenario == "wrong-control-policy" {
                    "example/wrong"
                } else {
                    ""
                },
            )
            .env("PUBLISHER_RUN_JSON", publisher_run_path_file)
            .env("RELEASE_JSON", release_path)
            .env("TRACE", &trace)
            .env("ATTESTATION_ARGS", temp.path().join("attestation-args"))
            .env("VERIFIER", bin.join("securefix-mock"));
        match scenario {
            "wrong-source" => {
                command.env("SOURCE_SHA", "f".repeat(40));
            }
            "malformed-pin" => {
                command.env("SOURCE_SHA", "not-a-sha");
            }
            "success-no-pin" => {}
            _ => {
                command.env("SOURCE_SHA", &source_sha);
            }
        }
        let result = command.output().unwrap();
        let should_succeed = matches!(
            scenario,
            "success"
                | "success-no-pin"
                | "success-unsuffixed-publisher"
                | "success-bootstrap"
                | "success-unsuffixed-bootstrap"
                | "success-publisher-later-generation"
                | "bootstrap-later-generation"
        );
        assert_eq!(
            result.status.success(),
            should_succeed,
            "{scenario}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let expected = match scenario {
            "success"
            | "success-no-pin"
            | "success-unsuffixed-publisher"
            | "success-bootstrap"
            | "success-unsuffixed-bootstrap"
            | "success-publisher-later-generation"
            | "bootstrap-later-generation" => {
                "download\nattestation\nextraction\nruntime-verify\ncontrol-identify\n"
            }
            "bad-metadata" => {
                "download\nattestation\nextraction\nruntime-verify\ncontrol-identify\n"
            }
            "bad-attestation" => "download\nattestation\n",
            "wrong-policy-namespace" => "download\nattestation\nextraction\n",
            "wrong-control-policy" => "download\nattestation\nextraction\n",
            "wrong-source"
            | "malformed-pin"
            | "wrong-publisher-source"
            | "wrong-publisher-path"
            | "wrong-publisher-suffix"
            | "wrong-publisher-ref"
            | "wrong-publisher-actor"
            | "wrong-publisher-repository"
            | "bootstrap-rerun" => "",
            "oversized" | "bad-digest" => "download\n",
            _ => "",
        };
        assert_eq!(fs::read_to_string(trace).unwrap(), expected, "{scenario}");
        assert_eq!(
            !fs::read(output).unwrap().is_empty(),
            should_succeed,
            "{scenario}"
        );
        if matches!(
            scenario,
            "success"
                | "success-no-pin"
                | "success-unsuffixed-publisher"
                | "success-bootstrap"
                | "success-unsuffixed-bootstrap"
                | "success-publisher-later-generation"
                | "bootstrap-later-generation"
        ) {
            let args = fs::read_to_string(temp.path().join("attestation-args")).unwrap();
            let expected_signer = if scenario == "success-bootstrap"
                || scenario == "success-unsuffixed-bootstrap"
                || scenario == "bootstrap-later-generation"
            {
                "example/runtime/.github/workflows/control-bootstrap.yml"
            } else {
                "example/runtime/.github/workflows/publish-runtime.yml"
            };
            let expected_signer = expected_signer
                .replace(".github/workflows/", &format!(".github/workflows/{prefix}"));
            assert!(
                args.lines().any(|line| line == expected_signer),
                "{scenario}: {args}"
            );
        }
    }
}

#[test]
fn workflows_use_pinned_actions_and_immutable_flattened_artifacts() {
    for (path, workflow) in workflows() {
        assert!(
            workflow["permissions"]
                .as_object()
                .is_some_and(|p| p.is_empty()),
            "{path}: top-level permissions must be empty"
        );
        for (job_id, job) in workflow["jobs"].as_object().unwrap() {
            if let Some(uses) = job["uses"].as_str() {
                if path == ".github/workflows/testing-native-securefix-event.yml" {
                    assert_eq!(job_id, "handler");
                    assert_eq!(
                        uses,
                        "civitaspo/securefix-server/.github/workflows/reusable-server-securefix.yml@d2d4b47781fcb40ca64e356af107ea8395f3e3f1"
                    );
                    assert_eq!(
                        job["with"]["config_path"],
                        "repo-settings/native-securefix-write-test-instance.toml"
                    );
                    assert_eq!(
                        job["secrets"]["SERVER_PRIVATE_KEY"],
                        "${{ secrets.SECUREFIX_SERVER_PRIVATE_KEY }}"
                    );
                } else if let Some(role) =
                    ["approve", "merge", "policy-check"]
                        .into_iter()
                        .find(|role| {
                            path == format!(".github/workflows/testing-native-{role}-event.yml")
                        })
                {
                    let config_path = "repo-settings/native-role-events-test-instance.toml";
                    assert_eq!(job_id, "handler");
                    let revision = if role == "merge" {
                        "5c52c7b6f61d58d3d0cafc35456777bc1b1e1ce3"
                    } else {
                        "2719567ddd2cb9e13294e12cb9537780c6643263"
                    };
                    assert_eq!(
                        uses,
                        format!(
                            "civitaspo/securefix-server/.github/workflows/reusable-server-{role}.yml@{revision}"
                        )
                    );
                    assert_eq!(job["with"]["config_path"], config_path);
                    assert_eq!(
                        job["if"],
                        format!("startsWith(github.event.label.name, 'securefix-native-{role}-')")
                    );
                    assert_eq!(
                        job["secrets"]["SERVER_PRIVATE_KEY"],
                        "${{ secrets.SECUREFIX_SERVER_PRIVATE_KEY }}"
                    );
                    if role == "approve" {
                        assert_eq!(
                            job["secrets"]["APPROVAL_TOKEN"],
                            "${{ secrets.CIVITASPO_BOT_PR_APPROVE_TOKEN }}"
                        );
                    }
                } else {
                    assert!(
                        uses.starts_with("./.github/workflows/"),
                        "{path}/{job_id}: reusable must use the running revision"
                    );
                }
                assert!(
                    job.get("secrets").is_none() || uses != "./.github/workflows/load-cli.yml",
                    "runtime loader cannot inherit secrets"
                );
                if uses == "./.github/workflows/load-cli.yml" {
                    assert_eq!(
                        job["permissions"]["actions"], "read",
                        "{path}/{job_id}: loader caller needs action run metadata read"
                    );
                    assert_eq!(
                        job["permissions"]["contents"], "read",
                        "{path}/{job_id}: loader caller needs content read"
                    );
                    assert_eq!(
                        job["permissions"]["attestations"], "read",
                        "{path}/{job_id}: loader caller needs attestation read"
                    );
                }
            }
            let Some(steps) = job["steps"].as_array() else {
                continue;
            };
            for step in steps {
                let Some(uses) = step["uses"].as_str() else {
                    continue;
                };
                if !uses.starts_with("./") && !uses.starts_with("$/") {
                    let (_, revision) = uses.rsplit_once('@').unwrap();
                    assert!(
                        securefix::policy::validate_sha(revision).is_ok(),
                        "{path}/{job_id}: {uses}"
                    );
                }
                assert!(
                    (!uses.contains("github-script")
                        || (path == ".github/workflows/ci.yml"
                            && step["name"] == "Check and test the package loader on Node.js 24"
                            && uses
                                == "actions/github-script@ed597411d8f924073f98dfc5c65a23a2325f34cd"))
                        && !uses.contains("approve-pr-action")
                        && !uses.contains("csm-actions/securefix-action"),
                    "business logic must be in Rust"
                );
                if uses.starts_with("actions/download-artifact@") {
                    let inputs = &step["with"];
                    if path == ".github/workflows/testing-provider-release.yml"
                        && job_id == "assemble-provider"
                    {
                        assert_eq!(
                            inputs["pattern"], "sigma-probe-${{ github.run_id }}-*",
                            "only the current run's provider matrix artifacts may be assembled"
                        );
                        assert_eq!(inputs["path"], "probe/assets");
                        assert_eq!(inputs["merge-multiple"], true);
                        assert!(inputs.get("artifact-ids").is_none());
                        assert!(inputs.get("repository").is_none());
                        assert!(inputs.get("run-id").is_none());
                        continue;
                    }
                    if path == ".github/workflows/testing-native-release-assets-publish.yml"
                        && job_id == "publish-scratch"
                        && inputs["artifact-ids"] == "${{ needs.qualify.outputs.artifact-ids }}"
                    {
                        assert_eq!(inputs["repository"], "civitaspo/securefix-server");
                        assert_eq!(inputs["run-id"], "${{ inputs.producer_run_id }}");
                        assert_eq!(inputs["github-token"], "${{ github.token }}");
                        assert_eq!(inputs["path"], "native-input");
                        assert!(inputs.get("merge-multiple").is_none());
                        assert!(inputs.get("name").is_none() && inputs.get("pattern").is_none());
                        continue;
                    }
                    if path == ".github/workflows/testing-release-pr.yml" && job_id == "execute" {
                        assert_eq!(inputs["merge-multiple"], true);
                        let artifact_id = inputs["artifact-ids"].as_str().unwrap();
                        if artifact_id == "${{ needs.trusted-runtime.outputs.artifact-id }}" {
                            assert_eq!(inputs["path"], "trusted-runtime");
                            assert!(inputs.get("repository").is_none());
                            assert!(inputs.get("run-id").is_none());
                        } else if artifact_id == "${{ needs.candidate-build.outputs.artifact-id }}"
                        {
                            assert_eq!(step["if"], "inputs.phase == 'prepare'");
                            assert_eq!(inputs["path"], "candidate");
                            assert!(inputs.get("repository").is_none());
                            assert!(inputs.get("run-id").is_none());
                        } else {
                            assert!(
                                artifact_id
                                    == "${{ steps.artifacts.outputs.candidate_artifact_id }}"
                                    || artifact_id
                                        == "${{ steps.artifacts.outputs.state_artifact_id }}"
                            );
                            assert_eq!(step["if"], "inputs.phase == 'verify'");
                            assert_eq!(inputs["repository"], "civitaspo/securefix-server");
                            assert_eq!(inputs["run-id"], "${{ inputs.prepare_run_id }}");
                            assert_eq!(inputs["github-token"], "${{ github.token }}");
                            assert_eq!(
                                inputs["path"],
                                if artifact_id.contains("candidate_artifact") {
                                    "candidate"
                                } else {
                                    "fixture-state"
                                }
                            );
                        }
                        continue;
                    }
                    if matches!(
                        path.as_str(),
                        ".github/workflows/reusable-release-tag.yml"
                            | ".github/workflows/testing-reusable-release-tag.yml"
                    ) && job_id == "assemble-native"
                        && inputs["pattern"].is_string()
                    {
                        assert_eq!(
                            inputs["pattern"], "native-target-*-${{ github.run_attempt }}",
                            "{path}/{job_id}"
                        );
                        assert_eq!(inputs["path"], "native-input");
                        assert!(inputs.get("merge-multiple").is_none());
                        assert!(inputs.get("artifact-ids").is_none());
                        assert!(inputs.get("repository").is_none());
                        assert!(inputs.get("run-id").is_none());
                        continue;
                    }
                    if path == ".github/workflows/testing-native-release-assets.yml"
                        && matches!(
                            job_id.as_str(),
                            "verify-native-targets" | "publish-scratch-prerelease"
                        )
                        && inputs["pattern"].is_string()
                    {
                        assert_eq!(
                            inputs["pattern"], "native-target-*-${{ github.run_attempt }}",
                            "{path}/{job_id}"
                        );
                        assert_eq!(inputs["path"], "native-input");
                        assert!(inputs.get("merge-multiple").is_none());
                        assert!(inputs.get("artifact-ids").is_none());
                        assert!(inputs.get("repository").is_none());
                        assert!(inputs.get("run-id").is_none());
                        continue;
                    }
                    assert!(
                        inputs["artifact-ids"].as_str().is_some_and(|v| {
                            v.starts_with("${{ needs.") || v.starts_with("${{ steps.state.")
                        }),
                        "{path}/{job_id}: immutable artifact ID required"
                    );
                    assert!(inputs.get("name").is_none() && inputs.get("pattern").is_none());
                    assert_eq!(
                        inputs["merge-multiple"], true,
                        "{path}/{job_id}: IDs otherwise extract into named subdirectories"
                    );
                }
                if uses.starts_with("actions/checkout@") {
                    assert_eq!(
                        step["with"]["persist-credentials"], false,
                        "{path}/{job_id}: checkout credentials must not persist"
                    );
                    if step["with"]["repository"] == "civitaspo/securefix-server" {
                        assert_eq!(
                            step["with"]["ref"],
                            if path == ".github/workflows/request-producer-probe.yml"
                                && job_id == "capture"
                            {
                                "${{ inputs.candidate_source_sha }}"
                            } else if path == ".github/workflows/testing-securefix-server.yml" {
                                if job_id == "baseline" {
                                    "${{ steps.resolve.outputs.sha }}"
                                } else if job_id == "build" {
                                    "${{ inputs.candidate_sha || job.workflow_sha }}"
                                } else if job_id == "managed-files-probe" {
                                    // The local install action comes from the dispatch workflow revision;
                                    // the candidate CLI itself arrives through the immutable build artifact.
                                    "${{ job.workflow_sha }}"
                                } else if job_id == "bootstrap-scratch" || job_id == "scratch" {
                                    "${{ github.workflow_sha }}"
                                } else {
                                    "${{ inputs.candidate_sha || job.workflow_sha }}"
                                }
                            } else if path == ".github/workflows/testing-load-cli.yml" {
                                "${{ steps.baseline.outputs.sha }}"
                            } else {
                                if path == ".github/workflows/control-bootstrap.yml" {
                                    "${{ github.workflow_sha }}"
                                } else {
                                    "${{ job.workflow_sha }}"
                                }
                            },
                            "{path}/{job_id}: actual defining workflow revision required"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn native_request_producer_reuses_the_exact_source_pinned_candidate() {
    let producer = workflow("request-producer-probe.yml");
    let inputs = &producer["on"]["workflow_call"]["inputs"];
    assert_eq!(inputs["candidate_source_sha"]["required"], true);
    assert!(inputs["candidate_source_sha"].get("default").is_none());

    let capture = &producer["jobs"]["capture"];
    let steps = capture["steps"].as_array().unwrap();
    let checkout = steps
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/checkout@"))
        })
        .unwrap();
    assert_eq!(checkout["with"]["repository"], "civitaspo/securefix-server");
    assert_eq!(
        checkout["with"]["ref"],
        "${{ inputs.candidate_source_sha }}"
    );
    assert_eq!(checkout["with"]["persist-credentials"], false);

    let reuse = steps
        .iter()
        .find(|step| step["name"] == "Reuse the exact source-bound candidate artifact")
        .unwrap();
    assert_eq!(reuse["uses"], "$/.github/actions/setup-cli");
    assert_eq!(
        reuse["with"]["candidate-run-id"],
        "${{ inputs.candidate_run_id }}"
    );
    assert!(reuse["with"]["candidate-source-sha"].is_null());
    assert!(steps.iter().any(|step| {
        step["name"] == "Require the exact source-bound candidate artifact"
            && step["if"] == "steps.candidate.outputs.reused != 'true'"
    }));

    let prepare = steps
        .iter()
        .find(|step| step["name"] == "Prepare a fixed Securefix source artifact")
        .unwrap();
    assert_eq!(prepare["if"], "inputs.operation == 'securefix'");
    assert_eq!(
        prepare["env"]["SOURCE_BRANCH"],
        "${{ github.event.pull_request.head.ref }}"
    );
    let capture_request = steps
        .iter()
        .find(|step| step["name"] == "Capture the exact pull request Securefix request")
        .unwrap();
    assert_eq!(
        capture_request["env"]["SOURCE_ARTIFACT_NAME"],
        "${{ steps.source.outputs.artifact_name }}"
    );
    let capture_approval = steps
        .iter()
        .find(|step| step["name"] == "Capture the exact pull request approval request")
        .unwrap();
    assert_eq!(capture_approval["if"], "inputs.operation == 'approval'");
    assert_eq!(
        capture_approval["env"]["SECUREFIX_CALLER_WORKFLOW_SHA"],
        "${{ github.workflow_sha }}"
    );
    assert!(
        capture_approval["run"]
            .as_str()
            .unwrap()
            .contains("securefix new-client approve capture")
    );
    let capture_merge = steps
        .iter()
        .find(|step| step["name"] == "Capture the exact pull request merge request")
        .unwrap();
    assert_eq!(capture_merge["if"], "inputs.operation == 'merge'");
    assert_eq!(
        capture_merge["env"]["SECUREFIX_CALLER_WORKFLOW_SHA"],
        "${{ github.workflow_sha }}"
    );
    assert!(
        capture_merge["run"]
            .as_str()
            .unwrap()
            .contains("securefix new-client merge capture")
    );
}

#[test]
fn native_policy_check_authority_validates_before_its_checks_only_writer() {
    const CONFIG_PATH: &str = "repo-settings/native-securefix-test-instance.toml";
    const WORKFLOW_PATH: &str = ".github/workflows/testing-native-policy-check-authority.yml";

    let config =
        securefix::instance_config::InstanceConfig::parse(&fs::read(CONFIG_PATH).unwrap()).unwrap();
    assert_eq!(
        config
            .workflow_roles
            .get(&securefix::instance_config::WorkflowRole::PolicyCheck)
            .map(String::as_str),
        Some(WORKFLOW_PATH)
    );
    let wrapper = workflow("testing-native-policy-check-authority.yml");
    let approval_wrapper = workflow("testing-native-approve.yml");
    let approval_loader = approval_wrapper["jobs"]["validate-request"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| {
            step["uses"]
                == "civitaspo/securefix-server/.github/actions/load-package@61fd0f85f2d02c78d333dbfcbf7848a1572e4f6d"
        })
        .unwrap();
    let inputs = &wrapper["on"]["workflow_dispatch"]["inputs"];
    assert_eq!(inputs["producer_run_id"]["required"], true);
    assert_eq!(inputs["package_publication_json"]["required"], true);
    assert_eq!(wrapper["permissions"], serde_json::json!({}));

    let jobs = wrapper["jobs"].as_object().unwrap();
    assert_eq!(jobs.len(), 2);
    for (name, job) in jobs {
        let guard = job["if"].as_str().unwrap();
        for condition in [
            "github.repository == 'civitaspo/securefix-server'",
            "github.ref == 'refs/heads/main'",
            "github.actor_id == '4525500'",
            "github.run_attempt == 1",
            "github.sha == github.workflow_sha",
        ] {
            assert!(guard.contains(condition), "{name}: missing {condition}");
        }
        assert_eq!(job["environment"], "main", "{name}");
        assert_eq!(
            job["permissions"],
            serde_json::json!({
                "actions": "read",
                "attestations": "read",
                "contents": "read",
                "pull-requests": "read"
            }),
            "{name}"
        );
        let steps = jobs[name]["steps"].as_array().unwrap();
        let package_loader = steps
            .iter()
            .find(|step| {
                step["uses"]
                    == "civitaspo/securefix-server/.github/actions/load-package@61fd0f85f2d02c78d333dbfcbf7848a1572e4f6d"
            })
            .unwrap();
        assert_eq!(
            package_loader["with"],
            serde_json::json!({"token":"${{ github.token }}"})
        );
        assert_eq!(package_loader["with"], approval_loader["with"]);

        if name == "validate-request" {
            assert!(steps.iter().any(|step| {
                step["run"] == "securefix new-server instance-policy-check-run --help"
            }));
            assert_eq!(
                steps
                    .iter()
                    .filter(|step| step["uses"] == package_loader["uses"])
                    .count(),
                1
            );
            let loader_index = steps
                .iter()
                .position(|step| step["uses"] == package_loader["uses"])
                .unwrap();
            let reader_index = steps
                .iter()
                .position(|step| step["id"] == "scratch-reader")
                .unwrap();
            assert!(loader_index < reader_index);
            if name == "validate-request" {
                let help_index = steps
                    .iter()
                    .position(|step| {
                        step["run"] == "securefix new-server instance-policy-check-run --help"
                    })
                    .unwrap();
                let validate_index = steps
                .iter()
                .position(|step| {
                    step["name"]
                        == "Validate the attested request and current authority without a writer token"
                })
                .unwrap();
                assert!(
                    loader_index < help_index
                        && help_index < reader_index
                        && reader_index < validate_index
                );
            }
        }
        let command = steps
            .iter()
            .find(|step| {
                step["run"].as_str().is_some_and(|run| {
                    run.contains("instance-policy-check-run") && run.contains("--producer-run-id")
                })
            })
            .unwrap();
        let run = command["run"].as_str().unwrap();
        assert!(run.contains("--config-path repo-settings/native-securefix-test-instance.toml"));
        assert!(run.contains("--producer-repository civitaspo/testing-securefix-server"));
        assert!(run.contains("--owner-selected-test-package"));
        assert_eq!(
            command["env"]["SECUREFIX_NATIVE_SCRATCH_PACKAGE_PUBLICATION_JSON"],
            "${{ inputs.package_publication_json }}"
        );
        assert_eq!(
            command["env"]["SECUREFIX_CLIENT_TOKEN"],
            "${{ steps.scratch-reader.outputs.token }}"
        );
        assert_eq!(command["env"]["SECUREFIX_APPROVE_TOKEN"], Value::Null);
        assert_eq!(command["env"]["SECUREFIX_NATIVE_MERGE_TOKEN"], Value::Null);
        assert_eq!(command["env"]["SECUREFIX_WRITE_TOKEN"], Value::Null);
    }

    let validate = jobs["validate-request"]["steps"].as_array().unwrap();
    assert!(validate.iter().all(|step| {
        step["env"]["SECUREFIX_NATIVE_CHECK_TOKEN"].is_null()
            && step["with"]["permission-checks"] != "write"
    }));
    let validate_command = validate
        .iter()
        .find(|step| {
            step["name"]
                == "Validate the attested request and current authority without a writer token"
        })
        .unwrap();
    assert!(
        !validate_command["run"]
            .as_str()
            .unwrap()
            .contains("--publish")
    );

    let publish = jobs["publish-check"]["steps"].as_array().unwrap();
    let writer = publish
        .iter()
        .find(|step| step["id"] == "check-writer")
        .unwrap();
    assert_eq!(writer["with"]["permission-checks"], "write");
    assert_eq!(writer["with"]["permission-contents"], Value::Null);
    assert_eq!(writer["with"]["permission-pull-requests"], Value::Null);
    let publish_command = publish
        .iter()
        .find(|step| step["name"] == "Revalidate and publish the exact-head policy check")
        .unwrap();
    assert!(
        publish_command["run"]
            .as_str()
            .unwrap()
            .contains("--publish")
    );
    assert_eq!(
        publish_command["env"]["SECUREFIX_NATIVE_CHECK_TOKEN"],
        "${{ steps.check-writer.outputs.token }}"
    );
    assert!(publish.iter().all(|step| {
        step["with"]["permission-contents"] != "write"
            && step["with"]["permission-pull-requests"] != "write"
    }));
}

#[test]
fn native_approval_uses_the_fixed_package_and_keeps_the_user_token_in_one_protected_step() {
    const CONFIG_PATH: &str = "repo-settings/native-securefix-test-instance.toml";
    const WORKFLOW_PATH: &str = ".github/workflows/testing-native-approve.yml";

    let config_bytes = fs::read(CONFIG_PATH).unwrap();
    let config = securefix::instance_config::InstanceConfig::parse(&config_bytes).unwrap();
    assert_eq!(
        config
            .workflow_roles
            .get(&securefix::instance_config::WorkflowRole::Approve)
            .map(String::as_str),
        Some(WORKFLOW_PATH)
    );
    let scratch = config
        .repositories
        .iter()
        .find(|repository| repository.repository == "civitaspo/testing-securefix-server")
        .unwrap();
    assert!(
        scratch
            .capabilities
            .contains(&crate::policy::Capability::Approve)
    );

    let wrapper = workflow("testing-native-approve.yml");
    assert!(wrapper["on"]["workflow_dispatch"].is_object());
    let jobs = wrapper["jobs"].as_object().unwrap();
    assert_eq!(jobs.len(), 2);
    assert!(!jobs.contains_key("build-host"));
    for (name, job) in jobs {
        let guard = job["if"].as_str().unwrap();
        for condition in [
            "github.repository == 'civitaspo/securefix-server'",
            "github.ref == 'refs/heads/main'",
            "github.actor_id == '4525500'",
            "github.run_attempt == 1",
            "github.sha == github.workflow_sha",
        ] {
            assert!(guard.contains(condition), "{name}: missing {condition}");
        }
        assert_eq!(job["environment"], "main", "{name}");
    }

    for job_name in ["validate-request", "apply-approval"] {
        let steps = jobs[job_name]["steps"].as_array().unwrap();
        let package = steps
            .iter()
            .find(|step| {
                step["uses"]
                    == "civitaspo/securefix-server/.github/actions/load-package@61fd0f85f2d02c78d333dbfcbf7848a1572e4f6d"
            })
            .unwrap();
        assert_eq!(package["name"], "Load the fixed immutable scratch package");
        assert_eq!(
            package["with"],
            serde_json::json!({"token":"${{ github.token }}"})
        );

        assert!(!steps.iter().any(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/download-artifact@"))
        }));
        assert!(steps.iter().any(|step| {
            step["run"]
                .as_str()
                .is_some_and(|run| run.contains("securefix new-server approval"))
        }));
    }

    let validate_steps = jobs["validate-request"]["steps"].as_array().unwrap();
    assert!(validate_steps.iter().all(|step| {
        step["env"]["SECUREFIX_APPROVE_TOKEN"].is_null()
            && step["env"]["CIVITASPO_BOT_PR_APPROVE_TOKEN"].is_null()
    }));
    let apply_steps = jobs["apply-approval"]["steps"].as_array().unwrap();
    let credential_steps = apply_steps
        .iter()
        .filter(|step| {
            step["env"]["SECUREFIX_APPROVE_TOKEN"]
                == "${{ secrets.CIVITASPO_BOT_PR_APPROVE_TOKEN }}"
        })
        .collect::<Vec<_>>();
    assert_eq!(credential_steps.len(), 1);
    assert_eq!(
        credential_steps[0]["name"],
        "Apply the current-head approval with the trusted Bot credential"
    );
    assert!(
        credential_steps[0]["run"]
            .as_str()
            .unwrap()
            .contains("--apply")
    );
    assert!(apply_steps.iter().any(|step| {
        step["name"] == "Independently read back the exact reviewer decision"
            && step["run"].as_str().is_some_and(|run| {
                run.contains("Cache-Control: no-cache")
                    && run.contains("for attempt in {1..5}")
                    && run.contains("no second review was submitted")
                    && !run.contains("--apply")
            })
    }));
    assert!(
        apply_steps
            .iter()
            .all(|step| { step["with"]["permission-pull-requests"] != "write" })
    );
}

#[test]
fn native_merge_host_pairs_proofs_and_limits_writes_to_one_scratch_merge() {
    const CONFIG_PATH: &str = "repo-settings/native-securefix-test-instance.toml";
    const WORKFLOW_PATH: &str = ".github/workflows/testing-native-merge.yml";

    let config =
        securefix::instance_config::InstanceConfig::parse(&fs::read(CONFIG_PATH).unwrap()).unwrap();
    assert_eq!(
        config
            .workflow_roles
            .get(&securefix::instance_config::WorkflowRole::Merge)
            .map(String::as_str),
        Some(WORKFLOW_PATH)
    );
    assert_eq!(
        config
            .workflow_roles
            .get(&securefix::instance_config::WorkflowRole::PolicyCheck)
            .map(String::as_str),
        Some(".github/workflows/testing-native-policy-check-authority.yml")
    );
    let scratch = config
        .repositories
        .iter()
        .find(|repository| repository.repository == "civitaspo/testing-securefix-server")
        .unwrap();
    assert!(
        scratch
            .capabilities
            .contains(&crate::policy::Capability::Merge)
    );

    let wrapper = workflow("testing-native-merge.yml");
    assert!(wrapper["on"]["workflow_dispatch"].is_object());
    let publication_description =
        wrapper["on"]["workflow_dispatch"]["inputs"]["package_publication_json"]["description"]
            .as_str()
            .unwrap();
    for field in [
        "source_sha",
        "source_branch",
        "tag",
        "release_id",
        "asset_id",
        "asset_sha256",
        "asset_size",
        "producer_run_id",
        "producer_run_attempt",
    ] {
        assert!(publication_description.contains(field), "missing {field}");
    }
    assert!(!publication_description.contains("publisher_workflow"));
    let jobs = wrapper["jobs"].as_object().unwrap();
    for (name, job) in jobs {
        let guard = job["if"].as_str().unwrap();
        for condition in [
            "github.repository == 'civitaspo/securefix-server'",
            "github.ref == 'refs/heads/main'",
            "github.actor_id == '4525500'",
            "github.run_attempt == 1",
        ] {
            assert!(guard.contains(condition), "{name}: missing {condition}");
        }
        if name != "build-host" {
            assert_eq!(job["environment"], "main", "{name}");
        }
    }

    let build_steps = jobs["build-host"]["steps"].as_array().unwrap();
    assert!(build_steps.iter().any(|step| {
        step["with"]["ref"] == "${{ github.workflow_sha }}"
            && step["with"]["persist-credentials"] == false
    }));
    assert!(build_steps.iter().any(|step| {
        step["name"] == "Build the protected merge host without secrets"
            && step["run"] == "cargo +1.99.0 build --locked --bin securefix"
    }));
    assert!(build_steps.iter().any(|step| {
        step["id"] == "host"
            && step["with"]["path"] == "target/debug/securefix"
            && step["with"]["retention-days"] == 1
    }));
    for job_name in ["validate-request", "apply-merge"] {
        let steps = jobs[job_name]["steps"].as_array().unwrap();
        assert!(steps.iter().any(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/download-artifact@"))
                && step["with"]["artifact-ids"] == "${{ needs.build-host.outputs.artifact-id }}"
        }));
        assert!(steps.iter().any(|step| {
            step["name"] == "Verify the protected host handoff"
                && step["env"]["EXPECTED_SHA256"] == "${{ needs.build-host.outputs.binary-sha256 }}"
                && step["run"]
                    .as_str()
                    .is_some_and(|run| run.contains("sha256sum --check"))
        }));
        assert!(steps.iter().any(|step| {
            step["run"]
                .as_str()
                .is_some_and(|run| run.contains("$RUNNER_TEMP/native-merge-host/securefix"))
        }));
    }

    let validate_steps = jobs["validate-request"]["steps"].as_array().unwrap();
    let validate = validate_steps
        .iter()
        .find(|step| step["name"] == "Validate both exact-head proofs without merge credentials")
        .unwrap();
    assert!(
        validate["run"]
            .as_str()
            .unwrap()
            .contains("--approval-producer-run-id")
    );
    assert!(!validate["run"].as_str().unwrap().contains("--apply"));
    assert!(
        validate_steps
            .iter()
            .all(|step| { step["env"]["SECUREFIX_NATIVE_MERGE_TOKEN"].is_null() })
    );

    let apply_steps = jobs["apply-merge"]["steps"].as_array().unwrap();
    let write_credentials = apply_steps
        .iter()
        .filter(|step| {
            step["id"] == "scratch-merge-writer"
                && step["with"]["permission-contents"] == "write"
                && step["with"]["permission-pull-requests"] == "write"
                && step["with"]["repositories"] == "testing-securefix-server"
        })
        .collect::<Vec<_>>();
    assert_eq!(write_credentials.len(), 1);
    let apply = apply_steps
        .iter()
        .find(|step| {
            step["name"] == "Apply the attested current-head merge with the scratch Server App"
        })
        .unwrap();
    assert_eq!(
        apply["env"]["SECUREFIX_NATIVE_MERGE_TOKEN"],
        "${{ steps.scratch-merge-writer.outputs.token }}"
    );
    assert!(apply["run"].as_str().unwrap().contains("--apply"));
    assert!(apply_steps.iter().any(|step| {
        step["name"] == "Independently read back the merged PR state"
            && step["run"].as_str().is_some_and(|run| {
                run.contains("Cache-Control: no-cache")
                    && run.contains(".merged == true")
                    && run.contains(".head == $head")
                    && run.contains(".merge_commit == $merge")
            })
    }));
    assert!(
        !serde_yaml::to_string(&wrapper)
            .unwrap()
            .contains("Administration")
    );
}

#[test]
fn native_policy_check_authority_host_revalidates_before_one_check_write() {
    const CONFIG_PATH: &str = "repo-settings/native-securefix-test-instance.toml";
    const WORKFLOW_PATH: &str = ".github/workflows/testing-native-policy-check-authority.yml";

    let config =
        securefix::instance_config::InstanceConfig::parse(&fs::read(CONFIG_PATH).unwrap()).unwrap();
    assert_eq!(
        config
            .workflow_roles
            .get(&securefix::instance_config::WorkflowRole::PolicyCheck)
            .map(String::as_str),
        Some(WORKFLOW_PATH)
    );

    let workflow = workflow("testing-native-policy-check-authority.yml");
    assert!(workflow["on"]["workflow_dispatch"]["inputs"]["producer_run_id"]["required"] == true);
    let publication_input =
        &workflow["on"]["workflow_dispatch"]["inputs"]["package_publication_json"];
    assert!(publication_input["required"] == true);
    assert_eq!(publication_input["type"], "string");
    assert!(workflow["on"].get("pull_request_target").is_none());
    let jobs = workflow["jobs"].as_object().unwrap();
    assert_eq!(jobs.len(), 2);
    for (name, job) in jobs {
        let guard = job["if"].as_str().unwrap();
        for condition in [
            "github.repository == 'civitaspo/securefix-server'",
            "github.ref == 'refs/heads/main'",
            "github.actor_id == '4525500'",
            "github.run_attempt == 1",
            "github.sha == github.workflow_sha",
        ] {
            assert!(guard.contains(condition), "{name}: missing {condition}");
        }
        assert_eq!(job["environment"], "main", "{name}");
        assert_eq!(job["permissions"]["actions"], "read");
        assert_eq!(job["permissions"]["contents"], "read");
    }

    let validate = &jobs["validate-request"];
    let validate_steps = validate["steps"].as_array().unwrap();
    let validate_command = validate_steps
        .iter()
        .find(|step| {
            step["name"]
                == "Validate the attested request and current authority without a writer token"
        })
        .unwrap();
    let validate_run = validate_command["run"].as_str().unwrap();
    assert!(validate_run.contains("new-server instance-policy-check-run"));
    assert!(validate_run.contains("--owner-selected-test-package"));
    assert!(!validate_run.contains("--publish"));
    assert!(
        validate_command["env"]
            .get("SECUREFIX_NATIVE_CHECK_TOKEN")
            .is_none()
    );
    assert!(
        validate_command["env"]
            .get("SECUREFIX_APPROVE_TOKEN")
            .is_none()
    );
    let reader = validate_steps
        .iter()
        .find(|step| step["id"] == "scratch-reader")
        .unwrap();
    assert_eq!(reader["with"]["permission-actions"], "read");
    assert_eq!(reader["with"]["permission-contents"], "read");
    assert_eq!(reader["with"]["permission-pull-requests"], "read");
    assert!(reader["with"].get("permission-checks").is_none());

    let publish = &jobs["publish-check"];
    let publish_steps = publish["steps"].as_array().unwrap();
    let publish_preflight = publish_steps
        .iter()
        .find(|step| {
            step["name"]
                == "Validate the owner-selected policy request before minting a check writer"
        })
        .unwrap();
    let publish_preflight_run = publish_preflight["run"].as_str().unwrap();
    assert!(publish_preflight_run.contains("new-server instance-policy-check-run"));
    assert!(publish_preflight_run.contains("--owner-selected-test-package"));
    assert!(!publish_preflight_run.contains("--publish"));
    assert!(
        publish_preflight["env"]
            .get("SECUREFIX_NATIVE_CHECK_TOKEN")
            .is_none()
    );
    assert!(
        publish_preflight["env"]
            .get("SECUREFIX_APPROVE_TOKEN")
            .is_none()
    );
    let writer = publish_steps
        .iter()
        .find(|step| step["id"] == "check-writer")
        .unwrap();
    assert_eq!(writer["with"]["permission-checks"], "write");
    let preflight_index = publish_steps
        .iter()
        .position(|step| step["name"] == publish_preflight["name"])
        .unwrap();
    let writer_index = publish_steps
        .iter()
        .position(|step| step["id"] == "check-writer")
        .unwrap();
    let publish_index = publish_steps
        .iter()
        .position(|step| step["name"] == "Revalidate and publish the exact-head policy check")
        .unwrap();
    assert!(preflight_index < writer_index && writer_index < publish_index);
    for permission in [
        "permission-actions",
        "permission-contents",
        "permission-pull-requests",
    ] {
        assert!(
            writer["with"].get(permission).is_none(),
            "unexpected {permission}"
        );
    }
    let publish_command = publish_steps
        .iter()
        .find(|step| step["name"] == "Revalidate and publish the exact-head policy check")
        .unwrap();
    assert!(
        publish_command["run"]
            .as_str()
            .unwrap()
            .contains("--publish")
    );
    assert!(
        publish_command["env"]
            .get("SECUREFIX_NATIVE_CHECK_TOKEN")
            .is_some()
    );
    assert!(
        publish_command["env"]
            .get("SECUREFIX_APPROVE_TOKEN")
            .is_none()
    );

    for job in jobs.values() {
        let steps = job["steps"].as_array().unwrap();
        let loader = steps
            .iter()
            .find(|step| step["name"] == "Load the exact verified scratch package")
            .unwrap();
        assert_eq!(
            loader["with"],
            serde_json::json!({"token":"${{ github.token }}"})
        );
    }
}

#[test]
fn native_securefix_test_wrapper_mints_the_configured_single_repo_app_token() {
    const CONFIG_PATH: &str = "repo-settings/native-securefix-test-instance.toml";
    const WORKFLOW_PATH: &str = ".github/workflows/testing-native-securefix-server.yml";

    let config_bytes = fs::read(CONFIG_PATH).unwrap();
    let config = securefix::instance_config::InstanceConfig::parse(&config_bytes).unwrap();
    assert_eq!(config.instance.repository, "civitaspo/securefix-server");
    assert_eq!(config.instance.default_branch, "main");
    assert_eq!(config.apps.server_id, 3_872_533);
    assert_eq!(
        config
            .workflow_roles
            .get(&securefix::instance_config::WorkflowRole::Securefix)
            .map(String::as_str),
        Some(WORKFLOW_PATH)
    );
    let scratch = config
        .repositories
        .iter()
        .find(|repository| {
            repository
                .capabilities
                .contains(&crate::policy::Capability::Securefix)
        })
        .unwrap();
    assert_eq!(scratch.repository, "civitaspo/testing-securefix-server");
    assert_eq!(scratch.id, 1_410_312_556);

    let wrapper = workflow("testing-native-securefix-server.yml");
    assert!(wrapper["on"]["workflow_dispatch"].is_object());
    let apply = &wrapper["jobs"]["apply"];
    for condition in [
        "github.repository == 'civitaspo/securefix-server'",
        "github.ref == 'refs/heads/main'",
        "github.actor_id == '4525500'",
        "github.run_attempt == 1",
    ] {
        assert!(apply["if"].as_str().unwrap().contains(condition));
    }
    assert_eq!(apply["environment"], "main");

    let steps = apply["steps"].as_array().unwrap();
    let mint = steps.iter().find(|step| step["id"] == "server").unwrap();
    let action = mint["uses"].as_str().unwrap();
    assert!(action.starts_with("actions/create-github-app-token@"));
    assert_eq!(action.rsplit_once('@').unwrap().1.len(), 40);
    assert_eq!(mint["with"]["app-id"], config.apps.server_id.to_string());
    assert_eq!(
        mint["with"]["private-key"],
        "${{ secrets.SECUREFIX_SERVER_PRIVATE_KEY }}"
    );
    assert_eq!(mint["with"]["owner"], "civitaspo");
    assert_eq!(mint["with"]["repositories"], "testing-securefix-server");
    assert_eq!(mint["with"]["permission-actions"], "read");
    assert_eq!(mint["with"]["permission-contents"], "write");
    assert_eq!(mint["with"]["permission-pull-requests"], "read");

    let execute = steps
        .iter()
        .find(|step| step["name"] == "Execute the selected source-bound Securefix request")
        .unwrap();
    assert_eq!(
        execute["env"]["SECUREFIX_CLIENT_TOKEN"],
        "${{ steps.server.outputs.token }}"
    );
    assert_eq!(
        execute["env"]["SECUREFIX_WRITE_TOKEN"],
        "${{ steps.server.outputs.token }}"
    );
    assert_eq!(execute["env"]["GITHUB_TOKEN"], "${{ github.token }}");
}

#[test]
fn verified_runtime_loading_and_publishing_keep_credentials_separate() {
    let loader = workflow("load-cli.yml");
    let load = &loader["jobs"]["load"];
    assert!(loader["on"].get("workflow_dispatch").is_none());
    assert_eq!(
        loader["defaults"]["run"]["shell"], "bash -euo pipefail {0}",
        "failed release fetch or attestation verification must stop the loader"
    );
    assert_eq!(
        load["permissions"],
        serde_json::json!({
            "actions":"read", "contents":"read", "attestations":"read"
        })
    );
    let steps = load["steps"].as_array().unwrap();
    assert_eq!(steps[0]["uses"], "$/.github/actions/load-runtime");
    assert!(steps[0]["with"].get("source-sha").is_none());
    assert_eq!(steps[0]["with"]["repository"], "civitaspo/securefix-server");
    assert_eq!(
        loader["on"]["workflow_call"]["outputs"]["source-sha"]["value"],
        "${{ jobs.load.outputs.source-sha }}"
    );
    assert_eq!(
        load["outputs"]["source-sha"],
        "${{ steps.runtime.outputs.source-sha }}"
    );
    assert_eq!(
        load["outputs"]["control-id"],
        "${{ steps.runtime.outputs.control-id }}"
    );
    assert_eq!(load["outputs"]["workflow-sha"], "${{ job.workflow_sha }}");
    assert_eq!(
        loader["on"]["workflow_call"]["outputs"]["control-id"]["value"],
        "${{ jobs.load.outputs.control-id }}"
    );
    assert_eq!(
        load["outputs"]["artifact-id"],
        "${{ steps.upload.outputs.artifact-id }}"
    );
    let upload = steps
        .iter()
        .position(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|value| value.starts_with("actions/upload-artifact@"))
        })
        .unwrap();
    assert_eq!(
        steps[upload]["with"]["path"],
        "${{ steps.runtime.outputs.directory }}/"
    );
    let action: Value =
        serde_yaml::from_slice(&fs::read(".github/actions/load-runtime/action.yml").unwrap())
            .unwrap();
    let load_text = format!("{load}{action}");
    for forbidden in [
        "secrets.",
        "actions/checkout",
        "setup-cli",
        "cargo ",
        "rustup ",
    ] {
        assert!(
            !load_text.contains(forbidden),
            "loader contains {forbidden}"
        );
    }
    assert_eq!(steps[upload]["with"]["retention-days"], 1);
    assert!(steps[0].get("if").is_none());
    assert_ne!(steps[0]["continue-on-error"], true);
    assert!(action["runs"]["steps"][0].get("if").is_none());
    assert_ne!(action["runs"]["steps"][0]["continue-on-error"], true);
    let script = fs::read_to_string(".github/actions/load-runtime/load.sh").unwrap();
    assert_eq!(
        action["runs"]["steps"][0]["run"],
        "bash \"$ACTION_PATH/load.sh\""
    );
    assert_eq!(
        action["runs"]["steps"][0]["env"]["ACTION_PATH"],
        "${{ github.action_path }}"
    );
    for required in [
        "control/active.json?ref=$main_sha",
        "actions/runs/$publisher_run_id",
        "releases/$release_id",
        "releases/assets/$asset_id",
        ".immutable",
        "archive_sha256",
        "-le 16384",
        "control-id",
        "gh attestation verify",
        "--repo \"$REPOSITORY\"",
        "--source-digest \"$source_sha\"",
        "--source-ref \"refs/heads/$DEFAULT_BRANCH\"",
        "--signer-workflow \"$signer_workflow\"",
        "control-bootstrap.yml@refs/heads/$DEFAULT_BRANCH",
        "publisher_run_id",
        "--signer-digest \"$source_sha\"",
        "--cert-oidc-issuer https://token.actions.githubusercontent.com",
        "--predicate-type https://slsa.dev/provenance/v1",
        "--deny-self-hosted-runners",
        "tar -xzf",
        "runtime verify --source-sha",
    ] {
        assert!(
            script.contains(required),
            "shared runtime loader lacks {required}"
        );
    }
    let attestation = script.find("gh attestation verify").unwrap();
    let extraction = script.find("tar -xzf").unwrap();
    let verify_runtime = script.find("runtime verify --source-sha").unwrap();
    assert!(attestation < extraction && extraction < verify_runtime);
    assert!(
        !script.contains("cargo ")
            && !script.contains("rustup ")
            && !script.contains("actions/checkout")
    );
    let client = fs::read_to_string(".github/actions/client/action.yml").unwrap();
    let client_action: Value = serde_yaml::from_slice(client.as_bytes()).unwrap();
    assert_eq!(client_action["inputs"]["control-repository"]["default"], "");
    let client_steps = client_action["runs"]["steps"].as_array().unwrap();
    let published_loader = client_steps
        .iter()
        .find(|step| step["id"] == "published-runtime")
        .unwrap();
    assert_eq!(published_loader["if"], "inputs.runtime-directory == ''");
    assert_eq!(
        published_loader["run"],
        "bash \"$ACTION_PATH/../load-runtime/load.sh\""
    );
    assert_eq!(
        published_loader["env"]["ACTION_PATH"],
        "${{ github.action_path }}"
    );
    assert_eq!(
        published_loader["env"]["SOURCE_SHA"],
        "${{ inputs.runtime-sha }}"
    );
    assert_eq!(
        published_loader["env"]["GH_TOKEN"],
        "${{ inputs.runtime-token || github.token }}"
    );
    assert_eq!(
        published_loader["env"]["CONTROL_REPOSITORY"],
        "${{ inputs.control-repository || inputs.runtime-repository || inputs.server-repository }}"
    );
    let shared_loader: Value =
        serde_yaml::from_slice(&fs::read(".github/actions/load-runtime/action.yml").unwrap())
            .unwrap();
    assert_eq!(
        shared_loader["runs"]["steps"][0]["env"]["CONTROL_REPOSITORY"],
        "${{ inputs.control-repository || inputs.repository }}"
    );
    let install_runtime = client_steps
        .iter()
        .find(|step| step["id"] == "runtime")
        .unwrap();
    assert_eq!(
        install_runtime["env"]["SECUREFIX_RUNTIME_SHA"],
        "${{ inputs.runtime-sha }}"
    );
    assert_eq!(
        install_runtime["env"]["VERIFIED_CONTROL_ID"],
        "${{ steps.published-runtime.outputs.control-id }}"
    );
    let prepare = client_steps
        .iter()
        .find(|step| step["id"] == "prepare")
        .unwrap();
    let dispatch = client_steps
        .iter()
        .find(|step| step["id"] == "dispatch")
        .unwrap();
    for step in [prepare, dispatch] {
        assert_eq!(
            step["env"]["SECUREFIX_SOURCE_SHA"],
            "${{ steps.runtime.outputs.source-sha }}"
        );
        assert_eq!(
            step["env"]["SECUREFIX_CONTROL_ID"],
            "${{ steps.runtime.outputs.control-id }}"
        );
        let script = step["run"].as_str().unwrap();
        assert!(script.contains("unset SECUREFIX_SOURCE_SHA"));
        assert!(script.contains("unset SECUREFIX_CONTROL_ID"));
    }
    assert_eq!(
        client_action["outputs"]["runtime-control-id"]["value"],
        "${{ steps.runtime.outputs.control-id }}"
    );
    let install_script = install_runtime["run"].as_str().unwrap();
    let candidate_branch = install_script
        .find("runtime_source=prebuilt-candidate")
        .unwrap();
    let published_branch = install_script
        .find("runtime_source=attested-release")
        .unwrap();
    let control_copy = install_script
        .find("install -m 644 \"$runtime_dir/control.json\" \"$bin_dir/control.json\"")
        .unwrap();
    assert!(candidate_branch < published_branch && published_branch < control_copy);
    assert!(install_script.contains("if [[ -n \"$control_id\" ]]; then"));
    assert!(client.contains("INPUT_RUNTIME_DIRECTORY"));
    assert!(client.contains("runtime_source=prebuilt-candidate"));
    assert!(client.contains("runtime_source=attested-release"));
    let ci = workflow("ci.yml");
    let ci_steps = ci["jobs"]["workflows"]["steps"].as_array().unwrap();
    let version_guard = ci_steps
        .iter()
        .position(|step| {
            step["name"] == "Require a runtime version bump over the pull request base"
        })
        .unwrap();
    let version_guard_run = ci_steps[version_guard]["run"].as_str().unwrap();
    assert!(version_guard_run.contains("git diff --name-only -z --no-renames"));
    assert!(version_guard_run.contains("runtime check-version"));
    assert!(version_guard_run.contains("--changed-files \"$changed_files\""));
    let build_cli = ci_steps
        .iter()
        .position(|step| step["id"] == "build-cli")
        .unwrap();
    let install_cli = ci_steps
        .iter()
        .position(|step| step["uses"] == "$/.github/actions/install-cli")
        .unwrap();
    assert!(build_cli < version_guard && version_guard < install_cli);

    let publisher = workflow("publish-runtime.yml");
    assert!(publisher["on"].get("workflow_dispatch").is_some());
    assert!(publisher["on"].get("push").is_none());
    assert_eq!(
        publisher["jobs"]["build"]["if"],
        "github.repository == 'civitaspo/securefix-server' && github.ref == 'refs/heads/main' && github.actor_id == '4525500'"
    );
    let build = &publisher["jobs"]["build"];
    assert_eq!(
        build["permissions"],
        serde_json::json!({
            "contents":"read", "id-token":"write", "attestations":"write"
        })
    );
    assert_eq!(
        build["outputs"]["source-sha"],
        "${{ steps.checkout.outputs.commit }}"
    );
    let build_text = serde_json::to_string(build).unwrap();
    assert!(!build_text.contains("secrets."));
    assert!(build_text.contains("$/.github/actions/setup-cli"));
    assert_eq!(
        build["outputs"]["artifact-id"],
        "${{ steps.upload.outputs.artifact-id }}"
    );
    let build_steps = build["steps"].as_array().unwrap();
    assert_eq!(
        build_steps
            .iter()
            .filter(|step| step["uses"] == "$/.github/actions/setup-cli")
            .count(),
        1,
        "the publisher validates and packages one source build"
    );
    assert!(build_steps.iter().any(|step| {
        step["with"]["repository"] == "civitaspo/securefix-server"
            && step["with"]["ref"] == "${{ job.workflow_sha }}"
            && step["with"]["persist-credentials"] == false
    }));
    let attest_steps = build_steps
        .iter()
        .filter(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/attest@"))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        attest_steps.len(),
        1,
        "exactly one archive subject is attested"
    );
    assert_eq!(
        attest_steps[0]["with"]["subject-path"],
        "distribution/securefix-runtime-linux-x86_64.tar.gz"
    );
    assert_eq!(attest_steps[0]["with"]["create-storage-record"], false);
    assert!(
        attest_steps[0]["with"]["subject-path"]
            .as_str()
            .unwrap()
            .ends_with(".tar.gz")
    );

    let controller = &publisher["jobs"]["controller"];
    assert_eq!(controller["uses"], "./.github/workflows/load-cli.yml");
    assert_eq!(controller["if"], build["if"]);
    assert_eq!(
        controller["permissions"],
        serde_json::json!({"actions":"read", "contents":"read", "attestations":"read"})
    );
    let publish = &publisher["jobs"]["publish"];
    assert_eq!(publish["needs"], serde_json::json!(["build", "controller"]));
    assert_eq!(
        publish["permissions"],
        serde_json::json!({"contents":"write", "attestations":"read"})
    );
    let publish_text = serde_json::to_string(publish).unwrap();
    for forbidden in ["id-token", "setup-cli", "actions/checkout"] {
        assert!(
            !publish_text.contains(forbidden),
            "publisher contains {forbidden}"
        );
    }
    assert_eq!(
        publish["env"]["SECUREFIX_SOURCE_SHA"],
        "${{ needs.controller.outputs.source-sha }}"
    );
    assert_eq!(
        publish["env"]["CANDIDATE_SOURCE_SHA"],
        "${{ needs.build.outputs.source-sha }}"
    );
    assert!(publish["steps"].as_array().unwrap().iter().any(|step| {
        step["uses"]
            .as_str()
            .is_some_and(|uses| uses.starts_with("actions/download-artifact@"))
            && step["with"]["artifact-ids"] == "${{ needs.build.outputs.artifact-id }}"
            && step["with"]["path"] == "distribution"
    }));
    let publish_steps = publish["steps"].as_array().unwrap();
    let publish_index = |predicate: &dyn Fn(&Value) -> bool| {
        publish_steps
            .iter()
            .position(predicate)
            .unwrap_or_else(|| panic!("required publisher step is missing"))
    };
    let downloaded = publish_index(&|step| {
        step["uses"].as_str().is_some_and(|uses| {
            uses.starts_with("actions/download-artifact@")
                && step["with"]["artifact-ids"] == "${{ needs.build.outputs.artifact-id }}"
        })
    });
    let verified = publish_index(&|step| {
        step["run"].as_str().is_some_and(|run| {
            run.contains("gh attestation verify distribution/securefix-runtime-linux-x86_64.tar.gz")
        })
    });
    let controller_downloaded = publish_index(&|step| {
        step["uses"].as_str().is_some_and(|uses| {
            uses.starts_with("actions/download-artifact@")
                && step["with"]["artifact-ids"] == "${{ needs.controller.outputs.artifact-id }}"
                && step["with"]["path"] == "${{ runner.temp }}/controller"
        })
    });
    let invoked = publish_index(&|step| {
        step["run"].as_str().is_some_and(|run| {
            run.contains("securefix runtime publish --source-sha \"$CANDIDATE_SOURCE_SHA\" --archive distribution/securefix-runtime-linux-x86_64.tar.gz")
        })
    });
    let installed = publish_index(&|step| step["uses"] == "$/.github/actions/install-cli");
    assert!(
        downloaded < controller_downloaded
            && controller_downloaded < verified
            && verified < installed
            && installed < invoked
    );
    assert!(publish_steps.iter().all(|step| {
        !step["uses"]
            .as_str()
            .is_some_and(|uses| uses.starts_with("actions/create-github-app-token@"))
    }));
    assert!(publish_steps[invoked]["env"].is_null());
    assert_eq!(
        publish_steps[installed]["with"]["binary"],
        "${{ runner.temp }}/controller/securefix"
    );
    assert!(
        publish_steps.iter().all(|step| !step["run"]
            .as_str()
            .is_some_and(|run| run.contains("tar -xzf"))),
        "credentialed publication must not extract the candidate archive"
    );
    assert!(
        !publish_text.contains("candidate-runtime/securefix")
            && !publish_text.contains("$/.github/actions/setup-cli")
    );
    let verification = publish_steps[verified]["run"].as_str().unwrap();
    for required in [
        "--repo civitaspo/securefix-server",
        "--source-digest \"$CANDIDATE_SOURCE_SHA\"",
        "--source-ref refs/heads/main",
        "--signer-workflow civitaspo/securefix-server/.github/workflows/publish-runtime.yml",
        "--signer-digest \"$CANDIDATE_SOURCE_SHA\"",
        "--cert-oidc-issuer https://token.actions.githubusercontent.com",
        "--predicate-type https://slsa.dev/provenance/v1",
        "--deny-self-hosted-runners",
    ] {
        assert!(
            verification.contains(required),
            "publisher missing attestation constraint: {required}"
        );
    }
    for index in [verified, invoked] {
        assert_ne!(publish_steps[index]["continue-on-error"], true);
        assert!(publish_steps[index].get("if").is_none());
    }
    let ci = workflow("ci.yml");
    let ci_build = &ci["jobs"]["workflows"];
    assert_eq!(
        ci_build["permissions"],
        serde_json::json!({"actions":"read","attestations":"read","contents":"read"})
    );
    assert!(
        !serde_json::to_string(ci_build)
            .unwrap()
            .contains("secrets.")
    );
    let mut setup_users = workflows()
        .into_iter()
        .flat_map(|(path, workflow)| {
            workflow["jobs"]
                .as_object()
                .cloned()
                .unwrap_or_default()
                .into_values()
                .filter_map(move |job| {
                    job["steps"].as_array().and_then(|steps| {
                        steps
                            .iter()
                            .any(|step| {
                                step["uses"].as_str().is_some_and(|uses| {
                                    uses.ends_with("/.github/actions/setup-cli")
                                })
                            })
                            .then(|| path.clone())
                    })
                })
        })
        .collect::<Vec<_>>();
    setup_users.sort();
    assert_eq!(
        setup_users,
        [
            ".github/workflows/ci.yml",
            ".github/workflows/control-bootstrap.yml",
            ".github/workflows/publish-runtime.yml",
            ".github/workflows/request-producer-probe.yml",
            ".github/workflows/testing-control-fixture.yml",
            ".github/workflows/testing-distribute-runtime.yml",
            ".github/workflows/testing-merge-caller-migration.yml",
            ".github/workflows/testing-migration-fixture.yml",
            ".github/workflows/testing-publish-runtime.yml",
            ".github/workflows/testing-release-pr.yml",
            ".github/workflows/testing-securefix-server.yml"
        ],
        "only approved source-bound workflows set up the CLI"
    );
    for (path, workflow) in workflows() {
        if matches!(
            path.as_str(),
            ".github/workflows/ci.yml"
                | ".github/workflows/publish-runtime.yml"
                | ".github/workflows/build-bootstrap-host.yml"
        ) {
            continue;
        }
        for (job_id, job) in workflow["jobs"].as_object().unwrap() {
            if path == ".github/workflows/testing-securefix-server.yml" && job_id == "build" {
                continue;
            }
            if path == ".github/workflows/publish-native-package.yml" && job_id == "host-build" {
                continue;
            }
            if path == ".github/workflows/testing-native-approve.yml" && job_id == "build-host" {
                continue;
            }
            if path == ".github/workflows/testing-native-merge.yml" && job_id == "build-host" {
                continue;
            }
            if path == ".github/workflows/testing-native-package-build.yml" && job_id == "build" {
                continue;
            }
            if path == ".github/workflows/native-package-build.yml" && job_id == "build" {
                continue;
            }
            if path == ".github/workflows/testing-publish-native-package.yml"
                && job_id == "host-build"
            {
                continue;
            }
            if path == ".github/workflows/testing-native-release-assets-publish.yml"
                && job_id == "host-build"
            {
                continue;
            }
            if path == ".github/workflows/testing-release-pr.yml" && job_id == "candidate-build" {
                continue;
            }
            if path == ".github/workflows/testing-provider-release.yml"
                && job_id == "compile-harness"
            {
                continue;
            }
            if path == ".github/workflows/testing-native-release-assets.yml"
                && matches!(job_id.as_str(), "compile-harness" | "build-native")
            {
                continue;
            }
            if (path == ".github/workflows/reusable-release-tag.yml"
                || path == ".github/workflows/testing-reusable-release-tag.yml")
                && job_id == "build-native"
            {
                continue;
            }
            for step in job["steps"].as_array().into_iter().flatten() {
                if let Some(run) = step["run"].as_str() {
                    assert!(
                        !run.contains("cargo ") && !run.contains("rustup "),
                        "{path}/{job_id}: operational jobs must load the published runtime"
                    );
                }
            }
        }
    }
    let setup = fs::read_to_string(".github/actions/setup-cli/action.yml").unwrap();
    assert!(setup.contains("build --locked --release"));
    assert!(!setup.contains("secrets."));
    let setup: Value = serde_yaml::from_str(&setup).unwrap();
    for step in setup["runs"]["steps"].as_array().unwrap() {
        if step["name"] == "Install Rust toolchain" || step["name"] == "Build CLI" {
            assert_eq!(step["working-directory"], "${{ github.workspace }}");
        }
    }
    assert_eq!(
        setup["runs"]["steps"][0]["run"],
        "bash \"$ACTION_PATH/reuse-build.sh\""
    );
    let reuse = fs::read_to_string(".github/actions/setup-cli/reuse-build.sh").unwrap();
    assert!(reuse.contains("root=\"$GITHUB_WORKSPACE\""));
    assert!(reuse.contains("$EVENT_NAME\" == pull_request_target"));
    assert!(reuse.contains("refusing to build locally"));
    let setup_text = serde_json::to_string(&setup).unwrap();
    assert!(setup_text.contains("inputs.candidate-run-id != ''"));
    assert!(setup_text.contains("steps.reuse.outputs.reused != 'true'"));
    let installer: Value =
        serde_yaml::from_slice(&fs::read(".github/actions/install-cli/action.yml").unwrap())
            .unwrap();
    let install = installer["runs"]["steps"][0]["run"].as_str().unwrap();
    assert!(install.contains("install -D -m 755"));
    assert!(install.contains("$GITHUB_PATH"));
    assert!(installer["inputs"].get("binary").is_some());
}

#[test]
fn testing_fixture_is_owner_guarded_and_never_executes_candidate_code_with_credentials() {
    let value = workflow("testing-migration-fixture.yml");
    for id in ["host", "fixture"] {
        let guard = value["jobs"][id]["if"].as_str().unwrap();
        assert!(guard.contains("refs/heads/main"));
        assert!(guard.contains("github.actor_id == '4525500'"));
        assert!(guard.contains("github.run_attempt == 1"));
    }
    assert!(
        !serde_json::to_string(&value["jobs"]["host"])
            .unwrap()
            .contains("secrets.")
    );
    let job = &value["jobs"]["fixture"];
    assert_eq!(job["environment"], "main");
    assert_eq!(job["concurrency"]["group"], "securefix-control");
    let steps = job["steps"].as_array().unwrap();
    let validate = steps
        .iter()
        .position(|s| {
            s["run"] == "securefix integration validate-testing-processor --kind migration-fixture"
        })
        .unwrap();
    for (index, step) in steps.iter().enumerate() {
        if step["uses"]
            .as_str()
            .is_some_and(|s| s.starts_with("actions/create-github-app-token@"))
        {
            assert!(validate < index);
            assert_eq!(step["with"]["repositories"], "testing-securefix-server");
        }
        if let Some(run) = step["run"].as_str() {
            assert!(!run.contains("/candidate/") && !run.contains("docker run"));
        }
        if step["env"].get("SECUREFIX_TEST_NONOWNER_TOKEN").is_some() {
            assert_eq!(step["if"], "inputs.case == 'nonowner-dispatch'");
            assert!(step["run"].as_str().unwrap().contains("testing-merge-caller-migration.yml/dispatches --input migration-nonowner-dispatch.json"));
        }
    }
}

#[test]
fn testing_distributor_reuses_normal_distribution_with_test_only_tokens() {
    let value = workflow("testing-distribute-runtime.yml");
    assert!(
        !serde_json::to_string(&value["jobs"]["host"])
            .unwrap()
            .contains("secrets.")
    );
    for id in ["host", "distribute"] {
        let guard = value["jobs"][id]["if"].as_str().unwrap();
        for clause in [
            "refs/heads/main",
            "github.actor_id == '4525500'",
            "github.run_attempt == 1",
        ] {
            assert!(guard.contains(clause));
        }
    }
    let job = &value["jobs"]["distribute"];
    assert_eq!(job["concurrency"]["group"], "securefix-control");
    let steps = job["steps"].as_array().unwrap();
    let preflight = steps
        .iter()
        .position(|s| {
            s["run"]
                == "securefix integration validate-testing-processor --kind caller-distribution"
        })
        .unwrap();
    let first_mint = steps.iter().position(|s| s["id"] == "read").unwrap();
    let prepare = steps
        .iter()
        .position(|s| s["name"] == "Validate publisher and prepare canonical test caller files")
        .unwrap();
    let writer = steps.iter().position(|s| s["id"] == "write").unwrap();
    assert!(preflight < first_mint && first_mint < prepare && prepare < writer);
    for step in steps {
        if step["uses"]
            .as_str()
            .is_some_and(|s| s.starts_with("actions/create-github-app-token@"))
        {
            assert_eq!(step["with"]["repositories"], "testing-securefix-server");
        }
    }
    let text = serde_json::to_string(job).unwrap();
    assert!(!text.contains("docker run"));
    assert!(text.contains("securefix distribute prepare-caller"));
    assert!(text.contains("securefix distribute apply-caller"));
    assert!(text.contains("steps.runtime.outputs.directory"));
}

#[test]
fn operational_lanes_use_the_active_control_and_keep_distribution_explicit() {
    for (name, loader_job, consumer_jobs) in [
        ("securefix.yml", "runtime", vec!["fix"]),
        ("approve.yml", "build", vec!["approve", "cleanup"]),
        (
            "merge.yml",
            "build",
            vec!["authorize", "wait", "apply", "cleanup"],
        ),
        ("policy-check.yml", "cli", vec!["request"]),
        ("merge-caller-migration.yml", "runtime", vec!["merge"]),
    ] {
        let value = workflow(name);
        let loader = &value["jobs"][loader_job];
        assert_eq!(loader["uses"], "./.github/workflows/load-cli.yml", "{name}");
        assert_eq!(loader["permissions"]["actions"], "read", "{name}");
        assert_eq!(loader["permissions"]["contents"], "read", "{name}");
        assert_eq!(loader["permissions"]["attestations"], "read", "{name}");
        for consumer_id in consumer_jobs {
            let consumer = &value["jobs"][consumer_id];
            assert_eq!(
                consumer["env"]["SECUREFIX_SOURCE_SHA"],
                format!("${{{{ needs.{loader_job}.outputs.source-sha }}}}"),
                "{name}/{consumer_id}: runtime source must come from active descriptor"
            );
            assert_eq!(
                consumer["env"]["SECUREFIX_CONTROL_ID"],
                format!("${{{{ needs.{loader_job}.outputs.control-id }}}}"),
                "{name}/{consumer_id}: control identity must come from active descriptor"
            );
        }
    }

    let merge = workflow("merge.yml");
    let wait = &merge["jobs"]["wait"];
    assert_eq!(wait["runs-on"], "ubuntu-latest");
    assert_eq!(wait["needs"], serde_json::json!(["build", "authorize"]));
    assert_eq!(wait["timeout-minutes"], 70);
    assert_eq!(wait["permissions"]["checks"], "read");
    assert_eq!(wait["permissions"]["statuses"], "read");
    for permission in ["contents", "issues", "pull-requests", "checks", "statuses"] {
        assert_ne!(
            wait["permissions"][permission], "write",
            "merge wait is read-only"
        );
    }
    assert!(
        wait["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| { step["run"] == "securefix merge wait" })
    );
    let apply = &merge["jobs"]["apply"];
    assert!(
        apply["needs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|job| job == "wait")
    );
    let merge_token = apply["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "merge-token")
        .unwrap();
    assert_eq!(merge_token["if"], "needs.wait.result == 'success'");

    let distribution = workflow("distribute-runtime.yml");
    let dispatch = &distribution["on"]["workflow_dispatch"]["inputs"]["publisher_run_id"];
    assert_eq!(dispatch["required"], true);
    assert!(distribution["on"].get("workflow_run").is_none());
    assert!(distribution["jobs"].get("caller").is_some());
    let publisher = workflow("publish-runtime.yml");
    assert!(publisher["on"].get("workflow_run").is_none());
    assert!(
        !serde_json::to_string(&publisher["jobs"]["publish"])
            .unwrap()
            .contains("distribute-runtime")
    );
}

#[test]
fn caller_migration_requires_read_validation_and_readiness_before_each_write_token() {
    let migration = workflow("merge-caller-migration.yml");
    assert_eq!(
        migration["jobs"]["merge"]["concurrency"]["group"],
        "securefix-control"
    );
    assert_eq!(migration["jobs"]["merge"]["concurrency"]["queue"], "max");
    let steps = migration["jobs"]["merge"]["steps"].as_array().unwrap();
    let target = steps.iter().position(|s| s["id"] == "target").unwrap();
    let read = steps.iter().position(|s| s["id"] == "read-token").unwrap();
    let prepare = steps
        .iter()
        .position(|s| {
            s["run"]
                .as_str()
                .is_some_and(|r| r.starts_with("securefix caller-migration prepare "))
        })
        .unwrap();
    let authorize = steps
        .iter()
        .position(|s| s["id"] == "authorization-token")
        .unwrap();
    let ready = steps
        .iter()
        .position(|s| s["run"] == "securefix caller-migration ready")
        .unwrap();
    let merge = steps.iter().position(|s| s["id"] == "merge-token").unwrap();
    assert!(
        target < read
            && read < prepare
            && prepare < authorize
            && authorize < ready
            && ready < merge
    );
    assert_eq!(steps[merge + 1]["run"], "securefix caller-migration merge");
    assert_eq!(steps[read]["with"]["permission-contents"], "read");
    assert!(
        steps[authorize]["with"]
            .get("permission-contents")
            .is_none()
    );
    assert_eq!(
        steps[authorize]["with"]["permission-pull-requests"],
        "write"
    );
    assert_eq!(steps[authorize]["with"]["permission-checks"], "write");
    assert_eq!(steps[authorize]["with"]["permission-issues"], "write");
    assert_eq!(
        steps[authorize]["with"]["repositories"],
        "${{ steps.target.outputs.repository_name }}"
    );
    assert_eq!(
        steps[merge]["with"]["repositories"],
        "${{ steps.target.outputs.repository_name }}"
    );
    assert!(steps.iter().all(|s| s["uses"] != "actions/checkout"));
    let source = fs::read_to_string("src/distribution.rs").unwrap();
    let production = source
        .split("Command::ApplyCaller {")
        .nth(1)
        .unwrap()
        .split("Command::ProbeCaller")
        .next()
        .unwrap();
    assert!(!production.contains("merge_runtime_update"));
}

#[test]
fn bootstrap_workflow_uses_fixed_host_code_and_serialized_main_authority() {
    let bootstrap = workflow("control-bootstrap.yml");
    assert_eq!(
        bootstrap["jobs"]["bootstrap-host"]["uses"],
        "./.github/workflows/build-bootstrap-host.yml"
    );
    let host_build = workflow("build-bootstrap-host.yml");
    let host_build = &host_build["jobs"]["build"];
    assert_eq!(
        host_build["permissions"],
        serde_json::json!({"contents":"read"})
    );
    let host_text = serde_json::to_string(host_build).unwrap();
    for forbidden in [
        "secrets.",
        "environment",
        "id-token",
        "attestations",
        "candidate-runtime",
        "create-github-app-token",
    ] {
        assert!(
            !host_text.contains(forbidden),
            "host build exposes {forbidden}"
        );
    }
    assert!(
        host_build["if"]
            .as_str()
            .unwrap()
            .contains("github.run_attempt == 1")
    );
    let build_steps = host_build["steps"].as_array().unwrap();
    assert_eq!(build_steps[0]["with"]["ref"], "${{ job.workflow_sha }}");
    let compile = build_steps
        .iter()
        .find(|step| step["env"]["SECUREFIX_BOOTSTRAP_SOURCE_SHA"].is_string())
        .unwrap();
    assert_eq!(
        compile["env"]["SECUREFIX_BOOTSTRAP_SOURCE_SHA"],
        "${{ job.workflow_sha }}"
    );
    assert_eq!(
        compile["run"],
        "cargo +1.99.0 build --locked --release --bin securefix-bootstrap"
    );
    for job_id in [
        "validate-proposal",
        "propose",
        "validate-merge",
        "merge",
        "repair-propose",
        "repair-merge",
    ] {
        let job = &bootstrap["jobs"][job_id];
        assert!(
            job["needs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|need| need == "bootstrap-host")
        );
        let steps = job["steps"].as_array().unwrap();
        let download = steps
            .iter()
            .position(|step| {
                step["with"]["artifact-ids"] == "${{ needs.bootstrap-host.outputs.artifact-id }}"
            })
            .unwrap();
        assert_eq!(steps[download]["with"]["path"], "bootstrap-host");
        let install = steps
            .iter()
            .position(|step| {
                step["run"].as_str().is_some_and(|run| {
                    run.contains("install -D -m 755 bootstrap-host/securefix-bootstrap")
                })
            })
            .unwrap();
        let invoke = steps
            .iter()
            .position(|step| {
                step["run"]
                    .as_str()
                    .is_some_and(|run| run.starts_with("\"$RUNNER_TEMP/securefix-bootstrap\" "))
            })
            .unwrap();
        assert!(download < install && install < invoke, "{job_id}");
    }
    for path in [
        "scripts/control-bootstrap.py",
        "scripts/test_control_bootstrap.py",
        "scripts/test_control_bootstrap_boundaries.py",
    ] {
        assert!(
            !std::path::Path::new(path).exists(),
            "bootstrap logic must stay in Rust: {path}"
        );
    }
    assert_eq!(
        bootstrap["concurrency"]["group"],
        "securefix-control-bootstrap"
    );
    let build = &bootstrap["jobs"]["build-candidate"];
    assert_eq!(
        build["permissions"],
        serde_json::json!({"contents":"read", "id-token":"write", "attestations":"write"})
    );
    assert_eq!(build["needs"], "baseline");
    assert!(
        build["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| { step["uses"] == "$/.github/actions/setup-cli" })
    );
    assert!(!serde_json::to_string(build).unwrap().contains("secrets."));
    let build_download = "${{ needs.build-candidate.outputs.artifact-id }}";
    for job_id in ["validate-proposal", "propose"] {
        assert!(
            bootstrap["jobs"][job_id]["steps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|step| step["with"]["artifact-ids"] == build_download),
            "{job_id} must consume the immutable candidate artifact ID"
        );
    }
    assert!(
        bootstrap["jobs"]["propose"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|step| step["with"]["artifact-ids"]
                == "${{ needs.validate-proposal.outputs.artifact-id }}")
    );

    for job_id in ["propose", "merge", "repair-propose", "repair-merge"] {
        let job = &bootstrap["jobs"][job_id];
        assert_eq!(job["environment"], "main", "{job_id}");
        assert_eq!(job["concurrency"]["group"], "securefix-control", "{job_id}");
        assert_eq!(job["concurrency"]["queue"], "max", "{job_id}");
        assert_eq!(job["concurrency"]["cancel-in-progress"], false, "{job_id}");
    }
    for job_id in ["propose", "merge", "repair-propose", "repair-merge"] {
        let job = &bootstrap["jobs"][job_id];
        for step in job["steps"].as_array().unwrap() {
            if step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/create-github-app-token@"))
            {
                assert_eq!(step["with"]["repositories"], "securefix-server", "{job_id}");
                assert!(
                    step["with"].get("permission-administration").is_none(),
                    "{job_id}"
                );
            }
        }
    }
    let propose = &bootstrap["jobs"]["propose"]["steps"];
    let propose = propose.as_array().unwrap();
    let writer = propose.iter().find(|step| step["id"] == "writer").unwrap();
    assert_eq!(writer["with"]["permission-contents"], "write");
    assert_eq!(writer["with"]["permission-pull-requests"], "write");

    let text = serde_json::to_string(&bootstrap).unwrap();
    assert!(!text.contains("candidate-runtime/securefix"));
    assert!(!text.contains("/candidate/securefix"));
    for (job_id, job) in bootstrap["jobs"].as_object().unwrap() {
        for step in job["steps"].as_array().into_iter().flatten() {
            if let Some(run) = step["run"].as_str() {
                assert!(
                    !run.contains("cargo ") && !run.contains("rustup "),
                    "{job_id}"
                );
            }
        }
    }
}

#[test]
fn initial_bootstrap_scratch_uses_a_fixed_host_for_outputs_and_pinned_legacy_baseline() {
    let testing = workflow("testing-securefix-server.yml");
    assert_eq!(
        testing["on"]["workflow_dispatch"]["inputs"]["phase"]["options"],
        serde_json::json!([
            "candidate-artifact",
            "prepare",
            "verify",
            "bootstrap",
            "provider",
            "release-assets",
            "managed-files"
        ])
    );
    let legacy = &testing["jobs"]["bootstrap-legacy-runtime"];
    let legacy_if = legacy["if"].as_str().unwrap();
    for guard in [
        "inputs.phase == 'bootstrap'",
        "github.ref == 'refs/heads/main'",
        "github.actor_id == '4525500'",
        "github.run_attempt == 1",
    ] {
        assert!(legacy_if.contains(guard));
    }
    let legacy_script = legacy["steps"][0]["run"].as_str().unwrap();
    for pin in [
        "v0.2.20",
        "414653308",
        "646481902",
        "1f0f991e766e287b1ff55cf8cbda05982c0ddb90295f988081bf5b85a480d96c",
        "gh attestation verify",
    ] {
        assert!(
            legacy_script.contains(pin),
            "bootstrap legacy runtime lacks {pin}"
        );
    }
    let scratch = &testing["jobs"]["bootstrap-scratch"];
    assert!(
        scratch["needs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|need| need == "bootstrap-legacy-runtime")
    );
    let steps = scratch["steps"].as_array().unwrap();
    let context = steps
        .iter()
        .position(|step| {
            step["name"] == "Validate current main and inactive descriptor before credentials"
        })
        .unwrap();
    let server_token = steps
        .iter()
        .position(|step| step["id"] == "server")
        .unwrap();
    let candidate_probe = steps
        .iter()
        .position(|step| {
            step["name"] == "Probe candidate control generation and CAS before approval"
        })
        .unwrap();
    assert!(context < server_token && server_token < candidate_probe);
    assert_eq!(scratch["environment"], "main");
    assert_eq!(
        steps[context]["run"],
        "\"$RUNNER_TEMP/securefix-bootstrap\" validate-legacy-context --source-sha \"$SOURCE_SHA\""
    );
    let server = steps.iter().find(|step| step["id"] == "server").unwrap();
    assert_eq!(server["with"]["repositories"], "testing-securefix-server");
    assert_eq!(server["with"]["permission-contents"], "write");
    let probe = steps[candidate_probe]["run"].as_str().unwrap();
    assert!(!probe.contains("docker run"));
    assert!(probe.contains("securefix integration control-probe"));
    assert!(steps[candidate_probe]["env"].get("GITHUB_TOKEN").is_none());
    assert!(steps[candidate_probe]["env"]["SECUREFIX_SERVER_APP_TOKEN"].is_string());

    let prepare = steps
        .iter()
        .position(|step| step["name"] == "Prepare scratch fixtures with the candidate runtime")
        .unwrap();
    let upload_control_probe = steps
        .iter()
        .position(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/upload-artifact@"))
                && step["with"]["name"] == "control-probe"
        })
        .unwrap();
    let upload_fixture_heads = steps
        .iter()
        .position(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/upload-artifact@"))
                && step["with"]["name"] == "bootstrap-fixture-heads"
        })
        .unwrap();
    let publish_proof = steps
        .iter()
        .position(|step| step["name"] == "Publish pre-approval scratch identities")
        .unwrap();
    let verify = steps
        .iter()
        .position(|step| {
            step["name"] == "Execute candidate verification against isolated scratch fixtures"
        })
        .unwrap();
    let upload_final = steps
        .iter()
        .position(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/upload-artifact@"))
                && step["with"]["name"] == "scratch-fixtures"
        })
        .unwrap();
    let validate_outputs = steps
        .iter()
        .position(|step| {
            step["name"] == "Validate scratch outputs with the fixed Rust bootstrap host"
        })
        .unwrap();
    assert!(verify < validate_outputs && validate_outputs < upload_final);
    let output_command = steps[validate_outputs]["run"].as_str().unwrap();
    assert!(
        output_command
            .starts_with("\"$RUNNER_TEMP/securefix-bootstrap\" validate-scratch-outputs ")
    );
    for argument in [
        "--source-sha \"$SOURCE_SHA\"",
        "--published-runtime-sha e8e2bc77d96a4e359417217f1d1c22f4e1ac4483",
        "--state-directory fixtures",
        "--probe-directory control-probe",
    ] {
        assert!(output_command.contains(argument));
    }
    assert!(!steps.iter().any(|step| {
        step["run"]
            .as_str()
            .is_some_and(|run| run.contains("securefix integration validate-outputs"))
    }));
    assert!(
        prepare < candidate_probe
            && candidate_probe < upload_control_probe
            && upload_control_probe < upload_fixture_heads
            && upload_fixture_heads < publish_proof
            && publish_proof < verify
            && verify < upload_final,
        "bootstrap proof identities must be available before verification waits for owner approval"
    );
    assert_eq!(
        steps[upload_control_probe]["with"]["path"],
        "control-probe/control-verification.json"
    );
    assert_eq!(
        steps[upload_fixture_heads]["with"]["path"],
        "fixtures/state.json"
    );
    assert_eq!(
        steps[upload_final]["with"]["path"],
        "fixtures/state.json\nfixtures/verification.json\n"
    );
    assert!(
        steps[publish_proof]["run"]
            .as_str()
            .unwrap()
            .contains("$GITHUB_STEP_SUMMARY")
    );
    assert_eq!(
        steps[publish_proof]["run"]
            .as_str()
            .unwrap()
            .matches("$GITHUB_STEP_SUMMARY")
            .count(),
        5
    );
    for step in steps {
        if step["uses"]
            .as_str()
            .is_some_and(|uses| uses.starts_with("actions/create-github-app-token@"))
        {
            assert_eq!(step["with"]["repositories"], "testing-securefix-server");
        }
    }
}

#[test]
fn workflow_local_actions_have_a_prior_matching_checkout() {
    for (path, value) in workflows() {
        for (job_id, job) in value["jobs"].as_object().unwrap() {
            let Some(steps) = job["steps"].as_array() else {
                continue;
            };
            for (index, step) in steps.iter().enumerate() {
                let Some(uses) = step["uses"].as_str() else {
                    continue;
                };
                let Some(local) = uses.strip_prefix("./") else {
                    continue;
                };
                let action_root = if local.starts_with(".github/actions/") {
                    ""
                } else if let Some((root, _)) = local.split_once("/.github/actions/") {
                    root
                } else {
                    continue;
                };
                let has_matching_checkout = steps[..index].iter().any(|prior| {
                    if !prior["uses"]
                        .as_str()
                        .is_some_and(|value| value.starts_with("actions/checkout@"))
                    {
                        return false;
                    }
                    let checkout_path = prior["with"]["path"].as_str().unwrap_or("");
                    checkout_path == action_root
                });
                assert!(
                    has_matching_checkout,
                    "{path}/{job_id}: local action {uses} needs an earlier checkout at its action root"
                );
            }
        }
    }

    let testing = workflow("testing-securefix-server.yml");
    for (job_id, probe_name) in [
        ("scratch", "Execute scratch control probe"),
        (
            "bootstrap-scratch",
            "Probe candidate control generation and CAS before approval",
        ),
    ] {
        let steps = testing["jobs"][job_id]["steps"].as_array().unwrap();
        let install = steps
            .iter()
            .position(|step| step["with"]["binary"] == "candidate-runtime/securefix")
            .unwrap();
        let probe = steps
            .iter()
            .position(|step| step["name"] == probe_name)
            .unwrap();
        assert!(install < probe);
        assert!(
            steps[probe]["run"]
                .as_str()
                .unwrap()
                .contains("securefix integration control-probe")
        );
    }
}

#[test]
fn operational_workflows_have_no_securefix_action_dependency() {
    for (path, value) in workflows() {
        assert!(
            !serde_json::to_string(&value)
                .unwrap()
                .contains("csm-actions/securefix-action"),
            "{path}"
        );
    }
}

#[test]
fn native_package_probe_separates_build_attest_publish_and_execution() {
    let build = workflow("testing-native-package-build.yml");
    assert_eq!(build["permissions"], serde_json::json!({}));
    let build_job = &build["jobs"]["build"];
    let build_guard = build_job["if"].as_str().unwrap();
    for required in [
        "github.repository == 'civitaspo/securefix-server'",
        "github.actor_id == '4525500'",
        "github.event_name == 'workflow_dispatch'",
        "github.run_attempt == 1",
    ] {
        assert!(build_guard.contains(required));
    }
    assert_eq!(
        build_job["permissions"],
        serde_json::json!({"contents":"read"})
    );
    let build_text = serde_json::to_string(build_job).unwrap();
    assert!(build_text.contains("cargo +1.99.0 test --locked"));
    assert!(build_text.contains("cargo +1.99.0 build --locked --release --bin securefix"));
    assert!(build_text.contains("package/securefix-linux-x86_64"));
    assert!(!build_text.contains("secrets."));
    assert!(!build_text.contains("id-token"));

    let attest_job = &build["jobs"]["attest"];
    assert_eq!(attest_job["needs"], "build");
    assert_eq!(
        attest_job["permissions"],
        serde_json::json!({"actions":"read","contents":"read","id-token":"write","attestations":"write"})
    );
    let attest_steps = attest_job["steps"].as_array().unwrap();
    assert!(attest_steps.iter().any(|step| {
        step["uses"] == "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"
            && step["with"]["subject-path"] == "package/securefix-linux-x86_64"
            && step["with"]["create-storage-record"] == false
    }));
    assert!(attest_steps.iter().any(|step| {
        step["with"]["name"] == "native-package-attested"
            && step["with"]["path"]
                .as_str()
                .is_some_and(|path| path.contains("package/bundle.json"))
    }));
    assert!(attest_steps.iter().all(|step| {
        step["run"]
            .as_str()
            .is_none_or(|run| !run.contains("cargo ") && !run.contains("rustup "))
    }));

    let publish = workflow("testing-publish-native-package.yml");
    assert_eq!(publish["permissions"], serde_json::json!({}));
    let host = &publish["jobs"]["host-build"];
    assert!(
        host["if"]
            .as_str()
            .unwrap()
            .contains("github.ref == 'refs/heads/main'")
    );
    assert_eq!(host["permissions"], serde_json::json!({"contents":"read"}));
    assert!(!serde_json::to_string(host).unwrap().contains("secrets."));
    let host_steps = host["steps"].as_array().unwrap();
    let validate_source = host_steps
        .iter()
        .find(|step| step["name"] == "Validate the selected source SHA")
        .unwrap();
    assert!(
        validate_source["run"]
            .as_str()
            .unwrap()
            .contains("^[0-9a-f]{40}$")
    );
    let checkout = host_steps
        .iter()
        .find(|step| step["uses"] == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1")
        .unwrap();
    assert_eq!(checkout["with"]["ref"], "${{ inputs.source_sha }}");
    assert_eq!(checkout["with"]["persist-credentials"], false);
    let build_host = host_steps
        .iter()
        .find(|step| step["name"] == "Build the selected-source publisher host")
        .unwrap();
    let build_host_run = build_host["run"].as_str().unwrap();
    assert!(build_host_run.contains("install -m 755 target/release/securefix publisher/securefix"));
    assert!(
        build_host_run.contains("install -m 644 .github/testing-policy.json publisher/policy.json")
    );
    assert!(!build_host_run.contains("install -m 644 policy.json publisher/policy.json"));

    let writer = &publish["jobs"]["publish"];
    assert_eq!(writer["environment"], "main");
    assert_eq!(
        writer["permissions"],
        serde_json::json!({"actions":"read","contents":"read"})
    );
    assert!(
        writer["if"]
            .as_str()
            .unwrap()
            .contains("github.ref == 'refs/heads/main'")
    );
    let steps = writer["steps"].as_array().unwrap();
    let download_host = steps
        .iter()
        .find(|step| {
            step["uses"] == "actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0"
        })
        .unwrap();
    assert_eq!(
        download_host["with"]["artifact-ids"],
        "${{ needs.host-build.outputs.artifact-id }}"
    );
    assert_eq!(download_host["with"]["merge-multiple"], true);
    let validate_host = steps
        .iter()
        .find(|step| step["name"] == "Validate the selected package inputs")
        .unwrap();
    let validate_host_run = validate_host["run"].as_str().unwrap();
    assert!(validate_host_run.contains("chmod 700 publisher/securefix"));
    assert!(validate_host_run.contains("test -x publisher/securefix"));
    let app = steps.iter().find(|step| step["id"] == "scratch").unwrap();
    assert_eq!(app["with"]["owner"], "civitaspo");
    assert_eq!(app["with"]["repositories"], "testing-securefix-server");
    assert_eq!(app["with"]["app-id"], "3872533");
    assert_eq!(app["with"]["permission-contents"], "write");
    assert!(app["with"].get("permission-administration").is_none());
    let publish_step = steps.iter().find(|step| step["id"] == "publish").unwrap();
    let publish_run = publish_step["run"].as_str().unwrap();
    assert!(publish_run.contains("integration publish-package"));
    assert!(publish_run.contains("--producer-run-id"));
    assert!(!publish_run.contains("securefix-linux-x86_64"));
    assert_eq!(
        publish_step["env"]["SECUREFIX_PACKAGE_TOKEN"],
        "${{ steps.scratch.outputs.token }}"
    );
    assert_eq!(
        publish_step["env"]["SECUREFIX_POLICY_PATH"],
        "publisher/policy.json"
    );
    let publish_run = publish_step["run"].as_str().unwrap();
    for projection in [
        "source-sha=\\(.source_sha)",
        "source-branch=\\(.source_branch)",
        "tag=\\(.tag)",
        "release-id=\\(.release_id)",
        "asset-id=\\(.asset_id)",
        "asset-sha256=\\(.asset_sha256)",
        "asset-size=\\(.asset_size)",
        "producer-run-id=\\(.producer_run_id)",
        "producer-run-attempt=\\(.producer_run_attempt)",
    ] {
        assert!(
            publish_run.contains(projection),
            "missing output projection: {projection}"
        );
    }

    let verify = &publish["jobs"]["verify"];
    assert_eq!(
        verify["permissions"],
        serde_json::json!({"actions":"read","attestations":"read","contents":"read"})
    );
    let verify_steps = verify["steps"].as_array().unwrap();
    let package_loader = verify_steps
        .iter()
        .find(|step| step["uses"] == "$/.github/actions/load-package")
        .unwrap();
    assert_eq!(
        package_loader["with"],
        serde_json::json!({"token":"${{ github.token }}"})
    );
    let execute = verify_steps
        .iter()
        .find(|step| step["name"] == "Execute the verified package without credentials")
        .unwrap();
    assert_eq!(execute["run"], "securefix --version");
    assert_eq!(execute["env"]["GH_TOKEN"], "");
    assert_eq!(execute["env"]["GITHUB_TOKEN"], "");

    let action: Value = serde_yaml::from_str(
        &fs::read_to_string(".github/actions/load-package/action.yml").unwrap(),
    )
    .unwrap();
    assert_eq!(
        action["inputs"],
        serde_json::json!({"token":{"description":"Read-only token for the package source and destination repositories","required":true}})
    );
    let mapping: Value =
        serde_json::from_slice(&fs::read(".github/actions/load-package/package.json").unwrap())
            .unwrap();
    assert_eq!(mapping["schema_version"], 3);
    assert_eq!(mapping["channel"], "scratch");
    assert_eq!(
        mapping["source_sha"],
        "9c122ee4f0a26a58ce40df6b921cad2969a1c350"
    );
    assert_eq!(
        mapping["source_manifest_sha256"],
        "1b4379620582aada4d0e34491531e4a5aa1f4379c88cb9fe62f1f285b49e3bba"
    );
    assert_eq!(mapping["version"], "0.2.45-pre.59");
    assert_eq!(mapping["tag"], "v0.2.45-pre.59");
    assert_eq!(mapping["release_id"], 421723144);
    assert_eq!(mapping["asset_id"], 668807095);
    assert_eq!(
        mapping["asset_sha256"],
        "643e85b5e4a0fb5bc0163b1f80204361f2e9ef7cf04f62c586a53ff0c26434c8"
    );
    assert_eq!(
        mapping["producer_run_id"],
        serde_json::json!(39940044272_u64)
    );
    assert_eq!(
        mapping["publisher_run_id"],
        serde_json::json!(39940649270_u64)
    );
}

#[test]
fn provider_release_probe_is_a_frozen_no_publish_scratch_test() {
    let provider_workflow = workflow("testing-provider-release.yml");
    assert!(provider_workflow["on"].get("workflow_call").is_some());
    assert_eq!(provider_workflow["permissions"], serde_json::json!({}));
    assert_eq!(
        provider_workflow["env"]["PROBE_REPOSITORY"],
        "civitaspo/testing-securefix-server"
    );
    assert_eq!(
        provider_workflow["env"]["PROBE_PROJECT"],
        "terraform-provider-sigma"
    );
    assert_eq!(
        provider_workflow["env"]["PROBE_EXPECTED_GPG_FINGERPRINT"],
        "12D7B26BEB5394D7AA579FB300F0D373EFFA1DC6"
    );
    assert_eq!(
        provider_workflow["on"]["workflow_call"]["secrets"],
        serde_json::json!({
            "TERRAFORM_PROVIDER_GPG_PRIVATE_KEY": {"required": true},
            "TERRAFORM_PROVIDER_GPG_PASSPHRASE": {"required": true},
            "SECUREFIX_SERVER_PRIVATE_KEY": {"required": true}
        })
    );
    let dispatcher = workflow("testing-securefix-server.yml");
    assert_eq!(
        dispatcher["jobs"]["provider-release-probe"]["secrets"],
        serde_json::json!({
            "TERRAFORM_PROVIDER_GPG_PRIVATE_KEY": "${{ secrets.TERRAFORM_PROVIDER_GPG_PRIVATE_KEY }}",
            "TERRAFORM_PROVIDER_GPG_PASSPHRASE": "${{ secrets.TERRAFORM_PROVIDER_GPG_PASSPHRASE }}",
            "SECUREFIX_SERVER_PRIVATE_KEY": "${{ secrets.SECUREFIX_SERVER_PRIVATE_KEY }}"
        })
    );

    let guard = &provider_workflow["jobs"]["guard"];
    assert!(
        guard["if"]
            .as_str()
            .unwrap()
            .contains("github.actor_id == '4525500'")
    );
    assert!(
        guard["if"]
            .as_str()
            .unwrap()
            .contains("refs/heads/integration/native-")
    );
    assert!(
        guard["steps"][0]["run"]
            .as_str()
            .unwrap()
            .contains("[[ \"$current\" == \"$CANDIDATE_SHA\" ]]")
    );

    let build = &provider_workflow["jobs"]["build-provider"];
    let checkout = build["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/checkout@"))
        })
        .unwrap();
    assert_eq!(
        checkout["with"]["repository"],
        "civitaspo/terraform-provider-sigma"
    );
    assert_eq!(
        checkout["with"]["ref"],
        "50a03ed7723ff026c0c8f1d567c4ee3f82e39675"
    );
    let matrix = build["strategy"]["matrix"]["include"].as_array().unwrap();
    let targets = matrix
        .iter()
        .filter(|item| item["kind"] == "target")
        .map(|item| {
            format!(
                "{}:{}",
                item["os"].as_str().unwrap(),
                item["arch"].as_str().unwrap()
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    let target_count = matrix
        .iter()
        .filter(|item| item["kind"] == "target")
        .count();
    let expected = crate::release::PROVIDER_TARGETS
        .iter()
        .map(|target| format!("{}:{}", target.os, target.arch))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        targets, expected,
        "matrix must build each supported provider target exactly once"
    );
    assert_eq!(target_count, crate::release::PROVIDER_TARGETS.len());
    assert_eq!(
        matrix
            .iter()
            .filter(|item| item["kind"] == "manifest")
            .count(),
        1
    );

    let compile = &provider_workflow["jobs"]["compile-harness"];
    assert!(compile["steps"].as_array().unwrap().iter().any(|step| {
        step["run"]
            .as_str()
            .is_some_and(|run| run.contains("cargo +1.99.0 test --locked --bin securefix --no-run"))
    }));
    assert!(compile["steps"].as_array().unwrap().iter().all(|step| {
        !serde_json::to_string(step).unwrap().contains("secrets.")
            && !step["env"].to_string().contains("GPG_")
            && !step["env"].to_string().contains("APP_TOKEN")
    }));

    assert!(build["steps"].as_array().unwrap().iter().any(|step| {
        step["env"]["SECUREFIX_PROVIDER_PROBE_PHASE"]
            == "${{ matrix.kind == 'manifest' && 'build-manifest' || 'build-target' }}"
    }));
    let build_text = serde_json::to_string(build).unwrap();
    for forbidden in [
        "secrets.",
        "TERRAFORM_PROVIDER_GPG",
        "SECUREFIX_SERVER_PRIVATE_KEY",
        "SECUREFIX_SERVER_APP_TOKEN",
    ] {
        assert!(
            !build_text.contains(forbidden),
            "provider build exposes {forbidden}"
        );
    }
    let expected_phases = [
        "fresh-sign",
        "create-draft",
        "stage-draft",
        "recover-download",
        "recover-sign",
        "complete-draft",
        "verify-draft",
        "cleanup-draft",
    ];
    for phase in expected_phases {
        let found = provider_workflow["jobs"]
            .as_object()
            .unwrap()
            .iter()
            .any(|(_, job)| {
                job["steps"].as_array().into_iter().flatten().any(|step| {
                    step["env"]["SECUREFIX_PROVIDER_PROBE_PHASE"] == phase
                        && step["run"].as_str().is_some_and(|run| {
                            run.contains("release::tests::provider_no_publish_probe")
                        })
                })
            });
        assert!(found, "missing test-only probe phase {phase}");
    }
    let text = serde_json::to_string(&provider_workflow).unwrap();
    assert!(
        !text.contains("draft:false"),
        "probe must never publish its release"
    );
    assert!(!text.contains("gh release create") && !text.contains("gh release edit"));

    for job_id in [
        "create-draft",
        "stage-draft",
        "recover-download",
        "complete-draft",
        "verify-draft",
        "cleanup-draft",
    ] {
        let job_text = serde_json::to_string(&provider_workflow["jobs"][job_id]).unwrap();
        assert!(job_text.contains("SECUREFIX_SERVER_PRIVATE_KEY"));
        assert!(job_text.contains("testing-securefix-server"));
        assert!(!job_text.contains("TERRAFORM_PROVIDER_GPG_PRIVATE_KEY"));
        assert!(!job_text.contains("GPG_PASSPHRASE"));
        let token = provider_workflow["jobs"][job_id]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|step| step["id"] == "scratch-token")
            .unwrap();
        assert_eq!(token["with"]["repositories"], "testing-securefix-server");
        assert_eq!(token["with"]["permission-contents"], "write");
        for permission in [
            "permission-actions",
            "permission-issues",
            "permission-pull-requests",
            "permission-workflows",
        ] {
            assert!(
                token["with"].get(permission).is_none(),
                "{job_id} token should not request {permission}"
            );
        }
    }
    for job_id in ["fresh-sign", "recover-sign"] {
        let job_text = serde_json::to_string(&provider_workflow["jobs"][job_id]).unwrap();
        assert!(job_text.contains("TERRAFORM_PROVIDER_GPG_PRIVATE_KEY"));
        assert!(!job_text.contains("SECUREFIX_SERVER_PRIVATE_KEY"));
        assert!(!job_text.contains("SECUREFIX_SERVER_APP_TOKEN"));
    }
    let aggregate = &provider_workflow["jobs"]["assemble-provider"]["steps"];
    assert!(aggregate.as_array().unwrap().iter().any(|step| {
        step["with"]["pattern"] == "sigma-probe-${{ github.run_id }}-*"
            && step["with"]["merge-multiple"] == true
    }));
}

#[test]
fn native_release_asset_probe_uses_the_shared_publisher_for_a_scratch_prerelease() {
    let dispatcher = workflow("testing-securefix-server.yml");
    let caller_if = dispatcher["jobs"]["native-release-assets-probe"]["if"]
        .as_str()
        .unwrap();
    for required in [
        "inputs.phase == 'release-assets'",
        "github.actor_id == '4525500'",
        "github.run_attempt == 1",
        "refs/heads/integration/native-",
        "inputs.candidate_sha == github.sha",
    ] {
        assert!(
            caller_if.contains(required),
            "caller guard lacks {required}"
        );
    }
    assert_eq!(
        dispatcher["jobs"]["native-release-assets-probe"]["secrets"],
        serde_json::json!({
            "SECUREFIX_SERVER_PRIVATE_KEY": "${{ secrets.SECUREFIX_SERVER_PRIVATE_KEY }}"
        })
    );

    let probe = workflow("testing-native-release-assets.yml");
    assert!(probe["on"].get("workflow_call").is_some());
    assert_eq!(probe["permissions"], serde_json::json!({}));
    assert_eq!(
        probe["env"]["PROBE_REPOSITORY"],
        "civitaspo/testing-securefix-server"
    );
    assert_eq!(
        probe["on"]["workflow_call"]["secrets"],
        serde_json::json!({"SECUREFIX_SERVER_PRIVATE_KEY":{"required":true}})
    );
    let guard = &probe["jobs"]["guard"];
    let guard_if = guard["if"].as_str().unwrap();
    for required in [
        "github.repository == 'civitaspo/securefix-server'",
        "github.actor_id == '4525500'",
        "github.run_attempt == 1",
        "refs/heads/integration/native-",
    ] {
        assert!(guard_if.contains(required), "probe guard lacks {required}");
    }
    assert!(
        guard["steps"][0]["run"]
            .as_str()
            .unwrap()
            .contains("[[ \"$current\" == \"$CANDIDATE_SHA\" ]]")
    );

    let compile = &probe["jobs"]["compile-harness"];
    let compile_text = serde_json::to_string(compile).unwrap();
    assert!(!compile_text.contains("secrets."));
    assert!(!compile_text.contains("APP_TOKEN"));
    assert!(compile_text.contains("Capture the active control policy for scratch writes"));
    assert_eq!(
        compile["steps"][0]["with"]["ref"],
        "${{ needs.guard.outputs.candidate-sha }}"
    );

    let build = &probe["jobs"]["build-native"];
    assert!(
        build["if"]
            .as_str()
            .unwrap()
            .contains("needs.compile-harness.result == 'success'")
    );
    assert_eq!(build["runs-on"], "${{ matrix.target.runner }}");
    assert_eq!(build["permissions"], serde_json::json!({"contents":"read"}));
    assert_eq!(
        build["strategy"]["matrix"]["target"],
        "${{ fromJSON(needs.compile-harness.outputs.native-targets) }}"
    );
    assert_eq!(
        probe["env"]["CLIENT_REPOSITORY"],
        "civitaspo/herdr-linear-agent"
    );
    assert_eq!(
        probe["env"]["CLIENT_SOURCE_SHA"],
        "ccdaada3efa78ebdef58f2db38aaf6ec5a8c8e00"
    );
    let build_text = serde_json::to_string(build).unwrap();
    assert_eq!(
        build["steps"][0]["with"]["repository"],
        "${{ env.CLIENT_REPOSITORY }}"
    );
    assert_eq!(
        build["steps"][0]["with"]["ref"],
        "${{ env.CLIENT_SOURCE_SHA }}"
    );
    assert!(build_text.contains("cargo +1.99.0 build --locked --release"));
    assert!(build_text.contains("rustup target add --toolchain 1.99.0"));
    assert!(build_text.contains("env -i PATH=\\\"$PATH\\\""));
    assert!(build_text.contains("--version"));
    for forbidden in [
        "secrets.",
        "create-github-app-token",
        "GITHUB_TOKEN",
        "GH_TOKEN",
    ] {
        assert!(
            !build_text.contains(forbidden),
            "native builder exposes {forbidden}"
        );
    }

    let verify = &probe["jobs"]["verify-native-targets"];
    let verify_if = verify["if"].as_str().unwrap();
    assert!(verify_if.contains("needs.build-native.result == 'success'"));
    assert!(verify_if.contains("needs.compile-harness.result == 'success'"));
    assert_eq!(
        verify["permissions"],
        serde_json::json!({"actions":"read","contents":"read"})
    );
    assert!(
        verify["needs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|need| need == "build-native")
    );
    assert!(
        serde_json::to_string(verify)
            .unwrap()
            .contains("native_release_assets_validate_probe_inputs")
    );

    let writer = &probe["jobs"]["publish-scratch-prerelease"];
    assert_eq!(writer["environment"], "main");
    let writer_if = writer["if"].as_str().unwrap();
    assert!(writer_if.contains("needs.build-native.result == 'success'"));
    assert!(writer_if.contains("needs.verify-native-targets.result == 'success'"));
    assert!(writer_if.contains("needs.compile-harness.result == 'success'"));
    assert!(
        writer["needs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|need| need == "verify-native-targets")
    );
    let token = writer["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "scratch-token")
        .unwrap();
    assert_eq!(token["with"]["owner"], "civitaspo");
    assert_eq!(token["with"]["repositories"], "testing-securefix-server");
    assert_eq!(token["with"]["permission-contents"], "write");
    let writer_text = serde_json::to_string(writer).unwrap();
    assert!(!writer_text.contains("SECUREFIX_CLIENT_PRIVATE_KEY"));
    assert!(writer_text.contains("SECUREFIX_SERVER_PRIVATE_KEY"));
    assert!(writer_text.contains("native_release_assets_scratch_publish_probe"));
    assert!(writer_text.contains("native_release_assets_validate_probe_inputs"));
    assert!(writer_text.contains("native-release-assets-probe-evidence"));

    let mut probe_invocations = 0;
    for job_id in ["verify-native-targets", "publish-scratch-prerelease"] {
        for step in probe["jobs"][job_id]["steps"].as_array().unwrap() {
            let Some(run) = step["run"].as_str() else {
                continue;
            };
            if run.contains("native_release_assets_validate_probe_inputs")
                || run.contains("native_release_assets_scratch_publish_probe")
            {
                assert_eq!(
                    step["env"]["SECUREFIX_POLICY_PATH"],
                    "${{ github.workspace }}/probe/active-policy.json"
                );
                assert_eq!(
                    step["env"]["SECUREFIX_NATIVE_RELEASE_PROBE_TARGET_POLICY_PATH"],
                    "${{ github.workspace }}/probe/policy.json"
                );
                assert_eq!(
                    step["env"]["SECUREFIX_NATIVE_RELEASE_PROBE_HARNESS_SHA"],
                    "${{ github.sha }}"
                );
                assert_eq!(
                    step["env"]["SECUREFIX_NATIVE_RELEASE_PROBE_SERVER_SHA"],
                    "${{ github.sha }}"
                );
                assert_eq!(
                    step["env"]["SECUREFIX_NATIVE_RELEASE_PROBE_PRODUCER_RUN_ID"],
                    "${{ github.run_id }}"
                );
                assert_eq!(
                    step["env"]["SECUREFIX_NATIVE_RELEASE_PROBE_PRODUCER_RUN_ATTEMPT"],
                    "${{ github.run_attempt }}"
                );
                probe_invocations += 1;
            }
        }
    }
    assert_eq!(probe_invocations, 3);

    let source = include_str!("release.rs");
    assert!(source.contains("SECUREFIX_NATIVE_RELEASE_PROBE_HARNESS_SHA"));
    assert!(source.contains("SECUREFIX_NATIVE_RELEASE_PROBE_SERVER_SHA"));
    assert!(source.contains("SECUREFIX_NATIVE_RELEASE_PROBE_PRODUCER_RUN_ID"));
    assert!(source.contains("SECUREFIX_NATIVE_RELEASE_PROBE_PRODUCER_RUN_ATTEMPT"));
    assert!(source.contains("SECUREFIX_NATIVE_RELEASE_PROBE_TARGET_POLICY_PATH"));
    assert!(source.contains(
        "publish_release_assets_with_upload(api, repo, release_id, plan, assets_dir, &mut upload)"
    ));
    assert!(source.contains(
        "publish_release_assets_with_upload(api, repo, release_id, &plan, &assets_dir, upload)"
    ));
    assert!(source.contains("incomplete native target set was accepted"));
    assert!(source.contains("std::io::copy(&mut file, &mut archive)?"));
    assert!(source.contains("Client source is not the pinned verified commit"));
    assert!(
        source
            .contains("ensure_published_immutable_release(&published, release_id, &success_tag)?")
    );
}

#[test]
fn scratch_uses_one_selected_runtime_and_test_scoped_tokens() {
    let value = workflow("testing-securefix-server.yml");
    let text = serde_json::to_string(&value).unwrap();
    assert!(!text.contains("docker run"));
    assert!(!text.contains("trusted-runtime"));
    assert!(value["jobs"].get("reuse").is_none());
    let build = &value["jobs"]["build"];
    assert!(!serde_json::to_string(build).unwrap().contains("secrets."));
    assert!(
        build["if"]
            .as_str()
            .unwrap()
            .contains("inputs.phase == 'verify'")
    );
    let setup = build["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["uses"] == "$/.github/actions/setup-cli")
        .unwrap();
    assert_eq!(
        setup["with"]["candidate-run-id"],
        "${{ inputs.phase == 'verify' && inputs.fixture_run_id || '' }}"
    );
    let scratch = &value["jobs"]["scratch"];
    assert_eq!(
        scratch["env"]["SECUREFIX_TEST_BASELINE_SHA"],
        "${{ needs.baseline.outputs.source-sha }}"
    );
    let steps = scratch["steps"].as_array().unwrap();
    let install = steps
        .iter()
        .position(|s| s["with"]["binary"] == "candidate-runtime/securefix")
        .unwrap();
    let producer = steps.iter().position(|s| s["id"] == "producer").unwrap();
    let mint = steps.iter().position(|s| s["id"] == "server").unwrap();
    assert!(install < producer && producer < mint);
    assert!(steps.iter().any(|s| s["id"] == "validate-outputs"));
    assert!(steps.iter().any(|s| s["id"] == "control-probe"));
    for step in steps {
        if step["uses"]
            .as_str()
            .is_some_and(|s| s.starts_with("actions/create-github-app-token@"))
        {
            assert_eq!(step["with"]["repositories"], "testing-securefix-server");
        }
    }
}

#[test]
fn cli_jobs_use_verified_artifacts_before_invocation() {
    for (path, workflow) in workflows() {
        for (job_id, job) in workflow["jobs"].as_object().unwrap() {
            let Some(steps) = job["steps"].as_array() else {
                continue;
            };
            let downloads_request_manifest = path == ".github/workflows/request-producer-probe.yml"
                && job_id == "attest"
                && steps.iter().any(|step| {
                    step["name"] == "Download request manifest"
                        && step["with"]["path"] == "native-policy-check"
                });
            if path == ".github/workflows/reusable-client-request.yml" && job_id == "attest" {
                continue;
            }
            if path == ".github/workflows/reusable-client-request-scratch.yml" && job_id == "attest"
            {
                let manifest_download = steps
                    .iter()
                    .find(|step| {
                        step["uses"]
                            .as_str()
                            .is_some_and(|uses| uses.starts_with("actions/download-artifact@"))
                    })
                    .unwrap();
                assert_eq!(
                    manifest_download["with"]["artifact-ids"],
                    "${{ needs.capture.outputs.artifact-id }}"
                );
                assert!(steps.iter().any(|step| {
                    step["uses"]
                        .as_str()
                        .is_some_and(|uses| uses.starts_with("actions/attest@"))
                }));
                assert!(!steps.iter().any(|step| {
                    step["run"]
                        .as_str()
                        .is_some_and(|run| run.contains("$CLI_BINARY"))
                }));
                continue;
            }
            if path == ".github/workflows/testing-native-package-build.yml" && job_id == "attest" {
                continue;
            }
            if path == ".github/workflows/native-package-build.yml" && job_id == "attest" {
                continue;
            }
            if path == ".github/workflows/publish-native-package.yml" {
                continue;
            }
            if path == ".github/workflows/testing-native-approve.yml" {
                continue;
            }
            if path == ".github/workflows/testing-native-merge.yml" {
                continue;
            }
            if path == ".github/workflows/testing-native-policy-check-authority.yml"
                && matches!(job_id.as_str(), "validate-request" | "publish-check")
            {
                assert!(steps.iter().any(|step| {
                    step["uses"]
                        == "civitaspo/securefix-server/.github/actions/load-package@61fd0f85f2d02c78d333dbfcbf7848a1572e4f6d"
                        && step["with"] == serde_json::json!({"token":"${{ github.token }}"})
                }));
                let loader_index = steps.iter().position(|step| {
                    step["uses"] == "civitaspo/securefix-server/.github/actions/load-package@61fd0f85f2d02c78d333dbfcbf7848a1572e4f6d"
                }).unwrap();
                let invocation_index = steps
                    .iter()
                    .position(|step| {
                        step["run"].as_str().is_some_and(|run| {
                            run.contains("securefix new-server instance-policy-check-run")
                        })
                    })
                    .unwrap();
                assert!(loader_index < invocation_index);
                continue;
            }
            if path == ".github/workflows/testing-publish-native-package.yml" && job_id == "publish"
            {
                continue;
            }
            if path == ".github/workflows/reusable-client-request-scratch.yml"
                && job_id == "dispatch"
            {
                let package = steps.iter().find(|step| step["id"] == "package").unwrap();
                assert!(
                    package["uses"]
                        .as_str()
                        .unwrap()
                        .ends_with("@61fd0f85f2d02c78d333dbfcbf7848a1572e4f6d")
                );
                assert_eq!(
                    package["with"],
                    serde_json::json!({"token": "${{ github.token }}"})
                );
                let invocation = steps
                    .iter()
                    .find(|step| {
                        step["run"].as_str().is_some_and(|run| {
                            run.contains("new-client dispatch") && run.contains("$CLI_BINARY")
                        })
                    })
                    .unwrap();
                assert_eq!(
                    invocation["env"]["CLI_BINARY"],
                    "${{ steps.package.outputs.binary }}"
                );
                continue;
            }
            let downloads_cli = path != ".github/workflows/control-bootstrap.yml"
                && path != ".github/workflows/reusable-server-release.yml"
                && !downloads_request_manifest
                && !(matches!(
                    path.as_str(),
                    ".github/workflows/reusable-release-tag.yml"
                        | ".github/workflows/testing-reusable-release-tag.yml"
                ) && job_id == "attest-manifest")
                && steps.iter().any(|step| {
                    step["uses"]
                        .as_str()
                        .is_some_and(|u| u.starts_with("actions/download-artifact@"))
                        && step["with"]["artifact-ids"].is_string()
                });
            if path == ".github/workflows/testing-provider-release.yml"
                || path == ".github/workflows/testing-native-release-assets-publish.yml"
            {
                continue;
            }
            if path == ".github/workflows/testing-native-release-assets.yml"
                && matches!(
                    job_id.as_str(),
                    "compile-harness" | "verify-native-targets" | "publish-scratch-prerelease"
                )
            {
                continue;
            }
            let installer = steps.iter().position(|step| {
                step["uses"] == "$/.github/actions/install-cli"
                    || step["uses"] == "./.github/actions/install-cli"
            });
            if path == ".github/workflows/testing-release-pr.yml" && job_id == "execute" {
                let trusted_installer = steps
                    .iter()
                    .position(|step| {
                        step["uses"] == "$/.github/actions/install-cli"
                            && step["with"]["binary"]
                                == "${{ github.workspace }}/trusted-runtime/securefix"
                    })
                    .unwrap();
                let candidate_installer = steps
                    .iter()
                    .position(|step| {
                        step["uses"] == "$/.github/actions/install-cli"
                            && step["with"]["binary"]
                                == "${{ github.workspace }}/candidate/securefix"
                    })
                    .unwrap();
                let producer_check = steps
                    .iter()
                    .position(|step| {
                        step["name"]
                            == "Validate frozen producer before minting scratch credentials"
                    })
                    .unwrap();
                let app_token = steps
                    .iter()
                    .position(|step| step["id"] == "server")
                    .unwrap();
                let mise = steps
                    .iter()
                    .position(|step| {
                        step["uses"]
                            .as_str()
                            .is_some_and(|value| value.starts_with("jdx/mise-action@"))
                    })
                    .unwrap();
                let candidate_run = steps
                    .iter()
                    .position(|step| step["name"] == "Exercise managed release PR refresh")
                    .unwrap();
                let trusted_download = steps
                    .iter()
                    .position(|step| {
                        step["with"]["artifact-ids"]
                            == "${{ needs.trusted-runtime.outputs.artifact-id }}"
                    })
                    .unwrap();
                assert!(trusted_download < trusted_installer);
                assert!(trusted_installer < producer_check && producer_check < app_token);
                let prepare_check = steps
                    .iter()
                    .position(|step| step["name"] == "Validate exact prepare run for verify phase")
                    .unwrap();
                let artifact_lookup = steps
                    .iter()
                    .position(|step| step["id"] == "artifacts")
                    .unwrap();
                assert!(producer_check < prepare_check && prepare_check < artifact_lookup);
                for (index, step) in steps.iter().enumerate() {
                    if step["with"]["artifact-ids"]
                        .as_str()
                        .is_some_and(|value| value.starts_with("${{ steps.artifacts.outputs."))
                    {
                        assert!(artifact_lookup < index && index < app_token);
                    }
                }
                assert!(
                    app_token < mise
                        && mise < candidate_installer
                        && candidate_installer < candidate_run
                );
                continue;
            }
            if downloads_cli {
                if path == ".github/workflows/reusable-client-request.yml" {
                    let package_loader = steps.iter().find(|step| step["id"] == "package").unwrap();
                    assert!(
                        package_loader["uses"]
                            .as_str()
                            .unwrap()
                            .ends_with("@61fd0f85f2d02c78d333dbfcbf7848a1572e4f6d")
                    );
                    assert!(
                        steps
                            .iter()
                            .filter_map(|step| step["run"].as_str())
                            .any(|run| run.contains("$CLI_BINARY")),
                        "{path}/{job_id}: verified package binary must be invoked"
                    );
                    continue;
                }
                assert!(
                    installer.is_some(),
                    "{path}/{job_id}: downloaded CLI must use the installer"
                );
                let download = steps
                    .iter()
                    .position(|step| {
                        step["uses"].as_str().is_some_and(|u| {
                            u.starts_with("actions/download-artifact@")
                                && step["with"]["artifact-ids"].is_string()
                        })
                    })
                    .unwrap();
                assert!(
                    download < installer.unwrap(),
                    "{path}/{job_id}: install follows immutable artifact download"
                );
                let last_path_setup = steps.iter().rposition(|step| {
                    step["uses"].as_str().is_some_and(|uses| {
                        uses.starts_with("jdx/mise-action@")
                            || uses.starts_with("actions/setup-go@")
                            || uses.starts_with("actions/setup-node@")
                            || uses.starts_with("actions/setup-python@")
                            || uses.starts_with("actions/setup-java@")
                    })
                });
                if let Some(setup) = last_path_setup {
                    assert!(
                        setup < installer.unwrap(),
                        "{path}/{job_id}: install follows PATH-changing tool setup"
                    );
                }
            }
            for (index, step) in steps.iter().enumerate() {
                let Some(run) = step["run"].as_str() else {
                    continue;
                };
                assert!(
                    !run.contains("${{ github.event."),
                    "{path}/{job_id}: event data must enter through env or the event file"
                );
                let bounded_baseline_reads = (path == ".github/workflows/testing-load-cli.yml"
                    && job_id == "load"
                    && step["id"] == "baseline"
                    && run
                        == "echo \"sha=$(gh api repos/civitaspo/securefix-server/commits/main --jq .sha)\" >> \"$GITHUB_OUTPUT\"")
                    || (path == ".github/workflows/testing-securefix-server.yml"
                        && job_id == "baseline"
                        && run.contains("gh api")
                        && (run.contains("repo=civitaspo/securefix-server")
                            || run.contains(
                                "gh api repos/civitaspo/securefix-server/commits/main --jq .sha",
                            ))
                        && (run.contains("repos/$repo/commits/main")
                            || run.contains("repos/civitaspo/securefix-server/commits/main"))
                        && !run.contains("gh api -X")
                        && !run.contains("--method")
                        && !run.contains("gh release")
                        && !run.contains("jq -e")
                        && !run.contains("jq -r '.content'"));
                let bounded_legacy_runtime_reads = path
                    == ".github/workflows/testing-securefix-server.yml"
                    && job_id == "bootstrap-legacy-runtime"
                    && run.contains("repos/$repo/releases/414653308")
                    && run.contains("assets[] | select(.id == 646481902)")
                    && run.contains("gh release download v0.2.20")
                    && run.contains("sha256sum --check")
                    && run.contains("gh attestation verify")
                    && !run.contains("gh api -X")
                    && !run.contains("--method")
                    && !run.contains("gh release upload")
                    && !run.contains("gh release create");
                let bounded_release_artifact_lookup = path
                    == ".github/workflows/testing-release-pr.yml"
                    && job_id == "execute"
                    && ((step["name"] == "Resolve immutable prepare artifacts"
                        && run.contains("actions/runs/$PREPARE_RUN_ID/artifacts?per_page=100")
                        && run.contains("total_count")
                        && run.contains("expired == false"))
                        || (step["name"] == "Validate exact prepare run for verify phase"
                            && run.contains("actions/runs/$PREPARE_RUN_ID")
                            && run.contains("head_sha == $sha")
                            && run.contains("conclusion == \"success\"")))
                    && !run.contains("gh api -X")
                    && !run.contains("--method");
                let native_test_precondition = step["name"]
                    == "Verify the selected scratch pull request head"
                    && run.contains(
                        "repos/civitaspo/testing-securefix-server/pulls/$PULL_REQUEST_NUMBER",
                    )
                    && run.matches("gh api ").count() == 1;
                let native_test_readback = step["name"] == "Independently read back the PR and signed commit state"
                    && run.contains("repos/civitaspo/testing-securefix-server/pulls/$PULL_REQUEST_NUMBER")
                    && run.contains("repos/civitaspo/testing-securefix-server/commits/$current_head")
                    && run.contains("repos/civitaspo/testing-securefix-server/contents/native-producer-proof.txt?ref=$current_head")
                    && run.matches("gh api ").count() == 3;
                let bounded_native_test_assertion = path
                    == ".github/workflows/testing-native-securefix-server.yml"
                    && job_id == "apply"
                    && (native_test_precondition || native_test_readback)
                    && !run.contains("gh api -X")
                    && !run.contains("--method")
                    && !run.contains("--input")
                    && !run.contains("--raw-field")
                    && !run.contains("--field")
                    && !run.contains(" -f ")
                    && !run.contains(" -F ");
                let selected_native_release_probe_build = path
                    == ".github/workflows/testing-native-release-assets-publish.yml"
                    && job_id == "host-build"
                    && step["name"] == "Build the selected-source native release probe harness"
                    && run.contains("cargo +1.99.0 test --locked --bin securefix --no-run")
                    && run.contains("jq -er");
                let native_release_assets_preflight = path
                    == ".github/workflows/testing-native-release-assets-publish.yml"
                    && ((job_id == "qualify"
                        && step["name"]
                            == "Qualify the frozen source, producer jobs, artifacts, and scratch target")
                        || (job_id == "publish-scratch"
                            && matches!(
                                step["name"].as_str(),
                                Some(
                                    "Recheck the selected source and target before minting a scratch token"
                                        | "Recheck current main and target immediately before scratch publication"
                                )
                            )))
                    && run.contains("gh api ")
                    && !run.contains("gh api -X")
                    && !run.contains("--method")
                    && !run.contains("--input")
                    && !run.contains("--raw-field")
                    && !run.contains("--field")
                    && !run.contains(" -f ")
                    && !run.contains(" -F ");
                let native_package_config_projection = path
                    == ".github/workflows/testing-publish-native-package.yml"
                    && job_id == "verify"
                    && step["id"] == "config"
                    && run.matches("jq ").count() == 1
                    && run.contains("jq -r")
                    && run.contains(".deployment.server.repository")
                    && run.contains(".deployment.integration.repository")
                    && run.contains(".owner_id")
                    && !run.contains("jq -e")
                    && !run.contains("select(")
                    && !run.contains(" == ")
                    && !run.contains("test(");
                let native_package_record_projection = path
                    == ".github/workflows/testing-publish-native-package.yml"
                    && job_id == "publish"
                    && step["id"] == "publish"
                    && run.matches("jq ").count() == 1
                    && run.contains("jq -r")
                    && [
                        "source_sha",
                        "source_branch",
                        "tag",
                        "release_id",
                        "asset_id",
                        "asset_sha256",
                        "asset_size",
                        "producer_run_id",
                        "producer_run_attempt",
                    ]
                    .iter()
                    .all(|field| run.contains(field))
                    && !run.contains("jq -e")
                    && !run.contains("select(")
                    && !run.contains(" == ")
                    && !run.contains("test(");
                let bounded_native_release_source_guard = path
                    == ".github/workflows/testing-native-release-assets.yml"
                    && job_id == "guard"
                    && step["name"] == "Require the frozen candidate branch to match this run"
                    && run.contains("git/ref/heads/${BRANCH}")
                    && run.contains("\"$current\" == \"$CANDIDATE_SHA\"")
                    && run.contains("integration/native-[0-9a-f]{12}")
                    && run.contains("${BRANCH##*-}")
                    && run.contains("${CANDIDATE_SHA:0:12}")
                    && run.matches("gh api ").count() == 1
                    && !run.contains("gh api -X")
                    && !run.contains("--method");
                let bounded_native_release_harness = path
                    == ".github/workflows/testing-native-release-assets.yml"
                    && job_id == "compile-harness"
                    && step["name"] == "Compile the isolated native release probe test binary"
                    && run.contains("cargo +1.99.0 test --locked --bin securefix --no-run")
                    && run.contains("target.name == \"securefix\"")
                    && run.contains(".executable")
                    && run.matches("jq ").count() == 1
                    && !run.contains("gh api")
                    && !run.contains("gh release");
                let bounded_native_release_target_matrix = path
                    == ".github/workflows/testing-native-release-assets.yml"
                    && job_id == "compile-harness"
                    && step["name"] == "Read the configured native target matrix"
                    && run.contains("jq -ce --arg repository")
                    && run.contains(".native_binaries[]")
                    && run.contains("jq 'length'")
                    && !run.contains("gh api")
                    && !run.contains("gh release");
                let bounded_native_release_target_build = path
                    == ".github/workflows/testing-native-release-assets.yml"
                    && job_id == "build-native"
                    && step["name"]
                        == "Build and execute the pinned Client source on its target runner"
                    && run.contains(
                        "cargo +1.99.0 build --locked --release --bin herdr-linear-agent --target",
                    )
                    && run.contains("git rev-parse HEAD")
                    && run.contains("--version")
                    && run.contains("jq -n")
                    && run.matches("jq ").count() == 1
                    && run.contains("source_run_id:$source_run_id")
                    && run.contains("source_run_attempt:$source_run_attempt")
                    && run.contains("release_pr_number:$release_pr_number")
                    && run.contains("release_pr_sha:$release_pr_sha")
                    && !run.contains("jq -e")
                    && !run.contains("select(")
                    && !run.contains("gh api")
                    && !run.contains("gh release");
                let bounded_native_target_evidence = (path
                    == ".github/workflows/reusable-release-tag.yml"
                    || path == ".github/workflows/testing-reusable-release-tag.yml")
                    && job_id == "build-native"
                    && step["name"] == "Build and execute the native binary on its target runner"
                    && run.contains("jq -n")
                    && run.matches("jq ").count() == 1
                    && run.contains("source_run_id:$source_run_id")
                    && run.contains("source_run_attempt:$source_run_attempt")
                    && run.contains("release_pr_number:$release_pr_number")
                    && run.contains("release_pr_sha:$release_pr_sha")
                    && !run.contains("jq -e")
                    && !run.contains("select(")
                    && !run.contains("test(")
                    && run.contains("mktemp -d");
                assert!(
                    !run.contains("python")
                        && !run.contains("ruby")
                        && !run.contains("node ")
                        && (!run.contains("jq ")
                            || bounded_baseline_reads
                            || bounded_legacy_runtime_reads
                            || bounded_release_artifact_lookup
                            || bounded_native_test_assertion
                            || selected_native_release_probe_build
                            || native_release_assets_preflight
                            || native_package_config_projection
                            || native_package_record_projection
                            || bounded_native_release_source_guard
                            || bounded_native_release_harness
                            || bounded_native_release_target_matrix
                            || bounded_native_release_target_build
                            || bounded_native_target_evidence)
                        && !run.contains("curl "),
                    "{path}/{job_id}: operation decisions must be in Rust except bounded runtime bootstrap reads"
                );
                assert!(
                    !run.contains("chmod") || !run.contains("securefix"),
                    "{path}/{job_id}: CLI permissions belong in installer action"
                );
                let invokes_cli = run
                    .lines()
                    .any(|line| line.trim().starts_with("securefix "));
                if invokes_cli {
                    if let Some(installer) = installer {
                        assert!(
                            index > installer,
                            "{path}/{job_id}: CLI must run after installer"
                        );
                    }
                    if !run.contains("--help") && !run.contains("policy validate") {
                        let source_bound_native_candidate = path
                            == ".github/workflows/request-producer-probe.yml"
                            && job_id == "capture"
                            && steps.iter().any(|candidate| {
                                candidate["uses"]
                                    == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
                                    && candidate["with"]["ref"]
                                        == "${{ inputs.candidate_source_sha }}"
                            });
                        let verified_native_package_smoke = path
                            == ".github/workflows/testing-publish-native-package.yml"
                            && job_id == "verify"
                            && step["name"] == "Execute the verified package without credentials"
                            && run == "securefix --version"
                            && steps.iter().any(|candidate| {
                                candidate["uses"] == "$/.github/actions/load-package"
                                    && candidate["with"].as_object().is_some_and(|inputs| {
                                        inputs.len() == 1
                                            && inputs.get("token").and_then(Value::as_str)
                                                == Some("${{ github.token }}")
                                    })
                            });
                        let selected_managed_files_candidate = path
                            == ".github/workflows/testing-securefix-server.yml"
                            && job_id == "managed-files-probe"
                            && steps.iter().any(|candidate| {
                                candidate["uses"] == "$/.github/actions/install-cli"
                                    && candidate["with"]["binary"]
                                        == "candidate-runtime/securefix"
                            })
                            && steps.iter().any(|candidate| {
                                candidate["name"]
                                    == "Validate the exact selected candidate before minting a writer token"
                                    && candidate["env"]["CANDIDATE_SHA"]
                                        == "${{ needs.build.outputs.source-sha }}"
                                    && candidate["run"]
                                        .as_str()
                                        .is_some_and(|run| run.contains("securefix integration validate-producer"))
                            });
                        let fixed_package_loaded = steps[..index].iter().any(|candidate| {
                            candidate["uses"].as_str().is_some_and(|uses| {
                                uses.strip_prefix(
                                    "civitaspo/securefix-server/.github/actions/load-package@",
                                )
                                .is_some_and(|sha| {
                                    sha.len() == 40
                                        && sha.bytes().all(|byte| byte.is_ascii_hexdigit())
                                })
                            }) && candidate["with"]
                                == serde_json::json!({"token": "${{ github.token }}"})
                        });
                        assert!(
                            job["env"]["SECUREFIX_SOURCE_SHA"].is_string()
                                || step["env"]["SECUREFIX_SOURCE_SHA"].is_string()
                                || source_bound_native_candidate
                                || verified_native_package_smoke
                                || selected_managed_files_candidate
                                || fixed_package_loaded
                                || (path == ".github/workflows/testing-securefix-server.yml"
                                    && (step["env"]["CANDIDATE_SHA"].is_string()
                                        || (job_id == "managed-files-probe"
                                            && step["env"]["SOURCE_SHA"].is_string())
                                        || job["env"]["CANDIDATE_SHA"].is_string()
                                        || (run.starts_with("securefix integration resolve-test-runtime --published-runtime-sha ")
                                            && step["env"]["PUBLISHED_RUNTIME_SHA"].is_string()
                                            && step["env"]["GITHUB_TOKEN"].is_string()))),
                            "{path}/{job_id}: runtime revision required"
                        );
                    }
                    if run.contains("request capture-") || run.contains("request dispatch") {
                        assert!(
                            job["env"]["GITHUB_TOKEN"].is_string()
                                || step["env"]["GITHUB_TOKEN"].is_string(),
                            "{path}/{job_id}: read token required"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn server_request_callers_pass_the_required_environment_secret_by_name() {
    for operation in ["approve", "merge"] {
        let caller = workflow(&format!("{operation}-request.yml"));
        let local_reusable = format!("./.github/workflows/reusable-{operation}-request.yml");
        assert_eq!(caller["jobs"]["request"]["uses"], local_reusable);
        assert_eq!(caller["jobs"]["request"]["permissions"]["issues"], "read");
        assert_eq!(
            caller["jobs"]["request"]["permissions"]["attestations"],
            "write"
        );
        assert_eq!(
            caller["jobs"]["request"]["permissions"]["id-token"],
            "write"
        );
        assert_eq!(
            caller["jobs"]["request"]["permissions"]["pull-requests"],
            "read"
        );
        assert_eq!(
            caller["jobs"]["request"]["secrets"],
            serde_json::json!({
                "SECUREFIX_CLIENT_PRIVATE_KEY": "${{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}"
            }),
            "environment-only secrets must be declared explicitly at call time"
        );
        let reusable = workflow(&format!("reusable-{operation}-request.yml"));
        assert_eq!(
            caller["jobs"]["request"]["with"]["server_repository"],
            "civitaspo/securefix-server"
        );
        assert_eq!(
            caller["jobs"]["request"]["with"]["instance_config_path"],
            "securefix-server.toml"
        );
        assert_eq!(
            reusable["on"]["workflow_call"]["secrets"]["SECUREFIX_CLIENT_PRIVATE_KEY"]["required"],
            true
        );
        assert_eq!(reusable["permissions"], serde_json::json!({}));
        assert_eq!(
            reusable["jobs"]["request"]["uses"],
            "./.github/workflows/reusable-client-request.yml"
        );
        assert_eq!(
            reusable["jobs"]["request"]["with"]["operation"],
            if operation == "approve" {
                "approval"
            } else {
                "merge"
            }
        );
        assert_eq!(
            reusable["jobs"]["request"]["with"]["server_repository"],
            "${{ inputs.server_repository }}"
        );
        assert_eq!(
            reusable["jobs"]["request"]["with"]["instance_config_path"],
            "${{ inputs.instance_config_path }}"
        );
        assert_eq!(
            reusable["jobs"]["request"]["secrets"]["SECUREFIX_CLIENT_PRIVATE_KEY"],
            "${{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}"
        );
        assert_eq!(
            reusable["jobs"]["request"]["permissions"]["attestations"],
            "write"
        );
        assert_eq!(
            reusable["jobs"]["request"]["permissions"]["id-token"],
            "write"
        );
    }

    let signer = workflow("reusable-client-request.yml");
    assert_eq!(signer["permissions"], serde_json::json!({}));
    assert!(signer["jobs"]["dispatch"].get("environment").is_none());
    let dispatch = signer["jobs"]["dispatch"]["steps"].as_array().unwrap();
    let token = dispatch
        .iter()
        .find(|step| step["id"] == "client-token")
        .unwrap();
    assert_eq!(
        token["with"]["owner"],
        "${{ needs.capture.outputs.server-owner }}"
    );
    assert_eq!(
        token["with"]["repositories"],
        "${{ needs.capture.outputs.server-repository-name }}"
    );
    assert_eq!(
        token["with"]["app-id"],
        "${{ needs.capture.outputs.client-app-id }}"
    );
    assert_eq!(token["with"]["permission-issues"], "write");
    let attest = &signer["jobs"]["attest"];
    assert!(attest.get("secrets").is_none());
    assert_eq!(attest["permissions"]["id-token"], "write");
    assert_eq!(attest["permissions"]["attestations"], "write");
    let capture = &signer["jobs"]["capture"];
    assert_eq!(capture["permissions"]["issues"], "read");
    assert_eq!(capture["permissions"]["pull-requests"], "read");
    let capture_step = capture["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "capture")
        .unwrap();
    assert_eq!(
        capture_step["env"]["SECUREFIX_SERVER_REPOSITORY"],
        "${{ inputs.server_repository }}"
    );
    assert_eq!(
        capture_step["env"]["SECUREFIX_INSTANCE_CONFIG_PATH"],
        "${{ inputs.instance_config_path }}"
    );
}

#[test]
fn client_policy_check_caller_uses_the_native_request_signer() {
    let caller_source = include_str!("distribution_templates/policy-check.yml")
        .replace("@SERVER_REPOSITORY@", "civitaspo/securefix-server")
        .replace("@SECUREFIX_RUNTIME_SHA@", &"a".repeat(40))
        .replace("@RUNTIME_VERSION@", "v0.2.0");
    let mut caller_yaml: serde_yaml::Value = serde_yaml::from_str(&caller_source).unwrap();
    if let Some(mapping) = caller_yaml.as_mapping_mut()
        && let Some(on) = mapping.remove(serde_yaml::Value::Bool(true))
    {
        mapping.insert(serde_yaml::Value::String("on".into()), on);
    }
    let caller: Value = serde_json::to_value(caller_yaml).unwrap();
    assert_eq!(
        caller["on"]["pull_request_target"]["types"],
        serde_json::json!(["opened", "synchronize", "reopened", "ready_for_review"])
    );
    assert!(caller["on"].get("push").is_none());
    let check = &caller["jobs"]["check"];
    assert!(
        check["uses"]
            .as_str()
            .unwrap()
            .contains("reusable-policy-check.yml@")
    );
    assert_eq!(
        check["with"]["server_repository"],
        "civitaspo/securefix-server"
    );
    assert_eq!(
        check["with"]["instance_config_path"],
        "securefix-server.toml"
    );
    for (permission, expected) in [
        ("actions", "read"),
        ("attestations", "write"),
        ("contents", "read"),
        ("id-token", "write"),
        ("issues", "read"),
        ("pull-requests", "read"),
    ] {
        assert_eq!(check["permissions"][permission], expected, "{permission}");
    }
    assert_eq!(
        check["secrets"]["SECUREFIX_CLIENT_PRIVATE_KEY"],
        "${{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}"
    );

    let reusable = workflow("reusable-policy-check.yml");
    assert_eq!(reusable["permissions"], serde_json::json!({}));
    assert_eq!(
        reusable["on"]["workflow_call"]["inputs"]["server_repository"]["required"],
        true
    );
    assert_eq!(
        reusable["on"]["workflow_call"]["inputs"]["instance_config_path"]["required"],
        true
    );
    assert_eq!(
        reusable["jobs"]["request"]["uses"],
        "./.github/workflows/reusable-client-request.yml"
    );
    assert_eq!(
        reusable["jobs"]["request"]["with"]["operation"],
        "policy_check"
    );
    let signer = workflow("reusable-client-request.yml");
    let loader_steps = signer["jobs"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|job| job["steps"].as_array().into_iter().flatten())
        .filter(|step| step["id"] == "package")
        .collect::<Vec<_>>();
    assert_eq!(loader_steps.len(), 2);
    for step in loader_steps {
        assert_eq!(
            step["with"],
            serde_json::json!({"token":"${{ github.token }}"})
        );
    }
    assert!(
        signer["on"]["workflow_call"]["inputs"]
            .as_object()
            .unwrap()
            .keys()
            .all(|key| !key.contains("scratch"))
    );
    let capture = signer["jobs"]["capture"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["name"] == "Capture the exact event and authenticated instance authority")
        .unwrap();
    assert!(
        capture["run"]
            .as_str()
            .unwrap()
            .contains("policy_check) command=(new-client policy-check capture)")
    );
}

#[test]
fn provider_probe_caller_passes_only_the_required_named_secrets() {
    let caller = workflow("testing-securefix-server.yml");
    assert_eq!(
        caller["jobs"]["provider-release-probe"]["secrets"],
        serde_json::json!({
            "TERRAFORM_PROVIDER_GPG_PRIVATE_KEY": "${{ secrets.TERRAFORM_PROVIDER_GPG_PRIVATE_KEY }}",
            "TERRAFORM_PROVIDER_GPG_PASSPHRASE": "${{ secrets.TERRAFORM_PROVIDER_GPG_PASSPHRASE }}",
            "SECUREFIX_SERVER_PRIVATE_KEY": "${{ secrets.SECUREFIX_SERVER_PRIVATE_KEY }}"
        })
    );

    let reusable = workflow("testing-provider-release.yml");
    for secret in [
        "TERRAFORM_PROVIDER_GPG_PRIVATE_KEY",
        "TERRAFORM_PROVIDER_GPG_PASSPHRASE",
        "SECUREFIX_SERVER_PRIVATE_KEY",
    ] {
        assert!(
            reusable["on"]["workflow_call"]["secrets"][secret]["required"]
                .as_bool()
                .unwrap_or(false),
            "provider workflow must declare {secret} required"
        );
    }

    for job_id in ["fresh-sign", "recover-sign"] {
        let job = serde_json::to_string(&reusable["jobs"][job_id]).unwrap();
        assert!(job.contains("secrets.TERRAFORM_PROVIDER_GPG_PRIVATE_KEY"));
        assert!(job.contains("secrets.TERRAFORM_PROVIDER_GPG_PASSPHRASE"));
        assert!(!job.contains("secrets.SECUREFIX_SERVER_PRIVATE_KEY"));
        assert!(!job.contains("SECUREFIX_SERVER_APP_TOKEN"));
    }
    for job_id in [
        "create-draft",
        "stage-draft",
        "complete-draft",
        "cleanup-draft",
    ] {
        let job = serde_json::to_string(&reusable["jobs"][job_id]).unwrap();
        assert!(job.contains("secrets.SECUREFIX_SERVER_PRIVATE_KEY"));
        assert!(!job.contains("TERRAFORM_PROVIDER_GPG_PRIVATE_KEY"));
        assert!(!job.contains("TERRAFORM_PROVIDER_GPG_PASSPHRASE"));
    }
}

#[test]
fn merge_workflow_prefilter_allows_whitespace_for_rust_command_validation() {
    let caller = workflow("merge-request.yml");
    let active_if = caller["jobs"]["request"]["if"].as_str().unwrap();
    let template = fs::read_to_string("src/distribution_templates/merge-request.yml")
        .unwrap()
        .replace(
            "@OWNER_ID@",
            &crate::config::trusted().unwrap().owner_id.to_string(),
        );
    for condition in [active_if, &template] {
        assert!(condition.contains("contains(github.event.comment.body, '/merge')"));
        assert!(condition.contains("github.event.issue.pull_request"));
        assert!(condition.contains("github.event.comment.user.id == 4525500"));
        assert!(condition.contains("github.run_attempt == 1"));
        assert!(!condition.contains("github.event.comment.body == '/merge'"));
    }
}

#[test]
fn approval_caller_prefilters_comments_without_disabling_automatic_approval() {
    let template = fs::read_to_string("src/distribution_templates/approve-request.yml")
        .unwrap()
        .replace("@OWNER_ID@", "4525500");
    let template: Value = serde_yaml::from_str(
        &template
            .replace("@SERVER_REPOSITORY@", "example/server")
            .replace("@SECUREFIX_RUNTIME_SHA@", &"a".repeat(40))
            .replace("@RUNTIME_VERSION@", "v0.2.33"),
    )
    .unwrap();
    let condition = template["jobs"]["approve"]["if"].as_str().unwrap();
    assert_eq!(
        condition,
        workflow("approve-request.yml")["jobs"]["request"]["if"]
    );
    assert!(condition.starts_with("github.event_name != 'issue_comment' ||"));
    assert!(condition.contains("github.event.issue.pull_request"));
    assert!(condition.contains("github.event.comment.user.id == 4525500"));
    assert!(condition.contains("contains(github.event.comment.body, '/approve')"));
}

#[test]
fn self_merge_consumes_its_label_before_apply_and_skips_stale_success_writes() {
    let merge = workflow("merge.yml");
    let authorize = &merge["jobs"]["authorize"];
    let job = &merge["jobs"]["apply"];
    assert_eq!(
        job["outputs"]["self_merged"],
        "${{ needs.authorize.outputs.repository == 'civitaspo/securefix-server' && steps.apply.outcome == 'success' }}"
    );
    let steps = job["steps"].as_array().unwrap();
    let position = |id: &str| {
        steps
            .iter()
            .position(|step| step["id"] == id)
            .unwrap_or_else(|| panic!("missing merge step {id}"))
    };
    let merge_token = position("merge-token");
    let token = position("self-cleanup-token");
    let preclean = position("self-cleanup");
    let apply = position("apply");
    let notify_token = position("notify-token");
    let notify = steps
        .iter()
        .position(|step| step["name"] == "Report the terminal result")
        .unwrap();
    assert!(merge_token < token && token < preclean && preclean < apply);
    assert_eq!(steps[merge_token]["if"], "needs.wait.result == 'success'");
    assert_eq!(
        steps[token]["if"],
        "needs.wait.result == 'success' && needs.authorize.outputs.repository == 'civitaspo/securefix-server'"
    );
    assert_eq!(steps[token]["with"]["repositories"], "securefix-server");
    assert_eq!(steps[token]["with"]["permission-issues"], "write");
    assert!(steps[token]["with"].get("permission-contents").is_none());
    assert!(
        steps[token]["with"]
            .get("permission-pull-requests")
            .is_none()
    );
    assert_eq!(steps[preclean]["run"], "securefix merge cleanup");
    assert_eq!(
        steps[preclean]["env"]["GITHUB_TOKEN"],
        "${{ steps.self-cleanup-token.outputs.token }}"
    );
    assert_eq!(
        steps[apply]["if"],
        "needs.wait.result == 'success' && (needs.authorize.outputs.repository != 'civitaspo/securefix-server' || steps.self-cleanup.outcome == 'success')"
    );
    assert_eq!(
        steps[notify_token]["if"],
        "always() && (needs.authorize.outputs.repository != 'civitaspo/securefix-server' || needs.wait.result != 'success' || steps.apply.outcome != 'success')"
    );
    assert_eq!(
        steps[notify]["if"],
        "always() && steps.notify-token.outcome == 'success'"
    );
    assert_eq!(steps[notify]["run"], "securefix merge notify");
    assert_eq!(
        steps[notify]["env"]["SECUREFIX_MERGE_SHA"],
        "${{ steps.apply.outputs.merge_sha }}"
    );
    assert_eq!(
        steps[notify]["env"]["SECUREFIX_MERGE_RESULT"],
        "${{ needs.wait.result == 'success' && steps.apply.outcome || 'wait-failed' }}"
    );
    assert!(apply < notify_token && notify_token < notify);
    assert_eq!(
        authorize["outputs"]["repository"],
        "${{ steps.validate.outputs.repository }}"
    );
    assert!(
        merge["jobs"]["cleanup"]["if"]
            .as_str()
            .unwrap()
            .contains("needs.apply.outputs.self_merged != 'true'")
    );
}

#[test]
fn native_caller_distribution_mints_only_target_scoped_write_credentials() {
    let distribution = workflow("distribute-runtime.yml");
    let job = &distribution["jobs"]["caller"];
    let steps = job["steps"].as_array().unwrap();
    let token = steps
        .iter()
        .find(|step| step["id"] == "server-write-token")
        .unwrap();
    assert_eq!(
        token["with"]["repositories"],
        "${{ steps.prepare.outputs.repository_name }}"
    );
    assert_eq!(token["with"]["permission-contents"], "write");
    assert_eq!(token["with"]["permission-pull-requests"], "write");
    assert!(steps.iter().any(|step| {
        step["run"]
            .as_str()
            .is_some_and(|run| run.contains("securefix distribute apply-caller"))
    }));
}

#[test]
fn release_build_sign_and_publish_keep_credentials_separate() {
    let client: Value =
        serde_yaml::from_slice(&fs::read(".github/workflows/reusable-release-tag.yml").unwrap())
            .unwrap();
    let build = &client["jobs"]["build"];
    assert!(build.get("environment").is_none());
    assert!(!serde_json::to_string(build).unwrap().contains("secrets."));
    assert_eq!(
        build["permissions"],
        serde_json::json!({"actions":"read","attestations":"read","contents":"read","pull-requests":"read"})
    );
    let client_inputs = &client["on"]["workflow_call"]["inputs"];
    assert_eq!(client_inputs["server_repository"]["required"], true);
    assert_eq!(client_inputs["instance_config_path"]["required"], true);
    assert_eq!(client_inputs["release_pr_number"]["type"], "number");
    let production_text = serde_json::to_string(&client).unwrap();
    assert!(!production_text.contains("load-cli.yml"));
    assert!(!production_text.contains("control/active.json"));
    assert!(!production_text.contains("SECUREFIX_SOURCE_SHA"));
    let loader_step_indices = |job: &Value| {
        job["steps"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .filter_map(|(index, step)| {
                step["uses"]
                    .as_str()
                    .is_some_and(|uses| uses.contains("/.github/actions/load-package@"))
                    .then_some(index)
            })
            .collect::<Vec<_>>()
    };
    for job_name in [
        "resolve",
        "build",
        "assemble-native",
        "tag",
        "request-server",
    ] {
        let job = &client["jobs"][job_name];
        let loaders = loader_step_indices(job);
        assert_eq!(loaders.len(), 1, "{job_name} must load the fixed package");
        let loader = &job["steps"][loaders[0]];
        let uses = loader["uses"].as_str().unwrap();
        let fixed_ref = uses
            .strip_prefix("civitaspo/securefix-server/.github/actions/load-package@")
            .unwrap();
        assert_eq!(fixed_ref.len(), 40);
        assert!(fixed_ref.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(fixed_ref, "e392b49ede4052319bd3ca4f859b528a51c07177");
        assert_eq!(
            loader["with"],
            serde_json::json!({"token":"${{ github.token }}"})
        );
    }
    for job_name in ["resolve", "build", "assemble-native", "tag"] {
        let steps = client["jobs"][job_name]["steps"].as_array().unwrap();
        let cli = steps
            .iter()
            .find(|step| {
                step["run"]
                    .as_str()
                    .is_some_and(|run| run.contains("securefix release "))
            })
            .unwrap();
        assert_eq!(
            cli["env"]["SECUREFIX_SERVER_REPOSITORY"],
            "${{ inputs.server_repository }}"
        );
        assert_eq!(
            cli["env"]["SECUREFIX_INSTANCE_CONFIG_PATH"],
            "${{ inputs.instance_config_path }}"
        );
    }
    assert!(
        build["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["with"]["ref"] == "${{ needs.resolve.outputs.merge_sha }}")
    );
    let native = &client["jobs"]["build-native"];
    assert_eq!(native["runs-on"], "${{ matrix.target.runner }}");
    assert_eq!(
        native["permissions"],
        serde_json::json!({"contents":"read"})
    );
    let native_text = serde_json::to_string(native).unwrap();
    for forbidden in [
        "secrets.",
        "create-github-app-token",
        "SECUREFIX_SERVER_PRIVATE_KEY",
        "SECUREFIX_CLIENT_PRIVATE_KEY",
    ] {
        assert!(
            !native_text.contains(forbidden),
            "native builder exposes {forbidden}"
        );
    }
    assert!(native_text.contains("musl-tools"));
    assert!(native_text.contains("cargo build --locked --release --bin"));
    assert!(native_text.contains("--version"));
    assert!(native_text.contains("version_output="));
    let build_step = native["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["name"] == "Build and execute the native binary on its target runner")
        .unwrap();
    assert_eq!(build_step["env"]["RUNNER_OS"], "${{ runner.os }}");
    assert_eq!(build_step["env"]["RUNNER_ARCH"], "${{ runner.arch }}");
    assert_eq!(
        build_step["env"]["NATIVE_SOURCE_SHA"],
        "${{ needs.resolve.outputs.merge_sha }}"
    );
    assert_eq!(
        build_step["env"]["RELEASE_PR_NUMBER"],
        "${{ needs.resolve.outputs.pr_number }}"
    );
    assert!(
        build_step["run"]
            .as_str()
            .unwrap()
            .contains("git rev-parse HEAD")
    );
    assert!(
        build_step["run"]
            .as_str()
            .unwrap()
            .contains("source_run_id:$source_run_id")
    );
    assert!(
        build_step["run"]
            .as_str()
            .unwrap()
            .contains("release_pr_sha:$release_pr_sha")
    );
    assert!(build_step["run"].as_str().unwrap().contains("mktemp -d"));
    let upload = native["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/upload-artifact@"))
        })
        .unwrap();
    assert_eq!(
        upload["with"]["path"],
        "${{ steps.target.outputs.artifact_dir }}/*"
    );
    assert!(
        native_text.contains("native-target-${{ matrix.target.target }}-${{ github.run_attempt }}")
    );
    assert!(native_text.contains("needs.resolve.outputs.native_targets"));
    assert!(!native_text.contains("securefix-runtime"));
    assert!(!native_text.contains("securefix release build-native"));
    for forbidden in ["GITHUB_TOKEN", "GH_TOKEN", "SECUREFIX_SERVER_APP_TOKEN"] {
        assert!(!native_text.contains(forbidden));
    }
    let release_source = include_str!("release.rs");
    assert!(!release_source.contains("fn build_native("));
    let native_assembler = release_source.split_once("fn assemble_native(").unwrap().1;
    assert!(native_assembler.contains("release_execution_context_sha("));
    assert_eq!(
        build_step["env"]["NATIVE_SOURCE_RUN_SHA"],
        "${{ needs.resolve.outputs.source_run_sha }}"
    );
    assert_eq!(
        client["jobs"]["resolve"]["outputs"]["source_run_sha"],
        "${{ steps.resolve.outputs.source_run_sha }}"
    );
    assert!(
        build_step["run"]
            .as_str()
            .unwrap()
            .contains("--arg source_run_sha \"$NATIVE_SOURCE_RUN_SHA\"")
    );
    assert!(native_assembler.contains("build.source_run_id == run_id"));
    assert!(native_assembler.contains("build.source_run_attempt == run_attempt"));
    assert!(native_assembler.contains("build.release_pr_sha == merge_sha"));
    assert!(native_assembler.contains("native-target-{}-{run_attempt}"));
    assert!(native_assembler.contains("validate_native_manifest"));
    assert!(native_assembler.contains("sha256_file(&binary_path)?"));
    let assemble = &client["jobs"]["assemble-native"];
    assert_eq!(
        assemble["permissions"],
        serde_json::json!({"actions":"read","attestations":"read","contents":"read","pull-requests":"read"})
    );
    assert!(
        serde_json::to_string(assemble)
            .unwrap()
            .contains("native-target-*")
    );
    let tag = &client["jobs"]["tag"];
    let tag_if = tag["if"].as_str().unwrap();
    assert!(tag_if.contains("needs.build-native.result == 'success'"));
    assert!(tag_if.contains("needs.assemble-native.result == 'success'"));
    assert!(!tag_if.contains("needs.build-native.result == 'failure'"));
    assert!(
        tag["needs"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("assemble-native"))
    );
    assert!(
        serde_json::to_string(tag)
            .unwrap()
            .contains("needs.assemble-native.outputs.artifact_id")
    );
    assert!(
        serde_json::to_string(tag)
            .unwrap()
            .contains("RELEASE_BUNDLE_ARTIFACT_ID")
    );
    let attest = &client["jobs"]["attest-manifest"];
    assert_eq!(
        attest["permissions"],
        serde_json::json!({
            "actions":"read", "contents":"read", "id-token":"write", "attestations":"write"
        })
    );
    let attest_text = serde_json::to_string(attest).unwrap();
    assert!(attest_text.contains("needs.tag.outputs.manifest_artifact_id"));
    assert!(attest_text.contains("release-proof/manifest.json"));
    assert!(attest_text.contains("release-proof/bundle.json"));
    for forbidden in [
        "SECUREFIX_CLIENT_PRIVATE_KEY",
        "create-github-app-token",
        "SECUREFIX_SERVER_TOKEN",
    ] {
        assert!(
            !attest_text.contains(forbidden),
            "manifest attestor exposes {forbidden}"
        );
    }
    let request = &client["jobs"]["request-server"];
    assert!(
        request["needs"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("attest-manifest"))
    );
    let request_text = serde_json::to_string(request).unwrap();
    assert!(request_text.contains("SECUREFIX_CLIENT_PRIVATE_KEY"));
    assert!(request_text.contains("securefix release request-server"));
    let server: Value =
        serde_yaml::from_slice(&fs::read(".github/workflows/release.yml").unwrap()).unwrap();
    let preflight_steps = server["jobs"]["preflight"]["steps"].as_array().unwrap();
    let preflight_token = preflight_steps
        .iter()
        .find(|step| step["id"] == "client-token")
        .unwrap();
    assert_eq!(
        preflight_token["with"]["repositories"],
        "${{ needs.resolve-request.outputs.repo_name }}"
    );
    assert_eq!(
        preflight_token["with"]["permission-contents"], "write",
        "draft-release inspection requires a push-scoped installation token"
    );
    for (permission, expected) in [
        ("permission-actions", "read"),
        ("permission-pull-requests", "read"),
    ] {
        assert_eq!(preflight_token["with"][permission], expected);
    }
    for permission in [
        "permission-administration",
        "permission-issues",
        "permission-workflows",
    ] {
        assert!(preflight_token["with"].get(permission).is_none());
    }
    let sign = &server["jobs"]["sign"];
    let sign_text = serde_json::to_string(sign).unwrap();
    assert!(sign_text.contains("TERRAFORM_PROVIDER_GPG_PRIVATE_KEY"));
    for forbidden in [
        "SECUREFIX_SERVER_PRIVATE_KEY",
        "SECUREFIX_CLIENT_PRIVATE_KEY",
        "create-github-app-token",
        "actions/checkout",
        "setup-go",
        "mise-action",
        "goreleaser",
    ] {
        assert!(!sign_text.contains(forbidden), "signer exposes {forbidden}");
    }
    assert_eq!(
        sign["permissions"],
        serde_json::json!({"contents":"read","actions":"read"})
    );
    let publish = serde_json::to_string(&server["jobs"]["publish"]).unwrap();
    assert!(
        publish.contains("permission-contents") && publish.contains("SECUREFIX_SERVER_PRIVATE_KEY")
    );
    for forbidden in ["TERRAFORM_PROVIDER_GPG", "actions/checkout", "goreleaser"] {
        assert!(
            !publish.contains(forbidden),
            "publisher exposes {forbidden}"
        );
    }
}

#[test]
fn policy_feedback_token_can_comment_on_pull_requests_without_contents_write() {
    let policy = workflow("policy-check.yml");
    let steps = policy["jobs"]["process"]["steps"].as_array().unwrap();
    let token = |id| steps.iter().find(|step| step["id"] == id).unwrap();
    let write = &token("write")["with"];
    assert_eq!(write["permission-checks"], "write");
    assert_eq!(write["permission-issues"], "write");
    assert_eq!(write["permission-pull-requests"], "write");
    assert_eq!(
        write["repositories"],
        "${{ steps.locate.outputs.repository_name }}"
    );
    assert!(write.get("permission-contents").is_none());
    assert_eq!(token("read")["with"]["permission-pull-requests"], "read");
}

#[test]
fn integration_testing_documents_the_active_control_review_marker() {
    let docs = fs::read_to_string("docs/integration-testing.md").unwrap();
    assert!(docs.contains("<!-- securefix:control-review:<control-id> -->"));
    assert!(!docs.contains("securefix:v3:approval:"));

    for source in ["src/request.rs", "src/approval.rs"] {
        let source = fs::read_to_string(source).unwrap();
        assert!(
            source.contains("<!-- securefix:control-review:{} -->"),
            "the documented review marker must match the production marker template"
        );
    }
}

#[test]
fn operational_workflows_do_not_request_administration_or_settings_credentials() {
    for (path, value) in workflows() {
        if path.ends_with("/repo-settings.yml") {
            continue;
        }
        for (job_id, job) in value["jobs"].as_object().unwrap() {
            for step in job["steps"].as_array().into_iter().flatten() {
                assert!(
                    step["with"].get("permission-administration").is_none(),
                    "{path} {job_id} requests Administration for an operational step"
                );
            }
        }
        assert!(
            !serde_json::to_string(&value)
                .unwrap()
                .contains("CIVITASPO_PUBLIC_REPO_SETTINGS_TOKEN"),
            "{path} exposes the repository-settings administrator credential"
        );
    }
}

#[test]
fn reusable_callers_grant_required_permissions() {
    let mut callers = workflows();
    let server = &crate::config::trusted()
        .unwrap()
        .deployment
        .server
        .repository;
    for (path, bytes) in
        crate::distribution::caller::rendered_files(&"a".repeat(40), "v0.2.22", "main", true)
            .unwrap()
    {
        if path == ".github/workflows/release-tag.yml" {
            // This legacy renderer is still tied to the retired runtime lane;
            // the current reusable contract is checked with the separate
            // adoption-time managed Client pin below.
            continue;
        }
        let mut value: Value = serde_yaml::from_slice(&bytes).unwrap();
        for job in value["jobs"].as_object_mut().unwrap().values_mut() {
            let uses = job["uses"].as_str().unwrap();
            let local = uses
                .strip_prefix(&format!("{server}/"))
                .unwrap()
                .split('@')
                .next()
                .unwrap();
            job["uses"] = Value::String(format!("./{local}"));
        }
        callers.push((format!("generated:{path}"), value));
    }
    let instance = securefix::instance_config::InstanceConfig::parse(include_bytes!(
        "../tests/fixtures/instance-config.toml"
    ))
    .unwrap();
    let client_pin = crate::distribution::caller::ClientImplementationPin::new(
        &instance.acceptable_clients.repository,
        &"b".repeat(40),
        "1.4.2",
    )
    .unwrap();
    let managed = crate::distribution::caller::render_managed_client_release_tag_from_template(
        &instance.acceptable_clients,
        &client_pin,
        &instance.instance.repository,
        "securefix-server.toml",
        include_bytes!("distribution_templates/managed-client-release-tag.yml"),
    )
    .unwrap();
    let mut managed: Value = serde_yaml::from_slice(&managed).unwrap();
    managed["jobs"]["tag"]["uses"] =
        Value::String("./.github/workflows/reusable-release-tag.yml".into());
    callers.push(("managed-client-release-tag".into(), managed));
    for (path, value) in callers {
        for (job_id, job) in value["jobs"].as_object().unwrap() {
            let Some(callee) = job["uses"]
                .as_str()
                .and_then(|uses| uses.strip_prefix("./.github/workflows/"))
            else {
                continue;
            };
            let called = workflow(callee);
            for (nested_id, nested) in called["jobs"].as_object().unwrap() {
                for (permission, required) in nested["permissions"].as_object().unwrap() {
                    let granted = job["permissions"][permission].as_str().unwrap_or("none");
                    assert!(
                        match required.as_str().unwrap() {
                            "none" => true,
                            "read" => matches!(granted, "read" | "write"),
                            "write" => granted == "write",
                            other => panic!("unsupported permission {other}"),
                        },
                        "{path} {job_id} grants {permission}:{granted}, but {callee} {nested_id} needs {required}"
                    );
                }
            }
        }
    }
}

#[test]
fn server_approval_token_is_only_exposed_to_the_apply_step() {
    let workflow = workflow("reusable-server-approve.yml");
    let job = &workflow["jobs"]["receive"];
    assert_eq!(workflow["permissions"], serde_json::json!({}));
    assert_eq!(job["environment"], "main");
    assert_eq!(job["permissions"]["contents"], "read");
    let steps = job["steps"].as_array().unwrap();
    let validate = steps
        .iter()
        .find(|step| step["name"] == "Validate the owner approval without a write credential")
        .unwrap();
    assert!(validate["env"]["SECUREFIX_APPROVE_TOKEN"].is_null());
    let apply = steps
        .iter()
        .find(|step| step["name"] == "Apply the owner approval after revalidation")
        .unwrap();
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
fn scratch_managed_file_writer_is_separate_from_repository_settings_admin() {
    let workflow = workflow("testing-securefix-server.yml");
    let client_repository = &workflow["on"]["workflow_dispatch"]["inputs"]["client_repository"];
    let client_sha = &workflow["on"]["workflow_dispatch"]["inputs"]["client_implementation_sha"];
    let client_version = &workflow["on"]["workflow_dispatch"]["inputs"]["client_version"];
    for input in [client_repository, client_sha, client_version] {
        let description = input["description"].as_str().unwrap_or_default();
        let description = description.to_ascii_lowercase();
        assert!(
            description.contains("owner-selected") || description.contains("owner-supplied"),
            "{description}"
        );
        assert!(description.contains("scratch-only"), "{description}");
    }
    assert!(
        client_repository["description"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("provenance is not qualified")
    );
    assert!(
        client_version["description"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("provenance is not qualified")
    );
    let validation_script = workflow["jobs"]["managed-files-probe"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| {
            step["name"] == "Validate the exact selected candidate before minting a writer token"
        })
        .unwrap()["run"]
        .as_str()
        .unwrap();
    assert!(
        validation_script
            .contains("owner-selected Client pin tuple is required for this scratch-only probe")
    );

    let managed = &workflow["jobs"]["managed-files-probe"];
    assert!(
        managed.is_object(),
        "managed-file reconciliation has its own job"
    );
    let integration_prepare =
        serde_json::to_string(&workflow["jobs"]["scratch"]).unwrap_or_default();
    assert!(
        !integration_prepare.contains("managed-reconcile-scratch"),
        "integration preparation must not mint the managed-file writer token"
    );
    assert_eq!(managed["permissions"]["contents"], "read");
    assert_eq!(managed["permissions"]["pull-requests"], Value::Null);
    let steps = managed["steps"].as_array().unwrap();
    let writer = steps
        .iter()
        .find(|step| step["id"] == "managed-writer")
        .unwrap();
    assert_eq!(writer["with"]["permission-contents"], "write");
    assert_eq!(writer["with"]["permission-pull-requests"], "write");
    assert_eq!(writer["with"]["permission-workflows"], "write");
    assert!(writer["with"].get("permission-administration").is_none());
    let reconcile = steps
        .iter()
        .find(|step| {
            step["name"] == "Create the reviewable managed-file PR from the selected source"
        })
        .unwrap();
    assert_eq!(
        reconcile["env"]["SECUREFIX_SERVER_APP_TOKEN"],
        "${{ steps.managed-writer.outputs.token }}"
    );
    assert!(
        reconcile["run"]
            .as_str()
            .unwrap()
            .contains("settings managed-reconcile-scratch --source-sha")
    );
    let serialized = serde_json::to_string(&managed).unwrap();
    assert!(!serialized.contains("CIVITASPO_PUBLIC_REPO_SETTINGS_TOKEN"));
}

#[test]
fn server_release_receiver_keeps_read_write_and_cleanup_credentials_separate() {
    let workflow = workflow("reusable-server-release.yml");
    assert_eq!(workflow["permissions"], serde_json::json!({}));
    assert_eq!(
        workflow["on"]["workflow_call"]["inputs"]["config_path"]["required"],
        true
    );
    assert_eq!(
        workflow["on"]["workflow_call"]["secrets"]["SERVER_PRIVATE_KEY"]["required"],
        true
    );
    let jobs = &workflow["jobs"];
    let parse = jobs["parse"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "parse")
        .unwrap();
    assert!(
        parse["run"]
            .as_str()
            .unwrap()
            .contains("release parse-request")
    );
    let preflight = jobs["preflight"]["steps"].as_array().unwrap();
    let preflight_writer = preflight
        .iter()
        .find(|step| step["id"] == "release-read")
        .unwrap();
    assert_eq!(preflight_writer["with"]["permission-contents"], "write");
    assert_eq!(preflight_writer["with"]["permission-issues"], "read");
    assert_eq!(preflight_writer["with"]["permission-pull-requests"], "read");
    let sign = &jobs["sign"];
    assert_eq!(
        sign["if"],
        "needs.preflight.outputs.strategy == 'terraform-provider'"
    );
    let sign_json = serde_json::to_string(sign).unwrap();
    assert!(sign_json.contains("TERRAFORM_PROVIDER_GPG_PRIVATE_KEY"));
    assert!(sign_json.contains("TERRAFORM_PROVIDER_GPG_PASSPHRASE"));
    let publish = jobs["publish"]["steps"].as_array().unwrap();
    let read = publish
        .iter()
        .find(|step| step["id"] == "release-read")
        .unwrap();
    let write = publish
        .iter()
        .find(|step| step["id"] == "release-write")
        .unwrap();
    assert_eq!(read["with"]["permission-contents"], "read");
    assert_eq!(read["with"]["permission-issues"], "read");
    assert_eq!(write["with"]["permission-contents"], "write");
    let publisher = publish
        .iter()
        .find(|step| step["name"] == "Revalidate and publish the immutable Client release")
        .unwrap();
    assert_eq!(
        publisher["env"]["SECUREFIX_RELEASE_READ_TOKEN"],
        "${{ steps.release-read.outputs.token }}"
    );
    assert_eq!(
        publisher["env"]["SECUREFIX_RELEASE_WRITE_TOKEN"],
        "${{ steps.release-write.outputs.token }}"
    );
    assert_eq!(
        publish
            .iter()
            .filter(|step| step["env"]["SECUREFIX_RELEASE_WRITE_TOKEN"].is_string())
            .count(),
        1,
        "release writer token is exposed only to the final publish command"
    );
    let publish_json = serde_json::to_string(&jobs["publish"]).unwrap();
    assert!(!publish_json.contains("TERRAFORM_PROVIDER_GPG_PRIVATE_KEY"));
    assert!(!publish_json.contains("TERRAFORM_PROVIDER_GPG_PASSPHRASE"));
    assert!(publish_json.contains("needs.sign.outputs.artifact_id"));
    let cleanup = &jobs["cleanup"];
    assert_eq!(cleanup["permissions"]["issues"], "write");
    assert_eq!(cleanup["permissions"]["contents"], "read");
    assert!(
        !serde_json::to_string(cleanup)
            .unwrap()
            .contains("SECUREFIX_RELEASE_WRITE_TOKEN")
    );
    let all = serde_json::to_string(&workflow).unwrap();
    assert!(all.contains("TERRAFORM_PROVIDER_GPG_PRIVATE_KEY"));
    assert!(all.contains("TERRAFORM_PROVIDER_GPG_PASSPHRASE"));
}

#[test]
fn server_role_receivers_use_fixed_package_and_separate_read_and_write_credentials() {
    for role in ["securefix", "approve", "merge"] {
        let receiver = workflow(&format!("testing-native-{role}-event.yml"));
        assert_eq!(
            receiver["jobs"]["handler"]["concurrency"],
            serde_json::json!({
                "group": "securefix-testing-native-control", "cancel-in-progress": false, "queue": "max"
            })
        );
        let template: serde_yaml::Value = serde_yaml::from_str(
            &fs::read_to_string(format!("repo-settings/managed-files/server-{role}.yml"))
                .unwrap()
                .replace("@SERVER_REPOSITORY@", "example/server")
                .replace("@SECUREFIX_RUNTIME_SHA@", &"a".repeat(40))
                .replace("@RUNTIME_VERSION@", "v1.0.0"),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&template["jobs"]["handler"]["concurrency"]).unwrap(),
            serde_json::json!({
                "group": "securefix-control", "cancel-in-progress": false, "queue": "max"
            })
        );
    }
    for role in ["policy-check", "securefix", "approve", "merge"] {
        let workflow = workflow(&format!("reusable-server-{role}.yml"));
        assert_eq!(workflow["permissions"], serde_json::json!({}), "{role}");
        let job = &workflow["jobs"]["receive"];
        assert_eq!(job["environment"], "main", "{role}");
        for permission in [
            "actions",
            "attestations",
            "checks",
            "contents",
            "issues",
            "pull-requests",
            "statuses",
        ] {
            assert_eq!(
                job["permissions"][permission], "read",
                "{role}: {permission}"
            );
        }
        let serialized = serde_json::to_string(&workflow).unwrap();
        assert!(serialized.contains("config_path"), "{role}");
        assert!(serialized.contains("secrets.SERVER_PRIVATE_KEY"), "{role}");
        assert!(!serialized.contains("SECUREFIX_SOURCE_SHA"), "{role}");
        assert!(!serialized.contains("load-cli.yml"), "{role}");
        let steps = job["steps"].as_array().unwrap();
        let loader = steps.iter().find(|step| step["id"] == "package").unwrap();
        assert_eq!(
            loader["with"],
            serde_json::json!({"token":"${{ github.token }}"})
        );
        assert!(loader["uses"].as_str().unwrap().contains("@"));
        for mint in steps.iter().filter(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.contains("create-github-app-token"))
        }) {
            assert_eq!(
                mint["with"]["owner"],
                "${{ steps.request.outputs.producer_owner }}"
            );
            assert_eq!(
                mint["with"]["repositories"],
                "${{ steps.request.outputs.producer_repository_name }}"
            );
            assert!(mint["with"].get("permission-administration").is_none());
        }
    }
}

#[test]
#[cfg(unix)]
fn setup_cli_reuses_only_a_digest_and_source_bound_ci_artifact() {
    use std::{io::Write, os::unix::fs::PermissionsExt, process::Command};

    let action_source = fs::read(".github/actions/setup-cli/reuse-build.sh").unwrap();
    let stubs = [
        (
            "gh",
            r#"#!/usr/bin/env bash
set -euo pipefail
case "$2" in
  repos/civitaspo/securefix-server)
    printf '{"id":1250079425,"full_name":"civitaspo/securefix-server"}\n'
    ;;
  repos/civitaspo/securefix-server/actions/workflows/ci.yml/runs*)
    if [[ "$MOCK_MODE" == candidate-* ]]; then
      printf '{"total_count":0,"workflow_runs":[]}'
      exit 0
    fi
    printf '{"total_count":1,"workflow_runs":[{"id":39212230237,"path":".github/workflows/ci.yml","event":"push","head_branch":"main","head_sha":"%s","repository":{"id":1250079425,"full_name":"civitaspo/securefix-server"},"head_repository":{"id":1250079425,"full_name":"civitaspo/securefix-server"},"status":"completed","conclusion":"success","run_attempt":1}]}\n' "$MOCK_RUN_SHA"
    ;;
  repos/civitaspo/securefix-server/actions/runs/39212230238)
    run_sha="$MOCK_WORKFLOW_SHA"
    printf '{"id":39212230238,"path":".github/workflows/testing-securefix-server.yml@refs/heads/main","event":"workflow_dispatch","head_branch":"main","head_sha":"%s","repository":{"id":1250079425,"full_name":"civitaspo/securefix-server"},"head_repository":{"id":1250079425,"full_name":"civitaspo/securefix-server"},"status":"completed","conclusion":"success","run_attempt":1,"actor":{"id":4525500},"triggering_actor":{"id":4525500}}\n' "$run_sha"
    ;;
  repos/civitaspo/securefix-server/actions/runs/39212230238/artifacts*)
    digest="$MOCK_CANDIDATE_DIGEST"
    [[ "$MOCK_MODE" != *digest-mismatch ]] || digest=0000000000000000000000000000000000000000000000000000000000000000
    printf '{"artifacts":[{"id":12171131611,"name":"candidate-runtime","expired":false,"size_in_bytes":5000,"digest":"sha256:%s","workflow_run":{"id":39212230238,"repository_id":1250079425,"head_repository_id":1250079425,"head_branch":"main","head_sha":"%s"}}]}\n' "$digest" "$MOCK_WORKFLOW_SHA"
    ;;
  repos/civitaspo/securefix-server/actions/runs/39212230237/artifacts*)
    printf '{"artifacts":[{"id":12171131610,"name":"securefix-cli-ubuntu-24.04-x64-rust-1.99.0-%s","expired":false,"size_in_bytes":5000,"digest":"sha256:%s","workflow_run":{"id":39212230237,"repository_id":1250079425,"head_repository_id":1250079425,"head_branch":"main","head_sha":"%s"}}]}\n' "$MOCK_RUN_SHA" "$MOCK_DIGEST" "$MOCK_RUN_SHA"
    ;;
  repos/civitaspo/securefix-server/actions/artifacts/12171131610/zip)
    cat "$MOCK_ARCHIVE"
    ;;
  repos/civitaspo/securefix-server/actions/artifacts/12171131611/zip)
    cat "$MOCK_CANDIDATE_ARCHIVE"
    ;;
  *) exit 2 ;;
esac
"#,
        ),
        (
            "uname",
            "#!/usr/bin/env bash\nif [[ \"${1:-}\" == -s ]]; then echo Linux; else echo x86_64; fi\n",
        ),
        (
            "stat",
            "#!/usr/bin/env bash\n[[ \"$1\" == -c && \"$2\" == %s ]]\nwc -c < \"$3\" | tr -d ' '\n",
        ),
        (
            "sha256sum",
            "#!/usr/bin/env bash\nshasum -a 256 \"$1\" | awk '{print $1}'\n",
        ),
    ];
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    for (name, body) in stubs {
        let path = bin.join(name);
        fs::write(&path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let repository = temp.path().join("repo");
    let action = temp.path().join("_actions/setup-cli");
    fs::create_dir_all(&repository).unwrap();
    fs::create_dir_all(&action).unwrap();
    fs::write(action.join("reuse-build.sh"), action_source).unwrap();
    fs::write(repository.join("policy.json"), b"{\"policy\":true}\n").unwrap();

    let git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(&repository)
            .output()
            .unwrap()
    };
    assert!(git(&["init", "-q"]).status.success());
    assert!(
        git(&["config", "user.email", "workflow-test@example.invalid"])
            .status
            .success()
    );
    assert!(
        git(&["config", "user.name", "Workflow test"])
            .status
            .success()
    );
    assert!(git(&["add", "."]).status.success());
    assert!(
        git(&["-c", "commit.gpgsign=false", "commit", "-qm", "source"])
            .status
            .success()
    );
    let source_sha = String::from_utf8(git(&["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_owned();

    let archive_path = temp.path().join("artifact.zip");
    let mut zip = zip::ZipWriter::new(fs::File::create(&archive_path).unwrap());
    zip.start_file("securefix", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"verified executable bytes").unwrap();
    zip.start_file("policy.json", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(b"{\"policy\":true}\n").unwrap();
    zip.finish().unwrap();
    let artifact_digest = {
        use sha2::{Digest, Sha256};
        crate::hex_encode(Sha256::digest(fs::read(&archive_path).unwrap()))
    };

    for (scenario, run_sha, reported_digest, expected_reuse, mode) in [
        (
            "valid",
            source_sha.as_str(),
            artifact_digest.as_str(),
            true,
            "ci",
        ),
        (
            "source-mismatch",
            "0000000000000000000000000000000000000000",
            artifact_digest.as_str(),
            false,
            "ci",
        ),
        (
            "digest-mismatch",
            source_sha.as_str(),
            "0000000000000000000000000000000000000000000000000000000000000000",
            false,
            "ci",
        ),
        (
            "candidate-valid",
            source_sha.as_str(),
            artifact_digest.as_str(),
            true,
            "candidate-valid",
        ),
        (
            "candidate-pr-target-valid",
            source_sha.as_str(),
            artifact_digest.as_str(),
            true,
            "candidate-pr-target-valid",
        ),
        (
            "candidate-source-mismatch",
            source_sha.as_str(),
            artifact_digest.as_str(),
            false,
            "candidate-source-mismatch",
        ),
        (
            "candidate-build-mismatch",
            source_sha.as_str(),
            artifact_digest.as_str(),
            false,
            "candidate-build-mismatch",
        ),
        (
            "candidate-digest-mismatch",
            source_sha.as_str(),
            artifact_digest.as_str(),
            false,
            "candidate-digest-mismatch",
        ),
        (
            "candidate-pr-target-digest-mismatch",
            source_sha.as_str(),
            artifact_digest.as_str(),
            false,
            "candidate-pr-target-digest-mismatch",
        ),
    ] {
        let scenario_dir = temp.path().join(scenario);
        fs::create_dir_all(&scenario_dir).unwrap();
        let output = scenario_dir.join("github-output");
        fs::write(&output, "").unwrap();
        let workflow_sha = "a".repeat(40);
        let candidate_archive = scenario_dir.join("candidate.zip");
        let mut candidate_zip = zip::ZipWriter::new(fs::File::create(&candidate_archive).unwrap());
        candidate_zip
            .start_file("securefix", zip::write::SimpleFileOptions::default())
            .unwrap();
        candidate_zip
            .write_all(b"verified executable bytes")
            .unwrap();
        candidate_zip
            .start_file("policy.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        candidate_zip.write_all(b"{\"policy\":true}\n").unwrap();
        candidate_zip
            .start_file("build.json", zip::write::SimpleFileOptions::default())
            .unwrap();
        let candidate_source = if mode == "candidate-source-mismatch" {
            "0".repeat(40)
        } else {
            source_sha.clone()
        };
        let platform = if mode == "candidate-build-mismatch" {
            "ubuntu-22.04"
        } else {
            "ubuntu-24.04-x86_64"
        };
        let manifest = serde_json::json!({"source_sha":candidate_source,"workflow_sha":workflow_sha,"platform":platform,"rust":"1.99.0","profile":"release","locked":true});
        candidate_zip
            .write_all(serde_json::to_string(&manifest).unwrap().as_bytes())
            .unwrap();
        candidate_zip.finish().unwrap();
        let candidate_digest = {
            use sha2::{Digest, Sha256};
            crate::hex_encode(Sha256::digest(fs::read(&candidate_archive).unwrap()))
        };
        let mut command = Command::new("bash");
        let result = command
            .arg(action.join("reuse-build.sh"))
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            )
            .env("ACTION_PATH", &action)
            .env("GITHUB_WORKSPACE", &repository)
            .env(
                "EVENT_NAME",
                if mode.starts_with("candidate-pr-target-") {
                    "pull_request_target"
                } else {
                    "workflow_dispatch"
                },
            )
            .env("ImageOS", "ubuntu24")
            .env("RUNNER_TEMP", &scenario_dir)
            .env("GITHUB_OUTPUT", &output)
            .env("GH_TOKEN", "stub")
            .env(
                "CANDIDATE_RUN_ID",
                if mode.starts_with("candidate-") {
                    "39212230238"
                } else {
                    ""
                },
            )
            .env("MOCK_MODE", mode)
            .env("MOCK_RUN_SHA", run_sha)
            .env("MOCK_WORKFLOW_SHA", &workflow_sha)
            .env("MOCK_DIGEST", reported_digest)
            .env("MOCK_ARCHIVE", &archive_path)
            .env("MOCK_CANDIDATE_ARCHIVE", &candidate_archive)
            .env("MOCK_CANDIDATE_DIGEST", candidate_digest)
            .output()
            .unwrap();
        if mode.starts_with("candidate-pr-target-") && !expected_reuse {
            assert!(!result.status.success(), "{scenario} must fail closed");
        } else {
            assert!(
                result.status.success(),
                "{scenario}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        let output = fs::read_to_string(output).unwrap();
        if expected_reuse {
            assert!(
                String::from_utf8_lossy(&result.stdout).contains("Reused "),
                "{scenario}: stdout={} stderr={}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(output.contains("reused=true\n"));
            assert!(output.contains(&format!(
                "binary={}/target/release/securefix",
                repository.display()
            )));
            assert_eq!(
                fs::read(repository.join("target/release/securefix")).unwrap(),
                b"verified executable bytes"
            );
            fs::remove_dir_all(repository.join("target")).unwrap();
        } else {
            assert!(
                output.is_empty(),
                "{scenario} unexpectedly selected an artifact"
            );
        }
    }
}

#[test]
fn lockfile_covers_every_workflow_and_ci_verifies_the_official_format() {
    let lock: Value =
        serde_yaml::from_slice(include_bytes!("../.github/workflows/actions.lock")).unwrap();
    let entries = lock["workflows"].as_object().unwrap();
    let workflow_files = workflows();
    assert_eq!(entries.len(), workflow_files.len());
    for (path, _) in workflow_files {
        assert!(
            entries.contains_key(&path),
            "missing lockfile workflow {path}"
        );
    }
    let ci = workflow("ci.yml");
    let steps = ci["jobs"]["workflows"]["steps"].as_array().unwrap();
    let install = steps
        .iter()
        .position(|s| s["uses"] == "$/.github/actions/install-actions-lock")
        .unwrap();
    let verify = steps
        .iter()
        .position(|s| s["run"] == "gh-actions-lock --verify")
        .unwrap();
    assert!(install < verify);
}

#[test]
fn production_native_package_workflows_isolate_build_preflight_and_publisher_write() {
    let build = workflow("native-package-build.yml");
    assert_eq!(build["permissions"], serde_json::json!({}));
    let build_job = &build["jobs"]["build"];
    let build_guard = build_job["if"].as_str().unwrap();
    for required in [
        "github.repository == 'civitaspo/securefix-server'",
        "github.actor_id == '4525500'",
        "github.event_name == 'workflow_dispatch'",
        "github.run_attempt == 1",
        "github.sha == github.workflow_sha",
    ] {
        assert!(build_guard.contains(required));
    }
    assert_eq!(
        build_job["permissions"],
        serde_json::json!({"contents":"read"})
    );
    let build_steps = build_job["steps"].as_array().unwrap();
    let checkout = build_steps
        .iter()
        .find(|step| step["uses"] == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1")
        .unwrap();
    assert_eq!(checkout["with"]["ref"], "${{ github.sha }}");
    assert_eq!(checkout["with"]["persist-credentials"], false);
    assert!(build_steps.iter().any(|step| {
        step["run"].as_str().is_some_and(|run| {
            run.contains("cargo +1.99.0 test --locked")
                && run.contains("cargo +1.99.0 build --locked --release --bin securefix")
        })
    }));
    let serialized_build = serde_json::to_string(build_job).unwrap();
    assert!(!serialized_build.contains("secrets."));
    assert!(!serialized_build.contains("id-token"));
    assert!(!serialized_build.contains("permission-contents: write"));

    let attest = &build["jobs"]["attest"];
    assert_eq!(attest["needs"], "build");
    assert_eq!(
        attest["permissions"],
        serde_json::json!({"actions":"read", "contents":"read", "id-token":"write", "attestations":"write"})
    );
    let attest_steps = attest["steps"].as_array().unwrap();
    assert!(attest_steps.iter().any(|step| {
        step["uses"] == "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"
            && step["with"]["subject-path"] == "package/securefix-linux-x86_64"
    }));
    assert!(attest_steps.iter().all(|step| {
        step["run"]
            .as_str()
            .is_none_or(|run| !run.contains("cargo "))
    }));

    let publisher = workflow("publish-native-package.yml");
    assert_eq!(publisher["permissions"], serde_json::json!({}));
    let inputs = &publisher["on"]["workflow_dispatch"]["inputs"];
    assert_eq!(inputs["producer_run_id"]["required"], true);
    assert_eq!(inputs["preflight_only"]["required"], false);
    assert_eq!(inputs["preflight_only"]["default"], false);
    assert_eq!(inputs["preflight_only"]["type"], "boolean");
    assert_eq!(
        inputs["channel"]["options"],
        serde_json::json!(["stable", "scratch"])
    );
    let host = &publisher["jobs"]["host-build"];
    let host_guard = host["if"].as_str().unwrap();
    for required in [
        "github.repository == 'civitaspo/securefix-server'",
        "github.actor_id == '4525500'",
        "github.ref == 'refs/heads/main'",
        "github.run_attempt == 1",
        "github.sha == github.workflow_sha",
    ] {
        assert!(host_guard.contains(required));
    }
    assert_eq!(host["permissions"], serde_json::json!({"contents":"read"}));
    let host_steps = host["steps"].as_array().unwrap();
    let host_checkout = host_steps
        .iter()
        .find(|step| step["uses"] == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1")
        .unwrap();
    assert_eq!(host_checkout["with"]["ref"], "${{ github.workflow_sha }}");
    assert_eq!(host_checkout["with"]["persist-credentials"], false);
    let host_text = serde_json::to_string(host).unwrap();
    assert!(!host_text.contains("secrets."));
    assert!(!host_text.contains("id-token"));
    assert!(!host_text.contains("SECUREFIX_PACKAGE_TOKEN"));

    let publish = &publisher["jobs"]["publish"];
    assert_eq!(publish["needs"], "host-build");
    assert_eq!(publish["environment"], "main");
    assert_eq!(
        publish["permissions"],
        serde_json::json!({"actions":"read", "contents":"read", "attestations":"read"})
    );
    let steps = publish["steps"].as_array().unwrap();
    let host_download = steps
        .iter()
        .find(|step| {
            step["uses"] == "actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0"
        })
        .unwrap();
    assert_eq!(
        host_download["with"]["artifact-ids"],
        "${{ needs.host-build.outputs.artifact-id }}"
    );
    let validate_host = steps
        .iter()
        .position(|step| step["name"] == "Validate the trusted publisher host and dispatch inputs")
        .unwrap();
    let preflight = steps
        .iter()
        .position(|step| step["id"] == "preflight")
        .unwrap();
    let writer = steps
        .iter()
        .position(|step| step["id"] == "writer")
        .unwrap();
    let publish_step = steps
        .iter()
        .position(|step| step["name"] == "Publish the exact attested executable")
        .unwrap();
    assert!(validate_host < preflight && preflight < writer && writer < publish_step);
    let read_only_record = steps
        .iter()
        .position(|step| step["name"] == "Record the read-only package preflight")
        .unwrap();
    assert!(preflight < read_only_record && read_only_record < writer);
    for step in [&steps[writer], &steps[publish_step]] {
        assert!(
            step["if"]
                .as_str()
                .unwrap()
                .contains("inputs.preflight_only != true")
        );
    }
    let validate_host_run = steps[validate_host]["run"].as_str().unwrap();
    for check in [
        "[[ -f publisher/securefix && ! -L publisher/securefix ]]",
        "test -x publisher/securefix",
        "test -s publisher/securefix",
    ] {
        assert!(validate_host_run.contains(check));
    }
    assert_eq!(
        steps[preflight]["env"]["GITHUB_TOKEN"],
        "${{ github.token }}"
    );
    assert!(
        steps[preflight]["env"]
            .get("SECUREFIX_PACKAGE_TOKEN")
            .is_none()
    );
    assert!(
        steps[preflight]["env"]
            .get("SECUREFIX_PACKAGE_PUBLISH_TOKEN")
            .is_none()
    );
    assert_eq!(
        steps[writer]["with"]["repositories"],
        "${{ inputs.channel == 'stable' && 'securefix-server' || 'testing-securefix-server' }}"
    );
    assert_eq!(
        steps[writer]["if"],
        "steps.preflight.outputs.already-published != 'true' && inputs.preflight_only != true"
    );
    assert_eq!(steps[writer]["with"]["permission-contents"], "write");
    assert!(
        steps[writer]["with"]
            .get("permission-administration")
            .is_none()
    );
    assert_eq!(
        steps[publish_step]["env"]["GITHUB_TOKEN"],
        "${{ github.token }}"
    );
    assert_eq!(
        steps[publish_step]["env"]["SECUREFIX_PACKAGE_TOKEN"],
        "${{ inputs.channel == 'scratch' && steps.writer.outputs.token || '' }}"
    );
    assert_eq!(
        steps[publish_step]["env"]["SECUREFIX_PACKAGE_PUBLISH_TOKEN"],
        "${{ inputs.channel == 'stable' && steps.writer.outputs.token || '' }}"
    );
    assert_eq!(
        steps[publish_step]["if"],
        "steps.preflight.outputs.already-published != 'true' && inputs.preflight_only != true"
    );
    assert!(
        !serde_json::to_string(publish)
            .unwrap()
            .contains("permission-administration")
    );
}
