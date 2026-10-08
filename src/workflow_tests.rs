use serde_json::Value;
use std::fs;

fn workflows() -> Vec<(String, Value)> {
    fs::read_dir(".github/workflows")
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let value: Value = serde_yaml::from_slice(&fs::read(&path).unwrap()).unwrap();
            (path.display().to_string(), value)
        })
        .collect()
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
                assert!(
                    uses.starts_with("./.github/workflows/"),
                    "{path}/{job_id}: local reusable must use the running revision"
                );
                assert!(
                    job.get("secrets").is_none() || uses != "./.github/workflows/build-cli.yml",
                    "builder cannot inherit secrets"
                );
            }
            let Some(steps) = job["steps"].as_array() else {
                continue;
            };
            for step in steps {
                let Some(uses) = step["uses"].as_str() else {
                    continue;
                };
                if !uses.starts_with("./") {
                    let (_, revision) = uses.rsplit_once('@').unwrap();
                    assert!(
                        securefix::policy::validate_sha(revision).is_ok(),
                        "{path}/{job_id}: {uses}"
                    );
                }
                assert!(
                    !uses.contains("github-script") && !uses.contains("approve-pr-action"),
                    "business logic must be in Rust"
                );
                if uses.starts_with("actions/download-artifact@") {
                    let inputs = &step["with"];
                    assert!(
                        inputs["artifact-ids"]
                            .as_str()
                            .is_some_and(|v| v.starts_with("${{ needs.")),
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
                            step["with"]["ref"], "${{ job.workflow_sha }}",
                            "{path}/{job_id}: actual defining workflow revision required"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn runtime_builder_has_no_custom_secrets_and_only_read_permissions() {
    let builder: Value =
        serde_yaml::from_slice(&fs::read(".github/workflows/build-cli.yml").unwrap()).unwrap();
    let job = &builder["jobs"]["build"];
    assert!(job.get("environment").is_none());
    assert_eq!(job["permissions"], serde_json::json!({"contents":"read"}));
    assert!(!serde_json::to_string(job).unwrap().contains("secrets."));
    assert_eq!(
        builder["on"]["workflow_call"]["outputs"]["source-sha"]["value"],
        "${{ jobs.build.outputs.source-sha }}"
    );
    let composite = fs::read_to_string(".github/actions/setup-cli/action.yml").unwrap();
    assert!(composite.contains("build --locked --release"));
    assert!(!composite.contains("secrets."));
}

#[test]
fn securefix_server_uses_native_writes_and_a_separate_trusted_runtime() {
    let workflow: Value =
        serde_yaml::from_slice(&fs::read(".github/workflows/securefix.yml").unwrap()).unwrap();
    let steps = workflow["jobs"]["gate"]["steps"].as_array().unwrap();
    assert!(steps.iter().all(|step| {
        !step["uses"].as_str().is_some_and(|uses| {
            uses.starts_with("actions/checkout@") || uses.starts_with("csm-actions/")
        })
    }));
    let download = steps
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/download-artifact@"))
        })
        .unwrap();
    assert_eq!(download["with"]["path"], "${{ runner.temp }}/securefix");
    for step in steps {
        if step["run"]
            .as_str()
            .is_some_and(|run| run.starts_with("./securefix "))
        {
            assert_eq!(step["working-directory"], "${{ runner.temp }}/securefix");
        }
    }
}

#[test]
fn cli_jobs_restore_executable_mode_and_supply_runtime_identity() {
    for (path, workflow) in workflows() {
        for (job_id, job) in workflow["jobs"].as_object().unwrap() {
            let Some(steps) = job["steps"].as_array() else {
                continue;
            };
            let downloads_cli = steps.iter().any(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|u| u.starts_with("actions/download-artifact@"))
                    && step["with"]["path"]
                        .as_str()
                        .is_some_and(|p| p == "runtime")
            });
            let mut executable = !downloads_cli;
            for step in steps {
                let Some(run) = step["run"].as_str() else {
                    continue;
                };
                assert!(
                    !run.contains("${{ github.event."),
                    "{path}/{job_id}: event data must enter through env or the event file"
                );
                assert!(
                    !run.contains("python")
                        && !run.contains("ruby")
                        && !run.contains("node ")
                        && !run.contains("jq ")
                        && !run.contains("curl "),
                    "{path}/{job_id}: operation decisions must be in Rust"
                );
                if run.contains("chmod") && run.contains("securefix") {
                    executable = true;
                }
                let invokes_cli = run.lines().any(|line| {
                    let line = line.trim();
                    line.starts_with("runtime/securefix ")
                        || line.starts_with("./securefix ")
                        || line.contains("&& runtime/securefix ")
                        || line.contains("&& ./securefix ")
                });
                if invokes_cli {
                    assert!(
                        executable,
                        "{path}/{job_id}: artifact permissions need restoring"
                    );
                    assert!(
                        job["env"]["SECUREFIX_SOURCE_SHA"].is_string()
                            || step["env"]["SECUREFIX_SOURCE_SHA"].is_string(),
                        "{path}/{job_id}: runtime revision required"
                    );
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
fn provider_build_sign_and_publish_have_distinct_credentials() {
    let client: Value =
        serde_yaml::from_slice(&fs::read(".github/workflows/reusable-release-tag.yml").unwrap())
            .unwrap();
    let build = &client["jobs"]["build"];
    assert!(build.get("environment").is_none());
    assert!(!serde_json::to_string(build).unwrap().contains("secrets."));
    assert_eq!(
        build["permissions"],
        serde_json::json!({"contents":"read","pull-requests":"read"})
    );
    assert!(
        build["steps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["with"]["ref"] == "${{ needs.resolve.outputs.merge_sha }}")
    );
    let server: Value =
        serde_yaml::from_slice(&fs::read(".github/workflows/release.yml").unwrap()).unwrap();
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
