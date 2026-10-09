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
                    job.get("secrets").is_none() || uses != "./.github/workflows/load-cli.yml",
                    "runtime loader cannot inherit secrets"
                );
                if uses == "./.github/workflows/load-cli.yml" {
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
                    !uses.contains("github-script")
                        && !uses.contains("approve-pr-action")
                        && !uses.contains("csm-actions/securefix-action"),
                    "business logic must be in Rust"
                );
                if uses.starts_with("actions/download-artifact@") {
                    let inputs = &step["with"];
                    if path == ".github/workflows/testing-securefix-server.yml" && job_id == "reuse"
                    {
                        if inputs["artifact-ids"]
                            == "${{ needs.trusted-runtime-main.outputs.artifact-id || needs.trusted-build.outputs.artifact-id }}"
                        {
                            assert_eq!(inputs["path"], "trusted-runtime");
                            assert_eq!(inputs["merge-multiple"], true);
                            assert!(inputs.get("repository").is_none());
                            assert!(inputs.get("run-id").is_none());
                        } else {
                            assert_eq!(
                                inputs["artifact-ids"],
                                "${{ steps.state.outputs.candidate_artifact_id }}"
                            );
                            assert_eq!(inputs["repository"], "civitaspo/securefix-server");
                            assert_eq!(inputs["run-id"], "${{ inputs.fixture_run_id }}");
                            assert_eq!(inputs["merge-multiple"], true);
                        }
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
                            if path == ".github/workflows/testing-securefix-server.yml" {
                                if job_id == "trusted-build" {
                                    "${{ job.workflow_sha }}"
                                } else {
                                    "${{ inputs.candidate_sha || job.workflow_sha }}"
                                }
                            } else {
                                "${{ job.workflow_sha }}"
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
            "contents":"read", "attestations":"read"
        })
    );
    let steps = load["steps"].as_array().unwrap();
    assert!(
        steps
            .iter()
            .filter(|step| {
                step["run"].as_str().is_some_and(|run| {
                    run.contains("gh release download") || run.contains("gh attestation verify")
                })
            })
            .all(|step| step["env"]["SECUREFIX_SOURCE_SHA"] == "${{ job.workflow_sha }}")
    );
    assert_eq!(
        loader["on"]["workflow_call"]["outputs"]["source-sha"]["value"],
        "${{ jobs.load.outputs.source-sha }}"
    );
    assert_eq!(load["outputs"]["source-sha"], "${{ job.workflow_sha }}");
    assert_eq!(
        load["outputs"]["artifact-id"],
        "${{ steps.upload.outputs.artifact-id }}"
    );
    let load_text = serde_json::to_string(load).unwrap();
    for forbidden in [
        "secrets.",
        "actions/checkout",
        "setup-cli",
        "cargo",
        "rustup",
    ] {
        assert!(
            !load_text.contains(forbidden),
            "loader contains {forbidden}"
        );
    }
    let index_of = |predicate: &dyn Fn(&Value) -> bool| {
        steps
            .iter()
            .position(predicate)
            .unwrap_or_else(|| panic!("required loader step is missing"))
    };
    let download = index_of(&|step| {
        step["run"].as_str().is_some_and(|run| {
            run.contains("gh release download")
                && run.contains("securefix-runtime-$SECUREFIX_SOURCE_SHA")
                && run.contains("--repo civitaspo/securefix-server")
                && run.contains("--pattern securefix-runtime-linux-x86_64.tar.gz")
        })
    });
    let verify = index_of(&|step| {
        step["run"].as_str().is_some_and(|run| {
            run.contains("gh attestation verify download/securefix-runtime-linux-x86_64.tar.gz")
        })
    });
    let extract = index_of(&|step| {
        step["run"]
            .as_str()
            .is_some_and(|run| run.contains("tar -xzf"))
    });
    let upload = index_of(&|step| {
        step["uses"]
            .as_str()
            .is_some_and(|uses| uses.starts_with("actions/upload-artifact@"))
    });
    assert!(download < verify && verify < extract && extract < upload);
    let verification = steps[verify]["run"].as_str().unwrap();
    for required in [
        "--source-digest \"$SECUREFIX_SOURCE_SHA\"",
        "--repo civitaspo/securefix-server",
        "--source-ref refs/heads/main",
        "--signer-workflow civitaspo/securefix-server/.github/workflows/publish-runtime.yml",
        "--signer-digest \"$SECUREFIX_SOURCE_SHA\"",
        "--cert-oidc-issuer https://token.actions.githubusercontent.com",
        "--predicate-type https://slsa.dev/provenance/v1",
        "--deny-self-hosted-runners",
    ] {
        assert!(
            verification.contains(required),
            "missing attestation constraint: {required}"
        );
    }
    for index in [verify, extract, upload] {
        assert_ne!(steps[index]["continue-on-error"], true);
        assert!(
            steps[index].get("if").is_none(),
            "attestation, extraction, and upload use fail-fast defaults"
        );
    }
    assert_eq!(
        steps[upload]["with"]["path"], "runtime/",
        "only the verified runtime is re-uploaded"
    );
    assert_eq!(
        steps[upload]["with"]["retention-days"], 1,
        "verified workflow artifact has short retention"
    );

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
    assert!(build_text.contains("./.github/actions/setup-cli"));
    assert_eq!(
        build["outputs"]["artifact-id"],
        "${{ steps.upload.outputs.artifact-id }}"
    );
    let build_steps = build["steps"].as_array().unwrap();
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

    let publish = &publisher["jobs"]["publish"];
    assert_eq!(publish["needs"], "build");
    assert_eq!(
        publish["permissions"],
        serde_json::json!({"contents":"write", "attestations":"read"})
    );
    let publish_text = serde_json::to_string(publish).unwrap();
    for forbidden in ["id-token", "secrets.", "setup-cli", "actions/checkout"] {
        assert!(
            !publish_text.contains(forbidden),
            "publisher contains {forbidden}"
        );
    }
    assert_eq!(
        publish["env"]["SECUREFIX_SOURCE_SHA"],
        "${{ needs.build.outputs.source-sha }}"
    );
    assert!(publish["steps"].as_array().unwrap().iter().any(|step| {
        step["uses"]
            .as_str()
            .is_some_and(|uses| uses.starts_with("actions/download-artifact@"))
            && step["with"]["artifact-ids"] == "${{ needs.build.outputs.artifact-id }}"
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
    let staged = publish_index(&|step| {
        step["run"]
            .as_str()
            .is_some_and(|run| run.contains("tar -xzf"))
    });
    let invoked = publish_index(&|step| {
        step["run"].as_str().is_some_and(|run| {
            run.contains("securefix runtime publish --archive distribution/securefix-runtime-linux-x86_64.tar.gz")
        })
    });
    let installed = publish_index(&|step| step["uses"] == "$/.github/actions/install-cli");
    assert!(
        downloaded < verified && verified < staged && staged < installed && installed < invoked
    );
    let verification = publish_steps[verified]["run"].as_str().unwrap();
    for required in [
        "--repo civitaspo/securefix-server",
        "--source-digest \"$SECUREFIX_SOURCE_SHA\"",
        "--source-ref refs/heads/main",
        "--signer-workflow civitaspo/securefix-server/.github/workflows/publish-runtime.yml",
        "--signer-digest \"$SECUREFIX_SOURCE_SHA\"",
        "--cert-oidc-issuer https://token.actions.githubusercontent.com",
        "--predicate-type https://slsa.dev/provenance/v1",
        "--deny-self-hosted-runners",
    ] {
        assert!(
            verification.contains(required),
            "publisher missing attestation constraint: {required}"
        );
    }
    for index in [verified, staged, invoked] {
        assert_ne!(publish_steps[index]["continue-on-error"], true);
        assert!(publish_steps[index].get("if").is_none());
    }
    let ci = workflow("ci.yml");
    let ci_build = &ci["jobs"]["workflows"];
    assert_eq!(
        ci_build["permissions"],
        serde_json::json!({"contents":"read"})
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
                            .any(|step| step["uses"] == "./.github/actions/setup-cli")
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
            ".github/workflows/publish-runtime.yml",
            ".github/workflows/testing-securefix-server.yml",
            ".github/workflows/testing-securefix-server.yml"
        ],
        "only secret-free CI and runtime producer compile CLI"
    );
    for (path, workflow) in workflows() {
        if matches!(
            path.as_str(),
            ".github/workflows/ci.yml" | ".github/workflows/publish-runtime.yml"
        ) {
            continue;
        }
        for (job_id, job) in workflow["jobs"].as_object().unwrap() {
            if path == ".github/workflows/testing-securefix-server.yml" && job_id == "build" {
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
    let installer: Value =
        serde_yaml::from_slice(&fs::read(".github/actions/install-cli/action.yml").unwrap())
            .unwrap();
    let install = installer["runs"]["steps"][0]["run"].as_str().unwrap();
    assert!(install.contains("install -D -m 755"));
    assert!(install.contains("$GITHUB_PATH"));
    assert!(installer["inputs"].get("binary").is_some());
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
fn candidate_execution_is_separate_from_secret_free_build_and_scoped_to_scratch() {
    let candidate = workflow("testing-securefix-server.yml");
    let trusted_main = &candidate["jobs"]["trusted-runtime-main"];
    assert_eq!(trusted_main["uses"], "./.github/workflows/load-cli.yml");
    assert!(
        trusted_main["if"]
            .as_str()
            .unwrap()
            .contains("github.ref == 'refs/heads/main'")
    );
    assert!(trusted_main.get("secrets").is_none());
    let trusted_build = &candidate["jobs"]["trusted-build"];
    assert_eq!(
        trusted_build["permissions"],
        serde_json::json!({"contents":"read"})
    );
    assert!(
        !serde_json::to_string(trusted_build)
            .unwrap()
            .contains("secrets.")
    );
    assert!(
        trusted_build["if"]
            .as_str()
            .unwrap()
            .contains("integration/native-")
    );
    for job_id in ["build", "reuse", "scratch"] {
        let guard = candidate["jobs"][job_id]["if"].as_str().unwrap();
        assert!(guard.contains("github.actor_id == '4525500'"), "{job_id}");
        assert!(guard.contains("github.run_attempt == 1"), "{job_id}");
        assert!(guard.contains("refs/heads/main"), "{job_id}");
        assert!(guard.contains("integration/native-"), "{job_id}");
    }
    let trusted_steps = trusted_build["steps"].as_array().unwrap();
    assert_eq!(trusted_steps[0]["with"]["ref"], "${{ job.workflow_sha }}");
    assert_eq!(trusted_steps[0]["with"]["persist-credentials"], false);
    assert!(
        trusted_steps
            .iter()
            .any(|step| step["uses"] == "./.github/actions/setup-cli")
    );
    assert!(trusted_steps.iter().any(|step| {
        step["with"]["name"] == "trusted-runtime"
            && step["with"]["path"].as_str().is_some_and(|path| {
                path.lines()
                    .eq(["target/release/securefix", "target/release/policy.json"])
            })
    }));
    let build = &candidate["jobs"]["build"];
    assert_eq!(build["permissions"], serde_json::json!({"contents":"read"}));
    assert!(!serde_json::to_string(build).unwrap().contains("secrets."));
    let scratch = &candidate["jobs"]["scratch"];
    let steps = scratch["steps"].as_array().unwrap();
    let trusted_fetch = steps
        .iter()
        .position(|step| step["name"] == "Validate fixture state with trusted runtime")
        .unwrap();
    let trusted_install = steps
        .iter()
        .position(|step| {
            step["uses"] == "$/.github/actions/install-cli"
                && step["with"]["binary"] == "trusted-runtime/securefix"
        })
        .unwrap();
    let candidate_install = steps
        .iter()
        .position(|step| {
            step["uses"] == "$/.github/actions/install-cli"
                && step["with"]["binary"] == "candidate-runtime/securefix"
        })
        .unwrap();
    let server_token = steps
        .iter()
        .position(|step| step["id"] == "server")
        .unwrap();
    let candidate_run = steps
        .iter()
        .position(|step| {
            step["name"] == "Execute candidate against the isolated scratch repository"
        })
        .unwrap();
    assert!(trusted_install < trusted_fetch && trusted_fetch < candidate_install);
    let producer_check = steps
        .iter()
        .position(|step| {
            step["name"] == "Validate the defining workflow before minting credentials"
        })
        .unwrap();
    assert!(trusted_install < producer_check && producer_check < candidate_install);
    assert_eq!(
        steps[producer_check]["env"]["GITHUB_TOKEN"],
        "${{ github.token }}"
    );
    assert!(candidate_install < server_token);
    assert!(server_token < candidate_run);
    assert!(
        steps[trusted_fetch]["run"]
            .as_str()
            .unwrap()
            .starts_with("$RUNNER_TEMP/securefix-bin/securefix integration fetch-state ")
    );
    assert!(steps[trusted_fetch]["env"].get("GITHUB_TOKEN").is_some());
    assert_eq!(scratch["environment"], "main");
    assert!(steps[candidate_run]["env"].get("GITHUB_TOKEN").is_none());
    assert!(steps[candidate_run]["env"]["SECUREFIX_SERVER_APP_TOKEN"].is_string());
    assert!(steps[candidate_run]["env"]["SECUREFIX_CLIENT_APP_TOKEN"].is_string());
    let isolated_run = steps[candidate_run]["run"].as_str().unwrap();
    for guard in [
        "docker run --rm --read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user",
        "--pids-limit",
        "ubuntu@sha256:",
    ] {
        assert!(
            isolated_run.contains(guard),
            "missing candidate isolation: {guard}"
        );
    }
    for forbidden in [
        "docker.sock",
        "--privileged",
        "--pid=host",
        "--network=host",
        "-e GITHUB_TOKEN",
        "-e GITHUB_ENV",
        "-e GITHUB_OUTPUT",
        "target=/home",
        "target=/var/run",
    ] {
        assert!(
            !isolated_run.contains(forbidden),
            "unsafe candidate isolation: {forbidden}"
        );
    }
    let output_validation = steps
        .iter()
        .position(|step| step["id"] == "validate-outputs")
        .unwrap();
    assert!(candidate_run < output_validation);
    let fixture_upload = steps
        .iter()
        .position(|step| step["with"]["name"] == "scratch-fixtures")
        .unwrap();
    assert!(output_validation < fixture_upload);
    assert_eq!(
        steps[fixture_upload]["if"],
        "always() && steps.validate-outputs.outcome == 'success'"
    );
    for step in steps {
        if step["uses"]
            .as_str()
            .is_some_and(|value| value.starts_with("actions/create-github-app-token@"))
        {
            assert_eq!(step["with"]["repositories"], "testing-securefix-server");
        }
    }
    let reuse = &candidate["jobs"]["reuse"]["steps"];
    let reuse = reuse.as_array().unwrap();
    let fetch = reuse.iter().position(|step| step["id"] == "state").unwrap();
    let trusted_installer = reuse
        .iter()
        .position(|step| {
            step["uses"] == "$/.github/actions/install-cli"
                && step["with"]["binary"] == "trusted-runtime/securefix"
        })
        .unwrap();
    let candidate_download = reuse
        .iter()
        .rposition(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|value| value.starts_with("actions/download-artifact@"))
        })
        .unwrap();
    assert!(trusted_installer < fetch && fetch < candidate_download);
    assert!(
        reuse[fetch]["run"]
            .as_str()
            .unwrap()
            .starts_with("$RUNNER_TEMP/securefix-bin/securefix integration fetch-state ")
    );
    assert_eq!(reuse[fetch]["env"]["GITHUB_TOKEN"], "${{ github.token }}");
    assert_eq!(reuse[fetch]["uses"], Value::Null);
    assert!(
        !serde_json::to_string(&reuse[fetch])
            .unwrap()
            .contains("candidate-runtime")
    );
    let text = serde_json::to_string(&candidate).unwrap();
    for forbidden in [
        "CIVITASPO_BOT_PR_APPROVE_TOKEN",
        "TERRAFORM_PROVIDER_GPG",
        "runtime publish",
        "gh release",
    ] {
        assert!(
            !text.contains(forbidden),
            "candidate runner contains {forbidden}"
        );
    }
}

#[test]
fn cli_jobs_install_verified_artifacts_on_path_before_invocation() {
    for (path, workflow) in workflows() {
        for (job_id, job) in workflow["jobs"].as_object().unwrap() {
            let Some(steps) = job["steps"].as_array() else {
                continue;
            };
            let downloads_cli = steps.iter().any(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|u| u.starts_with("actions/download-artifact@"))
                    && step["with"]["artifact-ids"].is_string()
            });
            let installer = steps
                .iter()
                .position(|step| step["uses"] == "$/.github/actions/install-cli");
            if downloads_cli {
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
                assert!(
                    !run.contains("python")
                        && !run.contains("ruby")
                        && !run.contains("node ")
                        && !run.contains("jq ")
                        && !run.contains("curl "),
                    "{path}/{job_id}: operation decisions must be in Rust"
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
                        assert!(
                            job["env"]["SECUREFIX_SOURCE_SHA"].is_string()
                                || step["env"]["SECUREFIX_SOURCE_SHA"].is_string()
                                || (path == ".github/workflows/testing-securefix-server.yml"
                                    && step["env"]["CANDIDATE_SHA"].is_string()),
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
        assert_eq!(
            caller["jobs"]["request"]["secrets"],
            serde_json::json!({
                "SECUREFIX_CLIENT_PRIVATE_KEY": "${{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}"
            }),
            "environment-only secrets must be declared explicitly at call time"
        );
        let reusable = workflow(&format!("reusable-{operation}-request.yml"));
        assert_eq!(
            reusable["on"]["workflow_call"]["secrets"]["SECUREFIX_CLIENT_PRIVATE_KEY"]["required"],
            true
        );
        let build = &reusable["jobs"]["build"];
        assert!(build.get("secrets").is_none());
        let capture = &reusable["jobs"]["capture"];
        assert_eq!(
            capture["environment"],
            "${{ github.repository == 'civitaspo/securefix-server' && 'main' || null }}"
        );
        let token = capture["steps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|step| step["id"] == "client-token")
            .unwrap();
        assert_eq!(
            token["with"]["private-key"],
            "${{ secrets.SECUREFIX_CLIENT_PRIVATE_KEY }}"
        );
        assert_eq!(token["with"]["owner"], "civitaspo");
        assert_eq!(token["with"]["repositories"], "securefix-server");
        assert_eq!(token["with"]["permission-issues"], "write");
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
fn self_merge_consumes_its_label_before_apply_and_skips_stale_success_writes() {
    let merge = workflow("merge.yml");
    let job = &merge["jobs"]["merge"];
    assert_eq!(
        job["outputs"]["self_merged"],
        "${{ steps.validate.outputs.repository == 'civitaspo/securefix-server' && steps.apply.outcome == 'success' }}"
    );
    let steps = job["steps"].as_array().unwrap();
    let position = |id: &str| {
        steps
            .iter()
            .position(|step| step["id"] == id)
            .unwrap_or_else(|| panic!("missing merge step {id}"))
    };
    let wait = position("wait");
    let merge_token = position("merge-token");
    let token = position("self-cleanup-token");
    let preclean = position("self-cleanup");
    let apply = position("apply");
    let notify_token = position("notify-token");
    let notify = steps
        .iter()
        .position(|step| step["name"] == "Report the terminal result")
        .unwrap();
    assert!(wait < merge_token && merge_token < token && token < preclean && preclean < apply);
    assert_eq!(steps[merge_token]["if"], "steps.wait.outcome == 'success'");
    assert_eq!(
        steps[token]["if"],
        "steps.wait.outcome == 'success' && steps.validate.outputs.repository == 'civitaspo/securefix-server'"
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
        "steps.wait.outcome == 'success' && (steps.validate.outputs.repository != 'civitaspo/securefix-server' || steps.self-cleanup.outcome == 'success')"
    );
    for index in [notify_token, notify] {
        assert!(steps[index]["if"].as_str().unwrap().contains(
            "(steps.validate.outputs.repository != 'civitaspo/securefix-server' || steps.apply.outcome != 'success')"
        ));
    }
    assert!(
        merge["jobs"]["cleanup"]["if"]
            .as_str()
            .unwrap()
            .contains("needs.merge.outputs.self_merged != 'true'")
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
