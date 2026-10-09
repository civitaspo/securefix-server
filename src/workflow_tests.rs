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
fn securefix_uses_the_pinned_upstream_action_behind_the_rust_policy_gate() {
    let workflow: Value =
        serde_yaml::from_slice(&fs::read(".github/workflows/securefix.yml").unwrap()).unwrap();
    let job = &workflow["jobs"]["fix"];
    assert_eq!(job["permissions"]["issues"], "write");
    let steps = job["steps"].as_array().unwrap();
    let download = steps
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/download-artifact@"))
        })
        .unwrap();
    assert_eq!(
        download["with"]["path"],
        "${{ runner.temp }}/securefix-runtime"
    );
    let position = |name: &str| {
        steps
            .iter()
            .position(|step| step["name"] == name)
            .unwrap_or_else(|| panic!("missing workflow step {name}"))
    };
    let event = position("Validate label event and source capability");
    let prepare = position("Prepare fix with Securefix Action");
    let gate = position("Validate Securefix prepare outputs");
    let commit = position("Apply fix with Securefix Action");
    assert!(event < prepare && prepare < gate && gate < commit);
    for name in [
        "Prepare fix with Securefix Action",
        "Apply fix with Securefix Action",
        "Notify validated fix failure",
    ] {
        let step = &steps[position(name)];
        assert_eq!(
            step["uses"],
            "csm-actions/securefix-action@1b770a7af0ec5e04517295b4e14c4b451359d550"
        );
    }
    let prepare = &steps[prepare];
    assert_eq!(prepare["with"]["action"], "prepare");
    assert_eq!(prepare["with"]["allow_workflow_fix"], "true");
    assert_eq!(
        prepare["with"]["config_file"],
        "${{ runner.temp }}/securefix-runtime/securefix-config.yaml"
    );
    let gate = &steps[gate];
    for output in [
        "SECUREFIX_CLIENT_REPOSITORY",
        "SECUREFIX_PUSH_REPOSITORY",
        "SECUREFIX_BRANCH",
        "SECUREFIX_WORKFLOW_RUN",
        "SECUREFIX_PULL_REQUEST",
        "SECUREFIX_CREATE_PULL_REQUEST",
    ] {
        assert!(gate["env"][output].is_string(), "missing {output}");
    }
    assert!(gate["env"].get("SECUREFIX_PREPARED_OUTPUTS").is_none());
    assert_eq!(
        steps[commit]["with"]["outputs"],
        "${{ toJSON(steps.prepare.outputs) }}"
    );
    let notify = &steps[position("Notify validated fix failure")];
    assert_eq!(notify["with"]["action"], "notify");
    assert_eq!(
        notify["if"],
        "failure() && steps.gate.outcome == 'success' && steps.commit.outcome == 'failure'"
    );
}

#[test]
fn securefix_config_allows_every_branch_for_exact_policy_clients() {
    let config: Value =
        serde_yaml::from_slice(&fs::read("securefix-config.yaml").unwrap()).unwrap();
    let entries = config["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let policy = securefix::policy::Policy::load("policy.json").unwrap();
    let expected: std::collections::BTreeSet<_> = policy
        .repositories
        .iter()
        .filter(|r| {
            r.capabilities
                .contains(&securefix::policy::Capability::Securefix)
                && r.capabilities
                    .contains(&securefix::policy::Capability::Release)
        })
        .map(|r| r.repository.clone())
        .collect();
    let clients: std::collections::BTreeSet<_> = entries[0]["client"]["repositories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(clients, expected);
    assert_eq!(entries[0]["client"]["branches"], serde_json::json!(["**"]));
    assert!(entries[0]["push"].get("repositories").is_none());
    assert_eq!(entries[0]["push"]["branches"], serde_json::json!(["**"]));
    assert_eq!(entries[0]["pull_request"], serde_json::json!({}));
    let distribution: std::collections::BTreeSet<_> = entries[1]["push"]["repositories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap().to_owned())
        .collect();
    let expected_distribution: std::collections::BTreeSet<_> = policy
        .repositories
        .iter()
        .filter(|r| {
            r.repository != securefix::policy::SERVER
                && r.capabilities
                    .contains(&securefix::policy::Capability::Securefix)
                && r.capabilities
                    .contains(&securefix::policy::Capability::Approve)
                && r.capabilities
                    .contains(&securefix::policy::Capability::Merge)
        })
        .map(|r| r.repository.clone())
        .collect();
    assert_eq!(distribution, expected_distribution);
    assert_eq!(
        entries[1]["client"]["repositories"],
        serde_json::json!([securefix::policy::SERVER])
    );
    assert_eq!(
        entries[1]["client"]["branches"],
        serde_json::json!(["main"])
    );
    assert_eq!(
        entries[1]["push"]["branches"],
        serde_json::json!(["automation/securefix-runtime"])
    );
    assert_eq!(entries[1]["pull_request"], serde_json::json!({}));
    let publisher: Value =
        serde_yaml::from_slice(&fs::read(".github/workflows/publish-runtime.yml").unwrap())
            .unwrap();
    let assemble = publisher["jobs"]["build"]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["name"] == "Assemble runtime archive")
        .unwrap()["run"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(assemble.contains("cp securefix-config.yaml runtime/securefix-config.yaml"));
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
                                || step["env"]["SECUREFIX_SOURCE_SHA"].is_string(),
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
fn scratch_test_workflow_builds_and_probes_same_run_artifact_without_releases() {
    let workflow = workflow("testing-securefix-server.yml");
    assert!(
        workflow["on"]
            .get("workflow_call")
            .is_some_and(Value::is_object)
    );
    assert_eq!(
        workflow["on"]["workflow_call"]["secrets"]["SECUREFIX_CLIENT_PRIVATE_KEY"]["required"],
        true
    );
    let build = &workflow["jobs"]["build"];
    let probe = &workflow["jobs"]["probe"];
    let build_text = serde_json::to_string(build).unwrap();
    assert!(!build_text.contains("secrets."));
    assert!(build_text.contains("job.workflow_sha"));
    assert_eq!(probe["needs"], "build");
    let probe_text = serde_json::to_string(probe).unwrap();
    assert!(probe_text.contains("github.actor_id == '4525500'"));
    assert!(probe_text.contains("civitaspo/testing-securefix-server"));
    assert!(probe_text.contains("$/.github/actions/install-cli"));
    assert!(probe_text.contains("needs.build.outputs.artifact-id"));
    assert!(probe_text.contains("SECUREFIX_CLIENT_PRIVATE_KEY"));
    assert!(probe_text.contains("client_app_token_is_scoped_to_scratch_repository"));
    assert!(!probe_text.contains("contents: write"));
    assert!(!probe_text.contains("pull-requests: write"));
    assert!(!probe_text.contains("releases/create"));
    let probe_steps = probe["steps"].as_array().unwrap();
    let token = probe_steps
        .iter()
        .position(|step| step["id"] == "client-token")
        .unwrap();
    let api_test = probe_steps
        .iter()
        .position(|step| step["name"] == "Confirm the Client App token is scoped to scratch")
        .unwrap();
    let validate_config = probe_steps
        .iter()
        .position(|step| {
            step["name"] == "Validate Securefix branch configuration with upstream action"
        })
        .unwrap();
    assert!(validate_config < token && token < api_test);
    assert_eq!(
        probe_steps[token]["with"]["repositories"],
        "testing-securefix-server"
    );
    assert_eq!(probe_steps[token]["with"]["permission-metadata"], "read");
    assert_eq!(
        probe_steps[api_test]["env"]["SECUREFIX_CLIENT_INSTALLATION_TOKEN"],
        "${{ steps.client-token.outputs.token }}"
    );
    assert!(
        probe_steps[api_test]["env"]
            .get("SECUREFIX_CLIENT_PRIVATE_KEY")
            .is_none()
    );
    assert!(probe_steps.iter().any(|step| {
        step["run"].as_str().is_some_and(|run| {
            run.contains("install -D -m 755") && run.contains("github-api-tests")
        })
    }));
    let installed_cli = probe_steps
        .iter()
        .find(|step| step["name"] == "Verify installed CLI and candidate policy")
        .unwrap()["run"]
        .as_str()
        .unwrap();
    assert!(installed_cli.contains("stat -c '%a' \"$SECUREFIX_BINARY\")"));
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
