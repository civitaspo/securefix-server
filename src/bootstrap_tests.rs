use super::*;
use crate::fixtures::{Fixture, Route};

pub(super) fn main_sha() -> String {
    "a".repeat(40)
}
pub(super) fn head_sha() -> String {
    "b".repeat(40)
}
pub(super) fn policy() -> Policy {
    Policy::parse(&securefix::config::trusted_policy_bytes().unwrap()).unwrap()
}
pub(super) fn path(suffix: &str) -> String {
    format!("/repos/{}/{suffix}", policy().deployment.server.repository)
}

pub(super) fn host(fixture: &Fixture, phase: &str) -> Host {
    let policy = policy();
    let server = &policy.deployment.server;
    let workflow = if phase == "bootstrap" {
        TEST_WORKFLOW
    } else {
        BOOTSTRAP_WORKFLOW
    };
    let context = Dispatch {
        repository: server.repository.clone(),
        reference: format!("refs/heads/{}", server.default_branch),
        event_name: "workflow_dispatch".into(),
        workflow_ref: format!(
            "{}/{workflow}@refs/heads/{}",
            server.repository, server.default_branch
        ),
        workflow_sha: main_sha(),
        compiled_sha: main_sha(),
        actor_id: policy.owner_id.to_string(),
        attempt: "1".into(),
        source_sha: main_sha(),
        run_id: 77,
        event: json!({"inputs":{"phase":phase,"candidate_sha":""}}),
    };
    Host {
        api: fixture.api.clone(),
        policy,
        policy_bytes: securefix::config::trusted_policy_bytes().unwrap(),
        context,
    }
}

pub(super) fn run_fixture(workflow: &str, complete: bool) -> Value {
    let policy = policy();
    let server = policy.deployment.server;
    json!({"id":77,"repository":{"id":server.id,"full_name":server.repository},
        "head_repository":{"id":server.id,"full_name":server.repository},"path":workflow,
        "event":"workflow_dispatch","head_branch":server.default_branch,"head_sha":main_sha(),"run_attempt":1,
        "actor":{"id":policy.owner_id},"triggering_actor":{"id":policy.owner_id},
        "status":if complete {"completed"} else {"in_progress"},"conclusion":if complete {json!("success")} else {Value::Null}})
}

pub(super) fn main_route() -> Route {
    Route::get(path("commits/main"), json!({"sha":main_sha()}))
}
pub(super) fn absent_route() -> Route {
    Route::request(
        "GET",
        path(&format!("contents/{ACTIVE}?ref={}", main_sha())),
        404,
        json!({}),
    )
}
pub(super) fn content_route(name: &str, sha: &str, bytes: &[u8]) -> Route {
    Route::get(
        path(&format!("contents/{name}?ref={sha}")),
        json!({"type":"file","path":name,"encoding":"base64","size":bytes.len(),"content":STANDARD.encode(bytes)}),
    )
}
pub(super) fn status_routes(sha: &str) -> Vec<Route> {
    vec![
        Route::get(
            path(&format!("commits/{sha}")),
            json!({"sha":sha,"commit":{"verification":{"verified":true}}}),
        ),
        Route::get(
            path(&format!("commits/{sha}/status")),
            json!({"state":"success","total_count":0}),
        ),
        Route::get(
            path(&format!(
                "commits/{sha}/check-runs?per_page=100&page=1&filter=latest"
            )),
            json!({"check_runs":[{"name":"status-check","app":{"id":policy().deployment.checks.status_app_id},"status":"completed","conclusion":"success"}]}),
        ),
    ]
}
pub(super) fn comparison(files: Value) -> Value {
    json!({"base_commit":{"sha":main_sha()},"merge_base_commit":{"sha":main_sha()},"status":"ahead","total_commits":1,"commits":[{"commit":{"verification":{"verified":true}}}],"files":files})
}
fn descriptor() -> ControlRevision {
    ControlRevision {
        version: 1,
        generation: 1,
        source_sha: main_sha(),
        policy_sha256: "1".repeat(64),
        archive_sha256: "2".repeat(64),
        release_id: 3,
        asset_id: 4,
        publisher_run_id: 77,
        verification_run_id: 88,
        previous: "0".repeat(64),
    }
}
pub(super) fn pull(head: &str) -> Value {
    let policy = policy();
    let server = policy.deployment.server;
    json!({"number":12,"state":"open","user":{"id":policy.server_bot_id},
        "head":{"ref":bootstrap_branch(&main_sha()).unwrap(),"sha":head,"repo":{"full_name":server.repository,"id":server.id}},
        "base":{"ref":server.default_branch,"sha":main_sha(),"repo":{"full_name":server.repository,"id":server.id}},"merged_at":null})
}

#[test]
fn dispatch_requires_the_compiled_authority_source_and_exact_owner_phase() {
    let fixture = Fixture::new(vec![]);
    for field in [
        "repository",
        "reference",
        "event_name",
        "workflow_ref",
        "workflow_sha",
        "compiled_sha",
        "actor_id",
        "attempt",
        "source_sha",
        "phase",
        "run_id",
    ] {
        let mut host = host(&fixture, "propose");
        host.context
            .validate(&host, &main_sha(), "propose", BOOTSTRAP_WORKFLOW)
            .unwrap();
        match field {
            "repository" => host.context.repository = "other/repo".into(),
            "reference" => host.context.reference = "refs/heads/other".into(),
            "event_name" => host.context.event_name = "pull_request".into(),
            "workflow_ref" => host.context.workflow_ref.push_str("-other"),
            "workflow_sha" => host.context.workflow_sha = head_sha(),
            "compiled_sha" => host.context.compiled_sha = head_sha(),
            "actor_id" => host.context.actor_id = "1".into(),
            "attempt" => host.context.attempt = "2".into(),
            "source_sha" => host.context.source_sha = head_sha(),
            "phase" => host.context.event["inputs"]["phase"] = json!("merge"),
            "run_id" => host.context.run_id = 0,
            _ => unreachable!(),
        }
        assert!(
            host.context
                .validate(&host, &main_sha(), "propose", BOOTSTRAP_WORKFLOW)
                .is_err(),
            "{field}"
        );
    }
    fixture.finish();
}

#[test]
fn publisher_run_accepts_native_path_and_rejects_mismatched_provenance() {
    let good = run_fixture(BOOTSTRAP_WORKFLOW, true);
    validate_run(&good, &policy(), 77, BOOTSTRAP_WORKFLOW, &main_sha(), false).unwrap();
    let mut suffixed = good.clone();
    suffixed["path"] = json!(format!("{BOOTSTRAP_WORKFLOW}@refs/heads/main"));
    validate_run(
        &suffixed,
        &policy(),
        77,
        BOOTSTRAP_WORKFLOW,
        &main_sha(),
        false,
    )
    .unwrap();
    for (key, value) in [
        (
            "path",
            json!(format!("{BOOTSTRAP_WORKFLOW}@refs/heads/untrusted")),
        ),
        ("head_branch", json!("untrusted")),
        ("run_attempt", json!(2)),
        ("head_sha", json!(head_sha())),
        ("actor", json!({"id":1})),
        ("triggering_actor", json!({"id":1})),
        ("conclusion", json!("failure")),
        (
            "repository",
            json!({"full_name":policy().deployment.server.repository,"id":1}),
        ),
        (
            "head_repository",
            json!({"full_name":policy().deployment.server.repository,"id":1}),
        ),
        ("id", json!(78)),
    ] {
        let mut bad = good.clone();
        bad[key] = value;
        assert!(
            validate_run(&bad, &policy(), 77, BOOTSTRAP_WORKFLOW, &main_sha(), false).is_err(),
            "{key}"
        );
    }
}

#[test]
fn failed_signature_and_pending_status_stop_before_further_qualification() {
    let fixture = Fixture::new(vec![Route::get(
        path(&format!("commits/{}", main_sha())),
        json!({"sha":main_sha(),"commit":{"verification":{"verified":false}}}),
    )]);
    assert!(
        host(&fixture, "propose")
            .required_status(&main_sha())
            .unwrap_err()
            .to_string()
            .contains("signature")
    );
    fixture.finish();
    let fixture = Fixture::new(vec![
        Route::get(
            path(&format!("commits/{}", main_sha())),
            json!({"sha":main_sha(),"commit":{"verification":{"verified":true}}}),
        ),
        Route::get(
            path(&format!("commits/{}/status", main_sha())),
            json!({"total_count":1,"state":"pending"}),
        ),
    ]);
    assert!(
        host(&fixture, "propose")
            .required_status(&main_sha())
            .unwrap_err()
            .to_string()
            .contains("combined")
    );
    fixture.finish();
}

#[test]
fn latest_owner_review_must_approve_the_exact_head() {
    let owner = policy().owner_id;
    let good = json!({"user":{"id":owner},"state":"APPROVED","commit_id":head_sha(),"submitted_at":"2026-10-17T00:00:00Z"});
    validate_review(std::slice::from_ref(&good), owner, &head_sha()).unwrap();
    for (key, value) in [
        ("state", json!("CHANGES_REQUESTED")),
        ("commit_id", json!(main_sha())),
    ] {
        let mut later = good.clone();
        later[key] = value;
        later["submitted_at"] = json!("2026-10-17T00:01:00Z");
        assert!(validate_review(&[good.clone(), later], owner, &head_sha()).is_err());
    }
    assert!(validate_review(&[], owner, &head_sha()).is_err());
}

fn archive(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
    let mut tar = Vec::new();
    for (name, kind, data) in entries {
        let mut header = tar::Header::new_ustar();
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_entry_type(tar::EntryType::new(*kind));
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.extend_from_slice(header.as_bytes());
        tar.extend_from_slice(data);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }
    tar.resize(tar.len() + 1024, 0);
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&tar).unwrap();
    gzip.finish().unwrap()
}

#[test]
fn archive_reads_policy_without_executing_candidate_and_rejects_unsafe_entries() {
    let bytes = archive(&[
        ("./", b'5', b""),
        ("./policy.json", b'0', br#"{"trusted":true}"#),
        ("./securefix", b'0', b"not an executable"),
    ]);
    assert_eq!(archive_policy(&bytes).unwrap(), br#"{"trusted":true}"#);
    for (name, kind) in [
        ("../escape", b'0'),
        ("././policy.json", b'0'),
        ("/policy.json", b'0'),
        ("securefix", b'2'),
        ("sparse", b'S'),
        ("metadata", b'x'),
        ("./policy.json", b'0'),
    ] {
        let bytes = archive(&[("policy.json", b'0', b"{}"), (name, kind, b"")]);
        assert!(archive_policy(&bytes).is_err(), "{name} {kind}");
    }
    let mut corrupt = bytes.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(archive_policy(&corrupt).is_err());
    assert!(archive_policy(&archive(&[("securefix", b'0', b"binary")])).is_err());
}

#[test]
fn scratch_zip_requires_unique_regular_bounded_json_files() {
    fn zip(entries: &[(&str, &str, u32)]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, value, permissions) in entries {
            writer
                .start_file(
                    *name,
                    zip::write::SimpleFileOptions::default().unix_permissions(*permissions),
                )
                .unwrap();
            writer.write_all(value.as_bytes()).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }
    let good = zip(&[("state.json", "{}", 0o644)]);
    assert_eq!(
        zip_json_files(&good, &["state.json"]).unwrap()["state.json"],
        json!({})
    );
    let extra = zip(&[
        ("state.json", "{}", 0o644),
        ("unreviewed.json", "{}", 0o644),
    ]);
    assert!(zip_json_files(&extra, &["state.json"]).is_err());
    assert!(zip_json_files(&zip(&[("state.json", "x", 0o644)]), &["state.json"]).is_err());
}

#[test]
fn mutable_release_and_changed_download_fail_before_attestation() {
    let bytes = archive(&[("policy.json", b'0', b"{}")]);
    let release = json!({"immutable":true,"draft":false,"assets":[{"id":12,"name":ASSET,"size":bytes.len(),"digest":format!("sha256:{}", sha256(&bytes)),"state":"uploaded"}]});
    immutable_asset(&release).unwrap();
    for value in [json!(false), Value::Null] {
        let mut mutable = release.clone();
        mutable["immutable"] = value;
        assert!(immutable_asset(&mutable).is_err());
    }
    let mut bad = release;
    bad["assets"][0]["digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    let fixture = Fixture::new(vec![Route::raw(
        "GET",
        path("releases/assets/12"),
        200,
        bytes,
    )]);
    assert!(
        host(&fixture, "propose")
            .verify_published_archive(&bad, &main_sha())
            .unwrap_err()
            .to_string()
            .contains("metadata")
    );
    fixture.finish();
}

#[test]
fn scratch_proof_requires_all_generation_and_cas_evidence() {
    let policy = policy();
    let scratch = &policy.deployment.integration;
    let state = json!({"repository":scratch.repository,"repository_id":scratch.id,"candidate_sha":main_sha(),"workflow_sha":main_sha()});
    let verification = json!({"version":2,"repository":scratch.repository,"candidate_sha":main_sha(),"positive_pr":1,"stale_pr":2,"distribution_pr":3,"merged_sha":head_sha(),"stale_head_sha":head_sha(),"managed_files":["README.md"],"annotated_tag_verified":true,"closed_or_merged":true});
    let probe = json!({"version":1,"repository":scratch.repository,"candidate_sha":main_sha(),"branch":"securefix-integration-control-test","base_sha":main_sha(),"generation_one_commit_sha":head_sha(),"generation_two_commit_sha":head_sha(),"generation_three_commit_sha":head_sha(),"generation_one":"1".repeat(64),"generation_two":"2".repeat(64),"generation_three":"3".repeat(64),"source_advance_kept_descriptor":true,"expected_head_conflict_rejected":true,"stale_identity_rejected_after_aba":true,"production_publication_verified":false,"production_activation_verified":false,"distribution_verified":false});
    validate_scratch_evidence(&state, &verification, &probe, &policy, &main_sha()).unwrap();
    for key in [
        "source_advance_kept_descriptor",
        "expected_head_conflict_rejected",
        "stale_identity_rejected_after_aba",
    ] {
        let mut bad = probe.clone();
        bad.as_object_mut().unwrap().remove(key);
        assert!(
            validate_scratch_evidence(&state, &verification, &bad, &policy, &main_sha()).is_err(),
            "{key}"
        );
    }
    let mut bad = probe.clone();
    bad["production_activation_verified"] = json!(true);
    assert!(validate_scratch_evidence(&state, &verification, &bad, &policy, &main_sha()).is_err());
    let mut bad = probe;
    bad["generation_two"] = bad["generation_one"].clone();
    assert!(validate_scratch_evidence(&state, &verification, &bad, &policy, &main_sha()).is_err());
}

#[test]
fn repair_qualification_uses_no_administrative_settings_or_writer_credential() {
    let mut routes = vec![
        main_route(),
        Route::get(
            path("actions/runs/77"),
            run_fixture(BOOTSTRAP_WORKFLOW, false),
        ),
        absent_route(),
        content_route(
            "policy.json",
            &main_sha(),
            &securefix::config::trusted_policy_bytes().unwrap(),
        ),
        Route::get(
            path(&format!("compare/{}...{}", main_sha(), head_sha())),
            comparison(json!([{"filename":"README.md","status":"modified"}])),
        ),
    ];
    routes.extend(status_routes(&head_sha()));
    routes.push(Route::get(
        path(&format!("commits/{}/branches-where-head", head_sha())),
        json!([{"name":"repair/green-head"}]),
    ));
    let fixture = Fixture::new(vec![]);
    let query = host(&fixture, "repair-propose")
        .pulls_query("open", "repair/green-head")
        .unwrap();
    fixture.finish();
    routes.push(Route::get(query, json!([])));
    let fixture = Fixture::new(routes);
    let branch = host(&fixture, "repair-propose")
        .validate_repair_commit(&main_sha(), &head_sha(), None)
        .unwrap();
    assert_eq!(branch.as_deref(), Some("repair/green-head"));
    fixture.finish();
}

#[test]
fn repair_cannot_modify_or_rename_its_host_authority_or_dependencies() {
    for name in [
        ACTIVE,
        BOOTSTRAP_WORKFLOW,
        ".github/workflows/build-bootstrap-host.yml",
        ".github/workflows/ci.yml",
        ".github/workflows/testing-securefix-server.yml",
        ".github/workflows/new-check-producer.yml",
        ".github/actions/setup-cli/action.yml",
        "src/bootstrap.rs",
        "src/bootstrap_main.rs",
        "src/lib.rs",
        "src/api.rs",
        "src/config.rs",
        "src/control.rs",
        "src/policy.rs",
        "src/workflow.rs",
        "Cargo.toml",
        "Cargo.lock",
        "policy.json",
        "build.rs",
        ".cargo/config.toml",
        "scripts/control-bootstrap.py",
    ] {
        assert!(changes_authority(&json!({"filename":name})), "{name}");
        assert!(
            changes_authority(&json!({"filename":"README.md","previous_filename":name})),
            "{name}"
        );
    }
    assert!(!changes_authority(
        &json!({"filename":"src/integration.rs"})
    ));
    let mut truncated = comparison(json!([{"filename":"README.md"}]));
    truncated["total_commits"] = json!(2);
    assert!(signed_descendant_files(&truncated, &main_sha()).is_err());
}

#[test]
fn repair_allows_only_package_version_bumps_in_the_locked_host_build_inputs() {
    let manifest =
        b"[package]\nname = \"securefix\"\nversion = \"0.2.21\"\n[dependencies]\nanyhow = \"1\"\n";
    let next = String::from_utf8(manifest.to_vec())
        .unwrap()
        .replace("0.2.21", "0.2.22");
    version_only_change("Cargo.toml", manifest, next.as_bytes()).unwrap();
    assert!(
        version_only_change(
            "Cargo.toml",
            manifest,
            next.replace("anyhow = \"1\"", "anyhow = \"2\"").as_bytes()
        )
        .is_err()
    );
    let lock = b"version = 4\n[[package]]\nname = \"securefix\"\nversion = \"0.2.21\"\ndependencies = [\"anyhow\"]\n";
    let next = String::from_utf8(lock.to_vec())
        .unwrap()
        .replace("0.2.21", "0.2.22");
    version_only_change("Cargo.lock", lock, next.as_bytes()).unwrap();
    assert!(
        version_only_change(
            "Cargo.lock",
            lock,
            next.replace("anyhow", "different").as_bytes()
        )
        .is_err()
    );
    assert!(version_only_change("Cargo.toml", manifest, manifest).is_err());
}

#[test]
fn active_descriptor_disables_proposal_before_archive_access_or_mutation() {
    let fixture = Fixture::new(vec![
        main_route(),
        Route::get(
            path("actions/runs/77"),
            run_fixture(BOOTSTRAP_WORKFLOW, false),
        ),
        Route::get(
            path(&format!("contents/{ACTIVE}?ref={}", main_sha())),
            json!({"type":"file"}),
        ),
    ]);
    assert!(
        host(&fixture, "propose")
            .validate_proposal(&main_sha(), 88, Path::new("missing-untrusted-candidate"))
            .unwrap_err()
            .to_string()
            .contains("permanently disabled")
    );
    fixture.finish();
}

#[test]
fn descriptor_retry_refreshes_only_publisher_evidence_and_binds_the_new_head() {
    let mut desired = descriptor();
    desired.publisher_run_id = 99;
    validate_retry_descriptor(&descriptor(), &desired).unwrap();
    let mut unsafe_change = desired.clone();
    unsafe_change.asset_id += 1;
    assert!(validate_retry_descriptor(&descriptor(), &unsafe_change).is_err());
    let branch = bootstrap_branch(&main_sha()).unwrap();
    let input = descriptor_commit(
        &policy().deployment.server.repository,
        &branch,
        &head_sha(),
        &desired,
    )
    .unwrap();
    assert_eq!(input["variables"]["input"]["expectedHeadOid"], head_sha());
    assert_eq!(
        input["variables"]["input"]["fileChanges"]["additions"][0]["path"],
        ACTIVE
    );
    let encoded = input["variables"]["input"]["fileChanges"]["additions"][0]["contents"]
        .as_str()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<ControlRevision>(&STANDARD.decode(encoded).unwrap()).unwrap(),
        desired
    );
    assert!(input["variables"]["input"]["fileChanges"]["deletions"].is_null());
}

fn writer<'a>(host: &'a Host, fixture: &Fixture) -> Writer<'a> {
    Writer {
        host,
        main: main_sha(),
        token: "fixture-writer".into(),
        api_base: fixture.base.clone(),
        client: Client::builder()
            .redirect(redirect::Policy::none())
            .build()
            .unwrap(),
    }
}

#[test]
fn writer_rechecks_main_and_absence_then_uses_exact_head_squash_cas() {
    let fixture = Fixture::new(vec![
        main_route(),
        absent_route(),
        Route::request("PUT", path("pulls/12/merge"), 200, json!({"merged":true}))
            .with_request_body(json!({"sha":head_sha(),"merge_method":"squash"}))
            .with_request_header("authorization", "Bearer fixture-writer"),
    ]);
    let first = host(&fixture, "merge");
    writer(&first, &fixture).merge(12, &head_sha()).unwrap();
    fixture.finish();
    let fixture = Fixture::new(vec![Route::get(
        path("commits/main"),
        json!({"sha":head_sha()}),
    )]);
    let host = host(&fixture, "merge");
    assert!(writer(&host, &fixture).merge(12, &head_sha()).is_err());
    fixture.finish();
}

#[test]
fn retry_resumes_a_verified_descriptor_branch_with_a_signed_compare_and_swap_commit() {
    let old_head = "c".repeat(40);
    let new_head = "d".repeat(40);
    let mut desired = descriptor();
    desired.publisher_run_id = 99;
    let branch = bootstrap_branch(&main_sha()).unwrap();
    let empty = Fixture::new(vec![]);
    let query = host(&empty, "propose").pulls_query("all", &branch).unwrap();
    empty.finish();
    let payload = descriptor_commit(
        &policy().deployment.server.repository,
        &branch,
        &old_head,
        &desired,
    )
    .unwrap();
    let fixture = Fixture::new(vec![
        Route::get(
            path(&format!("git/ref/heads/{branch}")),
            json!({"object":{"sha":old_head}}),
        ),
        Route::get(
            path(&format!("compare/{}...{old_head}", main_sha())),
            comparison(json!([{"filename":ACTIVE,"status":"added"}])),
        ),
        content_route(
            ACTIVE,
            &old_head,
            &serde_json::to_vec(&descriptor()).unwrap(),
        ),
        Route::get(query, json!([pull(&old_head)])),
        main_route(),
        absent_route(),
        Route::request(
            "POST",
            "/graphql",
            200,
            json!({"data":{"createCommitOnBranch":{"commit":{"oid":new_head}}}}),
        )
        .with_request_body(payload),
        Route::get(path("pulls/12"), pull(&new_head)),
    ]);
    let host = host(&fixture, "propose");
    let (head, pull) = host
        .resume_descriptor_branch(&writer(&host, &fixture), &branch, &desired)
        .unwrap();
    assert_eq!(head, Some(new_head));
    assert_eq!(pull.unwrap()["number"], 12);
    fixture.finish();
}

#[test]
fn writer_installation_must_be_scoped_to_the_configured_server() {
    let policy = policy();
    let good = json!({"total_count":1,"repositories":[{"full_name":policy.deployment.server.repository,"id":policy.deployment.server.id}]});
    validate_installation(&good, &policy).unwrap();
    let mut bad = good.clone();
    bad["total_count"] = json!(2);
    assert!(validate_installation(&bad, &policy).is_err());
    let mut bad = good;
    bad["repositories"][0]["id"] = json!(1);
    assert!(validate_installation(&bad, &policy).is_err());
}

#[test]
fn required_ci_accepts_multiple_successful_pr_suites_and_rejects_any_unfinished_or_failed_suite() {
    let check = json!({"name":"status-check","app":{"id":policy().deployment.checks.status_app_id},"status":"completed","conclusion":"success"});
    let mut pending = check.clone();
    pending["status"] = json!("in_progress");
    pending["conclusion"] = Value::Null;
    let mut failed = check.clone();
    failed["conclusion"] = json!("failure");
    let mut foreign = check.clone();
    foreign["app"]["id"] = json!(1);
    for (checks, accepted) in [
        (json!([]), false),
        (json!([check.clone(), check.clone()]), true),
        (json!([check.clone(), pending]), false),
        (json!([check.clone(), failed]), false),
        (json!([foreign.clone()]), false),
        (json!([check, foreign]), true),
    ] {
        let mut routes = status_routes(&main_sha());
        routes.pop();
        routes.push(Route::get(
            path(&format!(
                "commits/{}/check-runs?per_page=100&page=1&filter=latest",
                main_sha()
            )),
            json!({"check_runs":checks}),
        ));
        let fixture = Fixture::new(routes);
        assert_eq!(
            host(&fixture, "propose")
                .required_status(&main_sha())
                .is_ok(),
            accepted
        );
        fixture.finish();
    }
}

#[test]
fn bootstrap_plan_schema_rejects_missing_unknown_and_wrong_typed_fields() {
    let value = json!({"version":1,"operation":"prepare","repository":policy().deployment.server.repository,"repository_id":1,"default_branch":"main","owner_id":1,"server_bot_id":2,"status_app_id":3,"source_sha":main_sha(),"expected_main_sha":main_sha(),"archive_sha256":"1".repeat(64),"policy_sha256":"2".repeat(64),"verification_run_id":77,"publisher_run_id":88,"descriptor":null,"pull_request":null,"head_sha":null});
    serde_json::from_value::<Plan>(value.clone()).unwrap();
    let mut unknown = value.clone();
    unknown["unexpected"] = json!(true);
    assert!(serde_json::from_value::<Plan>(unknown).is_err());
    let mut missing = value.clone();
    missing.as_object_mut().unwrap().remove("head_sha");
    assert!(serde_json::from_value::<Plan>(missing).is_err());
    let mut boolean = value;
    boolean["publisher_run_id"] = json!(true);
    assert!(serde_json::from_value::<Plan>(boolean).is_err());
}
