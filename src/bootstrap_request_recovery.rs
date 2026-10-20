use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    version: u32,
    authority_branch: String,
    workflow: String,
    expected_main_sha: String,
    pull_request: u64,
    target_branch: String,
    expected_head_sha: String,
    expected_tree_sha: String,
    commits: Vec<String>,
    active: ControlRevision,
    files: Vec<FixedFile>,
    probe: Probe,
    workflow_probe: Probe,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixedFile {
    path: String,
    status: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    run_id: u64,
    source_sha: String,
    workflow: String,
    branch: String,
}

impl Authorization {
    fn load() -> Result<Self> {
        let auth: Self =
            serde_json::from_slice(include_bytes!("../control/request-recovery.json"))?;
        ensure!(
            auth.version == 1 && auth.pull_request > 0,
            "invalid fixed recovery record"
        );
        for sha in [
            &auth.expected_main_sha,
            &auth.expected_head_sha,
            &auth.expected_tree_sha,
            &auth.probe.source_sha,
            &auth.workflow_probe.source_sha,
        ] {
            validate_sha(sha)?;
        }
        auth.active.validate()?;
        ensure!(
            !auth.commits.is_empty()
                && auth.commits.last() == Some(&auth.expected_head_sha)
                && !auth.files.is_empty()
                && auth.files.len() <= 20,
            "invalid fixed target bounds"
        );
        let mut paths = BTreeSet::new();
        for file in &auth.files {
            ensure!(
                paths.insert(&file.path)
                    && !file.path.starts_with('/')
                    && !file
                        .path
                        .split('/')
                        .any(|part| matches!(part, "" | "." | ".."))
                    && matches!(file.status.as_str(), "added" | "modified")
                    && file.sha256.len() == 64
                    && file
                        .sha256
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "invalid fixed file record"
            );
        }
        Ok(auth)
    }

    fn digest(&self) -> String {
        sha256(include_bytes!("../control/request-recovery.json"))
    }

    fn owner_body(&self, source: &str) -> Result<String> {
        Ok(format!(
            "Authorize the reviewed one-use request-intake recovery.\n\nRepository: {}\nPR: {}\nExpected main: {}\nAccepted head: {}\nActive control: {}\nRecovery source: {}\nAuthorization record SHA-256: {}\nOperations: configured non-author review, then Server App squash merge of this exact PR only.\n\n<!-- securefix:request-recovery:{} -->",
            Policy::parse(include_bytes!("../policy.json"))?
                .deployment
                .server
                .repository,
            self.pull_request,
            self.expected_main_sha,
            self.expected_head_sha,
            self.active.identity()?,
            source,
            self.digest(),
            self.digest()
        ))
    }

    fn review_body(&self, source: &str) -> Result<String> {
        Ok(format!(
            "Independently qualified request-intake recovery for this exact head. Ordinary intake is unavailable; this review does not claim an ordinary policy check passed.\n\nRecovery source: {source}\n<!-- securefix:request-recovery:{} -->\n<!-- securefix:control-review:{} -->",
            self.digest(),
            self.active.identity()?
        ))
    }

    fn dispatch(&self, host: &Host, phase: &str) -> Result<()> {
        let context = &host.context;
        validate_sha(&context.compiled_sha)?;
        ensure!(
            context.repository == host.repository()
                && context.reference == format!("refs/heads/{}", self.authority_branch)
                && context.event_name == "workflow_dispatch"
                && context.workflow_ref
                    == format!(
                        "{}/{}@refs/heads/{}",
                        host.repository(),
                        self.workflow,
                        self.authority_branch
                    )
                && context.workflow_sha == context.compiled_sha
                && context.source_sha == context.compiled_sha
                && context.actor_id == host.policy.owner_id.to_string()
                && context.attempt == "1"
                && context.run_id > 0
                && context.event["inputs"]["phase"] == phase
                && context.event["inputs"]["authority_sha"] == context.compiled_sha,
            "not a first-attempt owner dispatch of the fixed recovery source"
        );
        let run: Value = host
            .api
            .get(&host.path(&format!("actions/runs/{}", context.run_id)))?;
        validate_run_identity(
            &run,
            host,
            &self.workflow,
            &self.authority_branch,
            &context.compiled_sha,
        )?;
        ensure!(
            run["id"].as_u64() == Some(context.run_id) && run["status"] == "in_progress",
            "recovery run is not current"
        );
        let branch: Value = host
            .api
            .get(&host.path(&format!("git/ref/heads/{}", self.authority_branch)))?;
        ensure!(
            branch["object"]["type"] == "commit" && branch["object"]["sha"] == context.compiled_sha,
            "recovery branch moved"
        );
        Ok(())
    }

    fn fence(&self, host: &Host) -> Result<()> {
        host.require_main(&self.expected_main_sha)?;
        let active: ControlRevision =
            serde_json::from_slice(&host.contents(ACTIVE, &self.expected_main_sha)?)?;
        ensure!(
            active == self.active,
            "active control differs from the fixed recovery record"
        );
        host.current_policy(&self.expected_main_sha)?;
        ensure!(
            sha256(&host.policy_bytes) == self.active.policy_sha256,
            "recovery policy differs from active policy"
        );
        Ok(())
    }

    fn pull_identity(&self, host: &Host, pull: &Value) -> Result<()> {
        let server = &host.policy.deployment.server;
        ensure!(
            pull["number"].as_u64() == Some(self.pull_request)
                && pull["state"] == "open"
                && pull["merged_at"].is_null()
                && pull["draft"] == false
                && pull["user"]["id"].as_u64() == Some(host.policy.owner_id)
                && pull["user"]["login"] == host.policy.deployment.owner_login
                && pull["user"]["type"] == "User"
                && pull["head"]["sha"] == self.expected_head_sha
                && pull["head"]["ref"] == self.target_branch
                && pull["base"]["sha"] == self.expected_main_sha
                && pull["base"]["ref"] == server.default_branch
                && [&pull["head"]["repo"], &pull["base"]["repo"]]
                    .iter()
                    .all(|r| r["id"].as_u64() == Some(server.id)
                        && r["full_name"] == server.repository),
            "fixed recovery PR identity, head, base or state changed"
        );
        Ok(())
    }

    fn target(&self, host: &Host) -> Result<()> {
        let pull: Value = host
            .api
            .get(&host.path(&format!("pulls/{}", self.pull_request)))?;
        self.pull_identity(host, &pull)?;
        let comparison: Value = host.api.get(&host.path(&format!(
            "compare/{}...{}",
            self.expected_main_sha, self.expected_head_sha
        )))?;
        let files = signed_descendant_files(&comparison, &self.expected_main_sha)?;
        self.target_comparison(host, &comparison, files)?;
        for file in &self.files {
            ensure!(
                sha256(&host.contents(&file.path, &self.expected_head_sha)?) == file.sha256,
                "fixed target file bytes changed: {}",
                file.path
            );
        }
        let commit: Value = host
            .api
            .get(&host.path(&format!("git/commits/{}", self.expected_head_sha)))?;
        ensure!(
            commit["sha"] == self.expected_head_sha
                && commit["tree"]["sha"] == self.expected_tree_sha,
            "fixed target tree changed"
        );
        Ok(())
    }

    fn target_comparison(&self, host: &Host, comparison: &Value, files: &[Value]) -> Result<()> {
        ensure!(
            files.len() == self.files.len()
                && comparison["total_commits"].as_u64() == Some(self.commits.len() as u64),
            "fixed target comparison incomplete"
        );
        let commits = array(&comparison["commits"])?;
        ensure!(
            commits.len() == self.commits.len(),
            "fixed target commits truncated"
        );
        let mut parent = &self.expected_main_sha;
        for (commit, expected) in commits.iter().zip(&self.commits) {
            validate_sha(expected)?;
            ensure!(
                commit["sha"] == *expected
                    && commit["commit"]["verification"]["verified"] == true
                    && commit["author"]["id"].as_u64() == Some(host.policy.owner_id)
                    && commit["committer"]["id"].as_u64() == Some(host.policy.owner_id)
                    && array(&commit["parents"])?.len() == 1
                    && commit["parents"][0]["sha"] == *parent,
                "fixed target requires the exact signed owner commit chain"
            );
            parent = expected;
        }
        let actual: BTreeSet<_> = files.iter().map(|f| f["filename"].as_str()).collect();
        ensure!(actual.len() == files.len(), "duplicate target file");
        for fixed in &self.files {
            let file = files
                .iter()
                .find(|file| file["filename"] == fixed.path)
                .context("fixed target file missing")?;
            ensure!(
                file["status"] == fixed.status && file.get("previous_filename").is_none(),
                "fixed target file status changed"
            );
        }
        Ok(())
    }

    fn source_ci(&self, host: &Host, sha: &str) -> Result<()> {
        host.required_status(sha)?;
        let result: Value = host.api.get(&host.path(&format!(
            "actions/workflows/ci.yml/runs?head_sha={sha}&per_page=100"
        )))?;
        let runs = array(&result["workflow_runs"])?;
        let ci = runs
            .iter()
            .find(|run| run["head_sha"] == sha && run["path"] == ".github/workflows/ci.yml")
            .context("source-bound CI run missing")?;
        ensure!(
            ci["status"] == "completed"
                && ci["conclusion"] == "success"
                && ci["run_attempt"] == 1
                && ci["repository"]["id"].as_u64() == Some(host.policy.deployment.server.id)
                && ci["head_repository"]["id"].as_u64() == Some(host.policy.deployment.server.id)
                && ci["actor"]["id"].as_u64() == Some(host.policy.owner_id)
                && ci["triggering_actor"]["id"].as_u64() == Some(host.policy.owner_id)
                && matches!(
                    ci["event"].as_str(),
                    Some("pull_request" | "workflow_dispatch")
                ),
            "source-bound required CI provenance or result mismatch"
        );
        Ok(())
    }

    fn other_checks(&self, host: &Host) -> Result<()> {
        let result: Value = host.api.get(&host.path(&format!(
            "commits/{}/check-runs?per_page=100&filter=latest",
            self.expected_head_sha
        )))?;
        self.check_results(host, &result)
    }

    fn check_results(&self, host: &Host, result: &Value) -> Result<()> {
        let checks = array(&result["check_runs"])?;
        ensure!(
            checks.len() <= 100 && result["total_count"].as_u64() == Some(checks.len() as u64),
            "target check list is incomplete or exceeds bounded recovery"
        );
        let mut policy_checks = 0;
        for check in checks {
            if check["name"] == "securefix-policy-check"
                && check["app"]["id"].as_u64() == Some(host.policy.deployment.checks.policy_app_id)
            {
                policy_checks += 1;
                ensure!(
                    check["external_id"]
                        == format!("{}:{}", self.expected_head_sha, self.active.identity()?)
                        && check["status"] == "completed"
                        && (check["conclusion"] == "success"
                            || ordinary_policy_reports_missing_owner_authorization(check)),
                    "ordinary policy failed for a different reason"
                );
            } else {
                ensure!(
                    check["status"] == "completed"
                        && matches!(
                            check["conclusion"].as_str(),
                            Some("success" | "skipped" | "neutral")
                        ),
                    "unrelated target check is pending or unsuccessful"
                );
            }
        }
        ensure!(
            policy_checks == 1,
            "exactly one ordinary policy check is required"
        );
        Ok(())
    }

    fn probe_jobs(&self, host: &Host, probe: &Probe, conclusion: &str) -> Result<Value> {
        let integration = &host.policy.deployment.integration;
        let run: Value = host.api.get(&format!(
            "/repos/{}/actions/runs/{}",
            integration.repository, probe.run_id
        ))?;
        ensure!(
            run["id"].as_u64() == Some(probe.run_id)
                && run["head_sha"] == probe.source_sha
                && run["path"] == probe.workflow
                && run["head_branch"] == probe.branch
                && run["event"] == "workflow_dispatch"
                && run["run_attempt"] == 1
                && run["repository"]["id"].as_u64() == Some(integration.id)
                && run["head_repository"]["id"].as_u64() == Some(integration.id)
                && run["actor"]["id"].as_u64() == Some(host.policy.owner_id)
                && run["triggering_actor"]["id"].as_u64() == Some(host.policy.owner_id)
                && run["status"] == "completed"
                && run["conclusion"] == conclusion,
            "fixed permission probe provenance mismatch"
        );
        host.api.get(&format!(
            "/repos/{}/actions/runs/{}/jobs?per_page=100",
            integration.repository, probe.run_id
        ))
    }

    fn permission_probe(&self, host: &Host) -> Result<()> {
        let jobs = self.probe_jobs(host, &self.probe, "failure")?;
        ensure!(
            jobs["total_count"] == 3 && array(&jobs["jobs"])?.len() == 3,
            "permission probe job list mismatch"
        );
        for (name, conclusion) in [
            ("issues-only", "failure"),
            ("pr-only", "success"),
            ("both", "success"),
        ] {
            let job = array(&jobs["jobs"])?
                .iter()
                .find(|job| job["name"] == name)
                .context("permission probe job missing")?;
            ensure!(
                job["status"] == "completed" && job["conclusion"] == conclusion,
                "permission probe result mismatch"
            );
        }
        let workflow_jobs = self.probe_jobs(host, &self.workflow_probe, "skipped")?;
        self.workflow_probe_jobs(&workflow_jobs)
    }

    fn workflow_probe_jobs(&self, jobs: &Value) -> Result<()> {
        let jobs_array = array(&jobs["jobs"])?;
        ensure!(
            jobs["total_count"] == 2 && jobs_array.len() == 2,
            "workflow permission probe job list mismatch"
        );
        for name in ["approve", "merge"] {
            ensure!(
                jobs_array
                    .iter()
                    .filter(|job| job["name"] == name
                        && job["status"] == "completed"
                        && job["conclusion"] == "skipped")
                    .count()
                    == 1,
                "workflow permission probe did not validate both legacy callers"
            );
        }
        Ok(())
    }

    fn qualify(&self, host: &Host, phase: &str) -> Result<()> {
        self.dispatch(host, phase)?;
        self.fence(host)?;
        self.source_ci(host, &host.context.compiled_sha)?;
        self.source_ci(host, &self.expected_head_sha)?;
        let comparison: Value = host.api.get(&host.path(&format!(
            "compare/{}...{}",
            self.expected_main_sha, host.context.compiled_sha
        )))?;
        signed_descendant_files(&comparison, &self.expected_main_sha)?;
        ensure!(
            array(&comparison["commits"])?
                .iter()
                .all(
                    |commit| commit["author"]["id"].as_u64() == Some(host.policy.owner_id)
                        && commit["committer"]["id"].as_u64() == Some(host.policy.owner_id)
                ),
            "recovery source has a non-owner effective committer"
        );
        self.target(host)?;
        self.other_checks(host)?;
        self.permission_probe(host)?;
        self.fence(host)
    }

    fn rehearsal_evidence(&self, host: &Host) -> Result<()> {
        let id = host.context.event["inputs"]["rehearsal_run_id"]
            .as_str()
            .context("successful rehearsal run required")?
            .parse::<u64>()?;
        ensure!(
            id > 0 && id != host.context.run_id,
            "invalid rehearsal run ID"
        );
        let run: Value = host.api.get(&host.path(&format!("actions/runs/{id}")))?;
        validate_run_identity(
            &run,
            host,
            &self.workflow,
            &self.authority_branch,
            &host.context.compiled_sha,
        )?;
        ensure!(
            run["id"].as_u64() == Some(id)
                && run["status"] == "completed"
                && run["conclusion"] == "success",
            "rehearsal run did not succeed"
        );
        let pair = zip_json_files(
            &host.artifact(id, "request-recovery-rehearsal", MAX_ARTIFACT)?,
            &["request-recovery-rehearsal.json"],
        )?;
        let proof: RehearsalEvidence =
            serde_json::from_value(pair["request-recovery-rehearsal.json"].clone())?;
        let state: Value =
            serde_json::from_slice(include_bytes!("../control/request-recovery-rehearsal.json"))?;
        let scratch = &host.policy.deployment.integration;
        ensure!(
            proof.recovery_source == host.context.compiled_sha
                && proof.repository == scratch.repository
                && Some(proof.positive_pr) == state["positive"]["number"].as_u64()
                && Some(proof.stale_pr) == state["stale"]["number"].as_u64()
                && proof.scratch_main_sha == state["scratch_main_sha"]
                && proof.stale_head_rejected
                && proof.scratch_main_unchanged
                && proof.fixtures_cleaned
                && !proof.production_merge_verified,
            "rehearsal evidence binding mismatch"
        );
        validate_sha(&proof.merge_sha)?;
        let root = format!("/repos/{}", scratch.repository);
        let positive: Value = host
            .api
            .get(&format!("{root}/pulls/{}", proof.positive_pr))?;
        let stale: Value = host.api.get(&format!("{root}/pulls/{}", proof.stale_pr))?;
        ensure!(
            positive["merged"] == true
                && positive["merge_commit_sha"] == proof.merge_sha
                && positive["head"]["sha"] == state["positive"]["head"]
                && stale["state"] == "closed"
                && stale["merged"] == false
                && stale["head"]["sha"] == state["stale"]["advanced_head"],
            "independent rehearsal PR state mismatch"
        );
        let commit: Value = host
            .api
            .get(&format!("{root}/commits/{}", proof.merge_sha))?;
        ensure!(
            commit["commit"]["verification"]["verified"] == true
                && array(&commit["parents"])?.len() == 1
                && commit["parents"][0]["sha"] == state["base_sha"]
                && commit["commit"]["tree"]["sha"] == state["positive"]["tree"],
            "independent rehearsal merge tree/signature mismatch"
        );
        let main: Value = host
            .api
            .get(&format!("{root}/git/ref/heads/{}", scratch.default_branch))?;
        ensure!(
            main["object"]["sha"] == proof.scratch_main_sha,
            "scratch protected main changed after rehearsal"
        );
        for branch in [
            &state["base_branch"],
            &state["positive"]["branch"],
            &state["stale"]["branch"],
        ] {
            let branch = branch.as_str().context("invalid fixture branch")?;
            match host
                .api
                .get::<Value>(&format!("{root}/git/ref/heads/{branch}"))
            {
                Err(error)
                    if error
                        .downcast_ref::<ApiError>()
                        .is_some_and(|e| e.status == StatusCode::NOT_FOUND) => {}
                Err(error) => return Err(error),
                Ok(_) => bail!("rehearsal branch remains after cleanup"),
            }
        }
        Ok(())
    }

    fn owner_authorization(&self, host: &Host) -> Result<()> {
        let source = std::env::var("SECUREFIX_REQUEST_RECOVERY_SOURCE_SHA")
            .context("missing exact-source owner approval")?;
        ensure!(
            source == host.context.compiled_sha,
            "recovery source is not separately approved"
        );
        let id = host.context.event["inputs"]["authorization_comment_id"]
            .as_str()
            .context("missing owner authorization comment")?
            .parse::<u64>()?;
        ensure!(id > 0, "invalid owner comment ID");
        let comment: Value = host.api.get(&host.path(&format!("issues/comments/{id}")))?;
        self.owner_comment(host, &comment, id)?;
        let events = host
            .api
            .paginate(&host.path(&format!("issues/{}/timeline", self.pull_request)))?;
        validate_authorization_timeline(
            &events,
            comment["created_at"]
                .as_str()
                .context("missing owner comment time")?,
        )
    }

    fn owner_comment(&self, host: &Host, comment: &Value, id: u64) -> Result<()> {
        ensure!(
            comment["id"].as_u64() == Some(id)
                && comment["issue_url"]
                    == format!(
                        "https://api.github.com/repos/{}/issues/{}",
                        host.repository(),
                        self.pull_request
                    )
                && comment["user"]["id"].as_u64() == Some(host.policy.owner_id)
                && comment["user"]["login"] == host.policy.deployment.owner_login
                && comment["user"]["type"] == "User"
                && comment["body"] == self.owner_body(&host.context.compiled_sha)?
                && comment["created_at"].is_string()
                && comment["created_at"] == comment["updated_at"],
            "owner recovery authorization is edited or bound to different source/head/control"
        );
        let created =
            chrono::DateTime::parse_from_rfc3339(comment["created_at"].as_str().unwrap())?;
        let age = chrono::Utc::now().signed_duration_since(created);
        ensure!(
            age >= chrono::Duration::zero() && age <= chrono::Duration::hours(24),
            "owner recovery authorization is expired or future-dated"
        );
        Ok(())
    }

    fn reviewer_approval(&self, host: &Host) -> Result<()> {
        let reviewer = &host.policy.deployment.approval_reviewer;
        let reviews = host
            .api
            .paginate(&host.path(&format!("pulls/{}/reviews", self.pull_request)))?;
        let latest = reviews
            .iter()
            .filter(|review| review["user"]["id"].as_u64() == Some(reviewer.id))
            .max_by_key(|review| review["id"].as_u64().unwrap_or(0))
            .context("configured non-author review missing")?;
        ensure!(
            latest["user"]["login"] == reviewer.login
                && latest["user"]["type"] == "User"
                && reviewer.id != host.policy.owner_id
                && latest["state"] == "APPROVED"
                && latest["commit_id"] == self.expected_head_sha
                && latest["body"] == self.review_body(&host.context.compiled_sha)?,
            "configured reviewer approval is stale, dismissed or mismatched"
        );
        let server = &host.policy.deployment.server;
        let (owner, name) = server
            .repository
            .split_once('/')
            .context("invalid repository")?;
        let value = host.api.graphql("query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewDecision}}}", json!({"owner":owner,"name":name,"number":self.pull_request}))?;
        ensure!(
            value["repository"]["pullRequest"]["reviewDecision"] == "APPROVED",
            "GitHub review decision is not approved"
        );
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RehearsalEvidence {
    recovery_source: String,
    repository: String,
    positive_pr: u64,
    merge_sha: String,
    stale_pr: u64,
    scratch_main_sha: String,
    stale_head_rejected: bool,
    scratch_main_unchanged: bool,
    fixtures_cleaned: bool,
    production_merge_verified: bool,
}

fn validate_authorization_timeline(events: &[Value], accepted: &str) -> Result<()> {
    let accepted = chrono::DateTime::parse_from_rfc3339(accepted)?.timestamp();
    for event in events {
        if matches!(
            event["event"].as_str(),
            Some(
                "head_ref_force_pushed"
                    | "head_ref_deleted"
                    | "head_ref_restored"
                    | "base_ref_force_pushed"
                    | "base_ref_deleted"
                    | "base_ref_changed"
                    | "merged"
                    | "closed"
                    | "reopened"
                    | "convert_to_draft"
                    | "ready_for_review"
            )
        ) {
            let created = chrono::DateTime::parse_from_rfc3339(
                event["created_at"]
                    .as_str()
                    .context("missing PR transition time")?,
            )?;
            ensure!(
                created.timestamp() < accepted,
                "PR changed after owner recovery authorization"
            );
        }
    }
    Ok(())
}

fn ordinary_policy_reports_missing_owner_authorization(check: &Value) -> bool {
    check["conclusion"] == "failure"
        && check["output"]["title"] == "Policy rejected"
        && check["output"]["summary"].as_str().is_some_and(|summary| {
            summary.ends_with(
                "Details: owner authorization for this exact pull request head is missing",
            )
        })
}

fn validate_run_identity(
    run: &Value,
    host: &Host,
    workflow: &str,
    branch: &str,
    source: &str,
) -> Result<()> {
    let server = &host.policy.deployment.server;
    ensure!(
        [&run["repository"], &run["head_repository"]]
            .iter()
            .all(|repository| repository["id"].as_u64() == Some(server.id)
                && repository["full_name"] == server.repository)
            && (run["path"] == workflow
                || run["path"] == format!("{workflow}@refs/heads/{branch}"))
            && run["event"] == "workflow_dispatch"
            && run["head_branch"] == branch
            && run["head_sha"] == source
            && run["run_attempt"] == 1
            && run["actor"]["id"].as_u64() == Some(host.policy.owner_id)
            && run["triggering_actor"]["id"].as_u64() == Some(host.policy.owner_id),
        "recovery run provenance mismatch"
    );
    Ok(())
}

pub(super) fn plan(host: &Host) -> Result<()> {
    let auth = Authorization::load()?;
    let phase = host.context.event["inputs"]["phase"]
        .as_str()
        .context("missing recovery phase")?;
    ensure!(
        matches!(
            phase,
            "request-recovery-plan"
                | "request-recovery-rehearsal"
                | "request-recovery-review"
                | "request-recovery-merge"
        ),
        "invalid recovery phase"
    );
    auth.qualify(host, phase)?;
    if phase != "request-recovery-plan" {
        auth.owner_authorization(host)?;
    }
    if matches!(phase, "request-recovery-review" | "request-recovery-merge") {
        auth.rehearsal_evidence(host)?;
    }
    if phase == "request-recovery-merge" {
        auth.reviewer_approval(host)?;
    }
    emit(
        &json!({"authority_sha":host.context.compiled_sha,"authorization_record_sha256":auth.digest(),"expected_main_sha":auth.expected_main_sha,"pull_request":auth.pull_request,"accepted_head":auth.expected_head_sha,"control_id":auth.active.identity()?,"phase":phase,"read_only":true,"production_write_performed":false,"required_owner_comment":auth.owner_body(&host.context.compiled_sha)?}),
    )
}

pub(super) fn review(host: &Host) -> Result<()> {
    let auth = Authorization::load()?;
    auth.qualify(host, "request-recovery-review")?;
    auth.rehearsal_evidence(host)?;
    auth.owner_authorization(host)?;
    let token = std::env::var("SECUREFIX_RECOVERY_REVIEW_TOKEN")
        .context("missing configured reviewer token")?;
    let reviewer = GitHub::new("https://api.github.com", token.clone())?;
    let identity: Value = reviewer.get("/user")?;
    let expected = &host.policy.deployment.approval_reviewer;
    ensure!(
        identity["id"].as_u64() == Some(expected.id)
            && identity["login"] == expected.login
            && identity["type"] == "User"
            && expected.id != host.policy.owner_id,
        "unexpected or self-approving reviewer credential"
    );
    auth.fence(host)?;
    auth.target(host)?;
    auth.owner_authorization(host)?;
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(redirect::Policy::none())
        .build()?;
    let result = read_response(client.post(format!("https://api.github.com{}", host.path(&format!("pulls/{}/reviews", auth.pull_request))))
        .bearer_auth(token).header("User-Agent", "securefix-request-recovery").header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .json(&json!({"commit_id":auth.expected_head_sha,"event":"APPROVE","body":auth.review_body(&host.context.compiled_sha)?})).send()?)?;
    ensure!(
        result["user"]["id"].as_u64() == Some(expected.id)
            && result["commit_id"] == auth.expected_head_sha
            && result["state"] == "APPROVED",
        "recovery review mutation readback mismatch"
    );
    auth.reviewer_approval(host)?;
    emit(&json!({"review_id":result["id"],"accepted_head":auth.expected_head_sha,"merged":false}))
}

pub(super) fn merge(host: &Host) -> Result<()> {
    let auth = Authorization::load()?;
    auth.qualify(host, "request-recovery-merge")?;
    auth.rehearsal_evidence(host)?;
    auth.owner_authorization(host)?;
    auth.reviewer_approval(host)?;
    let writer = host.writer(&auth.expected_main_sha)?;
    auth.target(host)?;
    auth.owner_authorization(host)?;
    auth.reviewer_approval(host)?;
    auth.other_checks(host)?;
    let result = auth.merge_fixed(host, &writer)?;
    emit(&result)
}

impl Authorization {
    fn merge_fixed(&self, host: &Host, writer: &Writer<'_>) -> Result<Value> {
        let pull: Value = host
            .api
            .get(&host.path(&format!("pulls/{}", self.pull_request)))?;
        self.pull_identity(host, &pull)?;
        self.fence(host)?;
        let result = read_response(
            writer
                .client
                .put(format!(
                    "{}{}",
                    writer.api_base,
                    host.path(&format!("pulls/{}/merge", self.pull_request))
                ))
                .bearer_auth(&writer.token)
                .header("User-Agent", "securefix-request-recovery")
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .json(&json!({"sha":self.expected_head_sha,"merge_method":"squash"}))
                .send()?,
        )?;
        ensure!(
            result["merged"] == true,
            "GitHub did not merge the fixed recovery PR"
        );
        Ok(result)
    }
}

#[cfg(test)]
#[path = "bootstrap_request_recovery_tests.rs"]
mod tests;
