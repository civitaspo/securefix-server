//! Unmerged, one-use successor authority. The candidate executable is never invoked.
use super::*;

const WORKFLOW: &str = ".github/workflows/control-activation.yml";
const PUBLISHER: &str = ".github/workflows/publish-runtime.yml";

#[cfg(test)]
#[path = "bootstrap_successor_recovery_tests.rs"]
mod tests;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    version: u32,
    authority_branch: String,
    expected_main_sha: String,
    pull_request: u64,
    expected_head_sha: String,
    active: ControlRevision,
    successor: ControlRevision,
}

impl Authorization {
    fn load() -> Result<Self> {
        let auth: Self =
            serde_json::from_slice(include_bytes!("../control/successor-recovery.json"))?;
        auth.validate()?;
        Ok(auth)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.pull_request > 0,
            "invalid successor recovery record"
        );
        validate_sha(&self.expected_main_sha)?;
        validate_sha(&self.expected_head_sha)?;
        ensure!(
            self.active.generation == 1
                && self.successor.generation == 2
                && self.successor.source_sha == self.expected_main_sha
                && self
                    .authority_branch
                    .starts_with("codex/recover-successor-")
                && self
                    .authority_branch
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/-".contains(&b)),
            "recovery is restricted to the fixed first normal successor"
        );
        self.active.validate_successor(&self.successor)
    }

    fn dispatch(&self, host: &Host, phase: &str) -> Result<()> {
        ensure!(
            matches!(phase, "successor-qualify" | "successor-merge"),
            "invalid recovery phase"
        );
        host.context.validate_branch(
            host,
            &host.context.compiled_sha,
            phase,
            WORKFLOW,
            &self.authority_branch,
        )?;
        ensure!(
            host.context.event["inputs"]["authority_sha"] == host.context.compiled_sha,
            "recovery authority input differs from compiled source"
        );
        let inputs = &host.context.event["inputs"];
        ensure!(
            inputs["source_sha"] == self.successor.source_sha
                && inputs["publisher_run_id"].as_str()
                    == Some(self.successor.publisher_run_id.to_string().as_str())
                && inputs["verification_run_id"].as_str()
                    == Some(self.successor.verification_run_id.to_string().as_str())
                && inputs["expected_control_id"] == self.active.identity()?,
            "recovery dispatch inputs differ from the fixed target"
        );
        Ok(())
    }

    fn fence(&self, host: &Host) -> Result<()> {
        host.require_main(&self.expected_main_sha)?;
        let active: ControlRevision =
            serde_json::from_slice(&host.contents(ACTIVE, &self.expected_main_sha)?)?;
        ensure!(
            active == self.active,
            "active control differs from fixed predecessor"
        );
        Ok(())
    }

    fn pull_identity(&self, host: &Host, pull: &Value) -> Result<()> {
        validate_pull_identity(
            pull,
            &host.policy,
            &self.expected_main_sha,
            &self.expected_head_sha,
        )?;
        ensure!(
            pull["number"].as_u64() == Some(self.pull_request)
                && pull["draft"] == false
                && pull["merged_at"].is_null()
                && pull["head"]["ref"]
                    == format!(
                        "automation/securefix-runtime/control-2-{}",
                        &self.successor.source_sha[..12]
                    )
                && pull["user"]["type"] == "Bot"
                && pull["user"]["login"].as_str().is_some_and(
                    |s| s.eq_ignore_ascii_case(&host.policy.deployment.server_bot_login)
                ),
            "successor PR ownership, state or branch differs from fixed target"
        );
        Ok(())
    }

    fn reviews_and_policy(&self, host: &Host) -> Result<()> {
        let reviews = host
            .api
            .paginate(&host.path(&format!("pulls/{}/reviews", self.pull_request)))?;
        validate_review(&reviews, host.policy.owner_id, &self.expected_head_sha)?;
        let reviewer = &host.policy.deployment.approval_reviewer;
        validate_review(&reviews, reviewer.id, &self.expected_head_sha)?;
        let marker = format!(
            "<!-- securefix:control-review:{} -->",
            self.active.identity()?
        );
        for (id, login) in [
            (
                host.policy.owner_id,
                host.policy.deployment.owner_login.as_str(),
            ),
            (reviewer.id, reviewer.login.as_str()),
        ] {
            let latest = reviews
                .iter()
                .filter(|r| r["user"]["id"].as_u64() == Some(id))
                .max_by_key(|r| {
                    (
                        r["submitted_at"].as_str().unwrap_or(""),
                        r["id"].as_u64().unwrap_or(0),
                    )
                })
                .context("required control-bound review missing")?;
            ensure!(
                latest["state"] == "APPROVED"
                    && latest["commit_id"] == self.expected_head_sha
                    && latest["user"]["type"] == "User"
                    && latest["user"]["login"]
                        .as_str()
                        .is_some_and(|s| s.eq_ignore_ascii_case(login))
                    && latest["body"]
                        .as_str()
                        .is_some_and(|body| body.lines().any(|line| line == marker)),
                "latest exact-head review is not bound to the fixed active control"
            );
        }
        let mut checks = Vec::new();
        for page in 1..=100 {
            let response: Value = host.api.get(&host.path(&format!(
                "commits/{}/check-runs?per_page=100&page={page}&filter=latest",
                self.expected_head_sha
            )))?;
            let batch = array(&response["check_runs"])?;
            checks.extend(batch.iter().cloned());
            if batch.len() < 100 {
                break;
            }
            ensure!(page < 100, "policy check pagination exceeded limit");
        }
        let policy: Vec<_> = checks
            .iter()
            .filter(|c| {
                c["name"] == "securefix-policy-check"
                    && c["app"]["id"].as_u64() == Some(host.policy.deployment.checks.policy_app_id)
            })
            .collect();
        ensure!(
            policy.len() == 1
                && policy[0]["status"] == "completed"
                && policy[0]["conclusion"] == "success"
                && policy[0]["external_id"]
                    == format!("{}:{}", self.expected_head_sha, self.active.identity()?),
            "exact-head active-control policy check is missing or unsuccessful"
        );
        let repository = host.repository();
        let review = host.api.graphql("query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewDecision}}}", json!({
            "owner":repository.split('/').next().unwrap_or_default(),
            "name":repository.split('/').nth(1).unwrap_or_default(), "number":self.pull_request
        }))?;
        ensure!(
            review["repository"]["pullRequest"]["reviewDecision"] == "APPROVED",
            "GitHub review decision is not approved"
        );
        Ok(())
    }

    fn qualify(&self, host: &Host, phase: &str) -> Result<()> {
        self.validate()?;
        self.dispatch(host, phase)?;
        self.fence(host)?;
        host.current_policy(&self.expected_main_sha)?;
        ensure!(
            sha256(&host.policy_bytes) == self.successor.policy_sha256
                && sha256(&host.policy_bytes) == self.active.policy_sha256,
            "fixed policy differs from active or successor policy"
        );
        let source = &host.context.compiled_sha;
        let run: Value = host
            .api
            .get(&host.path(&format!("actions/runs/{}", host.context.run_id)))?;
        validate_authority_run(&run, host, self)?;
        let reference: Value = host
            .api
            .get(&host.path(&format!("git/ref/heads/{}", self.authority_branch)))?;
        ensure!(
            reference["object"]["type"] == "commit" && reference["object"]["sha"] == *source,
            "recovery authority branch moved"
        );
        host.required_status(source)?;
        host.required_status(&self.expected_main_sha)?;
        for (base, head) in [
            (&self.active.source_sha, &self.expected_main_sha),
            (&self.expected_main_sha, source),
        ] {
            let comparison: Value = host
                .api
                .get(&host.path(&format!("compare/{base}...{head}")))?;
            signed_descendant_files(&comparison, base)?;
        }
        let pull: Value = host
            .api
            .get(&host.path(&format!("pulls/{}", self.pull_request)))?;
        self.pull_identity(host, &pull)?;
        let comparison: Value = host.api.get(&host.path(&format!(
            "compare/{}...{}",
            self.expected_main_sha, self.expected_head_sha
        )))?;
        let files = signed_descendant_files(&comparison, &self.expected_main_sha)?;
        ensure!(
            comparison["total_commits"] == 1
                && files.len() == 1
                && files[0]["filename"] == ACTIVE
                && files[0]["status"] == "modified",
            "successor must be one signed descriptor-only commit"
        );
        let proposed: ControlRevision =
            serde_json::from_slice(&host.contents(ACTIVE, &self.expected_head_sha)?)?;
        ensure!(
            proposed == self.successor,
            "successor descriptor differs from fixed target"
        );
        host.required_status(&self.expected_head_sha)?;
        self.reviews_and_policy(host)?;
        host.workflow_run(
            self.successor.publisher_run_id,
            PUBLISHER,
            &self.successor.source_sha,
            false,
        )?;
        let (tag, prerelease) = host.version_tag(&self.successor.source_sha)?;
        ensure!(
            !prerelease,
            "recovery requires the fixed stable publication"
        );
        let reference: Value = host.api.get(&host.path(&format!("git/ref/tags/{tag}")))?;
        validate_tag(&reference, &self.successor.source_sha)?;
        let release: Value = host
            .api
            .get(&host.path(&format!("releases/{}", self.successor.release_id)))?;
        validate_release_identity(&release, &self.successor.source_sha, &tag)?;
        ensure!(
            release["id"].as_u64() == Some(self.successor.release_id)
                && release["name"] == tag
                && release["prerelease"] == false,
            "release identity differs from fixed target"
        );
        let asset = immutable_asset(&release)?;
        ensure!(
            asset["id"].as_u64() == Some(self.successor.asset_id),
            "asset ID differs from fixed target"
        );
        let bytes = host.api.download(
            &host.path(&format!("releases/assets/{}", self.successor.asset_id)),
            MAX_ARCHIVE,
        )?;
        ensure!(
            asset["size"].as_u64() == Some(bytes.len() as u64)
                && asset["digest"] == format!("sha256:{}", self.successor.archive_sha256)
                && sha256(&bytes) == self.successor.archive_sha256
                && archive_policy(&bytes)? == host.policy_bytes,
            "archive digest, size or policy differs from fixed publication"
        );
        let mut archive = tempfile::NamedTempFile::new()?;
        archive.write_all(&bytes)?;
        archive.flush()?;
        host.verify_attestation_from(archive.path(), &self.successor.source_sha, PUBLISHER)?;
        host.validate_scratch(
            &self.successor.source_sha,
            self.successor.verification_run_id,
        )?;
        let pair = zip_json_files(
            &host.artifact(
                self.successor.verification_run_id,
                "scratch-fixtures",
                MAX_ARTIFACT,
            )?,
            &["state.json", "verification.json"],
        )?;
        ensure!(
            pair["state.json"]["published_runtime_sha"] == self.active.source_sha,
            "scratch proof used a different published baseline"
        );
        self.fence(host)
    }

    fn merge_after_qualification(&self, host: &Host, writer: &Writer<'_>) -> Result<Value> {
        self.fence(host)?;
        let pull: Value = host
            .api
            .get(&host.path(&format!("pulls/{}", self.pull_request)))?;
        self.pull_identity(host, &pull)?;
        let response = writer
            .client
            .put(format!(
                "{}{}",
                writer.api_base,
                host.path(&format!("pulls/{}/merge", self.pull_request))
            ))
            .bearer_auth(&writer.token)
            .header("User-Agent", "securefix-successor-recovery")
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&json!({"sha":self.expected_head_sha,"merge_method":"squash"}))
            .send()?;
        let result = read_response(response)?;
        ensure!(
            result["merged"] == true,
            "GitHub did not merge the fixed successor PR"
        );
        Ok(result)
    }
}

fn validate_authority_run(run: &Value, host: &Host, auth: &Authorization) -> Result<()> {
    let server = &host.policy.deployment.server;
    ensure!(
        run["id"].as_u64() == Some(host.context.run_id)
            && [&run["repository"], &run["head_repository"]]
                .iter()
                .all(|r| r["id"].as_u64() == Some(server.id) && r["full_name"] == server.repository)
            && run["path"].as_str().is_some_and(|p| p == WORKFLOW
                || p == format!("{WORKFLOW}@refs/heads/{}", auth.authority_branch))
            && run["event"] == "workflow_dispatch"
            && run["head_branch"] == auth.authority_branch
            && run["head_sha"] == host.context.compiled_sha
            && run["run_attempt"] == 1
            && run["actor"]["id"].as_u64() == Some(host.policy.owner_id)
            && run["triggering_actor"]["id"].as_u64() == Some(host.policy.owner_id)
            && run["status"] == "in_progress",
        "recovery workflow run provenance mismatch"
    );
    Ok(())
}

fn source_approval(host: &Host) -> Result<()> {
    let source = std::env::var("SECUREFIX_SUCCESSOR_RECOVERY_SOURCE_SHA")
        .context("missing separate source approval")?;
    require_source_approval(host, &source)
}

fn require_source_approval(host: &Host, source: &str) -> Result<()> {
    validate_sha(source)?;
    ensure!(
        source == host.context.compiled_sha,
        "fixed recovery source is not separately approved"
    );
    Ok(())
}

pub(super) fn validate(host: &Host) -> Result<()> {
    let auth = Authorization::load()?;
    let phase = host.context.event["inputs"]["phase"]
        .as_str()
        .context("missing recovery phase")?;
    if phase == "successor-merge" {
        source_approval(host)?;
    }
    auth.qualify(host, phase)?;
    emit(
        &json!({"authority_sha":host.context.compiled_sha,"expected_main_sha":auth.expected_main_sha,"pull_request":auth.pull_request,"expected_head_sha":auth.expected_head_sha,"active_control_id":auth.active.identity()?,"successor_control_id":auth.successor.identity()?}),
    )
}

pub(super) fn merge(host: &Host) -> Result<()> {
    source_approval(host)?;
    let auth = Authorization::load()?;
    auth.qualify(host, "successor-merge")?;
    let writer = host.writer(&auth.expected_main_sha)?;
    emit(&auth.merge_after_qualification(host, &writer)?)
}
