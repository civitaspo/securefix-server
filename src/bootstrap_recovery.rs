//! Unmerged, one-use recovery authority. This module must never enter protected main.
use super::*;

#[cfg(test)]
#[path = "bootstrap_recovery_tests.rs"]
mod tests;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    version: u32,
    expected_main_sha: String,
    expected_head_sha: String,
    expected_tree_sha: String,
    source_pull_request: u64,
    authority_branch: String,
    proposal_branch: String,
}

impl Authorization {
    fn load() -> Result<Self> {
        let auth: Self =
            serde_json::from_slice(include_bytes!("../control/bootstrap-recovery.json"))?;
        ensure!(
            auth.version == 1 && auth.source_pull_request > 0,
            "invalid recovery authorization"
        );
        for sha in [
            &auth.expected_main_sha,
            &auth.expected_head_sha,
            &auth.expected_tree_sha,
        ] {
            validate_sha(sha)?;
        }
        Ok(auth)
    }

    fn dispatch(&self, host: &Host, phase: &str) -> Result<()> {
        host.context.validate_branch(
            host,
            &host.context.compiled_sha,
            phase,
            BOOTSTRAP_WORKFLOW,
            &self.authority_branch,
        )?;
        ensure!(
            host.context.event["inputs"]["authority_sha"] == host.context.compiled_sha,
            "recovery authority input differs from compiled source"
        );
        Ok(())
    }

    fn qualify(&self, host: &Host, phase: &str) -> Result<()> {
        self.dispatch(host, phase)?;
        host.require_main(&self.expected_main_sha)?;
        host.require_absent(&self.expected_main_sha)?;
        host.current_policy(&self.expected_main_sha)?;
        let source = &host.context.compiled_sha;
        let run: Value = host
            .api
            .get(&host.path(&format!("actions/runs/{}", host.context.run_id)))?;
        validate_run_branch(
            &run,
            &host.policy,
            host.context.run_id,
            BOOTSTRAP_WORKFLOW,
            source,
            true,
            &self.authority_branch,
        )?;
        let reference: Value = host
            .api
            .get(&host.path(&format!("git/ref/heads/{}", self.authority_branch)))?;
        ensure!(
            reference["object"]["type"] == "commit" && reference["object"]["sha"] == *source,
            "recovery authority branch moved"
        );
        host.required_status(source)?;
        let source_pull: Value = host
            .api
            .get(&host.path(&format!("pulls/{}", self.source_pull_request)))?;
        let server = &host.policy.deployment.server;
        ensure!(
            source_pull["number"] == self.source_pull_request
                && source_pull["state"] == "open"
                && source_pull["head"]["sha"] == self.expected_head_sha
                && source_pull["base"]["sha"] == self.expected_main_sha
                && source_pull["base"]["ref"] == server.default_branch
                && [&source_pull["head"]["repo"], &source_pull["base"]["repo"]]
                    .iter()
                    .all(|r| r["full_name"] == server.repository
                        && r["id"].as_u64() == Some(server.id))
                && source_pull["user"]["id"].as_u64() == Some(host.policy.owner_id)
                && source_pull["draft"] == false
                && source_pull["merged_at"].is_null(),
            "recovery source PR identity changed"
        );
        let target: Value = host
            .api
            .get(&host.path(&format!("commits/{}", self.expected_head_sha)))?;
        ensure!(
            target["sha"] == self.expected_head_sha
                && target["commit"]["tree"]["sha"] == self.expected_tree_sha,
            "recovery target tree changed"
        );
        host.required_status(&self.expected_head_sha)?;
        for (base, head) in [
            (&self.expected_main_sha, &self.expected_head_sha),
            (&self.expected_head_sha, source),
        ] {
            let comparison: Value = host
                .api
                .get(&host.path(&format!("compare/{base}...{head}")))?;
            signed_descendant_files(&comparison, base)?;
        }
        Ok(())
    }

    fn approved_pull(&self, host: &Host) -> Result<u64> {
        let number = host.context.event["inputs"]["pull_request"]
            .as_str()
            .context("recovery PR number missing")?
            .parse::<u64>()?;
        ensure!(
            number > 0 && number != self.source_pull_request,
            "invalid recovery PR number"
        );
        let pull: Value = host.api.get(&host.path(&format!("pulls/{number}")))?;
        self.proposal_identity(host, &pull)?;
        ensure!(
            pull["number"] == number && pull["state"] == "open",
            "recovery PR is not open"
        );
        host.validate_review(number, &self.expected_head_sha)?;
        Ok(number)
    }

    fn proposal_identity(&self, host: &Host, pull: &Value) -> Result<()> {
        validate_reserved_pull(
            pull,
            &host.policy,
            &self.proposal_branch,
            &self.expected_main_sha,
            &self.expected_head_sha,
        )?;
        ensure!(pull["draft"] == false, "recovery PR must not be draft");
        Ok(())
    }
}

fn require_source_approval(host: &Host, approved: &str) -> Result<()> {
    validate_sha(approved)?;
    ensure!(
        approved == host.context.compiled_sha,
        "recovery executor lacks separate approval of its exact SHA"
    );
    Ok(())
}

fn source_approval(host: &Host) -> Result<()> {
    require_source_approval(
        host,
        &std::env::var("SECUREFIX_RECOVERY_SOURCE_SHA")
            .context("missing separately approved recovery source")?,
    )
}

pub(super) fn validate(host: &Host) -> Result<()> {
    let auth = Authorization::load()?;
    let phase = host.context.event["inputs"]["phase"]
        .as_str()
        .context("missing recovery phase")?;
    ensure!(
        matches!(
            phase,
            "recovery-qualify" | "recovery-propose" | "recovery-merge"
        ),
        "invalid recovery phase"
    );
    if phase != "recovery-qualify" {
        source_approval(host)?;
    }
    auth.qualify(host, phase)?;
    if phase == "recovery-merge" {
        auth.approved_pull(host)?;
    }
    emit(
        &json!({"authority_sha":host.context.compiled_sha,"expected_main_sha":auth.expected_main_sha,"expected_head_sha":auth.expected_head_sha,"expected_tree_sha":auth.expected_tree_sha,"phase":phase}),
    )
}

pub(super) fn propose(host: &Host) -> Result<()> {
    source_approval(host)?;
    let auth = Authorization::load()?;
    auth.qualify(host, "recovery-propose")?;
    let writer = host.writer(&auth.expected_main_sha)?;
    if let Some(reference) = host.optional(&format!("git/ref/heads/{}", auth.proposal_branch))? {
        ensure!(
            reference["object"]["type"] == "commit"
                && reference["object"]["sha"] == auth.expected_head_sha,
            "recovery proposal branch differs from fixed target"
        );
    } else {
        writer.request(Method::POST, "git/refs", &json!({"ref":format!("refs/heads/{}",auth.proposal_branch),"sha":auth.expected_head_sha}))?;
    }
    let mut pulls: Vec<Value> = host
        .api
        .get(&host.pulls_query("all", &auth.proposal_branch)?)?;
    ensure!(
        pulls.len() <= 1,
        "recovery proposal branch has multiple PRs"
    );
    let pull = match pulls.pop() {
        Some(pull) => {
            auth.proposal_identity(host, &pull)?;
            ensure!(pull["state"] == "open", "recovery PR is closed");
            pull
        }
        None => writer.request(Method::POST, "pulls", &json!({"head":auth.proposal_branch,"base":host.policy.deployment.server.default_branch,"title":"Recover the fixed Rust bootstrap authority (PR #98)","body":format!("Exact replacement for PR #98; no recovery executor enters main.\n\nTarget: {}\nTree: {}\nExpected main: {}\nOne-time executor: {}",auth.expected_head_sha,auth.expected_tree_sha,auth.expected_main_sha,host.context.compiled_sha),"draft":false}))?,
    };
    auth.proposal_identity(host, &pull)?;
    print_result(&pull, &auth.expected_head_sha, None)
}

pub(super) fn merge(host: &Host) -> Result<()> {
    source_approval(host)?;
    let auth = Authorization::load()?;
    auth.qualify(host, "recovery-merge")?;
    let number = auth.approved_pull(host)?;
    host.writer(&auth.expected_main_sha)?
        .merge(number, &auth.expected_head_sha)
}
