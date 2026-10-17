//! Fixed, source-pinned host authority for generation one. Candidate archives are data.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Subcommand;
use reqwest::{Method, StatusCode, blocking::Client, redirect};
use securefix::{
    api::{ApiError, GitHub},
    control::ControlRevision,
    hex_encode,
    policy::{Policy, validate_sha},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    process::{Command as Process, Stdio},
    time::Duration,
};

const ACTIVE: &str = "control/active.json";
const ASSET: &str = "securefix-runtime-linux-x86_64.tar.gz";
const BOOTSTRAP_WORKFLOW: &str = ".github/workflows/control-bootstrap.yml";
const TEST_WORKFLOW: &str = ".github/workflows/testing-securefix-server.yml";
const MAX_ARCHIVE: usize = 128 * 1024 * 1024;
const MAX_ARTIFACT: usize = 64 * 1024;
const MAX_UNPACKED: u64 = 512 * 1024 * 1024;
const MAX_MEMBERS: usize = 4096;

#[path = "bootstrap_recovery.rs"]
mod recovery;

#[derive(Subcommand)]
pub enum Command {
    RecoveryValidate,
    RecoveryPropose,
    RecoveryMerge,
    Prepare {
        #[arg(long)]
        source_sha: String,
        #[arg(long)]
        verification_run_id: u64,
        #[arg(long)]
        archive: PathBuf,
    },
    Propose {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        archive: PathBuf,
    },
    ValidateMerge {
        #[arg(long)]
        pull_request: u64,
        #[arg(long)]
        expected_main_sha: String,
        #[arg(long)]
        expected_head_sha: String,
        #[arg(long)]
        control_id: String,
    },
    Merge {
        #[arg(long)]
        repository: String,
        #[arg(long)]
        pull_request: u64,
        #[arg(long)]
        expected_main_sha: String,
        #[arg(long)]
        expected_head_sha: String,
        #[arg(long)]
        control_id: String,
    },
    RepairPropose {
        #[arg(long)]
        expected_main_sha: String,
        #[arg(long)]
        expected_head_sha: String,
    },
    RepairMerge {
        #[arg(long)]
        repository: String,
        #[arg(long)]
        pull_request: u64,
        #[arg(long)]
        expected_main_sha: String,
        #[arg(long)]
        expected_head_sha: String,
    },
    ValidateLegacyContext {
        #[arg(long)]
        source_sha: String,
    },
    ValidateScratchOutputs {
        #[arg(long)]
        source_sha: String,
        #[arg(long)]
        published_runtime_sha: String,
        #[arg(long)]
        state_directory: PathBuf,
        #[arg(long)]
        probe_directory: PathBuf,
    },
}

pub fn run(command: Command) -> Result<()> {
    let host = Host::from_env()?;
    match command {
        Command::RecoveryValidate => recovery::validate(&host),
        Command::RecoveryPropose => recovery::propose(&host),
        Command::RecoveryMerge => recovery::merge(&host),
        Command::Prepare {
            source_sha,
            verification_run_id,
            archive,
        } => emit(&host.validate_proposal(&source_sha, verification_run_id, &archive)?),
        Command::Propose { plan, archive } => {
            host.create_descriptor_pr(&read_plan(&plan)?, &archive)
        }
        Command::ValidateMerge {
            pull_request,
            expected_main_sha,
            expected_head_sha,
            control_id,
        } => emit(&host.validate_bootstrap_merge(
            pull_request,
            &expected_main_sha,
            &expected_head_sha,
            &control_id,
        )?),
        Command::Merge {
            repository,
            pull_request,
            expected_main_sha,
            expected_head_sha,
            control_id,
        } => {
            ensure!(repository == host.repository(), "unexpected repository");
            host.validate_bootstrap_merge(
                pull_request,
                &expected_main_sha,
                &expected_head_sha,
                &control_id,
            )?;
            host.writer(&expected_main_sha)?
                .merge(pull_request, &expected_head_sha)
        }
        Command::RepairPropose {
            expected_main_sha,
            expected_head_sha,
        } => host.create_repair_pr(&expected_main_sha, &expected_head_sha),
        Command::RepairMerge {
            repository,
            pull_request,
            expected_main_sha,
            expected_head_sha,
        } => {
            ensure!(repository == host.repository(), "unexpected repository");
            host.validate_repair_commit(
                &expected_main_sha,
                &expected_head_sha,
                Some(pull_request),
            )?;
            host.writer(&expected_main_sha)?
                .merge(pull_request, &expected_head_sha)
        }
        Command::ValidateLegacyContext { source_sha } => {
            host.validate_legacy_context(&source_sha)?;
            emit(&json!({"source_sha":source_sha}))
        }
        Command::ValidateScratchOutputs {
            source_sha,
            published_runtime_sha,
            state_directory,
            probe_directory,
        } => {
            host.validate_scratch_outputs(
                &source_sha,
                &published_runtime_sha,
                &state_directory,
                &probe_directory,
            )?;
            emit(&json!({"source_sha":source_sha}))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u32,
    operation: String,
    repository: String,
    repository_id: u64,
    default_branch: String,
    owner_id: u64,
    server_bot_id: u64,
    status_app_id: u64,
    source_sha: String,
    expected_main_sha: String,
    archive_sha256: String,
    policy_sha256: String,
    verification_run_id: u64,
    publisher_run_id: u64,
    descriptor: Value,
    pull_request: Value,
    head_sha: Value,
}

struct Dispatch {
    repository: String,
    reference: String,
    event_name: String,
    workflow_ref: String,
    workflow_sha: String,
    compiled_sha: String,
    actor_id: String,
    attempt: String,
    source_sha: String,
    run_id: u64,
    event: Value,
}

impl Dispatch {
    fn validate(&self, host: &Host, source: &str, phase: &str, workflow: &str) -> Result<()> {
        self.validate_branch(
            host,
            source,
            phase,
            workflow,
            &host.policy.deployment.server.default_branch,
        )
    }

    fn validate_branch(
        &self,
        host: &Host,
        source: &str,
        phase: &str,
        workflow: &str,
        branch: &str,
    ) -> Result<()> {
        validate_sha(source)?;
        ensure!(
            self.repository == host.repository()
                && self.reference == format!("refs/heads/{branch}")
                && self.event_name == "workflow_dispatch"
                && self.workflow_ref
                    == format!("{}/{workflow}@refs/heads/{branch}", host.repository())
                && self.workflow_sha == source
                && self.compiled_sha == source
                && self.actor_id == host.policy.owner_id.to_string()
                && self.attempt == "1"
                && self.source_sha == source
                && self.run_id > 0
                && self.event["inputs"]["phase"] == phase,
            "operation is not a first-attempt owner dispatch of the compiled protected-main authority"
        );
        Ok(())
    }
}

struct Host {
    api: GitHub,
    policy: Policy,
    policy_bytes: Vec<u8>,
    context: Dispatch,
}

impl Host {
    fn from_env() -> Result<Self> {
        let env = |key: &str| std::env::var(key).with_context(|| format!("missing {key}"));
        let policy_bytes = include_bytes!("../policy.json").to_vec();
        let policy = Policy::parse(&policy_bytes)?;
        let compiled_sha = option_env!("SECUREFIX_BOOTSTRAP_SOURCE_SHA")
            .context("bootstrap host must be built by its source-pinned workflow")?
            .to_owned();
        validate_sha(&compiled_sha)?;
        let context = Dispatch {
            repository: env("GITHUB_REPOSITORY")?,
            reference: env("GITHUB_REF")?,
            event_name: env("GITHUB_EVENT_NAME")?,
            workflow_ref: env("GITHUB_WORKFLOW_REF")?,
            workflow_sha: env("GITHUB_WORKFLOW_SHA")?,
            compiled_sha,
            actor_id: env("GITHUB_ACTOR_ID")?,
            attempt: env("GITHUB_RUN_ATTEMPT")?,
            source_sha: env("GITHUB_SHA")?,
            run_id: env("GITHUB_RUN_ID")?.parse()?,
            event: serde_json::from_slice(&read_bounded(
                Path::new(&env("GITHUB_EVENT_PATH")?),
                1024 * 1024,
            )?)?,
        };
        let api = GitHub::new("https://api.github.com", env("GITHUB_TOKEN")?)?;
        Ok(Self {
            api,
            policy,
            policy_bytes,
            context,
        })
    }

    fn repository(&self) -> &str {
        &self.policy.deployment.server.repository
    }
    fn path(&self, suffix: &str) -> String {
        format!("/repos/{}/{suffix}", self.repository())
    }

    fn optional(&self, suffix: &str) -> Result<Option<Value>> {
        match self.api.get(&self.path(suffix)) {
            Ok(value) => Ok(Some(value)),
            Err(error)
                if error
                    .downcast_ref::<ApiError>()
                    .is_some_and(|e| e.status == StatusCode::NOT_FOUND) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn contents(&self, path: &str, source: &str) -> Result<Vec<u8>> {
        validate_sha(source)?;
        let value: Value = self
            .api
            .get(&self.path(&format!("contents/{path}?ref={source}")))?;
        ensure!(
            value["type"] == "file" && value["path"] == path && value["encoding"] == "base64",
            "source content identity or encoding mismatch"
        );
        let raw = STANDARD.decode(
            value["content"]
                .as_str()
                .context("source content missing")?
                .replace(['\r', '\n'], ""),
        )?;
        ensure!(
            raw.len() <= 1024 * 1024 && value["size"].as_u64() == Some(raw.len() as u64),
            "source content size mismatch"
        );
        Ok(raw)
    }

    fn current_policy(&self, source: &str) -> Result<()> {
        ensure!(
            self.contents("policy.json", source)? == self.policy_bytes,
            "source policy differs from compiled trusted bootstrap policy"
        );
        Ok(())
    }

    fn require_main(&self, source: &str) -> Result<()> {
        validate_sha(source)?;
        let main: Value = self.api.get(&self.path(&format!(
            "commits/{}",
            self.policy.deployment.server.default_branch
        )))?;
        ensure!(main["sha"] == source, "protected main moved after dispatch");
        Ok(())
    }

    fn require_absent(&self, source: &str) -> Result<()> {
        validate_sha(source)?;
        ensure!(
            self.optional(&format!("contents/{ACTIVE}?ref={source}"))?
                .is_none(),
            "active descriptor exists; bootstrap is permanently disabled"
        );
        Ok(())
    }

    fn dispatch(&self, source: &str, phase: &str, workflow: &str) -> Result<Value> {
        self.context.validate(self, source, phase, workflow)?;
        self.require_main(source)?;
        self.workflow_run(self.context.run_id, workflow, source, true)
    }

    fn workflow_run(
        &self,
        run_id: u64,
        workflow: &str,
        source: &str,
        in_progress: bool,
    ) -> Result<Value> {
        ensure!(run_id > 0, "invalid workflow run ID");
        validate_sha(source)?;
        let run: Value = self
            .api
            .get(&self.path(&format!("actions/runs/{run_id}")))?;
        validate_run(&run, &self.policy, run_id, workflow, source, in_progress)?;
        Ok(run)
    }

    fn required_status(&self, sha: &str) -> Result<()> {
        validate_sha(sha)?;
        let commit: Value = self.api.get(&self.path(&format!("commits/{sha}")))?;
        ensure!(
            commit["sha"] == sha && commit["commit"]["verification"]["verified"] == true,
            "source commit signature is not verified"
        );
        let combined: Value = self.api.get(&self.path(&format!("commits/{sha}/status")))?;
        ensure!(
            combined["total_count"]
                .as_u64()
                .is_some_and(|n| n == 0 || combined["state"] == "success"),
            "combined commit status is failing"
        );
        let mut matches = Vec::new();
        for page in 1..=100 {
            let checks: Value = self.api.get(&self.path(&format!(
                "commits/{sha}/check-runs?per_page=100&page={page}&filter=latest"
            )))?;
            let batch = array(&checks["check_runs"])?;
            matches.extend(
                batch
                    .iter()
                    .filter(|c| {
                        c["name"] == "status-check"
                            && c["app"]["id"].as_u64()
                                == Some(self.policy.deployment.checks.status_app_id)
                    })
                    .cloned(),
            );
            if batch.len() < 100 {
                ensure!(
                    !matches.is_empty()
                        && matches.iter().all(|check| {
                            check["status"] == "completed" && check["conclusion"] == "success"
                        }),
                    "required status-check is missing, pending, or failing"
                );
                return Ok(());
            }
        }
        bail!("check pagination exceeded limit")
    }

    fn validate_review(&self, number: u64, head: &str) -> Result<()> {
        let reviews = self
            .api
            .paginate(&self.path(&format!("pulls/{number}/reviews")))?;
        validate_review(&reviews, self.policy.owner_id, head)
    }

    fn validate_pull(&self, number: u64, main: &str, head: &str, bootstrap: bool) -> Result<Value> {
        ensure!(number > 0, "invalid pull request number");
        validate_sha(main)?;
        validate_sha(head)?;
        let pull: Value = self.api.get(&self.path(&format!("pulls/{number}")))?;
        validate_pull_identity(&pull, &self.policy, main, head)?;
        let files: Vec<Value> = self
            .api
            .get(&self.path(&format!("pulls/{number}/files?per_page=100")))?;
        ensure!(
            pull["changed_files"].as_u64() == Some(files.len() as u64) && !files.is_empty(),
            "pull request file list is empty or truncated"
        );
        if bootstrap {
            let descriptor: ControlRevision =
                serde_json::from_slice(&self.contents(ACTIVE, head)?)?;
            ensure!(
                pull["head"]["ref"] == bootstrap_branch(&descriptor.source_sha)?
                    && files.len() == 1
                    && files[0]["filename"] == ACTIVE
                    && files[0]["status"] == "added",
                "bootstrap PR must add only the active descriptor on its reserved branch"
            );
        } else {
            self.validate_repair_files(&files, main, head)?;
        }
        self.validate_review(number, head)?;
        self.required_status(head)?;
        Ok(pull)
    }

    fn artifact(&self, run_id: u64, name: &str, max: usize) -> Result<Vec<u8>> {
        let list: Value = self
            .api
            .get(&self.path(&format!("actions/runs/{run_id}/artifacts?per_page=100")))?;
        let artifacts = array(&list["artifacts"])?;
        ensure!(
            list["total_count"].as_u64() == Some(artifacts.len() as u64),
            "artifact list is truncated"
        );
        let matching: Vec<_> = artifacts.iter().filter(|a| a["name"] == name).collect();
        ensure!(matching.len() == 1, "{name} artifact missing or duplicated");
        let artifact = matching[0];
        let id = positive(&artifact["id"])?;
        let size = positive(&artifact["size_in_bytes"])?;
        ensure!(
            artifact["expired"] == false && size <= max as u64,
            "{name} artifact expired or oversized"
        );
        let digest = artifact["digest"]
            .as_str()
            .context("artifact digest missing")?;
        ensure!(
            digest.strip_prefix("sha256:").is_some_and(valid_digest),
            "artifact digest invalid"
        );
        let bytes = self
            .api
            .download(&self.path(&format!("actions/artifacts/{id}/zip")), max)?;
        ensure!(
            bytes.len() as u64 == size && digest == format!("sha256:{}", sha256(&bytes)),
            "artifact digest/size mismatch"
        );
        Ok(bytes)
    }

    fn validate_scratch(&self, source: &str, run_id: u64) -> Result<()> {
        self.workflow_run(run_id, TEST_WORKFLOW, source, false)?;
        let pair = zip_json_files(
            &self.artifact(run_id, "scratch-fixtures", MAX_ARTIFACT)?,
            &["state.json", "verification.json"],
        )?;
        let probe = zip_json_files(
            &self.artifact(run_id, "control-probe", 16 * 1024)?,
            &["control-verification.json"],
        )?;
        validate_scratch_evidence(
            &pair["state.json"],
            &pair["verification.json"],
            &probe["control-verification.json"],
            &self.policy,
            source,
        )
    }

    fn validate_legacy_context(&self, source: &str) -> Result<()> {
        self.dispatch(source, "bootstrap", TEST_WORKFLOW)?;
        ensure!(
            self.context.event["inputs"]["candidate_sha"]
                .as_str()
                .is_some_and(|s| s.is_empty() || s == source),
            "legacy scratch source input mismatch"
        );
        self.require_absent(source)?;
        self.current_policy(source)
    }

    fn validate_scratch_outputs(
        &self,
        source: &str,
        published_runtime: &str,
        state_directory: &Path,
        probe_directory: &Path,
    ) -> Result<()> {
        self.validate_legacy_context(source)?;
        validate_sha(published_runtime)?;
        let pair = output_json_files(state_directory, &["state.json", "verification.json"])?;
        let probe = output_json_files(probe_directory, &["control-verification.json"])?;
        ensure!(
            pair["state.json"]["published_runtime_sha"] == published_runtime,
            "scratch output published baseline mismatch"
        );
        validate_scratch_evidence(
            &pair["state.json"],
            &pair["verification.json"],
            &probe["control-verification.json"],
            &self.policy,
            source,
        )
    }

    fn validate_proposal(
        &self,
        source: &str,
        verification_run_id: u64,
        archive: &Path,
    ) -> Result<Plan> {
        self.dispatch(source, "propose", BOOTSTRAP_WORKFLOW)?;
        self.require_absent(source)?;
        self.current_policy(source)?;
        self.required_status(source)?;
        let bytes = read_bounded(archive, MAX_ARCHIVE)?;
        ensure!(
            archive_policy(&bytes)? == self.policy_bytes,
            "published runtime policy differs from exact source policy"
        );
        self.verify_attestation(archive, source)?;
        self.validate_scratch(source, verification_run_id)?;
        Ok(Plan {
            version: 1,
            operation: "prepare".into(),
            repository: self.repository().into(),
            repository_id: self.policy.deployment.server.id,
            default_branch: self.policy.deployment.server.default_branch.clone(),
            owner_id: self.policy.owner_id,
            server_bot_id: self.policy.server_bot_id,
            status_app_id: self.policy.deployment.checks.status_app_id,
            source_sha: source.into(),
            expected_main_sha: source.into(),
            archive_sha256: sha256(&bytes),
            policy_sha256: sha256(&self.policy_bytes),
            verification_run_id,
            publisher_run_id: self.context.run_id,
            descriptor: Value::Null,
            pull_request: Value::Null,
            head_sha: Value::Null,
        })
    }

    fn verify_attestation(&self, archive: &Path, source: &str) -> Result<()> {
        validate_sha(source)?;
        let branch = format!(
            "refs/heads/{}",
            self.policy.deployment.server.default_branch
        );
        let signer = format!("{}/{BOOTSTRAP_WORKFLOW}", self.repository());
        let status = Process::new("gh")
            .args(["attestation", "verify"])
            .arg(archive)
            .args([
                "--repo",
                self.repository(),
                "--source-digest",
                source,
                "--source-ref",
                &branch,
                "--signer-workflow",
                &signer,
                "--signer-digest",
                source,
                "--cert-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                "--predicate-type",
                "https://slsa.dev/provenance/v1",
                "--deny-self-hosted-runners",
            ])
            .env("GH_TOKEN", std::env::var("GITHUB_TOKEN")?)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        ensure!(status.success(), "archive attestation verification failed");
        Ok(())
    }

    fn version_tag(&self, source: &str) -> Result<(String, bool)> {
        let bytes = self.contents("Cargo.toml", source)?;
        let manifest = std::str::from_utf8(&bytes)?.parse::<toml_edit::DocumentMut>()?;
        let version = manifest["package"]["version"]
            .as_str()
            .context("source package version missing")?;
        let parsed = semver::Version::parse(version)?;
        ensure!(
            parsed.to_string() == version,
            "source package version is not canonical"
        );
        Ok((format!("v{parsed}"), !parsed.pre.is_empty()))
    }

    fn validate_bootstrap_merge(
        &self,
        number: u64,
        main: &str,
        head: &str,
        identity: &str,
    ) -> Result<Value> {
        ensure!(valid_digest(identity), "invalid control identity");
        self.dispatch(main, "merge", BOOTSTRAP_WORKFLOW)?;
        self.require_absent(main)?;
        self.current_policy(main)?;
        self.validate_pull(number, main, head, true)?;
        let descriptor: ControlRevision = serde_json::from_slice(&self.contents(ACTIVE, head)?)?;
        ensure!(
            descriptor.generation == 1
                && descriptor.source_sha == main
                && descriptor.identity()? == identity,
            "bootstrap descriptor generation, source, or identity mismatch"
        );
        self.required_status(main)?;
        self.workflow_run(descriptor.publisher_run_id, BOOTSTRAP_WORKFLOW, main, false)?;
        let (tag, _) = self.version_tag(main)?;
        let reference: Value = self.api.get(&self.path(&format!("git/ref/tags/{tag}")))?;
        validate_tag(&reference, main)?;
        let release: Value = self
            .api
            .get(&self.path(&format!("releases/{}", descriptor.release_id)))?;
        validate_release_identity(&release, main, &tag)?;
        ensure!(
            release["id"].as_u64() == Some(descriptor.release_id),
            "bootstrap release ID mismatch"
        );
        let digest = self.verify_published_archive(&release, main)?;
        ensure!(
            digest == descriptor.archive_sha256
                && sha256(&self.policy_bytes) == descriptor.policy_sha256
                && release["assets"][0]["id"].as_u64() == Some(descriptor.asset_id),
            "bootstrap descriptor differs from verified publication"
        );
        self.validate_scratch(main, descriptor.verification_run_id)?;
        Ok(
            json!({"version":1,"operation":"merge","repository":self.repository(),"expected_main_sha":main,"expected_head_sha":head,"pull_request":number,"control_id":identity,"descriptor":descriptor}),
        )
    }

    fn verify_published_archive(&self, release: &Value, source: &str) -> Result<String> {
        let asset = immutable_asset(release)?;
        let id = positive(&asset["id"])?;
        let bytes = self
            .api
            .download(&self.path(&format!("releases/assets/{id}")), MAX_ARCHIVE)?;
        let digest = sha256(&bytes);
        ensure!(
            asset["size"].as_u64() == Some(bytes.len() as u64)
                && asset["digest"] == format!("sha256:{digest}"),
            "immutable bootstrap asset download differs from GitHub metadata"
        );
        ensure!(
            archive_policy(&bytes)? == self.policy_bytes,
            "immutable bootstrap archive policy differs from trusted source"
        );
        let mut archive = tempfile::NamedTempFile::new()?;
        archive.write_all(&bytes)?;
        archive.flush()?;
        self.verify_attestation(archive.path(), source)?;
        Ok(digest)
    }

    fn validate_repair_commit(
        &self,
        main: &str,
        head: &str,
        number: Option<u64>,
    ) -> Result<Option<String>> {
        self.dispatch(
            main,
            if number.is_some() {
                "repair-merge"
            } else {
                "repair-propose"
            },
            BOOTSTRAP_WORKFLOW,
        )?;
        self.require_absent(main)?;
        self.current_policy(main)?;
        validate_sha(head)?;
        let comparison: Value = self
            .api
            .get(&self.path(&format!("compare/{main}...{head}")))?;
        let files = signed_descendant_files(&comparison, main)?;
        ensure!(
            !files.is_empty() && files.len() < 300,
            "repair head is empty or too large"
        );
        self.validate_repair_files(files, main, head)?;
        self.required_status(head)?;
        if let Some(number) = number {
            self.validate_pull(number, main, head, false)?;
            Ok(None)
        } else {
            let branches: Vec<Value> = self
                .api
                .get(&self.path(&format!("commits/{head}/branches-where-head")))?;
            ensure!(
                !branches.is_empty() && branches.len() < 30,
                "repair branch response is empty or potentially truncated"
            );
            for branch in &branches {
                let name = branch["name"]
                    .as_str()
                    .context("repair branch name missing")?;
                securefix::config::validate_branch(name)?;
                let pulls: Vec<Value> = self.api.get(&self.pulls_query("open", name)?)?;
                ensure!(pulls.is_empty(), "repair head already has a pull request");
            }
            Ok(Some(
                branches[0]["name"]
                    .as_str()
                    .context("repair branch missing")?
                    .into(),
            ))
        }
    }

    fn validate_repair_files(&self, files: &[Value], main: &str, head: &str) -> Result<()> {
        for file in files {
            if matches!(file["filename"].as_str(), Some("Cargo.toml" | "Cargo.lock")) {
                ensure!(
                    file["status"] == "modified" && file["previous_filename"].is_null(),
                    "repair cannot replace or rename bootstrap build inputs"
                );
                let path = file["filename"]
                    .as_str()
                    .context("build input path missing")?;
                version_only_change(
                    path,
                    &self.contents(path, main)?,
                    &self.contents(path, head)?,
                )?;
            } else {
                ensure!(
                    !changes_authority(file),
                    "repair changes active descriptor/bootstrap authority"
                );
            }
        }
        Ok(())
    }

    fn pulls_query(&self, state: &str, branch: &str) -> Result<String> {
        securefix::config::validate_branch(branch)?;
        let mut url =
            reqwest::Url::parse(&format!("https://api.github.com{}", self.path("pulls")))?;
        url.query_pairs_mut()
            .append_pair("state", state)
            .append_pair(
                "head",
                &format!("{}:{branch}", self.policy.deployment.repository_owner.login),
            )
            .append_pair("base", &self.policy.deployment.server.default_branch);
        Ok(format!(
            "{}?{}",
            url.path(),
            url.query().context("pull query missing")?
        ))
    }

    fn create_repair_pr(&self, main: &str, head: &str) -> Result<()> {
        let branch = self
            .validate_repair_commit(main, head, None)?
            .context("repair branch missing")?;
        let writer = self.writer(main)?;
        let branches: Vec<Value> = self
            .api
            .get(&self.path(&format!("commits/{head}/branches-where-head")))?;
        ensure!(
            branches.iter().any(|b| b["name"] == branch),
            "repair head is no longer on its branch"
        );
        let pull = writer.request(Method::POST, "pulls", &json!({"head":branch,"base":self.policy.deployment.server.default_branch,"title":"Repair Securefix bootstrap candidate","body":format!("Repair candidate source while the active descriptor is absent.\n\nExpected main: {main}\nRepair head: {head}")}))?;
        ensure!(
            pull["head"]["sha"] == head
                && pull["user"]["id"].as_u64() == Some(self.policy.server_bot_id),
            "Server App repair PR identity mismatch"
        );
        print_result(&pull, head, None)
    }

    fn writer(&self, main: &str) -> Result<Writer<'_>> {
        let token = std::env::var("GH_TOKEN").context("missing Server App writer token")?;
        let credential = GitHub::new("https://api.github.com", token.clone())?;
        let installation: Value = credential.get("/installation/repositories?per_page=100")?;
        validate_installation(&installation, &self.policy)?;
        Ok(Writer {
            host: self,
            main: main.to_owned(),
            token,
            api_base: "https://api.github.com".into(),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .redirect(redirect::Policy::none())
                .build()?,
        })
    }

    fn create_descriptor_pr(&self, plan: &Plan, archive_path: &Path) -> Result<()> {
        ensure!(
            plan.operation == "prepare",
            "proposal requires a prepare plan"
        );
        let actual =
            self.validate_proposal(&plan.source_sha, plan.verification_run_id, archive_path)?;
        ensure!(
            *plan == actual,
            "bootstrap plan differs from fixed trusted revalidation"
        );
        let writer = self.writer(&plan.expected_main_sha)?;
        let bytes = read_bounded(archive_path, MAX_ARCHIVE)?;
        ensure!(
            sha256(&bytes) == plan.archive_sha256,
            "candidate archive differs from validated plan"
        );
        let source = &plan.source_sha;
        let (tag, prerelease) = self.version_tag(source)?;
        if let Some(reference) = self.optional(&format!("git/ref/tags/{tag}"))? {
            validate_tag(&reference, source)?;
        } else {
            let reference = writer.request(
                Method::POST,
                "git/refs",
                &json!({"ref":format!("refs/tags/{tag}"),"sha":source}),
            )?;
            validate_tag(&reference, source)?;
        }
        let mut release = match self.optional(&format!("releases/tags/{tag}"))? {
            Some(release) => release,
            None => writer.request(Method::POST, "releases", &json!({"tag_name":tag,"name":tag,"target_commitish":source,"draft":true,"prerelease":prerelease,"make_latest":"false","generate_release_notes":false}))?,
        };
        validate_release_identity(&release, source, &tag)?;
        let assets = array(&release["assets"])?;
        ensure!(
            assets.len() <= 1,
            "reserved release contains unexpected assets"
        );
        let digest = if release["immutable"] == true {
            self.verify_published_archive(&release, source)?
        } else {
            ensure!(
                release["draft"] == true,
                "existing published release is mutable"
            );
            if let Some(asset) = assets.first() {
                ensure!(
                    asset["name"] == ASSET
                        && asset["state"] == "uploaded"
                        && asset["size"].as_u64() == Some(bytes.len() as u64)
                        && asset["digest"] == format!("sha256:{}", plan.archive_sha256),
                    "reserved draft asset differs from validated candidate"
                );
            } else {
                writer.upload(positive(&release["id"])?, bytes.clone())?;
            }
            plan.archive_sha256.clone()
        };
        if release["draft"] == true {
            writer.request(
                Method::PATCH,
                &format!("releases/{}", positive(&release["id"])?),
                &json!({"draft":false}),
            )?;
        }
        release = self
            .api
            .get(&self.path(&format!("releases/{}", positive(&release["id"])?)))?;
        validate_release_identity(&release, source, &tag)?;
        let asset = immutable_asset(&release)?;
        ensure!(
            asset["digest"] == format!("sha256:{digest}")
                && (digest != plan.archive_sha256
                    || asset["size"].as_u64() == Some(bytes.len() as u64)),
            "published runtime asset differs from verified archive"
        );
        let descriptor = ControlRevision {
            version: 1,
            generation: 1,
            source_sha: source.clone(),
            policy_sha256: plan.policy_sha256.clone(),
            archive_sha256: digest,
            release_id: positive(&release["id"])?,
            asset_id: positive(&asset["id"])?,
            publisher_run_id: plan.publisher_run_id,
            verification_run_id: plan.verification_run_id,
            previous: "0".repeat(64),
        };
        let branch = bootstrap_branch(source)?;
        let (head, existing_pull) = self.resume_descriptor_branch(&writer, &branch, &descriptor)?;
        let head = match head {
            Some(head) => head,
            None => {
                ensure!(
                    self.optional(&format!("git/ref/heads/{branch}"))?.is_none(),
                    "reserved bootstrap branch appeared during creation"
                );
                writer.request(
                    Method::POST,
                    "git/refs",
                    &json!({"ref":format!("refs/heads/{branch}"),"sha":plan.expected_main_sha}),
                )?;
                writer.commit_descriptor(&branch, &plan.expected_main_sha, &descriptor)?
            }
        };
        let pull = match existing_pull {
            Some(pull) => pull,
            None => writer.request(Method::POST, "pulls", &json!({"head":branch,"base":plan.default_branch,"title":"Bootstrap active control descriptor","body":format!("Create the first active control descriptor after independent validation.\n\nSource: {source}"),"draft":false}))?,
        };
        ensure!(
            pull["head"]["sha"] == head
                && pull["user"]["id"].as_u64() == Some(self.policy.server_bot_id),
            "bootstrap pull request identity mismatch"
        );
        print_result(&pull, &head, Some(&descriptor.identity()?))
    }

    fn resume_descriptor_branch(
        &self,
        writer: &Writer<'_>,
        branch: &str,
        desired: &ControlRevision,
    ) -> Result<(Option<String>, Option<Value>)> {
        let Some(reference) = self.optional(&format!("git/ref/heads/{branch}"))? else {
            return Ok((None, None));
        };
        let mut head = reference["object"]["sha"]
            .as_str()
            .context("reserved branch head missing")?
            .to_owned();
        validate_sha(&head)?;
        let comparison: Value = self
            .api
            .get(&self.path(&format!("compare/{}...{head}", writer.main)))?;
        let files = signed_descendant_files(&comparison, &writer.main)?;
        ensure!(
            files.len() == 1 && files[0]["filename"] == ACTIVE && files[0]["status"] == "added",
            "reserved bootstrap branch is not a signed descriptor-only descendant of expected main"
        );
        let stored: ControlRevision = serde_json::from_slice(&self.contents(ACTIVE, &head)?)?;
        validate_retry_descriptor(&stored, desired)?;
        let pulls: Vec<Value> = self.api.get(&self.pulls_query("all", branch)?)?;
        ensure!(
            pulls.len() <= 1,
            "reserved bootstrap branch has multiple pull requests"
        );
        let mut pull = pulls.into_iter().next();
        if let Some(pull) = &pull {
            validate_reserved_pull(pull, &self.policy, branch, &writer.main, &head)?;
        }
        if stored != *desired {
            head = writer.commit_descriptor(branch, &head, desired)?;
        }
        if let Some(existing) = &pull {
            let number = positive(&existing["number"])?;
            if existing["state"] != "open" {
                writer.request(
                    Method::PATCH,
                    &format!("pulls/{number}"),
                    &json!({"state":"open"}),
                )?;
            }
            let current: Value = self.api.get(&self.path(&format!("pulls/{number}")))?;
            validate_reserved_pull(&current, &self.policy, branch, &writer.main, &head)?;
            ensure!(
                current["state"] == "open",
                "resumed bootstrap PR is not open"
            );
            pull = Some(current);
        }
        Ok((Some(head), pull))
    }
}

struct Writer<'a> {
    host: &'a Host,
    main: String,
    token: String,
    api_base: String,
    client: Client,
}

impl Writer<'_> {
    fn fence(&self) -> Result<()> {
        self.host.require_main(&self.main)?;
        self.host.require_absent(&self.main)
    }

    fn request(&self, method: Method, suffix: &str, body: &Value) -> Result<Value> {
        ensure!(
            !suffix.contains(['?', '#', '%', '\\'])
                && !suffix.split('/').any(|p| p == "." || p == ".."),
            "invalid bootstrap write path"
        );
        self.fence()?;
        let path = self.host.path(suffix);
        let response = self
            .client
            .request(method, format!("{}{path}", self.api_base))
            .bearer_auth(&self.token)
            .header("User-Agent", "securefix-bootstrap")
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(body)
            .send()?;
        read_response(response)
    }

    fn upload(&self, release_id: u64, bytes: Vec<u8>) -> Result<()> {
        ensure!(
            release_id > 0 && bytes.len() <= MAX_ARCHIVE,
            "invalid bootstrap asset upload"
        );
        self.fence()?;
        let response = self
            .client
            .post(format!(
                "https://uploads.github.com/repos/{}/releases/{release_id}/assets",
                self.host.repository()
            ))
            .query(&[("name", ASSET)])
            .bearer_auth(&self.token)
            .header("User-Agent", "securefix-bootstrap")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("Content-Type", "application/gzip")
            .body(bytes)
            .send()?;
        read_response(response)?;
        Ok(())
    }

    fn commit_descriptor(
        &self,
        branch: &str,
        head: &str,
        descriptor: &ControlRevision,
    ) -> Result<String> {
        ensure!(
            branch == bootstrap_branch(&descriptor.source_sha)?,
            "invalid bootstrap descriptor branch"
        );
        validate_sha(head)?;
        descriptor.validate()?;
        self.fence()?;
        let response = self
            .client
            .post(format!("{}/graphql", self.api_base))
            .bearer_auth(&self.token)
            .header("User-Agent", "securefix-bootstrap")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&descriptor_commit(
                self.host.repository(),
                branch,
                head,
                descriptor,
            )?)
            .send()?;
        let result = read_response(response)?;
        ensure!(
            result.get("errors").is_none(),
            "bootstrap descriptor commit failed"
        );
        let new_head = result["data"]["createCommitOnBranch"]["commit"]["oid"]
            .as_str()
            .context("bootstrap descriptor commit missing")?;
        validate_sha(new_head)?;
        ensure!(
            new_head != head,
            "bootstrap descriptor commit did not advance the compare-and-swap head"
        );
        Ok(new_head.into())
    }

    fn merge(&self, number: u64, head: &str) -> Result<()> {
        ensure!(number > 0, "invalid merge pull request number");
        validate_sha(head)?;
        let result = self.request(
            Method::PUT,
            &format!("pulls/{number}/merge"),
            &json!({"sha":head,"merge_method":"squash"}),
        )?;
        ensure!(
            result["merged"] == true,
            "GitHub did not merge the reviewed pull request"
        );
        Ok(())
    }
}

fn read_response(response: reqwest::blocking::Response) -> Result<Value> {
    ensure!(
        response.status().is_success(),
        "GitHub bootstrap write returned {}",
        response.status()
    );
    let mut bytes = Vec::new();
    response
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 16 * 1024 * 1024,
        "GitHub response exceeds size limit"
    );
    if bytes.is_empty() {
        Ok(Value::Null)
    } else {
        Ok(serde_json::from_slice(&bytes)?)
    }
}

fn validate_run(
    run: &Value,
    policy: &Policy,
    id: u64,
    workflow: &str,
    source: &str,
    in_progress: bool,
) -> Result<()> {
    validate_run_branch(
        run,
        policy,
        id,
        workflow,
        source,
        in_progress,
        &policy.deployment.server.default_branch,
    )
}

fn validate_run_branch(
    run: &Value,
    policy: &Policy,
    id: u64,
    workflow: &str,
    source: &str,
    in_progress: bool,
    branch: &str,
) -> Result<()> {
    let server = &policy.deployment.server;
    ensure!(
        run["id"].as_u64() == Some(id)
            && [&run["repository"], &run["head_repository"]]
                .iter()
                .all(|r| r["full_name"] == server.repository && r["id"].as_u64() == Some(server.id))
            && run["path"]
                .as_str()
                .is_some_and(|p| p == workflow || p == format!("{workflow}@refs/heads/{branch}"))
            && run["event"] == "workflow_dispatch"
            && run["head_branch"] == branch
            && run["run_attempt"] == 1
            && run["head_sha"] == source
            && run["actor"]["id"].as_u64() == Some(policy.owner_id)
            && run["triggering_actor"]["id"].as_u64() == Some(policy.owner_id),
        "workflow run provenance mismatch"
    );
    ensure!(
        if in_progress {
            run["status"] == "in_progress"
        } else {
            run["status"] == "completed" && run["conclusion"] == "success"
        },
        "workflow run has not reached its required state"
    );
    Ok(())
}

fn validate_review(reviews: &[Value], owner: u64, head: &str) -> Result<()> {
    let latest = reviews
        .iter()
        .filter(|r| r["user"]["id"].as_u64() == Some(owner))
        .max_by_key(|r| r["submitted_at"].as_str().unwrap_or(""))
        .context("pull request lacks owner review")?;
    ensure!(
        latest["submitted_at"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
            && latest["state"] == "APPROVED"
            && latest["commit_id"] == head,
        "latest owner review does not approve exact head"
    );
    Ok(())
}

fn validate_pull_identity(pull: &Value, policy: &Policy, main: &str, head: &str) -> Result<()> {
    let server = &policy.deployment.server;
    ensure!(
        pull["state"] == "open"
            && pull["head"]["sha"] == head
            && pull["base"]["ref"] == server.default_branch
            && pull["base"]["sha"] == main
            && [&pull["head"]["repo"], &pull["base"]["repo"]]
                .iter()
                .all(|r| r["full_name"] == server.repository && r["id"].as_u64() == Some(server.id))
            && pull["user"]["id"].as_u64() == Some(policy.server_bot_id),
        "pull request identity is invalid"
    );
    Ok(())
}

fn validate_reserved_pull(
    pull: &Value,
    policy: &Policy,
    branch: &str,
    main: &str,
    head: &str,
) -> Result<()> {
    let mut open = pull.clone();
    open["state"] = json!("open");
    validate_pull_identity(&open, policy, main, head)?;
    ensure!(
        matches!(pull["state"].as_str(), Some("open" | "closed"))
            && pull["head"]["ref"] == branch
            && pull["merged_at"].is_null(),
        "reserved bootstrap pull request identity is invalid"
    );
    Ok(())
}

fn validate_installation(value: &Value, policy: &Policy) -> Result<()> {
    let repositories = array(&value["repositories"])?;
    ensure!(
        value["total_count"] == 1
            && repositories.len() == 1
            && repositories[0]["full_name"] == policy.deployment.server.repository
            && repositories[0]["id"].as_u64() == Some(policy.deployment.server.id),
        "Server App token must be installed only on the configured server repository"
    );
    Ok(())
}

fn signed_descendant_files<'a>(comparison: &'a Value, main: &str) -> Result<&'a Vec<Value>> {
    let commits = array(&comparison["commits"])?;
    ensure!(
        comparison["base_commit"]["sha"] == main
            && comparison["merge_base_commit"]["sha"] == main
            && comparison["status"] == "ahead"
            && !commits.is_empty()
            && comparison["total_commits"].as_u64() == Some(commits.len() as u64)
            && commits
                .iter()
                .all(|c| c["commit"]["verification"]["verified"] == true),
        "head is not a complete signed descendant of expected main"
    );
    array(&comparison["files"])
}

fn authority_path(path: &str) -> bool {
    matches!(
        path,
        ACTIVE
            | BOOTSTRAP_WORKFLOW
            | ".github/workflows/build-bootstrap-host.yml"
            | "src/bootstrap.rs"
            | "src/bootstrap_main.rs"
            | "src/lib.rs"
            | "src/api.rs"
            | "src/config.rs"
            | "src/control.rs"
            | "src/policy.rs"
            | "src/workflow.rs"
            | "Cargo.toml"
            | "Cargo.lock"
            | "rust-toolchain.toml"
            | "policy.json"
            | "build.rs"
    ) || path == ".cargo"
        || path == ".github"
        || path.starts_with(".github/")
        || path.starts_with(".cargo/")
        || path.starts_with("scripts/")
}

fn changes_authority(file: &Value) -> bool {
    file["filename"].as_str().is_none_or(authority_path)
        || file["previous_filename"]
            .as_str()
            .is_some_and(authority_path)
}

fn validate_retry_descriptor(stored: &ControlRevision, desired: &ControlRevision) -> Result<()> {
    stored.validate()?;
    desired.validate()?;
    let mut normalized = stored.clone();
    normalized.publisher_run_id = desired.publisher_run_id;
    ensure!(
        normalized == *desired,
        "reserved bootstrap descriptor differs beyond its prior publisher run identity"
    );
    Ok(())
}

fn descriptor_commit(
    repository: &str,
    branch: &str,
    head: &str,
    descriptor: &ControlRevision,
) -> Result<Value> {
    let bytes = format!("{}\n", serde_json::to_string_pretty(descriptor)?);
    Ok(
        json!({"query":"mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid } } }", "variables":{"input":{
            "branch":{"repositoryNameWithOwner":repository,"branchName":branch},"expectedHeadOid":head,
            "message":{"headline":"chore: bootstrap active Securefix control revision"},
            "fileChanges":{"additions":[{"path":ACTIVE,"contents":STANDARD.encode(bytes)}]}
        }}}),
    )
}

fn validate_tag(reference: &Value, source: &str) -> Result<()> {
    ensure!(
        reference["object"]["type"] == "commit" && reference["object"]["sha"] == source,
        "runtime tag is reserved for another source"
    );
    Ok(())
}

fn validate_release_identity(release: &Value, source: &str, tag: &str) -> Result<()> {
    ensure!(
        release["tag_name"] == tag
            && release["target_commitish"] == source
            && release["draft"].is_boolean()
            && release["id"].as_u64().is_some_and(|n| n > 0),
        "reserved release identity differs from candidate"
    );
    Ok(())
}

fn immutable_asset(release: &Value) -> Result<&Value> {
    ensure!(
        release["immutable"] == true && release["draft"] == false,
        "bootstrap release is not immutable and published"
    );
    let assets = array(&release["assets"])?;
    ensure!(
        assets.len() == 1,
        "immutable bootstrap release must contain exactly one asset"
    );
    let asset = &assets[0];
    ensure!(
        asset["name"] == ASSET
            && asset["state"] == "uploaded"
            && positive(&asset["id"])? > 0
            && positive(&asset["size"])? <= MAX_ARCHIVE as u64
            && asset["digest"]
                .as_str()
                .and_then(|d| d.strip_prefix("sha256:"))
                .is_some_and(valid_digest),
        "immutable bootstrap asset metadata is invalid"
    );
    Ok(asset)
}

fn archive_policy(bytes: &[u8]) -> Result<Vec<u8>> {
    ensure!(bytes.len() <= MAX_ARCHIVE, "candidate archive is oversized");
    let decoder = flate2::read::MultiGzDecoder::new(bytes);
    let mut bounded = decoder.take(MAX_UNPACKED + MAX_MEMBERS as u64 * 512 + 1024 * 1024 + 1);
    let mut seen = BTreeSet::new();
    let mut policy = None;
    let mut unpacked = 0u64;
    {
        let mut archive = tar::Archive::new(&mut bounded);
        for (index, entry) in archive.entries()?.raw(true).enumerate() {
            ensure!(
                index < MAX_MEMBERS,
                "candidate archive has too many entries"
            );
            let mut entry = entry?;
            let path = entry.path_bytes();
            let path = std::str::from_utf8(&path)?;
            let normalized = path
                .strip_prefix("./")
                .unwrap_or(path)
                .trim_end_matches('/');
            ensure!(
                !path.starts_with('/')
                    && !path.contains('\\')
                    && (normalized.is_empty()
                        || normalized == "."
                        || normalized.split('/').all(|p| !matches!(p, "" | "." | "..")))
                    && seen.insert(normalized.to_owned()),
                "candidate archive contains an unsafe or duplicate path"
            );
            let kind = entry.header().entry_type();
            ensure!(
                kind.is_file() || kind.is_dir(),
                "candidate archive contains a link or special entry"
            );
            let size = entry.size();
            ensure!(
                (!kind.is_dir() || size == 0)
                    && (kind.is_dir()
                        || (!path.ends_with('/') && !normalized.is_empty() && normalized != ".")),
                "candidate archive entry type or size is invalid"
            );
            unpacked = unpacked
                .checked_add(size)
                .context("archive size overflow")?;
            ensure!(
                unpacked <= MAX_UNPACKED,
                "candidate archive expands beyond size limit"
            );
            if normalized == "policy.json" {
                ensure!(
                    kind.is_file() && size <= 256 * 1024 && policy.is_none(),
                    "candidate archive has unsafe or duplicate policy.json"
                );
                let mut raw = Vec::new();
                entry.by_ref().take(256 * 1024 + 1).read_to_end(&mut raw)?;
                ensure!(
                    raw.len() as u64 == size,
                    "candidate archive policy size mismatch"
                );
                policy = Some(raw);
            }
        }
    }
    let mut tail = Vec::new();
    bounded
        .by_ref()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut tail)?;
    ensure!(
        tail.len() <= 1024 * 1024 && tail.iter().all(|b| *b == 0) && bounded.limit() > 0,
        "candidate archive has excess or invalid trailing data"
    );
    policy.context("candidate archive is missing policy.json")
}

fn version_only_change(path: &str, before: &[u8], after: &[u8]) -> Result<()> {
    let previous = std::str::from_utf8(before)?.parse::<toml_edit::DocumentMut>()?;
    let mut next = std::str::from_utf8(after)?.parse::<toml_edit::DocumentMut>()?;
    if path == "Cargo.toml" {
        ensure!(
            previous["package"]["name"].as_str() == Some("securefix"),
            "unexpected bootstrap package"
        );
        let old = previous["package"]["version"]
            .as_str()
            .context("previous package version missing")?;
        let new = next["package"]["version"]
            .as_str()
            .context("next package version missing")?;
        ensure!(
            semver::Version::parse(new)? > semver::Version::parse(old)?,
            "repair package version must advance"
        );
        next["package"]["version"] = previous["package"]["version"].clone();
    } else {
        ensure!(path == "Cargo.lock", "unexpected bootstrap build input");
        let old = previous["package"]
            .as_array_of_tables()
            .context("previous lockfile packages missing")?;
        let new = next["package"]
            .as_array_of_tables_mut()
            .context("next lockfile packages missing")?;
        let old_root: Vec<_> = old
            .iter()
            .filter(|p| p["name"].as_str() == Some("securefix") && !p.contains_key("source"))
            .collect();
        let new_root: Vec<_> = new
            .iter_mut()
            .filter(|p| p["name"].as_str() == Some("securefix") && !p.contains_key("source"))
            .collect();
        ensure!(
            old_root.len() == 1 && new_root.len() == 1,
            "bootstrap lockfile root package is ambiguous"
        );
        let old_version = old_root[0]["version"]
            .as_str()
            .context("previous locked version missing")?;
        let new_version = new_root[0]["version"]
            .as_str()
            .context("next locked version missing")?;
        ensure!(
            semver::Version::parse(new_version)? > semver::Version::parse(old_version)?,
            "repair locked version must advance"
        );
        new_root
            .into_iter()
            .next()
            .context("locked package missing")?["version"] = old_root[0]["version"].clone();
    }
    ensure!(
        next.to_string() == previous.to_string(),
        "repair changes bootstrap build inputs beyond the package version"
    );
    Ok(())
}

fn zip_json_files(bytes: &[u8], names: &[&str]) -> Result<BTreeMap<String, Value>> {
    ensure!(
        bytes.len() <= MAX_ARTIFACT,
        "scratch artifact zip is oversized"
    );
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))?;
    ensure!(
        zip.len() == names.len(),
        "scratch artifact has unexpected file set"
    );
    let mut result = BTreeMap::new();
    for index in 0..zip.len() {
        let mut file = zip.by_index(index)?;
        let name = file.name().to_owned();
        ensure!(
            names.contains(&name.as_str())
                && !result.contains_key(&name)
                && !file.is_dir()
                && file
                    .unix_mode()
                    .is_none_or(|m| matches!(m & 0o170000, 0 | 0o100000))
                && file.size() <= MAX_ARTIFACT as u64,
            "scratch artifact has unsafe or unexpected file"
        );
        let size = file.size();
        let mut raw = Vec::new();
        file.by_ref()
            .take(MAX_ARTIFACT as u64 + 1)
            .read_to_end(&mut raw)?;
        ensure!(
            raw.len() as u64 == size && raw.len() <= MAX_ARTIFACT,
            "scratch artifact file size mismatch"
        );
        result.insert(name, serde_json::from_slice(&raw)?);
    }
    Ok(result)
}

fn validate_scratch_evidence(
    state: &Value,
    verification: &Value,
    probe: &Value,
    policy: &Policy,
    source: &str,
) -> Result<()> {
    let scratch = &policy.deployment.integration;
    exact_keys(
        state,
        &[
            "version",
            "repository",
            "repository_id",
            "candidate_sha",
            "published_runtime_sha",
            "workflow_sha",
            "default_branch",
            "base_sha",
            "prepared_at",
            "positive",
            "stale",
            "distribution",
        ],
    )?;
    exact_keys(
        verification,
        &[
            "version",
            "repository",
            "candidate_sha",
            "positive_pr",
            "merged_sha",
            "stale_pr",
            "stale_head_sha",
            "distribution_pr",
            "managed_files",
            "annotated_tag_verified",
            "closed_or_merged",
        ],
    )?;
    exact_keys(
        probe,
        &[
            "version",
            "repository",
            "candidate_sha",
            "branch",
            "base_sha",
            "generation_one_commit_sha",
            "generation_two_commit_sha",
            "generation_three_commit_sha",
            "generation_one",
            "generation_two",
            "generation_three",
            "source_advance_kept_descriptor",
            "expected_head_conflict_rejected",
            "stale_identity_rejected_after_aba",
            "production_publication_verified",
            "production_activation_verified",
            "distribution_verified",
        ],
    )?;
    ensure!(
        state["version"] == 2
            && state["candidate_sha"] == source
            && state["repository"] == scratch.repository
            && state["repository_id"].as_u64() == Some(scratch.id)
            && state["workflow_sha"] == source
            && state["default_branch"] == scratch.default_branch
            && ["base_sha", "published_runtime_sha"]
                .iter()
                .all(|k| state[k].as_str().is_some_and(|s| validate_sha(s).is_ok()))
            && state["prepared_at"]
                .as_str()
                .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok()),
        "scratch-fixtures artifact identity mismatch"
    );
    let mut numbers = BTreeSet::new();
    for name in ["positive", "stale", "distribution"] {
        let fixture = &state[name];
        exact_keys(fixture, &["number", "branch", "head_sha", "url"])?;
        let number = positive(&fixture["number"])?;
        ensure!(
            numbers.insert(number)
                && fixture["head_sha"]
                    .as_str()
                    .is_some_and(|s| validate_sha(s).is_ok())
                && fixture["branch"].as_str().is_some_and(|s| s
                    .starts_with(&format!("securefix-integration-{name}-"))
                    && s.len() <= 100
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)))
                && fixture["url"]
                    == format!("https://github.com/{}/pull/{number}", scratch.repository)
                && verification[format!("{name}_pr")] == number,
            "scratch fixture identity or verification binding mismatch"
        );
    }
    ensure!(
        verification["version"] == 2
            && verification["repository"] == scratch.repository
            && verification["candidate_sha"] == source
            && ["positive_pr", "stale_pr", "distribution_pr"]
                .iter()
                .all(|k| verification[k].as_u64().is_some_and(|n| n > 0))
            && ["merged_sha", "stale_head_sha"]
                .iter()
                .all(|k| verification[k]
                    .as_str()
                    .is_some_and(|s| validate_sha(s).is_ok()))
            && verification["managed_files"]
                .as_array()
                .is_some_and(|f| !f.is_empty() && f.iter().all(Value::is_string))
            && verification["annotated_tag_verified"] == true
            && verification["closed_or_merged"] == true,
        "scratch verification evidence incomplete or mismatched"
    );
    ensure!(
        probe["version"] == 1
            && probe["repository"] == scratch.repository
            && probe["candidate_sha"] == source
            && probe["branch"]
                .as_str()
                .is_some_and(|s| s.starts_with("securefix-integration-control-")
                    && securefix::config::validate_branch(s).is_ok())
            && [
                "base_sha",
                "generation_one_commit_sha",
                "generation_two_commit_sha",
                "generation_three_commit_sha"
            ]
            .iter()
            .all(|k| probe[k].as_str().is_some_and(|s| validate_sha(s).is_ok())),
        "control probe identity mismatch"
    );
    let generations: Vec<_> = ["generation_one", "generation_two", "generation_three"]
        .iter()
        .filter_map(|k| probe[k].as_str())
        .collect();
    ensure!(
        generations.len() == 3
            && generations.iter().all(|s| valid_digest(s))
            && generations.iter().collect::<BTreeSet<_>>().len() == 3
            && [
                "source_advance_kept_descriptor",
                "expected_head_conflict_rejected",
                "stale_identity_rejected_after_aba"
            ]
            .iter()
            .all(|k| probe[k] == true)
            && [
                "production_publication_verified",
                "production_activation_verified",
                "distribution_verified"
            ]
            .iter()
            .all(|k| probe[k] == false),
        "control probe generation or CAS evidence incomplete"
    );
    Ok(())
}

fn exact_keys(value: &Value, expected: &[&str]) -> Result<()> {
    let object = value.as_object().context("scratch JSON object missing")?;
    ensure!(
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)),
        "scratch JSON fields differ from the strict schema"
    );
    Ok(())
}

fn output_json_files(directory: &Path, expected: &[&str]) -> Result<BTreeMap<String, Value>> {
    ensure!(
        directory.is_relative() && !directory.as_os_str().is_empty(),
        "scratch output directory must be relative"
    );
    let mut parent = PathBuf::new();
    for component in directory.components() {
        ensure!(
            matches!(component, std::path::Component::Normal(_)),
            "invalid scratch output directory component"
        );
        parent.push(component.as_os_str());
        ensure!(
            std::fs::symlink_metadata(&parent)?.file_type().is_dir(),
            "scratch output directory is not a real directory"
        );
    }
    let mut values = BTreeMap::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("scratch output filename is not UTF-8"))?;
        ensure!(
            expected.contains(&name.as_str()),
            "unexpected scratch output file"
        );
        let metadata = std::fs::symlink_metadata(entry.path())?;
        ensure!(
            metadata.file_type().is_file() && metadata.len() <= 16 * 1024,
            "scratch output is not a bounded regular file"
        );
        let bytes = read_bounded(&entry.path(), 16 * 1024)?;
        ensure!(
            bytes.len() as u64 == metadata.len(),
            "scratch output size changed while reading"
        );
        values.insert(name, serde_json::from_slice(&bytes)?);
    }
    ensure!(
        values.len() == expected.len(),
        "scratch output files are incomplete"
    );
    Ok(values)
}

fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    ensure!(
        file.metadata()?.len() <= max as u64,
        "file exceeds size limit"
    );
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max, "file exceeds size limit");
    Ok(bytes)
}
fn read_plan(path: &Path) -> Result<Plan> {
    Ok(serde_json::from_slice(&read_bounded(path, 1024 * 1024)?)?)
}
fn array(value: &Value) -> Result<&Vec<Value>> {
    value.as_array().context("GitHub array response malformed")
}
fn positive(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .filter(|n| *n > 0)
        .context("nonzero integer identity missing")
}
fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn sha256(bytes: &[u8]) -> String {
    hex_encode(Sha256::digest(bytes))
}
fn bootstrap_branch(source: &str) -> Result<String> {
    validate_sha(source)?;
    Ok(format!("securefix-control-bootstrap-{}", &source[..12]))
}
fn emit(value: &impl Serialize) -> Result<()> {
    securefix::output_multiline("plan", &serde_json::to_string(value)?)
}
fn print_result(pull: &Value, head: &str, identity: Option<&str>) -> Result<()> {
    let number = positive(&pull["number"])?;
    let mut result = json!({"pull_request":number,"head_sha":head});
    if let Some(identity) = identity {
        result["control_id"] = json!(identity);
    }
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod tests;
