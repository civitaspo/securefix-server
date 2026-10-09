use std::collections::BTreeSet;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};

use crate::api::{ApiError, GitHub};
use crate::policy::{Capability, Policy, ReleaseStrategy, validate_repository};
use crate::workflow::{
    ReferencedWorkflow, manifest_from_zip, referenced_revision, require_current_runtime,
    successful_source_run, write_json,
};
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use clap::{Args, Subcommand};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const MAX_PROVIDER_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_PROVIDER_ARCHIVE_FILES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository(String);

impl Repository {
    pub fn parse(value: &str) -> Result<Self> {
        let mut parts = value.split('/');
        let owner = parts.next().unwrap_or_default();
        let name = parts.next().unwrap_or_default();
        if parts.next().is_some() || owner.is_empty() || name.is_empty() {
            bail!("expected a single owner/repository value");
        }
        if !owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
            || name == "."
            || name == ".."
        {
            bail!("repository contains invalid path or URL characters");
        }
        Ok(Self(format!("{owner}/{name}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn name(&self) -> &str {
        self.0
            .split_once('/')
            .map(|(_, name)| name)
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RunId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommitSha(String);

impl CommitSha {
    pub fn parse(value: &str) -> Result<Self> {
        if value.len() != 40
            || !value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            bail!("expected a lowercase 40-character commit SHA");
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReleaseTag(String);

impl ReleaseTag {
    pub fn parse(value: &str) -> Result<Self> {
        let version = value
            .strip_prefix('v')
            .context("release tag must start with v")?;
        Version::parse(version).context("release tag must contain a semantic version")?;
        if value.len() > 100 || value.contains('/') {
            bail!("release tag is too long or contains a path separator");
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn version(&self) -> &str {
        self.0.strip_prefix('v').unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifestV2 {
    pub schema_version: u8,
    pub repository: String,
    pub source_run_id: RunId,
    pub source_run_sha: CommitSha,
    pub run_attempt: u64,
    pub source_revision: CommitSha,
    pub release_pr_number: u64,
    pub release_pr_sha: CommitSha,
    pub tag: ReleaseTag,
    pub artifact_id: Option<u64>,
}

impl ReleaseManifestV2 {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 2 {
            bail!("unsupported release manifest schema version");
        }
        Repository::parse(&self.repository)?;
        CommitSha::parse(self.source_run_sha.as_str())?;
        CommitSha::parse(self.source_revision.as_str())?;
        CommitSha::parse(self.release_pr_sha.as_str())?;
        ReleaseTag::parse(self.tag.as_str())?;
        if self.source_run_id.0 == 0
            || self.run_attempt == 0
            || self.release_pr_number == 0
            || self.artifact_id == Some(0)
        {
            bail!("release manifest contains an empty numeric identifier");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderTarget {
    pub os: &'static str,
    pub arch: &'static str,
}

pub const PROVIDER_TARGETS: &[ProviderTarget] = &[
    ProviderTarget {
        os: "freebsd",
        arch: "amd64",
    },
    ProviderTarget {
        os: "freebsd",
        arch: "386",
    },
    ProviderTarget {
        os: "freebsd",
        arch: "arm",
    },
    ProviderTarget {
        os: "freebsd",
        arch: "arm64",
    },
    ProviderTarget {
        os: "windows",
        arch: "amd64",
    },
    ProviderTarget {
        os: "windows",
        arch: "386",
    },
    ProviderTarget {
        os: "windows",
        arch: "arm64",
    },
    ProviderTarget {
        os: "linux",
        arch: "amd64",
    },
    ProviderTarget {
        os: "linux",
        arch: "386",
    },
    ProviderTarget {
        os: "linux",
        arch: "arm",
    },
    ProviderTarget {
        os: "linux",
        arch: "arm64",
    },
    ProviderTarget {
        os: "darwin",
        arch: "amd64",
    },
    ProviderTarget {
        os: "darwin",
        arch: "arm64",
    },
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePlanV2 {
    pub schema_version: u8,
    pub server_revision: String,
    pub repository: String,
    pub strategy: ReleaseStrategy,
    pub source_run_id: RunId,
    pub source_run_attempt: u64,
    pub source_revision: String,
    pub release_pr_number: u64,
    pub release_pr_sha: String,
    pub tag: ReleaseTag,
    pub source_manifest: ReleaseManifestV2,
    pub release_id: Option<u64>,
    pub assets: Vec<PlannedAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedAsset {
    pub name: String,
    pub sha256: String,
}

impl ReleasePlanV2 {
    fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 2, "unsupported release plan schema");
        validate_repository(&self.repository)?;
        CommitSha::parse(&self.server_revision)?;
        CommitSha::parse(&self.source_revision)?;
        CommitSha::parse(&self.release_pr_sha)?;
        ReleaseTag::parse(self.tag.as_str())?;
        self.source_manifest.validate()?;
        ensure!(
            self.source_manifest.repository == self.repository
                && self.source_manifest.source_run_id == self.source_run_id
                && self.source_manifest.run_attempt == self.source_run_attempt
                && self.source_manifest.source_revision.as_str() == self.source_revision
                && self.source_manifest.release_pr_number == self.release_pr_number
                && self.source_manifest.release_pr_sha.as_str() == self.release_pr_sha
                && self.source_manifest.tag == self.tag,
            "release plan does not match its source manifest"
        );
        ensure!(
            self.source_run_id.0 > 0 && self.source_run_attempt > 0 && self.release_pr_number > 0,
            "invalid release plan identifiers"
        );
        ensure!(
            self.release_id.is_none_or(|id| id > 0),
            "invalid release ID"
        );
        let mut names = BTreeSet::new();
        for asset in &self.assets {
            ensure!(names.insert(&asset.name), "duplicate asset name");
            ensure!(
                !asset.name.is_empty()
                    && asset
                        .name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
                "unsafe asset filename"
            );
            ensure!(
                asset.sha256.len() == 64
                    && asset
                        .sha256
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "invalid asset digest"
            );
        }
        if self.strategy == ReleaseStrategy::GithubRelease {
            ensure!(
                self.assets.is_empty(),
                "GitHub Release plans cannot contain provider assets"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct PrArgs {
    #[arg(long)]
    pub release_pr_number: u64,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Prepare {
        #[arg(long, default_value = "")]
        version: String,
    },
    SyncPr,
    Classify,
    ResolvePr(PrArgs),
    BuildProvider(PrArgs),
    TagPr {
        #[command(flatten)]
        pr: PrArgs,
        #[arg(long)]
        artifact_id: Option<u64>,
    },
    RequestServer,
    ParseRequest,
    Preflight,
    Sign,
    Publish,
    Cleanup,
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Prepare { version } => prepare(&version),
        Command::SyncPr => sync_pr(),
        Command::Classify => classify(),
        Command::ResolvePr(pr) => resolve_pr_command(pr.release_pr_number),
        Command::BuildProvider(pr) => build_provider(pr.release_pr_number),
        Command::TagPr { pr, artifact_id } => tag_pr(pr.release_pr_number, artifact_id),
        Command::RequestServer => request_server(),
        Command::ParseRequest => parse_request(),
        Command::Preflight => preflight(),
        Command::Sign => sign(),
        Command::Publish => publish(),
        Command::Cleanup => cleanup(),
    }
}

#[derive(Debug, Deserialize)]
struct PullRequest {
    number: u64,
    merged: Option<bool>,
    merged_at: Option<DateTime<Utc>>,
    merge_commit_sha: Option<String>,
    merged_by: Option<Actor>,
    head: PullRequestBranch,
    base: PullRequestBranch,
}

#[derive(Debug, Deserialize)]
struct PullRequestBranch {
    #[serde(rename = "ref")]
    name: String,
    sha: String,
    repo: Option<PullRequestRepository>,
}

#[derive(Debug, Deserialize)]
struct PullRequestRepository {
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct Actor {
    id: u64,
    #[serde(rename = "type")]
    kind: String,
}

fn env(name: &str) -> Result<String> {
    let value = std::env::var(name).with_context(|| format!("missing {name}"))?;
    ensure!(!value.is_empty(), "{name} is empty");
    Ok(value)
}

fn api() -> Result<GitHub> {
    GitHub::from_env("GITHUB_TOKEN")
}

fn current_repository() -> Result<Repository> {
    Repository::parse(&env("GITHUB_REPOSITORY")?)
}

fn current_policy(api: &GitHub) -> Result<Policy> {
    Policy::active(api)
}

fn authorized_release_pr(
    api: &GitHub,
    policy: &Policy,
    repo: &Repository,
    number: u64,
) -> Result<(PullRequest, CommitSha)> {
    let release_branch = crate::config::trusted()?.deployment.release_branch.as_str();
    let repository: Value = api.get(&format!("/repos/{}", repo.as_str()))?;
    let default_branch = repository["default_branch"]
        .as_str()
        .context("release caller default branch missing")?;
    ensure!(number > 0, "release PR number must be positive");
    let pr: PullRequest = api.get(&format!("/repos/{}/pulls/{number}", repo.as_str()))?;
    ensure!(
        pr.number == number,
        "GitHub returned a different pull request"
    );
    ensure!(
        pr.merged == Some(true) && pr.merged_at.is_some(),
        "release PR is not merged"
    );
    ensure!(
        pr.base.name == default_branch && pr.head.name == release_branch,
        "release PR must merge the configured release branch into the caller default branch"
    );
    ensure!(
        pr.head
            .repo
            .as_ref()
            .is_some_and(|head| head.full_name == repo.as_str()),
        "release PR must come from the same repository"
    );
    ensure!(
        pr.base
            .repo
            .as_ref()
            .is_some_and(|base| base.full_name == repo.as_str()),
        "release PR base must be the same repository"
    );
    ensure!(
        pr.merged_by
            .as_ref()
            .is_some_and(|actor| actor.id == policy.server_bot_id && actor.kind == "Bot"),
        "release PR was not merged by Securefix Server"
    );
    let merge_sha = CommitSha::parse(
        pr.merge_commit_sha
            .as_deref()
            .context("merged PR lacks a merge commit SHA")?,
    )?;
    CommitSha::parse(&pr.head.sha)?;
    crate::request::require_owner_marker(api, policy, repo.as_str(), number, &pr.head.sha)?;
    let compare: Value = api.get(&format!(
        "/repos/{}/compare/{}...{}",
        repo.as_str(),
        merge_sha.as_str(),
        default_branch
    ))?;
    ensure!(
        matches!(compare["status"].as_str(), Some("ahead" | "identical")),
        "release PR merge commit is not contained in main"
    );
    Ok((pr, merge_sha))
}

fn strategy_for(api: &GitHub, repo: &Repository) -> Result<ReleaseStrategy> {
    let policy = current_policy(api)?;
    let repository = policy.repository(repo.as_str())?;
    repository.require(Capability::Release)?;
    repository
        .release
        .context("release strategy is not configured")
}

fn resolve_pr_command(number: u64) -> Result<()> {
    let api = api()?;
    let repo = current_repository()?;
    let policy = current_policy(&api)?;
    require_dispatch_owner(&api, &policy)?;
    let (pr, merge_sha) = authorized_release_pr(&api, &policy, &repo, number)?;
    let strategy = strategy_for(&api, &repo)?;
    crate::output("merge_sha", merge_sha.as_str())?;
    crate::output("head_sha", &pr.head.sha)?;
    crate::output("strategy", serde_yaml::to_string(&strategy)?.trim())?;
    Ok(())
}

fn classify() -> Result<()> {
    let api = api()?;
    let repo = current_repository()?;
    let strategy = strategy_for(&api, &repo)?;
    crate::output("strategy", serde_yaml::to_string(&strategy)?.trim())?;
    crate::output(
        "build_provider",
        if strategy == ReleaseStrategy::TerraformProvider {
            "true"
        } else {
            "false"
        },
    )?;
    Ok(())
}

fn git_output(args: &[&str]) -> Result<String> {
    let output = ProcessCommand::new("git")
        .args(args)
        .output()
        .context("run git")?;
    ensure!(
        output.status.success(),
        "git {} failed",
        args.first().copied().unwrap_or_default()
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn tool_output(program: &str, args: &[&str]) -> Result<String> {
    let output = ProcessCommand::new(program)
        .args(args)
        .output()
        .with_context(|| format!("run {program}"))?;
    ensure!(output.status.success(), "{program} command failed");
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn next_version(input: &str) -> Result<Option<Version>> {
    if !input.is_empty() {
        let version = input.strip_prefix('v').unwrap_or(input);
        ensure!(
            !version.contains('+'),
            "build metadata is not supported for release versions"
        );
        return Ok(Some(
            Version::parse(version).context("invalid explicit release version")?,
        ));
    }
    let base = stable_release_base()?;
    ensure_cliff_base_tag(&base)?;
    let raw = tool_output("git-cliff", &["--bumped-version"])?;
    let version = raw.strip_prefix('v').unwrap_or(&raw);
    let bumped = Version::parse(version).context("git-cliff returned an invalid version")?;
    if bumped == base {
        return Ok(None);
    }
    ensure!(
        bumped > base,
        "git-cliff returned a version older than the release base"
    );
    Ok(Some(bumped))
}

fn ensure_cliff_base_tag(base: &Version) -> Result<()> {
    if base == &Version::new(0, 0, 0) {
        return Ok(());
    }
    let tag = format!("v{base}");
    let exists = ProcessCommand::new("git")
        .args([
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("refs/tags/{tag}^{{commit}}"),
        ])
        .status()?;
    if exists.success() {
        return Ok(());
    }
    let commit = [
        format!("^chore(release): {tag}$"),
        format!("^chore(release): prepare {tag}$"),
    ]
    .iter()
    .find_map(|pattern| {
        git_output(&["log", "--grep", pattern, "--format=%H", "-1"])
            .ok()
            .filter(|commit| !commit.is_empty())
    })
    .context("shipped version has no matching release commit for git-cliff base")?;
    git_output(&["tag", "-f", &tag, &commit])?;
    Ok(())
}

fn stable_release_base() -> Result<Version> {
    let tagged = ProcessCommand::new("git")
        .args([
            "describe",
            "--tags",
            "--abbrev=0",
            "--match",
            "v[0-9]*",
            "--exclude",
            "v*-*",
        ])
        .output()?;
    let tagged = if tagged.status.success() {
        String::from_utf8(tagged.stdout)?
            .trim()
            .trim_start_matches('v')
            .to_owned()
    } else {
        "0.0.0".to_owned()
    };
    let mut base =
        Version::parse(&tagged).context("latest stable tag is not semantic versioning")?;
    if let Ok(shipped) = std::fs::read_to_string(".release-version") {
        let shipped = shipped.trim();
        if let Ok(version) = Version::parse(shipped)
            && version.pre.is_empty()
            && version.build.is_empty()
            && version > base
        {
            base = version;
        }
    }
    Ok(base)
}

fn prepare(input_version: &str) -> Result<()> {
    let api = api()?;
    let policy = current_policy(&api)?;
    policy
        .repository(current_repository()?.as_str())?
        .require(Capability::Release)?;
    require_current_runtime(&api, ".github/workflows/reusable-release-pr.yml")?;
    let Some(version) = next_version(input_version)? else {
        crate::output("releasable", "false")?;
        return Ok(());
    };
    let version = version.to_string();
    let tag = format!("v{version}");
    let existing = ProcessCommand::new("git")
        .args([
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("refs/tags/{tag}"),
        ])
        .status()?;
    if existing.success() {
        bail!("release tag {tag} already exists");
    }
    let _ = tool_output("git-cliff", &["--tag", &tag, "--output", "CHANGELOG.md"])?;
    std::fs::write(".release-version", format!("{version}\n"))?;
    if Path::new("dbt_project.yml").is_file() {
        update_top_level_yaml_version(Path::new("dbt_project.yml"), &version)?;
    }
    if Path::new("pyproject.toml").is_file() {
        update_pyproject_version(Path::new("pyproject.toml"), &version)?;
    }
    let mut files = vec![".release-version", "CHANGELOG.md"];
    if Path::new("dbt_project.yml").is_file() {
        files.push("dbt_project.yml");
    }
    if Path::new("pyproject.toml").is_file() {
        files.push("pyproject.toml");
    }
    output_multiline("files", &files)?;
    crate::output("version", &version)?;
    crate::output(
        "body_extra",
        if files.len() > 2 {
            "package version metadata"
        } else {
            "release metadata"
        },
    )?;
    crate::output("releasable", "true")?;
    Ok(())
}

fn update_top_level_yaml_version(path: &Path, version: &str) -> Result<()> {
    let source = std::fs::read_to_string(path)?;
    let mut matches = 0;
    let mut lines = Vec::new();
    for line in source.lines() {
        if !line.starts_with(' ') && !line.starts_with('\t') && line.starts_with("version:") {
            matches += 1;
            let comment = line
                .split_once(" #")
                .map(|(_, comment)| format!(" #{comment}"))
                .unwrap_or_default();
            lines.push(format!("version: {version}{comment}"));
        } else {
            lines.push(line.to_owned());
        }
    }
    ensure!(
        matches == 1,
        "{} must contain exactly one top-level version field",
        path.display()
    );
    let mut updated = lines.join("\n");
    if source.ends_with('\n') {
        updated.push('\n');
    }
    std::fs::write(path, updated)?;
    Ok(())
}

fn update_pyproject_version(path: &Path, version: &str) -> Result<()> {
    let source = std::fs::read_to_string(path)?;
    let mut document = source
        .parse::<toml_edit::DocumentMut>()
        .context("parse pyproject.toml")?;
    let project = document
        .get_mut("project")
        .and_then(toml_edit::Item::as_table_like_mut)
        .context("pyproject.toml must have a [project] table")?;
    let item = project
        .get_mut("version")
        .context("[project] lacks version")?;
    *item = toml_edit::value(version);
    std::fs::write(path, document.to_string())?;
    Ok(())
}

fn output_multiline(name: &str, values: &[&str]) -> Result<()> {
    let delimiter = "SECUREFIX_RELEASE_FILES";
    ensure!(
        values.iter().all(|value| !value.contains(delimiter)),
        "unsafe multiline output value"
    );
    if let Ok(path) = std::env::var("GITHUB_OUTPUT") {
        let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
        writeln!(file, "{name}<<{delimiter}")?;
        for value in values {
            writeln!(file, "{value}")?;
        }
        writeln!(file, "{delimiter}")?;
    } else {
        println!("{}", values.join("\n"));
    }
    Ok(())
}

fn sync_pr() -> Result<()> {
    let api = api()?;
    let repo = current_repository()?;
    let policy = current_policy(&api)?;
    let _runtime = require_current_runtime(&api, ".github/workflows/reusable-release-pr-sync.yml")?;
    policy
        .repository(repo.as_str())?
        .require(Capability::Release)?;
    let version = std::fs::read_to_string(".release-version")?;
    let version = version.split_whitespace().collect::<String>();
    ensure!(
        Version::parse(&version).is_ok() && !version.contains('+'),
        "invalid .release-version"
    );
    let release_branch = crate::config::trusted()?.deployment.release_branch.as_str();
    let repo_info: Value = api.get(&format!("/repos/{}", repo.as_str()))?;
    let default_branch = repo_info["default_branch"]
        .as_str()
        .context("caller default branch missing")?;
    let head = format!(
        "{}:{release_branch}",
        repo.as_str().split('/').next().unwrap_or_default()
    );
    let encoded_head = url_encode(&head);
    let pulls: Vec<Value> = api.get(&format!(
        "/repos/{}/pulls?state=open&head={encoded_head}&base={}",
        repo.as_str(),
        url_encode(default_branch)
    ))?;
    let Some(pr) = pulls.first() else {
        return Ok(());
    };
    ensure!(pulls.len() == 1, "multiple open release PRs found");
    let number = pr["number"]
        .as_u64()
        .context("release PR response lacks number")?;
    let metadata =
        if Path::new("dbt_project.yml").is_file() || Path::new("pyproject.toml").is_file() {
            "package version metadata"
        } else {
            "release metadata"
        };
    let body = format!(
        "## Summary\n- Prepare release v{version}\n- Update the changelog and {metadata}\n\nThis pull request is managed by the Release PR workflow."
    );
    let _: Value = api.patch(
        &format!("/repos/{}/pulls/{number}", repo.as_str()),
        &json!({"title":format!("chore(release): v{version}"),"body":body}),
    )?;
    Ok(())
}

fn url_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn build_provider(release_pr_number: u64) -> Result<()> {
    let api = api()?;
    let repo = current_repository()?;
    let policy = current_policy(&api)?;
    let _runtime = require_current_runtime(&api, ".github/workflows/reusable-release-tag.yml")?;
    require_dispatch_owner(&api, &policy)?;
    ensure!(
        strategy_for(&api, &repo)? == ReleaseStrategy::TerraformProvider,
        "provider build is not enabled for this repository"
    );
    let project = repo.name();
    let (_pr, merge_sha) = authorized_release_pr(&api, &policy, &repo, release_pr_number)?;
    ensure!(
        git_output(&["rev-parse", "HEAD"])? == merge_sha.as_str(),
        "checked out source is not the approved release merge commit"
    );
    let version = std::fs::read_to_string(".release-version")?;
    let version = version.trim();
    let tag = ReleaseTag::parse(&format!("v{version}"))?;
    let manifest: Value =
        serde_json::from_slice(&std::fs::read("terraform-registry-manifest.json")?)?;
    ensure!(
        manifest["version"] == 1 && manifest["metadata"]["protocol_versions"] == json!(["6.0"]),
        "unexpected Terraform Registry manifest"
    );
    let output_dir = Path::new("dist/release-assets");
    if output_dir.exists() {
        std::fs::remove_dir_all(output_dir)?;
    }
    std::fs::create_dir_all(output_dir)?;
    for target in PROVIDER_TARGETS {
        let windows = target.os == "windows";
        let binary_name = format!(
            "{project}_v{}{}",
            tag.version(),
            if windows { ".exe" } else { "" }
        );
        let binary_path = output_dir.join(format!(
            ".build-{}-{}{}",
            target.os,
            target.arch,
            if windows { ".exe" } else { "" }
        ));
        let mut cmd = ProcessCommand::new("go");
        cmd.current_dir(".")
            .args([
                "build",
                "-mod=readonly",
                "-trimpath",
                "-ldflags",
                &format!("-s -w -X main.version={}", tag.version()),
                "-o",
            ])
            .arg(&binary_path)
            .arg(".")
            .env("CGO_ENABLED", "0")
            .env("GOOS", target.os)
            .env("GOARCH", target.arch);
        match target.arch {
            "amd64" => {
                cmd.env("GOAMD64", "v1");
            }
            "arm" => {
                cmd.env("GOARM", "6");
            }
            "arm64" => {
                cmd.env("GOARM64", "v8.0");
            }
            _ => {}
        }
        let status = cmd
            .status()
            .with_context(|| format!("build {} {} provider", target.os, target.arch))?;
        ensure!(
            status.success(),
            "Go provider build failed for {} {}",
            target.os,
            target.arch
        );
        let archive_name = format!(
            "{project}_{}_{}_{}.zip",
            tag.version(),
            target.os,
            target.arch
        );
        let archive_path = output_dir.join(&archive_name);
        write_provider_zip(&binary_path, &binary_name, Path::new("."), &archive_path)?;
        std::fs::remove_file(binary_path)?;
    }
    let manifest_name = format!("{project}_{}_manifest.json", tag.version());
    std::fs::copy(
        "terraform-registry-manifest.json",
        output_dir.join(manifest_name),
    )?;
    let files = validate_asset_directory(output_dir, &tag, project)?;
    crate::output("tag", tag.as_str())?;
    crate::output("merge_sha", merge_sha.as_str())?;
    crate::output("asset_count", files.len().to_string())?;
    Ok(())
}

fn write_provider_zip(
    binary_path: &Path,
    binary_name: &str,
    documentation_dir: &Path,
    archive_path: &Path,
) -> Result<()> {
    let output = std::fs::File::create(archive_path)?;
    let mut archive = zip::ZipWriter::new(output);
    for (path, name, mode) in [
        (
            documentation_dir.join("CHANGELOG.md"),
            "CHANGELOG.md",
            0o644,
        ),
        (documentation_dir.join("LICENSE"), "LICENSE", 0o644),
        (documentation_dir.join("README.md"), "README.md", 0o644),
        (binary_path.to_owned(), binary_name, 0o755),
    ] {
        let metadata = std::fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "provider archive input must be a regular file: {}",
            path.display()
        );
        ensure!(
            metadata.len() > 0 && metadata.len() <= MAX_PROVIDER_ARCHIVE_BYTES,
            "provider archive input has invalid size: {}",
            path.display()
        );
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(mode);
        archive.start_file(name, options)?;
        let copied = std::io::copy(
            &mut std::fs::File::open(path)?.take(MAX_PROVIDER_ARCHIVE_BYTES + 1),
            &mut archive,
        )?;
        ensure!(
            copied == metadata.len() && copied <= MAX_PROVIDER_ARCHIVE_BYTES,
            "provider archive input changed while packaging: {name}"
        );
    }
    archive.finish()?;
    Ok(())
}

fn tag_pr(release_pr_number: u64, artifact_id: Option<u64>) -> Result<()> {
    let artifact_id = artifact_id.filter(|id| *id != 0);
    let api = api()?;
    let repo = current_repository()?;
    let policy = current_policy(&api)?;
    let _runtime = require_current_runtime(&api, ".github/workflows/reusable-release-tag.yml")?;
    require_dispatch_owner(&api, &policy)?;
    let strategy = strategy_for(&api, &repo)?;
    ensure!(
        strategy != ReleaseStrategy::TerraformProvider || artifact_id.is_some_and(|id| id > 0),
        "provider release requires an unsigned build artifact ID"
    );
    ensure!(
        strategy != ReleaseStrategy::GithubRelease || artifact_id.is_none(),
        "GitHub release does not accept a provider artifact"
    );
    let (pr, merge_sha) = authorized_release_pr(&api, &policy, &repo, release_pr_number)?;
    let version_bytes = api.content(repo.as_str(), ".release-version", merge_sha.as_str())?;
    let version = String::from_utf8(version_bytes)?.trim().to_owned();
    let tag = ReleaseTag::parse(&format!("v{version}"))?;
    create_annotated_tag(&api, &repo, &tag, &merge_sha)?;
    let run_id = RunId(env("GITHUB_RUN_ID")?.parse()?);
    let run: Value = api.get(&format!(
        "/repos/{}/actions/runs/{}",
        repo.as_str(),
        run_id.0
    ))?;
    let source_run_sha = CommitSha::parse(
        run["head_sha"]
            .as_str()
            .context("workflow run lacks head SHA")?,
    )?;
    let source_revision = CommitSha::parse(&env("SECUREFIX_SOURCE_SHA")?)?;
    ensure!(
        source_revision.as_str() == policy.revision,
        "release tag runtime is stale"
    );
    let manifest = ReleaseManifestV2 {
        schema_version: 2,
        repository: repo.as_str().to_owned(),
        source_run_id: run_id,
        source_run_sha,
        run_attempt: run["run_attempt"]
            .as_u64()
            .context("workflow run lacks attempt")?,
        source_revision,
        release_pr_number,
        release_pr_sha: merge_sha,
        tag,
        artifact_id,
    };
    manifest.validate()?;
    let path = PathBuf::from("manifest.json");
    write_json(&path, &manifest)?;
    crate::output("tag", manifest.tag.as_str())?;
    crate::output("merge_sha", manifest.release_pr_sha.as_str())?;
    crate::output("head_sha", &pr.head.sha)?;
    crate::output("manifest_path", path.display().to_string())?;
    Ok(())
}

pub(crate) fn create_annotated_tag(
    api: &GitHub,
    repo: &Repository,
    tag: &ReleaseTag,
    target: &CommitSha,
) -> Result<()> {
    let ref_path = format!(
        "/repos/{}/git/ref/tags/{}",
        repo.as_str(),
        url_encode(tag.as_str())
    );
    match api.get::<Value>(&ref_path) {
        Ok(reference) => {
            ensure!(
                reference["object"]["type"] == "tag",
                "existing release tag is not annotated"
            );
            let object_sha = reference["object"]["sha"]
                .as_str()
                .context("tag reference lacks object SHA")?;
            let object: Value =
                api.get(&format!("/repos/{}/git/tags/{object_sha}", repo.as_str()))?;
            ensure!(
                object["object"]["sha"] == target.as_str(),
                "existing release tag points to a different commit"
            );
            return Ok(());
        }
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|api_error| api_error.status == reqwest::StatusCode::NOT_FOUND) => {}
        Err(error) => return Err(error),
    }
    let tag_object: Value = api.post(&format!("/repos/{}/git/tags", repo.as_str()), &json!({"tag":tag.as_str(),"message":format!("Release {}",tag.as_str()),"object":target.as_str(),"type":"commit"}))?;
    let object_sha = tag_object["sha"]
        .as_str()
        .context("GitHub did not return an annotated tag SHA")?;
    match api.post::<Value>(
        &format!("/repos/{}/git/refs", repo.as_str()),
        &json!({"ref":format!("refs/tags/{}",tag.as_str()),"sha":object_sha}),
    ) {
        Ok(_) => Ok(()),
        Err(error) => {
            let verify: Value = api
                .get(&ref_path)
                .context("tag creation failed and no matching existing tag was found")?;
            ensure!(
                verify["object"]["type"] == "tag",
                "release tag was created as a lightweight tag"
            );
            let actual: Value = api.get(&format!(
                "/repos/{}/git/tags/{}",
                repo.as_str(),
                verify["object"]["sha"]
                    .as_str()
                    .context("tag lacks object SHA")?
            ))?;
            ensure!(
                actual["object"]["sha"] == target.as_str(),
                "concurrent release tag points to a different commit"
            );
            let _ = error;
            Ok(())
        }
    }
}

fn request_server() -> Result<()> {
    let api = GitHub::from_env("GH_TOKEN")?;
    let read = GitHub::from_env("GITHUB_TOKEN")?;
    let repo = current_repository()?;
    let policy = current_policy(&read)?;
    let _runtime = require_current_runtime(&read, ".github/workflows/reusable-release-tag.yml")?;
    policy
        .repository(repo.as_str())?
        .require(Capability::Release)?;
    let run_id: u64 = env("GITHUB_RUN_ID")?.parse()?;
    let label = format!("release-request-{run_id}");
    let description = format!("{}/{run_id}", repo.as_str());
    ensure!(
        description.len() <= 100,
        "release request label description is too long"
    );
    let server_repository = &crate::config::trusted()?.deployment.server.repository;
    let path = format!("/repos/{server_repository}/labels/{}", url_encode(&label));
    match api.get::<Value>(&path) {
        Ok(existing) => ensure!(
            existing["description"] == description,
            "release request label already exists with different provenance"
        ),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|api_error| api_error.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            let _: Value = api.post(
                &format!("/repos/{server_repository}/labels"),
                &json!({"name":label,"color":"1f6feb","description":description}),
            )?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

fn request_parts(event: &Value) -> Result<(Repository, RunId)> {
    let client_bot_id = crate::config::trusted()?.client_bot_id;
    ensure!(
        event["sender"]["id"].as_u64() == Some(client_bot_id) && event["sender"]["type"] == "Bot",
        "release request was not created by the Securefix Client App"
    );
    let label = event["label"]["name"]
        .as_str()
        .context("event lacks request label")?;
    let description = event["label"]["description"]
        .as_str()
        .context("event lacks request description")?;
    let run = label
        .strip_prefix("release-request-")
        .context("label is not a release request")?;
    let run_id = RunId(
        run.parse()
            .context("invalid run ID in release request label")?,
    );
    ensure!(run_id.0 > 0, "release request run ID must be positive");
    let (repository, described_run) = description
        .rsplit_once('/')
        .context("invalid release request description")?;
    ensure!(
        described_run == run,
        "release request label and description run IDs differ"
    );
    ensure!(
        description.matches('/').count() == 2,
        "release request must identify one owner/repository/run"
    );
    let repository = Repository::parse(repository)?;
    Ok((repository, run_id))
}

fn parse_request() -> Result<()> {
    let api = api()?;
    let policy = current_policy(&api)?;
    let _runtime = require_current_runtime(&api, ".github/workflows/release.yml")?;
    let event = crate::event()?;
    let (repo, run_id) = request_parts(&event)?;
    policy
        .repository(repo.as_str())?
        .require(Capability::Release)?;
    crate::output("repository", repo.as_str())?;
    crate::output("repo_name", repo.name())?;
    crate::output("run_id", run_id.0.to_string())?;
    Ok(())
}

fn preflight() -> Result<()> {
    let read = GitHub::from_env("GITHUB_TOKEN")?;
    let app = GitHub::from_env("GH_TOKEN")?;
    let policy = current_policy(&read)?;
    let event = crate::event()?;
    let (repo, run_id) = request_parts(&event)?;
    let repo_policy = policy.repository(repo.as_str())?;
    repo_policy.require(Capability::Release)?;
    let strategy = repo_policy
        .release
        .context("release strategy is not configured")?;
    let _runtime = require_current_runtime(&read, ".github/workflows/release.yml")?;
    let manifest = validated_source(&app, &policy, &repo, run_id, strategy)?;
    let tag = manifest.tag.clone();
    let release_id = find_release(&app, &repo, &tag)?.and_then(|release| release["id"].as_u64());
    if let Some(id) = release_id {
        let release: Value = app.get(&format!("/repos/{}/releases/{id}", repo.as_str()))?;
        ensure!(
            release["tag_name"] == tag.as_str(),
            "existing release uses a different tag"
        );
        ensure!(
            release["draft"] == true || release["draft"] == false,
            "existing release lacks draft state"
        );
        ensure!(
            release["draft"] == true || release["immutable"] == true,
            "published release is not marked immutable"
        );
    }
    let server_revision = policy.revision.clone();
    let mut plan = ReleasePlanV2 {
        schema_version: 2,
        server_revision,
        repository: repo.as_str().to_owned(),
        strategy,
        source_run_id: manifest.source_run_id,
        source_run_attempt: manifest.run_attempt,
        source_revision: manifest.source_revision.as_str().to_owned(),
        release_pr_number: manifest.release_pr_number,
        release_pr_sha: manifest.release_pr_sha.as_str().to_owned(),
        tag,
        source_manifest: manifest.clone(),
        release_id,
        assets: Vec::new(),
    };
    let input_dir = PathBuf::from("release-input");
    if input_dir.exists() {
        std::fs::remove_dir_all(&input_dir)?;
    }
    std::fs::create_dir_all(&input_dir)?;
    if strategy == ReleaseStrategy::TerraformProvider {
        let bundle_id = manifest
            .artifact_id
            .context("provider release manifest lacks its bundle artifact ID")?;
        let artifact = get_artifact(&app, &repo, bundle_id, run_id)?;
        let bytes = app.download(
            &format!("/repos/{}/actions/artifacts/{bundle_id}/zip", repo.as_str()),
            512 * 1024 * 1024,
        )?;
        let assets_dir = input_dir.join("assets");
        std::fs::create_dir_all(&assets_dir)?;
        unpack_provider_bundle(&bytes, &assets_dir, &plan.tag, repo.name())?;
        let assets = validate_asset_directory(&assets_dir, &plan.tag, repo.name())?;
        plan.assets = assets
            .iter()
            .map(|path| {
                Ok(PlannedAsset {
                    name: path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .context("invalid asset filename")?
                        .to_owned(),
                    sha256: sha256_file(path)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            artifact["size_in_bytes"].as_u64().unwrap_or_default() <= 512 * 1024 * 1024,
            "provider artifact is too large"
        );
    } else {
        ensure!(
            manifest.artifact_id.is_none(),
            "GitHub Release manifest must not include provider artifacts"
        );
    }
    plan.validate()?;
    write_json(input_dir.join("plan.json"), &plan)?;
    crate::output("strategy", serde_yaml::to_string(&strategy)?.trim())?;
    crate::output("tag", plan.tag.as_str())?;
    crate::output("repository", repo.as_str())?;
    crate::output("release_pr_number", plan.release_pr_number.to_string())?;
    let label_name = event["label"]["name"]
        .as_str()
        .context("missing release label name")?;
    crate::output("request_label", label_name)?;
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ArtifactList {
    artifacts: Vec<Value>,
}

fn get_artifact(api: &GitHub, repo: &Repository, artifact_id: u64, run_id: RunId) -> Result<Value> {
    let list: ArtifactList = api.get(&format!(
        "/repos/{}/actions/runs/{}/artifacts?per_page=100",
        repo.as_str(),
        run_id.0
    ))?;
    let mut found = list
        .artifacts
        .into_iter()
        .filter(|artifact| artifact["id"].as_u64() == Some(artifact_id));
    let artifact = found
        .next()
        .context("release artifact is not attached to the source run")?;
    ensure!(found.next().is_none(), "duplicate artifact ID");
    ensure!(
        artifact["expired"] == false && artifact["name"] == "provider-bundle",
        "unexpected or expired provider artifact"
    );
    ensure!(
        artifact["size_in_bytes"].as_u64().unwrap_or_default() > 0,
        "provider artifact is empty"
    );
    Ok(artifact)
}

fn unpack_provider_bundle(
    bytes: &[u8],
    destination: &Path,
    tag: &ReleaseTag,
    project: &str,
) -> Result<()> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).context("read uploaded provider artifact")?;
    ensure!(
        archive.len() == PROVIDER_TARGETS.len() + 1,
        "provider artifact has an unexpected entry count"
    );
    let expected = provider_asset_names(tag, project);
    let mut found = BTreeSet::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .context("read provider artifact entry")?;
        let name = entry.name().to_owned();
        let path = Path::new(&name);
        ensure!(
            path.components().count() == 1
                && !path.is_absolute()
                && !name.contains(['/', '\\'])
                && !entry.is_dir(),
            "provider artifact contains an invalid path"
        );
        ensure!(
            entry
                .unix_mode()
                .is_none_or(|mode| mode & 0o170000 != 0o120000),
            "provider artifact contains a symbolic link"
        );
        ensure!(
            expected.contains(&name) && found.insert(name.clone()),
            "provider artifact contains an unexpected or duplicate asset"
        );
        ensure!(
            entry.size() > 0 && entry.size() <= MAX_PROVIDER_ARCHIVE_BYTES,
            "provider artifact asset has invalid size"
        );
        let mut output = std::fs::File::create(destination.join(&name))?;
        let declared_size = entry.size();
        let copied = std::io::copy(
            &mut entry.by_ref().take(MAX_PROVIDER_ARCHIVE_BYTES + 1),
            &mut output,
        )?;
        ensure!(
            copied == declared_size && copied <= MAX_PROVIDER_ARCHIVE_BYTES,
            "provider artifact asset size or checksum is invalid"
        );
    }
    ensure!(found == expected, "provider artifact is incomplete");
    Ok(())
}

fn validate_source_manifest_provenance(
    api: &GitHub,
    policy: &Policy,
    repo: &Repository,
    manifest: &ReleaseManifestV2,
    strategy: ReleaseStrategy,
) -> Result<()> {
    manifest.validate()?;
    ensure!(
        manifest.repository == repo.as_str(),
        "source manifest repository changed"
    );
    ensure!(
        manifest.source_revision.as_str() == policy.revision,
        "source runtime revision is stale"
    );
    let run: Value = api.get(&format!(
        "/repos/{}/actions/runs/{}",
        repo.as_str(),
        manifest.source_run_id.0
    ))?;
    ensure!(
        run["name"] == "Release Tag"
            && run["status"] == "completed"
            && run["conclusion"] == "success",
        "source Release Tag run is not successful"
    );
    ensure!(
        run["repository"]["full_name"] == repo.as_str()
            && run["head_repository"]["full_name"] == repo.as_str(),
        "source run is not from the same repository"
    );
    ensure!(
        run["head_sha"] == manifest.source_run_sha.as_str()
            && run["run_attempt"].as_u64() == Some(manifest.run_attempt),
        "source run identity changed"
    );
    let referenced: Vec<ReferencedWorkflow> =
        serde_json::from_value(run["referenced_workflows"].clone())
            .context("source workflow lacks referenced workflow provenance")?;
    referenced_revision(
        &referenced,
        ".github/workflows/reusable-release-tag.yml",
        &policy.revision,
    )?;
    let wrapper_path = run["path"]
        .as_str()
        .context("source run lacks caller workflow path")?;
    ensure_valid_caller_path(wrapper_path)?;
    let wrapper_sha = CommitSha::parse(run["head_sha"].as_str().unwrap_or_default())?;
    let default_branch: Value = api.get(&format!("/repos/{}", repo.as_str()))?;
    let default_branch = default_branch["default_branch"]
        .as_str()
        .filter(|branch| !branch.is_empty() && !branch.contains(['/', '\\', '@']))
        .context("repository has no valid default branch")?;
    let (pr, merge_sha) = authorized_release_pr(api, policy, repo, manifest.release_pr_number)?;
    ensure!(
        merge_sha == manifest.release_pr_sha,
        "source release PR merge SHA changed"
    );
    let release_version = api.content(repo.as_str(), ".release-version", merge_sha.as_str())?;
    let release_version = String::from_utf8(release_version)?;
    let expected_tag = ReleaseTag::parse(&format!("v{}", release_version.trim()))?;
    ensure!(
        manifest.tag == expected_tag,
        "release tag does not match .release-version at the merged commit"
    );
    let caller_sha = match run["event"].as_str() {
        Some("pull_request") => {
            ensure!(
                run["head_branch"] == pr.head.name
                    && manifest.source_run_sha.as_str() == pr.head.sha,
                "source PR head does not match the release PR"
            );
            // GitHub's run head_sha and pull_requests[].head.sha identify the
            // PR head. Read the caller workflow from the PR's base revision,
            // which is already part of the default branch, not that PR head.
            let ancestry: Value = api.get(&format!(
                "/repos/{}/compare/{}...{}",
                repo.as_str(),
                pr.base.sha,
                url_encode(default_branch)
            ))?;
            ensure!(
                matches!(ancestry["status"].as_str(), Some("ahead" | "identical")),
                "release caller base revision is not on the default branch"
            );
            CommitSha::parse(&pr.base.sha)?
        }
        Some("workflow_dispatch") => {
            ensure!(
                run["triggering_actor"]["id"].as_u64() == Some(policy.owner_id)
                    && run["triggering_actor"]["type"] == "User",
                "manual retry was not dispatched by the repository owner"
            );
            ensure!(
                wrapper_sha.as_str() == manifest.source_run_sha.as_str(),
                "manual retry wrapper revision changed"
            );
            let ancestry: Value = api.get(&format!(
                "/repos/{}/compare/{}...{}",
                repo.as_str(),
                wrapper_sha.as_str(),
                url_encode(default_branch)
            ))?;
            ensure!(
                matches!(ancestry["status"].as_str(), Some("ahead" | "identical")),
                "manual retry caller workflow revision is not on the default branch"
            );
            wrapper_sha.clone()
        }
        _ => bail!("unsupported Release Tag event"),
    };
    let wrapper = api.content(repo.as_str(), wrapper_path, caller_sha.as_str())?;
    crate::workflow::require_reusable_pin(
        &wrapper,
        ".github/workflows/reusable-release-tag.yml",
        &policy.revision,
    )?;
    let tag_ref: Value = api.get(&format!(
        "/repos/{}/git/ref/tags/{}",
        repo.as_str(),
        url_encode(manifest.tag.as_str())
    ))?;
    ensure!(
        tag_ref["object"]["type"] == "tag",
        "release tag is not annotated"
    );
    let tag_object: Value = api.get(&format!(
        "/repos/{}/git/tags/{}",
        repo.as_str(),
        tag_ref["object"]["sha"]
            .as_str()
            .context("tag ref lacks SHA")?
    ))?;
    ensure!(
        tag_object["object"]["sha"] == merge_sha.as_str(),
        "release tag points to a different commit"
    );
    if strategy == ReleaseStrategy::TerraformProvider {
        ensure!(
            manifest.artifact_id.is_some_and(|id| id > 0),
            "provider manifest lacks artifact provenance"
        );
    } else {
        ensure!(
            manifest.artifact_id.is_none(),
            "GitHub Release manifest unexpectedly names provider artifact"
        );
    }
    Ok(())
}

fn ensure_valid_caller_path(path: &str) -> Result<()> {
    ensure!(
        path.starts_with(".github/workflows/")
            && path.ends_with(".yml")
            && path.len() <= 200
            && !path.contains(['\\', '@', '?', '#'])
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."),
        "source run has an invalid caller workflow path"
    );
    Ok(())
}

fn validated_source(
    api: &GitHub,
    policy: &Policy,
    repo: &Repository,
    run_id: RunId,
    strategy: ReleaseStrategy,
) -> Result<ReleaseManifestV2> {
    let run = successful_source_run(api, repo.as_str(), run_id.0)?;
    ensure!(
        run["name"] == "Release Tag",
        "source workflow is not named Release Tag"
    );
    ensure!(
        run["repository"]["full_name"] == repo.as_str()
            && run["head_repository"]["full_name"] == repo.as_str(),
        "source workflow must run in the allowlisted repository"
    );
    let source_run_sha = CommitSha::parse(
        run["head_sha"]
            .as_str()
            .context("source workflow lacks head SHA")?,
    )?;
    let referenced: Vec<ReferencedWorkflow> =
        serde_json::from_value(run["referenced_workflows"].clone())
            .context("source workflow lacks referenced workflow provenance")?;
    referenced_revision(
        &referenced,
        ".github/workflows/reusable-release-tag.yml",
        &policy.revision,
    )?;
    let server_repository = &crate::config::trusted()?.deployment.server.repository;
    let source_revision = CommitSha::parse(
        &referenced
            .iter()
            .find(|workflow| {
                workflow.path.starts_with(&format!(
                    "{server_repository}/.github/workflows/reusable-release-tag.yml@"
                ))
            })
            .context("source workflow did not call pinned Release Tag reusable")?
            .sha,
    )?;
    let artifact_list: ArtifactList = api.get(&format!(
        "/repos/{}/actions/runs/{}/artifacts?per_page=100",
        repo.as_str(),
        run_id.0
    ))?;
    let mut manifests = artifact_list
        .artifacts
        .into_iter()
        .filter(|artifact| artifact["name"] == "release-manifest" && artifact["expired"] == false);
    let manifest_artifact = manifests
        .next()
        .context("source run lacks release manifest artifact")?;
    ensure!(
        manifests.next().is_none(),
        "source run has multiple release manifest artifacts"
    );
    let manifest_id = manifest_artifact["id"]
        .as_u64()
        .context("manifest artifact lacks ID")?;
    ensure!(
        manifest_artifact["size_in_bytes"]
            .as_u64()
            .unwrap_or_default()
            <= 1024 * 1024,
        "release manifest artifact is too large"
    );
    let bytes = api.download(
        &format!(
            "/repos/{}/actions/artifacts/{manifest_id}/zip",
            repo.as_str()
        ),
        1024 * 1024,
    )?;
    let manifest: ReleaseManifestV2 = manifest_from_zip(&bytes)?;
    manifest.validate()?;
    ensure!(
        manifest.repository == repo.as_str() && manifest.source_run_id == run_id,
        "release manifest does not match the source run"
    );
    ensure!(
        manifest.source_run_sha == source_run_sha
            && manifest.run_attempt
                == run["run_attempt"]
                    .as_u64()
                    .context("source run lacks attempt")?,
        "release manifest does not match the source attempt"
    );
    ensure!(
        manifest.source_revision == source_revision,
        "release manifest runtime revision does not match workflow provenance"
    );
    ensure!(
        manifest.source_revision.as_str() == policy.revision,
        "release runtime revision is stale"
    );
    let release_pr_number = manifest.release_pr_number;
    let (pr, merge_sha) = authorized_release_pr(api, policy, repo, release_pr_number)?;
    ensure!(
        manifest.release_pr_sha == merge_sha,
        "release manifest names a different merge commit"
    );
    let tag_ref: Value = api.get(&format!(
        "/repos/{}/git/ref/tags/{}",
        repo.as_str(),
        url_encode(manifest.tag.as_str())
    ))?;
    ensure!(
        tag_ref["object"]["type"] == "tag",
        "release tag is not annotated"
    );
    let tag_object: Value = api.get(&format!(
        "/repos/{}/git/tags/{}",
        repo.as_str(),
        tag_ref["object"]["sha"]
            .as_str()
            .context("tag ref lacks SHA")?
    ))?;
    ensure!(
        tag_object["object"]["sha"] == merge_sha.as_str(),
        "release tag points to a different commit"
    );
    if strategy == ReleaseStrategy::TerraformProvider {
        ensure!(
            manifest.artifact_id.is_some_and(|id| id > 0),
            "provider release manifest lacks artifact provenance"
        );
    } else {
        ensure!(
            manifest.artifact_id.is_none(),
            "GitHub Release request unexpectedly names a provider artifact"
        );
    }
    if run["event"] == "pull_request" {
        ensure!(
            run["pull_requests"]
                .as_array()
                .is_some_and(|prs| prs.iter().any(|pr| pr["number"] == release_pr_number)),
            "source run is not associated with the release PR"
        );
        let pr_head = CommitSha::parse(&pr.head.sha)?;
        ensure!(
            source_run_sha == pr_head,
            "source pull request run head does not match the release PR head"
        );
    } else if run["event"] == "workflow_dispatch" {
        ensure!(
            run["triggering_actor"]["id"].as_u64() == Some(policy.owner_id),
            "manual release retries must be dispatched by the owner"
        );
    } else {
        bail!("unsupported Release Tag event");
    }
    Ok(manifest)
}

fn require_dispatch_owner(api: &GitHub, policy: &Policy) -> Result<()> {
    if std::env::var("GITHUB_EVENT_NAME").as_deref() == Ok("workflow_dispatch") {
        let run_id: u64 = env("GITHUB_RUN_ID")?.parse()?;
        let run: Value = api.get(&format!(
            "/repos/{}/actions/runs/{run_id}",
            current_repository()?.as_str()
        ))?;
        ensure!(
            run["triggering_actor"]["id"].as_u64() == Some(policy.owner_id),
            "manual release retries must be dispatched by the repository owner"
        );
        ensure!(
            run["triggering_actor"]["type"] == "User",
            "manual release retry actor is not a user"
        );
    }
    Ok(())
}

fn find_release(api: &GitHub, repo: &Repository, tag: &ReleaseTag) -> Result<Option<Value>> {
    let path = format!(
        "/repos/{}/releases/tags/{}",
        repo.as_str(),
        url_encode(tag.as_str())
    );
    match api.get(&path) {
        Ok(release) => Ok(Some(release)),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|api_error| api_error.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn sign() -> Result<()> {
    let server = GitHub::from_env("GITHUB_TOKEN")?;
    let policy = current_policy(&server)?;
    let _runtime = require_current_runtime(&server, ".github/workflows/release.yml")?;
    let public = GitHub::anonymous()?;
    let input = PathBuf::from("release-input");
    let assets_dir = input.join("assets");
    let mut plan: ReleasePlanV2 = serde_json::from_slice(&std::fs::read(input.join("plan.json"))?)?;
    plan.validate()?;
    ensure!(
        plan.server_revision == policy.revision,
        "signing plan is stale"
    );
    let repo = Repository::parse(&plan.repository)?;
    let repo_policy = policy.repository(repo.as_str())?;
    repo_policy.require(Capability::Release)?;
    ensure!(
        repo_policy.release == Some(ReleaseStrategy::TerraformProvider)
            && plan.strategy == ReleaseStrategy::TerraformProvider,
        "signing is only allowed for Terraform provider releases"
    );
    validate_source_manifest_provenance(
        &public,
        &policy,
        &repo,
        &plan.source_manifest,
        plan.strategy,
    )?;
    let assets = validate_asset_directory(&assets_dir, &plan.tag, repo.name())?;
    ensure!(
        assets.len() == plan.assets.len(),
        "signing bundle asset count changed"
    );
    for asset in &plan.assets {
        let path = assets_dir.join(&asset.name);
        ensure!(
            sha256_file(&path)? == asset.sha256,
            "signing bundle asset digest changed: {}",
            asset.name
        );
    }
    let mut sums = String::new();
    for asset in &plan.assets {
        sums.push_str(&format!("{}  {}\n", asset.sha256, asset.name));
    }
    let sums_path = assets_dir.join(format!("{}_{}_SHA256SUMS", repo.name(), plan.tag.version()));
    std::fs::write(&sums_path, &sums)?;
    let signature_path = assets_dir.join(format!(
        "{}_{}_SHA256SUMS.sig",
        repo.name(),
        plan.tag.version()
    ));
    let mut gpg = ProcessCommand::new("gpg");
    gpg.args([
        "--batch",
        "--pinentry-mode",
        "loopback",
        "--passphrase-fd",
        "0",
        "--local-user",
    ])
    .arg(env("GPG_FINGERPRINT")?)
    .arg("--output")
    .arg(&signature_path)
    .arg("--detach-sign")
    .arg(&sums_path)
    .stdin(Stdio::piped())
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    let mut child = gpg.spawn().context("start checksum signing")?;
    let passphrase = std::env::var("GPG_PASSPHRASE").unwrap_or_default();
    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "{passphrase}")?;
    }
    let result = child.wait_with_output()?;
    ensure!(result.status.success(), "checksum signing failed");
    ensure!(
        signature_path.metadata()?.len() > 0,
        "signing produced an empty signature"
    );
    ensure!(
        plan.assets
            .iter()
            .all(|asset| assets_dir.join(&asset.name).is_file()),
        "signed bundle is incomplete"
    );
    plan.assets.push(PlannedAsset {
        name: sums_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("invalid checksum filename")?
            .to_owned(),
        sha256: sha256_file(&sums_path)?,
    });
    plan.assets.push(PlannedAsset {
        name: signature_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("invalid signature filename")?
            .to_owned(),
        sha256: sha256_file(&signature_path)?,
    });
    plan.validate()?;
    validate_signed_provider_assets(&assets_dir, &plan)?;
    write_json(input.join("plan.json"), &plan)?;
    Ok(())
}

fn publish() -> Result<()> {
    let api = GitHub::from_env("GH_TOKEN")?;
    let read = GitHub::from_env("GITHUB_TOKEN")?;
    let policy = current_policy(&read)?;
    let _runtime = require_current_runtime(&read, ".github/workflows/release.yml")?;
    let input = PathBuf::from("release-package");
    let assets_dir = input.join("assets");
    let plan: ReleasePlanV2 = serde_json::from_slice(&std::fs::read(input.join("plan.json"))?)?;
    plan.validate()?;
    ensure!(
        plan.server_revision == policy.revision,
        "publish plan is stale"
    );
    let repo = Repository::parse(&plan.repository)?;
    let repo_policy = policy.repository(repo.as_str())?;
    repo_policy.require(Capability::Release)?;
    ensure!(
        repo_policy.release == Some(plan.strategy),
        "release strategy changed after preflight"
    );
    let manifest = validated_source(&read, &policy, &repo, plan.source_run_id, plan.strategy)?;
    ensure!(
        manifest.release_pr_number == plan.release_pr_number
            && manifest.release_pr_sha.as_str() == plan.release_pr_sha
            && manifest.tag == plan.tag,
        "publish plan no longer matches authorized source"
    );
    ensure_immutable_releases_enabled(&api, &repo)?;
    let tag_ref: Value = api.get(&format!(
        "/repos/{}/git/ref/tags/{}",
        repo.as_str(),
        url_encode(plan.tag.as_str())
    ))?;
    ensure!(
        tag_ref["object"]["type"] == "tag",
        "release tag is not annotated"
    );
    let tag_object: Value = api.get(&format!(
        "/repos/{}/git/tags/{}",
        repo.as_str(),
        tag_ref["object"]["sha"]
            .as_str()
            .context("tag ref lacks SHA")?
    ))?;
    ensure!(
        tag_object["object"]["sha"] == plan.release_pr_sha,
        "release tag moved after preflight"
    );
    let existing = find_release(&api, &repo, &plan.tag)?;
    if let (Some(expected_id), Some(current)) = (plan.release_id, existing.as_ref()) {
        ensure!(
            current["id"].as_u64() == Some(expected_id),
            "release identity changed after preflight"
        );
    }
    let release = match existing {
        Some(release) => {
            ensure!(
                release["draft"] == true || release["immutable"] == true,
                "existing published release is not immutable"
            );
            release
        }
        None => {
            let repository: Value = api.get(&format!("/repos/{}", repo.as_str()))?;
            let default_branch = repository["default_branch"]
                .as_str()
                .context("release repository default branch missing")?;
            api.post(&format!("/repos/{}/releases", repo.as_str()), &json!({"tag_name":plan.tag.as_str(),"name":plan.tag.as_str(),"generate_release_notes":true,"prerelease":!plan.tag.version().split('-').nth(1).unwrap_or_default().is_empty(),"draft":true,"target_commitish":default_branch}))?
        }
    };
    let release_id = release["id"]
        .as_u64()
        .context("release response lacks ID")?;
    if plan.strategy == ReleaseStrategy::TerraformProvider {
        ensure!(
            plan.assets.len() == PROVIDER_TARGETS.len() + 3,
            "signed provider asset set is incomplete"
        );
        validate_signed_provider_assets(&assets_dir, &plan)?;
        let published_assets: Vec<Value> = api.paginate(&format!(
            "/repos/{}/releases/{release_id}/assets",
            repo.as_str()
        ))?;
        if release["draft"] == false {
            validate_release_asset_state(&plan.assets, &published_assets, true)?;
            ensure_published_immutable_release(&release, release_id, &plan.tag)?;
            return Ok(());
        }
        validate_release_asset_state(&plan.assets, &published_assets, false)?;
        for asset in &plan.assets {
            let path = assets_dir.join(&asset.name);
            ensure!(
                path.is_file() && sha256_file(&path)? == asset.sha256,
                "publish asset digest mismatch: {}",
                asset.name
            );
            if let Some(existing) = published_assets
                .iter()
                .find(|published| published["name"] == asset.name)
            {
                let digest = format!("sha256:{}", asset.sha256);
                ensure!(
                    existing["digest"] == digest,
                    "release asset already exists with different bytes: {}",
                    asset.name
                );
                continue;
            }
            let upload_url = format!(
                "https://uploads.github.com/repos/{}/releases/{release_id}/assets?name={}",
                repo.as_str(),
                url_encode(&asset.name)
            );
            api.upload(
                &upload_url,
                std::fs::read(path)?,
                "application/octet-stream",
            )?;
        }
    }
    if release["draft"] == true {
        let _: Value = api.patch(
            &format!("/repos/{}/releases/{release_id}", repo.as_str()),
            &json!({"draft":false}),
        )?;
    }
    let published: Value = api.get(&format!("/repos/{}/releases/{release_id}", repo.as_str()))?;
    ensure_published_immutable_release(&published, release_id, &plan.tag)?;
    Ok(())
}

fn ensure_immutable_releases_enabled(api: &GitHub, repo: &Repository) -> Result<()> {
    let setting: Value = api.get(&format!("/repos/{}/immutable-releases", repo.as_str()))?;
    ensure!(
        setting["enabled"] == true,
        "immutable releases are disabled for {}",
        repo.as_str()
    );
    Ok(())
}

fn ensure_published_immutable_release(
    release: &Value,
    expected_id: u64,
    tag: &ReleaseTag,
) -> Result<()> {
    ensure!(
        release["id"].as_u64() == Some(expected_id),
        "published release identity changed"
    );
    ensure!(
        release["tag_name"] == tag.as_str(),
        "published release tag changed"
    );
    ensure!(release["draft"] == false, "release remains a draft");
    ensure!(
        release["immutable"] == true,
        "published release is not immutable"
    );
    Ok(())
}

fn validate_release_asset_state(
    expected: &[PlannedAsset],
    existing: &[Value],
    require_complete: bool,
) -> Result<()> {
    let expected: std::collections::BTreeMap<_, _> = expected
        .iter()
        .map(|asset| (asset.name.as_str(), asset.sha256.as_str()))
        .collect();
    let mut found = BTreeSet::new();
    for asset in existing {
        let name = asset["name"]
            .as_str()
            .context("existing release asset lacks name")?;
        let digest = expected
            .get(name)
            .with_context(|| format!("release contains an unexpected asset: {name}"))?;
        ensure!(
            asset["digest"] == format!("sha256:{digest}"),
            "release asset already exists with different bytes: {name}"
        );
        ensure!(found.insert(name), "duplicate release asset: {name}");
    }
    if require_complete {
        ensure!(
            found.len() == expected.len(),
            "published immutable release is missing an expected asset"
        );
    }
    Ok(())
}

fn validate_signed_provider_assets(directory: &Path, plan: &ReleasePlanV2) -> Result<()> {
    let repository = Repository::parse(&plan.repository)?;
    let project = repository.name();
    let mut expected = provider_asset_names(&plan.tag, project);
    let sums_name = format!("{project}_{}_SHA256SUMS", plan.tag.version());
    let signature_name = format!("{sums_name}.sig");
    expected.insert(sums_name.clone());
    expected.insert(signature_name.clone());
    let mut found = BTreeSet::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        ensure!(
            entry.file_type()?.is_file(),
            "signed provider asset directory contains a non-file"
        );
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("provider asset name is not UTF-8"))?;
        ensure!(
            expected.contains(&name) && found.insert(name.clone()),
            "signed provider bundle has unexpected or duplicate asset {name}"
        );
        ensure!(
            entry.metadata()?.len() > 0 && entry.metadata()?.len() <= MAX_PROVIDER_ARCHIVE_BYTES,
            "signed provider asset has invalid size"
        );
        if name.ends_with(".zip") {
            validate_provider_archive(&entry.path(), &name, &plan.tag, project)?;
        }
    }
    ensure!(found == expected, "signed provider asset set is incomplete");
    let planned = plan
        .assets
        .iter()
        .map(|asset| asset.name.as_str())
        .collect::<BTreeSet<_>>();
    let expected_names = expected.iter().map(String::as_str).collect::<BTreeSet<_>>();
    ensure!(
        planned == expected_names,
        "signed plan asset names do not match the canonical set"
    );
    for asset in &plan.assets {
        ensure!(
            sha256_file(&directory.join(&asset.name))? == asset.sha256,
            "signed asset digest mismatch: {}",
            asset.name
        );
    }
    let mut sums = String::new();
    for name in provider_asset_names(&plan.tag, project) {
        sums.push_str(&format!(
            "{}  {}\n",
            sha256_file(&directory.join(&name))?,
            name
        ));
    }
    ensure!(
        std::fs::read_to_string(directory.join(sums_name))? == sums,
        "checksum file does not match provider assets"
    );
    Ok(())
}

fn cleanup() -> Result<()> {
    let api = GitHub::from_env("GITHUB_TOKEN")?;
    let _runtime = require_current_runtime(&api, ".github/workflows/release.yml")?;
    let event = crate::event()?;
    let Some(label) = event["label"]["name"].as_str() else {
        return Ok(());
    };
    if !label.starts_with("release-request-") {
        return Ok(());
    }
    let server_repository = &crate::config::trusted()?.deployment.server.repository;
    let path = format!("/repos/{server_repository}/labels/{}", url_encode(label));
    match api.delete(&path) {
        Ok(()) => Ok(()),
        Err(error)
            if error
                .downcast_ref::<ApiError>()
                .is_some_and(|api_error| api_error.status == reqwest::StatusCode::NOT_FOUND) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

pub fn provider_asset_names(tag: &ReleaseTag, project: &str) -> BTreeSet<String> {
    let mut files = PROVIDER_TARGETS
        .iter()
        .map(|target| {
            format!(
                "{project}_{}_{}_{}.zip",
                tag.version(),
                target.os,
                target.arch
            )
        })
        .collect::<BTreeSet<_>>();
    files.insert(format!("{project}_{}_manifest.json", tag.version()));
    files
}

pub fn validate_asset_directory(
    directory: &Path,
    tag: &ReleaseTag,
    project: &str,
) -> Result<Vec<PathBuf>> {
    let expected = provider_asset_names(tag, project);
    let mut found = BTreeSet::new();
    for entry in std::fs::read_dir(directory).context("read provider asset directory")? {
        let entry = entry.context("read provider asset entry")?;
        let metadata = entry.file_type().context("inspect provider asset entry")?;
        if !metadata.is_file() || metadata.is_symlink() {
            bail!("provider asset directory may contain regular files only");
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("provider asset filename is not UTF-8"))?;
        if !expected.contains(&name) {
            bail!("unexpected provider asset: {name}");
        }
        if !found.insert(name.clone()) {
            bail!("duplicate provider asset: {name}");
        }
        let size = entry
            .metadata()
            .context("inspect provider asset size")?
            .len();
        if size == 0 || size > MAX_PROVIDER_ARCHIVE_BYTES {
            bail!("provider asset has an invalid size: {name}");
        }
        if name.ends_with(".zip") {
            validate_provider_archive(&entry.path(), &name, tag, project)?;
        }
    }
    if found != expected {
        let missing = expected.difference(&found).cloned().collect::<Vec<_>>();
        bail!(
            "provider asset set is incomplete; missing: {}",
            missing.join(", ")
        );
    }
    Ok(found.into_iter().map(|name| directory.join(name)).collect())
}

fn validate_provider_archive(
    path: &Path,
    archive_name: &str,
    tag: &ReleaseTag,
    project: &str,
) -> Result<()> {
    let file = std::fs::File::open(path).context("open provider archive")?;
    let mut zip = zip::ZipArchive::new(file).context("read provider archive")?;
    ensure!(
        zip.len() == 4 && zip.len() <= MAX_PROVIDER_ARCHIVE_FILES,
        "provider archive must contain exactly four files: {archive_name}"
    );
    let expected_binary = format!(
        "{project}_v{}{}",
        tag.version(),
        if archive_name.contains("_windows_") {
            ".exe"
        } else {
            ""
        }
    );
    let mut found = BTreeSet::new();
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).context("read provider archive entry")?;
        let name = entry.name().to_owned();
        let path = Path::new(&name);
        if path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
            || name.contains('\\')
            || entry.is_dir()
        {
            bail!("provider archive contains an invalid entry path: {name}");
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            bail!("provider archive contains a symbolic link: {name}");
        }
        let declared_size = entry.size();
        if declared_size > MAX_PROVIDER_ARCHIVE_BYTES {
            bail!("provider archive entry is too large: {name}");
        }
        let copied = std::io::copy(
            &mut entry.by_ref().take(MAX_PROVIDER_ARCHIVE_BYTES + 1),
            &mut std::io::sink(),
        )?;
        ensure!(
            copied == declared_size,
            "provider archive entry size or checksum is invalid: {name}"
        );
        ensure!(
            [
                "CHANGELOG.md",
                "LICENSE",
                "README.md",
                expected_binary.as_str()
            ]
            .contains(&name.as_str())
                && found.insert(name.clone()),
            "provider archive contains an unexpected or duplicate file: {name}"
        );
    }
    ensure!(
        found
            == [
                "CHANGELOG.md",
                "LICENSE",
                "README.md",
                expected_binary.as_str()
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "provider archive lacks required files: {archive_name}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_rejects_path_injection() {
        assert!(Repository::parse("civitaspo/terraform-provider-sigma").is_ok());
        assert!(Repository::parse("civitaspo/../secrets").is_err());
        assert!(Repository::parse("civitaspo/terraform-provider-sigma/extra").is_err());
    }

    #[test]
    fn release_tag_requires_prefixed_semver() {
        assert_eq!(
            ReleaseTag::parse("v0.0.1-pre.1").unwrap().version(),
            "0.0.1-pre.1"
        );
        assert!(ReleaseTag::parse("0.0.1").is_err());
        assert!(ReleaseTag::parse("v01.0.0").is_err());
    }

    #[test]
    fn manifest_requires_supported_version_and_identifiers() {
        let valid = ReleaseManifestV2 {
            schema_version: 2,
            repository: "civitaspo/terraform-provider-sigma".into(),
            source_run_id: RunId(7),
            source_revision: CommitSha::parse(&"a".repeat(40)).unwrap(),
            release_pr_number: 8,
            release_pr_sha: CommitSha::parse(&"b".repeat(40)).unwrap(),
            tag: ReleaseTag::parse("v1.2.3").unwrap(),
            source_run_sha: CommitSha::parse(&"c".repeat(40)).unwrap(),
            run_attempt: 1,
            artifact_id: Some(9),
        };
        assert!(valid.validate().is_ok());
        let mut wrong_schema = valid.clone();
        wrong_schema.schema_version = 1;
        assert!(wrong_schema.validate().is_err());
        let mut zero_artifact = valid;
        zero_artifact.artifact_id = Some(0);
        assert!(zero_artifact.validate().is_err());
    }

    #[test]
    fn release_plan_is_bound_to_its_verified_source_manifest() {
        let source_manifest = ReleaseManifestV2 {
            schema_version: 2,
            repository: "civitaspo/example".into(),
            source_run_id: RunId(7),
            source_run_sha: CommitSha::parse(&"a".repeat(40)).unwrap(),
            run_attempt: 1,
            source_revision: CommitSha::parse(&"b".repeat(40)).unwrap(),
            release_pr_number: 8,
            release_pr_sha: CommitSha::parse(&"c".repeat(40)).unwrap(),
            tag: ReleaseTag::parse("v1.2.3").unwrap(),
            artifact_id: None,
        };
        let plan = ReleasePlanV2 {
            schema_version: 2,
            server_revision: "d".repeat(40),
            repository: source_manifest.repository.clone(),
            strategy: ReleaseStrategy::GithubRelease,
            source_run_id: source_manifest.source_run_id,
            source_run_attempt: source_manifest.run_attempt,
            source_revision: source_manifest.source_revision.as_str().to_owned(),
            release_pr_number: source_manifest.release_pr_number,
            release_pr_sha: source_manifest.release_pr_sha.as_str().to_owned(),
            tag: source_manifest.tag.clone(),
            source_manifest: source_manifest.clone(),
            release_id: None,
            assets: Vec::new(),
        };
        assert!(plan.validate().is_ok());
        let mut tampered = plan;
        tampered.release_pr_sha = "e".repeat(40);
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn sigma_asset_names_are_fixed_and_versioned() {
        let names = provider_asset_names(
            &ReleaseTag::parse("v1.2.3").unwrap(),
            "terraform-provider-sigma",
        );
        assert_eq!(PROVIDER_TARGETS.len(), 13);
        assert!(names.contains("terraform-provider-sigma_1.2.3_manifest.json"));
        assert!(names.contains("terraform-provider-sigma_1.2.3_linux_amd64.zip"));
        assert!(!names.contains("terraform-provider-sigma_1.2.3_darwin_arm.zip"));
    }

    #[test]
    fn provider_archives_reject_path_traversal_and_extra_files() {
        let dir = tempfile::tempdir().unwrap();
        let tag = ReleaseTag::parse("v1.2.3").unwrap();
        let archive_path = dir.path().join("provider.zip");
        let mut archive = zip::ZipWriter::new(std::fs::File::create(&archive_path).unwrap());
        archive
            .start_file("../escape", zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"bad").unwrap();
        archive.finish().unwrap();
        assert!(
            validate_provider_archive(
                &archive_path,
                "terraform-provider-sigma_1.2.3_linux_amd64.zip",
                &tag,
                "terraform-provider-sigma"
            )
            .is_err()
        );

        let mut archive = zip::ZipWriter::new(std::fs::File::create(&archive_path).unwrap());
        archive
            .start_file(
                "terraform-provider-sigma_v1.2.3",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        archive.write_all(b"provider").unwrap();
        archive
            .start_file("README.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"extra").unwrap();
        archive.finish().unwrap();
        assert!(
            validate_provider_archive(
                &archive_path,
                "terraform-provider-sigma_1.2.3_linux_amd64.zip",
                &tag,
                "terraform-provider-sigma"
            )
            .is_err()
        );
    }

    #[test]
    fn provider_archive_preserves_registry_four_file_contract() {
        let dir = tempfile::tempdir().unwrap();
        let tag = ReleaseTag::parse("v1.2.3").unwrap();
        let binary = dir.path().join("provider");
        std::fs::write(&binary, b"provider").unwrap();
        let docs = dir.path().join("docs");
        std::fs::create_dir(&docs).unwrap();
        for name in ["CHANGELOG.md", "LICENSE", "README.md"] {
            std::fs::write(docs.join(name), format!("{name} contents")).unwrap();
        }
        let archive_path = dir.path().join("provider.zip");
        write_provider_zip(
            &binary,
            "terraform-provider-sigma_v1.2.3",
            &docs,
            &archive_path,
        )
        .unwrap();
        validate_provider_archive(
            &archive_path,
            "terraform-provider-sigma_1.2.3_darwin_arm64.zip",
            &tag,
            "terraform-provider-sigma",
        )
        .unwrap();
        let mut archive = zip::ZipArchive::new(std::fs::File::open(archive_path).unwrap()).unwrap();
        let names = (0..archive.len())
            .map(|index| archive.by_index(index).unwrap().name().to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            [
                "CHANGELOG.md",
                "LICENSE",
                "README.md",
                "terraform-provider-sigma_v1.2.3",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
    }

    #[test]
    fn release_request_requires_client_app_bot_sender_before_parsing() {
        let trusted = crate::config::trusted().unwrap();
        let event = json!({
            "sender": {"id":trusted.client_bot_id,"type":"Bot"},
            "label": {
                "name":"release-request-42",
                "description":"civitaspo/terraform-provider-sigma/42"
            }
        });
        assert_eq!(request_parts(&event).unwrap().1, RunId(42));
        let mut spoofed = event.clone();
        spoofed["sender"]["id"] = json!(123);
        assert!(request_parts(&spoofed).is_err());
        let mut human = event;
        human["sender"]["type"] = json!("User");
        assert!(request_parts(&human).is_err());
    }

    #[test]
    fn release_caller_workflow_paths_are_confined() {
        assert!(ensure_valid_caller_path(".github/workflows/release-tag.yml").is_ok());
        for path in [
            "../release-tag.yml",
            ".github/workflows/../release.yml",
            ".github/workflows/release.yml@refs/heads/main",
            ".github/workflows/release-tag.yaml",
        ] {
            assert!(ensure_valid_caller_path(path).is_err(), "accepted {path}");
        }
    }

    fn provenance_test_policy() -> Policy {
        let mut policy = Policy::parse(include_bytes!("../policy.json")).unwrap();
        policy.revision = "a".repeat(40);
        policy
    }

    fn provenance_test_manifest() -> ReleaseManifestV2 {
        ReleaseManifestV2 {
            schema_version: 2,
            repository: "civitaspo/terraform-provider-sigma".into(),
            source_run_id: RunId(99),
            source_run_sha: CommitSha::parse(&"b".repeat(40)).unwrap(),
            run_attempt: 1,
            source_revision: CommitSha::parse(&"a".repeat(40)).unwrap(),
            release_pr_number: 55,
            release_pr_sha: CommitSha::parse(&"d".repeat(40)).unwrap(),
            tag: ReleaseTag::parse("v1.2.3").unwrap(),
            artifact_id: None,
        }
    }

    fn successful_pr_provenance_routes(version: &str) -> Vec<crate::fixtures::Route> {
        use crate::fixtures::Route;
        use base64::Engine;
        let trusted = crate::config::trusted().unwrap();
        let repo = "civitaspo/terraform-provider-sigma";
        let server_repository = trusted.deployment.server.repository.as_str();
        let release_branch = trusted.deployment.release_branch.as_str();
        let default_branch = trusted.deployment.server.default_branch.as_str();
        let head = "b".repeat(40);
        let base = "c".repeat(40);
        let merge = "d".repeat(40);
        let workflow = format!(
            "name: Release Tag\non:\n  pull_request:\njobs:\n  tag:\n    uses: {server_repository}/.github/workflows/reusable-release-tag.yml@{}\n",
            "a".repeat(40)
        );
        let content = |path: &str, sha: &str, text: &str| {
            Route::get(
                format!("/repos/{repo}/contents/{path}?ref={sha}"),
                json!({
                    "encoding":"base64",
                    "content":base64::engine::general_purpose::STANDARD.encode(text)
                }),
            )
        };
        vec![
            Route::get(
                format!("/repos/{repo}/actions/runs/99"),
                json!({
                    "name":"Release Tag",
                    "status":"completed",
                    "conclusion":"success",
                    "repository":{"full_name":repo},
                    "head_repository":{"full_name":repo},
                    "head_sha":head,
                    "head_branch":release_branch,
                    "run_attempt":1,
                    "path":".github/workflows/release-tag.yml",
                    "event":"pull_request",
                    "pull_requests":[{"number":115}],
                    "referenced_workflows":[{
                        "path":format!("{server_repository}/.github/workflows/reusable-release-tag.yml@{}", "a".repeat(40)),
                        "sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    }]
                }),
            ),
            Route::get(
                format!("/repos/{repo}"),
                json!({"default_branch":default_branch}),
            ),
            Route::get(
                format!("/repos/{repo}"),
                json!({"default_branch":default_branch}),
            ),
            Route::get(
                format!("/repos/{repo}/pulls/55"),
                json!({
                    "number":55,
                    "merged":true,
                    "merged_at":"2026-01-01T00:00:00Z",
                    "merge_commit_sha":merge,
                    "merged_by":{"id":trusted.server_bot_id,"type":"Bot"},
                    "head":{"ref":release_branch,"sha":head,"repo":{"full_name":repo}},
                    "base":{"ref":default_branch,"sha":base,"repo":{"full_name":repo}}
                }),
            ),
            Route::get(
                format!("/repos/{repo}/issues/55/comments?per_page=100&page=1"),
                json!([{
                    "user":{
                        "id":trusted.server_bot_id,
                        "login":trusted.deployment.server_bot_login,
                        "type":"Bot"
                    },
                    "body":format!("<!-- securefix:v2:owner:{head}:101 -->")
                }]),
            ),
            Route::get(
                format!("/repos/{repo}/compare/{merge}...{default_branch}"),
                json!({"status":"identical"}),
            ),
            content(".release-version", &merge, version),
            Route::get(
                format!("/repos/{repo}/compare/{base}...{default_branch}"),
                json!({"status":"identical"}),
            ),
            content(".github/workflows/release-tag.yml", &base, &workflow),
            Route::get(
                format!("/repos/{repo}/git/ref/tags/v1.2.3"),
                json!({"object":{"type":"tag","sha":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}}),
            ),
            Route::get(
                format!("/repos/{repo}/git/tags/{}", "e".repeat(40)),
                json!({"object":{"type":"commit","sha":merge}}),
            ),
        ]
    }

    #[test]
    fn merged_pr_provenance_uses_default_branch_wrapper_and_verified_version() {
        let api = crate::fixtures::Fixture::new(successful_pr_provenance_routes("1.2.3"));
        let policy = provenance_test_policy();
        let repo = Repository::parse("civitaspo/terraform-provider-sigma").unwrap();
        validate_source_manifest_provenance(
            &api.api,
            &policy,
            &repo,
            &provenance_test_manifest(),
            ReleaseStrategy::GithubRelease,
        )
        .unwrap();
        api.finish();
    }

    #[test]
    fn merged_pr_provenance_rejects_mismatched_version_repository_and_run_sha() {
        let mut wrong_version_routes = successful_pr_provenance_routes("1.2.4");
        wrong_version_routes.truncate(6);
        let api = crate::fixtures::Fixture::new(wrong_version_routes);
        let policy = provenance_test_policy();
        let repo = Repository::parse("civitaspo/terraform-provider-sigma").unwrap();
        assert!(
            validate_source_manifest_provenance(
                &api.api,
                &policy,
                &repo,
                &provenance_test_manifest(),
                ReleaseStrategy::GithubRelease,
            )
            .is_err()
        );
        api.finish();

        for (run_repo, run_sha) in [
            ("civitaspo/other", "b".repeat(40)),
            ("civitaspo/terraform-provider-sigma", "f".repeat(40)),
        ] {
            let api = crate::fixtures::Fixture::new(vec![crate::fixtures::Route::get(
                "/repos/civitaspo/terraform-provider-sigma/actions/runs/99",
                json!({
                    "name":"Release Tag",
                    "status":"completed",
                    "conclusion":"success",
                    "repository":{"full_name":run_repo},
                    "head_repository":{"full_name":run_repo},
                    "head_sha":run_sha,
                    "run_attempt":1
                }),
            )]);
            assert!(
                validate_source_manifest_provenance(
                    &api.api,
                    &policy,
                    &repo,
                    &provenance_test_manifest(),
                    ReleaseStrategy::GithubRelease,
                )
                .is_err()
            );
            api.finish();
        }
    }

    #[test]
    fn draft_release_recovery_accepts_only_matching_expected_assets() {
        let expected = vec![
            PlannedAsset {
                name: "one.zip".into(),
                sha256: "a".repeat(64),
            },
            PlannedAsset {
                name: "two.zip".into(),
                sha256: "b".repeat(64),
            },
        ];
        let partial = vec![json!({"name":"one.zip","digest":format!("sha256:{}", "a".repeat(64))})];
        assert!(validate_release_asset_state(&expected, &partial, false).is_ok());
        assert!(validate_release_asset_state(&expected, &partial, true).is_err());
        let mismatch =
            vec![json!({"name":"one.zip","digest":format!("sha256:{}", "c".repeat(64))})];
        assert!(validate_release_asset_state(&expected, &mismatch, false).is_err());
        let unexpected =
            vec![json!({"name":"extra.zip","digest":format!("sha256:{}", "a".repeat(64))})];
        assert!(validate_release_asset_state(&expected, &unexpected, false).is_err());
    }

    #[test]
    fn immutable_release_preflight_fails_closed_before_release_writes() {
        use crate::fixtures::{Fixture, Route};

        let repo = Repository::parse("civitaspo/terraform-provider-sigma").unwrap();
        let api = Fixture::new(vec![Route::get(
            "/repos/civitaspo/terraform-provider-sigma/immutable-releases",
            json!({"enabled":false}),
        )]);
        assert!(ensure_immutable_releases_enabled(&api.api, &repo).is_err());
        api.finish();
    }

    #[test]
    fn immutable_release_preflight_fails_closed_on_github_disabled_response() {
        use crate::fixtures::{Fixture, Route};

        let repo = Repository::parse("civitaspo/terraform-provider-sigma").unwrap();
        let api = Fixture::new(vec![Route::request(
            "GET",
            "/repos/civitaspo/terraform-provider-sigma/immutable-releases",
            404,
            json!({"message":"Not Found"}),
        )]);
        assert!(ensure_immutable_releases_enabled(&api.api, &repo).is_err());
        api.finish();
    }

    #[test]
    fn immutable_release_preflight_accepts_enabled_setting() {
        use crate::fixtures::{Fixture, Route};

        let repo = Repository::parse("civitaspo/terraform-provider-sigma").unwrap();
        let api = Fixture::new(vec![Route::get(
            "/repos/civitaspo/terraform-provider-sigma/immutable-releases",
            json!({"enabled":true,"enforced_by_owner":false}),
        )]);
        ensure_immutable_releases_enabled(&api.api, &repo).unwrap();
        api.finish();
    }

    #[test]
    fn post_publish_verification_rejects_a_mutable_release() {
        use crate::fixtures::{Fixture, Route};

        let tag = ReleaseTag::parse("v1.2.3").unwrap();
        let api = Fixture::new(vec![Route::get(
            "/repos/civitaspo/terraform-provider-sigma/releases/42",
            json!({"id":42,"tag_name":"v1.2.3","draft":false,"immutable":false}),
        )]);
        let published: Value = api
            .api
            .get("/repos/civitaspo/terraform-provider-sigma/releases/42")
            .unwrap();
        assert!(ensure_published_immutable_release(&published, 42, &tag).is_err());
        api.finish();
    }
}
