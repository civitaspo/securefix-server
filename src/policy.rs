use crate::api::GitHub;
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use globset::{Glob, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
use std::{collections::HashSet, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    Approve,
    Merge,
    Securefix,
    Release,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseStrategy {
    GithubRelease,
    TerraformProvider,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPolicy {
    pub repository: String,
    pub capabilities: Vec<Capability>,
    pub release: Option<ReleaseStrategy>,
    #[serde(default)]
    pub native_binaries: Vec<NativeBinaryTarget>,
    #[serde(default)]
    pub sensitive_paths: Vec<String>,
    pub protect_tags: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBinaryTarget {
    pub target: String,
    pub runner: String,
}

pub fn validate_native_binary_targets(
    release: Option<ReleaseStrategy>,
    targets: &[NativeBinaryTarget],
) -> Result<()> {
    ensure!(
        targets.is_empty() || release == Some(ReleaseStrategy::GithubRelease),
        "native binaries require the GitHub Release strategy"
    );
    ensure!(targets.len() <= 8, "too many native binary targets");
    let mut native_targets = HashSet::new();
    for target in targets {
        ensure!(
            !target.target.is_empty()
                && target.target.len() <= 80
                && target.target.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'-'
                        || byte == b'_'
                }),
            "invalid native binary target"
        );
        ensure!(
            native_targets.insert(target.target.as_str()),
            "duplicate native binary target"
        );
        ensure!(
            matches!(
                target.runner.as_str(),
                "ubuntu-24.04" | "ubuntu-24.04-arm" | "macos-15" | "macos-15-intel"
            ),
            "unsupported native binary runner"
        );
        let (runner_os, runner_arch) = match target.runner.as_str() {
            "ubuntu-24.04" => ("linux", "x86_64"),
            "ubuntu-24.04-arm" => ("linux", "aarch64"),
            "macos-15" => ("apple-darwin", "aarch64"),
            "macos-15-intel" => ("apple-darwin", "x86_64"),
            _ => unreachable!(),
        };
        let target_os_matches = if runner_os == "linux" {
            target.target.contains("-linux-")
        } else {
            target.target.ends_with("-apple-darwin")
        };
        ensure!(
            target.target.starts_with(&format!("{runner_arch}-")) && target_os_matches,
            "native binary target does not match its runner"
        );
    }
    Ok(())
}

/// Principals allowed to make additional owner-sensitive approvals unnecessary.
/// These identities must still be trusted committers and are authenticated from
/// GitHub's user or Bot response by the request authorization layer.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SensitivePathApprovalExemptions {
    #[serde(default)]
    pub users: Vec<SensitivePathApprovalUser>,
    #[serde(default)]
    pub github_apps: Vec<SensitivePathApprovalGitHubApp>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SensitivePathApprovalUser {
    pub id: u64,
    pub login: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SensitivePathApprovalGitHubApp {
    pub bot_id: u64,
    pub bot_login: String,
}

impl RepositoryPolicy {
    pub fn require(&self, capability: Capability) -> Result<()> {
        ensure!(
            self.capabilities.contains(&capability),
            "operation is not enabled for {}",
            self.repository
        );
        Ok(())
    }

    pub fn sensitive<'a>(&self, paths: impl IntoIterator<Item = &'a str>) -> Result<bool> {
        Ok(!self.matching_sensitive_paths(paths)?.is_empty())
    }

    pub fn matching_sensitive_paths<'a>(
        &self,
        paths: impl IntoIterator<Item = &'a str>,
    ) -> Result<Vec<&'a str>> {
        let mut builder = GlobSetBuilder::new();
        for pattern in &self.sensitive_paths {
            builder.add(Glob::new(pattern)?);
        }
        let patterns = builder.build()?;
        Ok(paths
            .into_iter()
            .filter(|path| patterns.is_match(path))
            .collect())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub deployment: crate::config::Deployment,
    pub owner_id: u64,
    pub client_bot_id: u64,
    pub server_bot_id: u64,
    pub trusted_committers: Vec<String>,
    #[serde(skip)]
    pub renovate_merge_bot: Option<crate::config::Principal>,
    #[serde(default)]
    pub sensitive_path_approval_exemptions: SensitivePathApprovalExemptions,
    pub default_sensitive_paths: Vec<String>,
    pub merge_controls_enabled: bool,
    pub repositories: Vec<RepositoryPolicy>,
    #[serde(skip)]
    pub revision: String,
    #[serde(skip)]
    pub control: Option<crate::control::ControlRevision>,
}

impl Policy {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Self::parse(&std::fs::read(path)?)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 256 * 1024, "policy exceeds size limit");
        let mut policy: Self = serde_json::from_slice(bytes)?;
        ensure!(policy.version == 1, "unsupported policy version");
        policy.deployment.validate()?;
        ensure!(
            policy.owner_id > 0
                && policy.client_bot_id > 0
                && policy.server_bot_id > 0
                && policy.owner_id != policy.client_bot_id
                && policy.owner_id != policy.server_bot_id
                && policy.client_bot_id != policy.server_bot_id,
            "invalid security principals"
        );
        ensure!(
            !policy.trusted_committers.is_empty(),
            "no trusted committers"
        );
        validate_sensitive_path_approval_exemptions(
            &policy.sensitive_path_approval_exemptions,
            &policy.trusted_committers,
        )?;
        ensure!(
            !policy.default_sensitive_paths.is_empty(),
            "missing default sensitive paths"
        );
        let mut names = HashSet::new();
        for repository in &mut policy.repositories {
            if repository.sensitive_paths.is_empty() {
                repository
                    .sensitive_paths
                    .clone_from(&policy.default_sensitive_paths);
            }
            validate_repository(&repository.repository)?;
            ensure!(
                repository.repository.split('/').next()
                    == Some(policy.deployment.repository_owner.login.as_str()),
                "repository must belong to the configured account"
            );
            ensure!(
                names.insert(&repository.repository),
                "duplicate repository policy"
            );
            let capabilities: HashSet<_> = repository.capabilities.iter().collect();
            ensure!(
                capabilities.len() == repository.capabilities.len() && !capabilities.is_empty(),
                "invalid capabilities"
            );
            ensure!(
                repository.release.is_some()
                    == repository.capabilities.contains(&Capability::Release),
                "release strategy/capability mismatch"
            );
            validate_native_binary_targets(repository.release, &repository.native_binaries)?;
            ensure!(
                !repository.sensitive_paths.is_empty(),
                "missing sensitive paths"
            );
            for pattern in &repository.sensitive_paths {
                Glob::new(pattern)?;
            }
        }
        if policy.deployment.control_repository.is_some() {
            ensure!(
                policy.repositories.len() == 1
                    && policy.repositories[0].repository
                        == policy.deployment.integration.repository
                    && !policy.repositories[0]
                        .capabilities
                        .contains(&Capability::Settings),
                "isolated testing policy must grant only test-repository operations without settings authority"
            );
        }
        Ok(policy)
    }

    #[cfg(test)]
    pub(crate) fn with_renovate_merge_bot(
        mut self,
        bot: Option<crate::config::Principal>,
    ) -> Result<Self> {
        if let Some(bot) = &bot {
            ensure!(
                bot.id > 0
                    && ![
                        self.owner_id,
                        self.client_bot_id,
                        self.server_bot_id,
                        self.deployment.approval_reviewer.id
                    ]
                    .contains(&bot.id)
                    && bot.login.ends_with("[bot]")
                    && bot.login.len() <= 100
                    && bot
                        .login
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_[].".contains(&b))
                    && self
                        .trusted_committers
                        .iter()
                        .any(|login| login.eq_ignore_ascii_case(&bot.login)),
                "invalid Renovate merge bot"
            );
        }
        self.renovate_merge_bot = bot;
        Ok(self)
    }

    pub fn active(api: &GitHub) -> Result<Self> {
        let control = crate::control::ControlRevision::require_runtime(api)?;
        let bytes = crate::config::trusted_policy_bytes()?;
        let digest = crate::hex_encode(sha2::Sha256::digest(&bytes));
        ensure!(
            digest == control.policy_sha256,
            "bundled policy digest mismatch"
        );
        let trusted = crate::config::trusted()?;
        let mut policy = Self::parse(&bytes)?;
        ensure!(
            policy.deployment == trusted.deployment
                && policy.owner_id == trusted.owner_id
                && policy.client_bot_id == trusted.client_bot_id
                && policy.server_bot_id == trusted.server_bot_id,
            "active policy identity differs from trusted runtime"
        );
        policy.revision = control.source_sha.clone();
        policy.control = Some(control);
        Ok(policy)
    }
    pub fn repository(&self, full_name: &str) -> Result<&RepositoryPolicy> {
        self.repositories
            .iter()
            .find(|r| r.repository == full_name)
            .with_context(|| format!("repository is not allowed: {full_name}"))
    }
    pub fn latest_revision(api: &GitHub, workflow_path: &str) -> Result<String> {
        let _ = workflow_path;
        Ok(crate::control::ControlRevision::require_runtime(api)?.source_sha)
    }
}

pub(crate) fn validate_sensitive_path_approval_exemptions(
    exemptions: &SensitivePathApprovalExemptions,
    trusted_committers: &[String],
) -> Result<()> {
    let mut ids = HashSet::new();
    let mut logins = HashSet::new();
    for (id, login, is_app) in exemptions
        .users
        .iter()
        .map(|user| (user.id, user.login.as_str(), false))
        .chain(
            exemptions
                .github_apps
                .iter()
                .map(|app| (app.bot_id, app.bot_login.as_str(), true)),
        )
    {
        ensure!(
            id > 0,
            "sensitive-path approval exemption ID must be nonzero"
        );
        ensure!(
            crate::config::is_valid_login(login),
            "invalid sensitive-path approval exemption login"
        );
        ensure!(
            !is_app || login.ends_with("[bot]"),
            "GitHub App exemption login must end with [bot]"
        );
        ensure!(
            ids.insert(id) && logins.insert(login.to_ascii_lowercase()),
            "duplicate sensitive-path approval exemption principal"
        );
        ensure!(
            trusted_committers
                .iter()
                .any(|trusted| trusted.eq_ignore_ascii_case(login)),
            "sensitive-path approval exemption must be a trusted committer"
        );
    }
    Ok(())
}

pub fn validate_repository(value: &str) -> Result<()> {
    let parts: Vec<_> = value.split('/').collect();
    ensure!(
        parts.len() == 2
            && parts.iter().all(|part| !part.is_empty()
                && *part != "."
                && *part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))),
        "invalid repository"
    );
    Ok(())
}

pub fn validate_sha(value: &str) -> Result<()> {
    ensure!(
        value.len() == 40
            && value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid commit SHA"
    );
    Ok(())
}

pub fn latest_revision(api: &GitHub, workflow_path: &str) -> Result<String> {
    ensure!(
        workflow_path.starts_with(".github/workflows/")
            && workflow_path.ends_with(".yml")
            && !workflow_path.contains(".."),
        "invalid reusable workflow path"
    );
    let server = &crate::config::trusted()?.deployment.server;
    let repository: Value = api.get(&format!("/repos/{}", server.repository))?;
    ensure!(
        repository["default_branch"] == server.default_branch
            && repository["id"].as_u64() == Some(server.id),
        "unexpected server default branch"
    );
    let commit: Value = api.get(&format!(
        "/repos/{}/commits/{}",
        server.repository, server.default_branch
    ))?;
    let sha = commit["sha"].as_str().context("missing server revision")?;
    validate_sha(sha)?;
    Ok(sha.to_string())
}

#[derive(Subcommand)]
pub enum Command {
    Validate {
        #[arg(long, default_value = "policy.json")]
        policy: String,
    },
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Validate { policy } => {
            Policy::load(policy)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolated_testing_policy_has_no_production_or_settings_authority() {
        let testing = Policy::parse(include_bytes!("../.github/testing-policy.json")).unwrap();
        let production = Policy::parse(include_bytes!("../policy.json")).unwrap();
        assert_eq!(testing.deployment.server, production.deployment.server);
        assert_eq!(
            testing.deployment.approval_reviewer,
            production.deployment.approval_reviewer
        );
        assert_eq!(
            testing.deployment.control_repository(),
            &testing.deployment.integration
        );
        assert_eq!(testing.repositories.len(), 1);
        let mut policy: Value =
            serde_json::from_slice(include_bytes!("../tests/fixtures/policy.json")).unwrap();
        policy["deployment"]["workflow_prefix"] = serde_json::json!("testing-");
        policy["deployment"]["control_repository"] = policy["deployment"]["integration"].clone();
        assert!(Policy::parse(&serde_json::to_vec(&policy).unwrap()).is_err());
        let repository = policy["deployment"]["integration"]["repository"].clone();
        policy["repositories"] = serde_json::json!([{"repository":repository,"capabilities":["approve","merge","securefix"],"release":null,"protect_tags":false}]);
        Policy::parse(&serde_json::to_vec(&policy).unwrap()).unwrap();
        policy["repositories"][0]["capabilities"] =
            serde_json::json!(["approve", "merge", "securefix", "settings"]);
        assert!(Policy::parse(&serde_json::to_vec(&policy).unwrap()).is_err());
    }

    #[test]
    fn renovate_merge_authority_is_optional_separate_and_trusted() {
        let mut policy = Policy::load("tests/fixtures/policy.json").unwrap();
        assert!(policy.renovate_merge_bot.is_none());
        policy.trusted_committers.push("updater[bot]".into());
        let bot = crate::config::Principal {
            id: 43,
            login: "updater[bot]".into(),
        };
        assert!(policy.clone().with_renovate_merge_bot(Some(bot)).is_ok());
        for (id, login) in [
            (0, "updater[bot]"),
            (policy.owner_id, "updater[bot]"),
            (policy.client_bot_id, "updater[bot]"),
            (policy.server_bot_id, "updater[bot]"),
            (policy.deployment.approval_reviewer.id, "updater[bot]"),
            (43, "untrusted[bot]"),
            (43, "updater"),
        ] {
            assert!(
                policy
                    .clone()
                    .with_renovate_merge_bot(Some(crate::config::Principal {
                        id,
                        login: login.into()
                    }))
                    .is_err(),
                "{id}/{login}"
            );
        }
        let mut value = serde_json::to_value(policy).unwrap();
        value["renovate_merge_bot"] = serde_json::json!({"id":43,"login":"updater[bot]"});
        assert!(Policy::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    #[test]
    fn central_policy_is_exact_and_has_no_duplicate_repositories() {
        let policy = Policy::load("tests/fixtures/policy.json").unwrap();
        assert_eq!(policy.repositories.len(), 9);
        assert!(policy.repository("civitaspo/unlisted").is_err());
        let mut invalid = serde_json::to_value(&policy).unwrap();
        invalid["repositories"][0]["repository"] = Value::String("civitaspo/*".into());
        assert!(Policy::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }

    #[test]
    fn native_binary_release_targets_are_optional_and_repository_specific() {
        let mut value =
            serde_json::to_value(Policy::load("tests/fixtures/policy.json").unwrap()).unwrap();
        let native_index = value["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .position(|repository| repository["repository"] == "civitaspo/herdr-linear-agent")
            .unwrap();
        value["repositories"][native_index]["native_binaries"] = serde_json::json!([
            {"target":"aarch64-apple-darwin", "runner":"macos-15"},
            {"target":"x86_64-apple-darwin", "runner":"macos-15-intel"},
            {"target":"aarch64-unknown-linux-musl", "runner":"ubuntu-24.04-arm"},
            {"target":"x86_64-unknown-linux-musl", "runner":"ubuntu-24.04"}
        ]);
        let configured = Policy::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        let native = &configured
            .repository("civitaspo/herdr-linear-agent")
            .unwrap()
            .native_binaries;
        assert_eq!(
            native,
            &vec![
                NativeBinaryTarget {
                    target: "aarch64-apple-darwin".into(),
                    runner: "macos-15".into(),
                },
                NativeBinaryTarget {
                    target: "x86_64-apple-darwin".into(),
                    runner: "macos-15-intel".into(),
                },
                NativeBinaryTarget {
                    target: "aarch64-unknown-linux-musl".into(),
                    runner: "ubuntu-24.04-arm".into(),
                },
                NativeBinaryTarget {
                    target: "x86_64-unknown-linux-musl".into(),
                    runner: "ubuntu-24.04".into(),
                },
            ]
        );
        assert!(
            configured
                .repository("civitaspo/dbt-authorized-models")
                .unwrap()
                .native_binaries
                .is_empty()
        );
        assert!(
            Policy::load("tests/fixtures/policy.json")
                .unwrap()
                .repositories
                .iter()
                .all(|repository| repository.native_binaries.is_empty())
        );

        value["repositories"][native_index]["native_binaries"][1]["target"] =
            serde_json::json!("aarch64-apple-darwin");
        assert!(Policy::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        value["repositories"][native_index]["native_binaries"][1]["target"] =
            serde_json::json!("x86_64-apple-darwin");
        value["repositories"][native_index]["native_binaries"][1]["runner"] =
            serde_json::json!("ubuntu-24.04");
        assert!(Policy::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn sensitive_paths_cover_code_workflows_and_dependencies() {
        let policy = Policy::load("tests/fixtures/policy.json").unwrap();
        let server = policy
            .repository(&policy.deployment.server.repository)
            .unwrap();
        assert!(server.sensitive(["README.md"]).unwrap());
        let client = policy
            .repository("civitaspo/dbt-authorized-models")
            .unwrap();
        for path in [
            ".github/workflows/ci.yml",
            "Cargo.lock",
            ".goreleaser.yaml",
            ".github/actions/setup/action.yml",
            "build.rs",
            "crates/client/build.rs",
            ".cargo/config.toml",
            "crates/client/.cargo/config.toml",
        ] {
            assert!(client.sensitive([path]).unwrap(), "{path}");
        }
        assert!(
            !client
                .sensitive(["README.md", "models/example.sql"])
                .unwrap()
        );
    }

    #[test]
    fn sensitive_path_approval_exemptions_are_optional_typed_and_trusted() {
        let mut value =
            serde_json::to_value(Policy::load("tests/fixtures/policy.json").unwrap()).unwrap();

        // Older policy documents remain valid and receive an empty exemption list.
        value
            .as_object_mut()
            .unwrap()
            .remove("sensitive_path_approval_exemptions");
        let parsed = Policy::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(parsed.sensitive_path_approval_exemptions.users.is_empty());
        assert!(
            parsed
                .sensitive_path_approval_exemptions
                .github_apps
                .is_empty()
        );

        value["trusted_committers"] =
            serde_json::json!(["maintainer", "automation-reviewer", "example-renovate[bot]"]);
        value["sensitive_path_approval_exemptions"] = serde_json::json!({
            "users": [{"id": 601, "login": "automation-reviewer"}],
            "github_apps": [{"bot_id": 602, "bot_login": "example-renovate[bot]"}]
        });
        let parsed = Policy::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(parsed.sensitive_path_approval_exemptions.users[0].id, 601);
        assert_eq!(
            parsed.sensitive_path_approval_exemptions.github_apps[0].bot_login,
            "example-renovate[bot]"
        );

        for malformed in [
            serde_json::json!({"users": [{"id": 0, "login": "automation-reviewer"}]}),
            serde_json::json!({"github_apps": [{"bot_id": 602, "bot_login": "renovate"}]}),
            serde_json::json!({"users": [{"id": "601", "login": "automation-reviewer"}]}),
            serde_json::json!({"users": [{"id": 601, "login": "untrusted"}]}),
            serde_json::json!({"users": [
                {"id": 601, "login": "automation-reviewer"},
                {"id": 601, "login": "another"}
            ]}),
            serde_json::json!({"github_apps": [
                {"bot_id": 602, "bot_login": "example-renovate[bot]"},
                {"bot_id": 603, "bot_login": "EXAMPLE-RENOVATE[bot]"}
            ]}),
            serde_json::json!({"users": "automation-reviewer"}),
        ] {
            let mut invalid = value.clone();
            invalid["sensitive_path_approval_exemptions"] = malformed.clone();
            assert!(
                Policy::parse(&serde_json::to_vec(&invalid).unwrap()).is_err(),
                "accepted malformed exemptions: {malformed}"
            );
        }
    }

    #[test]
    fn alternate_deployment_requires_no_personal_identities() {
        let mut value =
            serde_json::to_value(Policy::load("tests/fixtures/policy.json").unwrap()).unwrap();
        value["owner_id"] = 101.into();
        value["client_bot_id"] = 202.into();
        value["server_bot_id"] = 303.into();
        let deployment = &mut value["deployment"];
        deployment["server"] = serde_json::json!({"repository":"example-org/controller","id":404,"default_branch":"trunk"});
        deployment["integration"] = serde_json::json!({"repository":"example-org/sandbox","id":405,"default_branch":"trunk"});
        deployment["repository_owner"] = serde_json::json!({"login":"example-org","id":406});
        deployment["owner_login"] = "maintainer".into();
        deployment["client_app_id"] = 501.into();
        deployment["server_app_id"] = 502.into();
        deployment["client_bot_login"] = "example-client[bot]".into();
        deployment["server_bot_login"] = "example-server[bot]".into();
        deployment["approval_reviewer"] = serde_json::json!({"login":"reviewer","id":601});
        deployment["checks"] = serde_json::json!({"status_app_id":701,"policy_app_id":502});
        deployment["release_branch"] = "releases/candidate".into();
        deployment["runtime_update_branch"] = "automation/runtime".into();
        value["trusted_committers"] = serde_json::json!(["maintainer", "example-server[bot]"]);
        value["repositories"] = serde_json::json!([{"repository":"example-org/project","capabilities":["approve","merge","securefix","release"],"release":"github-release","protect_tags":true}]);
        let parsed = Policy::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(parsed.repository("example-org/project").is_ok());
        for (field, invalid) in [
            ("server_app_id", serde_json::json!(501)),
            ("integration", value["deployment"]["server"].clone()),
            ("runtime_update_branch", serde_json::json!("trunk")),
            ("release_branch", serde_json::json!("bad^branch")),
        ] {
            let mut malformed = value.clone();
            malformed["deployment"][field] = invalid;
            assert!(
                Policy::parse(&serde_json::to_vec(&malformed).unwrap()).is_err(),
                "{field}"
            );
        }
        value["repositories"][0]["repository"] = "other-org/project".into();
        assert!(Policy::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}
