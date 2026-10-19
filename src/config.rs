//! Deployment identities come only from the trusted runtime's policy files.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::OnceLock};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub repository: String,
    pub id: u64,
    pub default_branch: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub login: String,
    pub id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Checks {
    pub status_app_id: u64,
    pub policy_app_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub server: Repository,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub workflow_prefix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_repository: Option<Repository>,
    pub owner_login: String,
    pub repository_owner: Principal,
    pub client_app_id: u64,
    pub server_app_id: u64,
    pub client_bot_login: String,
    pub server_bot_login: String,
    pub approval_reviewer: Principal,
    pub checks: Checks,
    pub integration: Repository,
    pub release_branch: String,
    pub runtime_update_branch: String,
}

impl Deployment {
    pub fn label_prefix(&self, prefix: &str) -> String {
        format!("{}{prefix}", self.workflow_prefix)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.workflow_prefix.as_str(), "" | "testing-"),
            "workflow prefix must be empty or testing-"
        );
        for repository in [&self.server, &self.integration] {
            crate::policy::validate_repository(&repository.repository)?;
            ensure!(repository.id > 0, "repository ID must be nonzero");
            validate_branch(&repository.default_branch)?;
            ensure!(
                repository.repository.split('/').next()
                    == Some(self.repository_owner.login.as_str()),
                "repository owner differs from configured account"
            );
        }
        ensure!(
            self.server.id != self.integration.id
                && self.server.repository != self.integration.repository,
            "integration repository must differ from production server"
        );
        if let Some(control) = &self.control_repository {
            ensure!(
                self.workflow_prefix == "testing-" && control == &self.integration,
                "separate control storage must be the exact configured test repository in the testing namespace"
            );
        }
        ensure!(
            self.client_app_id > 0
                && self.server_app_id > 0
                && self.client_app_id != self.server_app_id,
            "invalid App identities"
        );
        ensure!(
            self.checks.status_app_id > 0 && self.checks.policy_app_id == self.server_app_id,
            "required check App does not match the server App"
        );
        ensure!(
            self.repository_owner.id > 0 && self.approval_reviewer.id > 0,
            "configured principal IDs must be nonzero"
        );
        for login in [
            &self.owner_login,
            &self.repository_owner.login,
            &self.client_bot_login,
            &self.server_bot_login,
            &self.approval_reviewer.login,
        ] {
            ensure!(
                !login.is_empty()
                    && login.len() <= 100
                    && login
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_[].".contains(&b)),
                "invalid configured login"
            );
        }
        validate_branch(&self.release_branch)?;
        validate_branch(&self.runtime_update_branch)?;
        ensure!(
            self.release_branch != self.server.default_branch
                && self.runtime_update_branch != self.server.default_branch,
            "automation branch cannot be the server default branch"
        );
        Ok(())
    }

    /// Descriptor state may be isolated without changing workflow/source authority.
    pub fn control_repository(&self) -> &Repository {
        self.control_repository.as_ref().unwrap_or(&self.server)
    }

    /// Map a canonical expected path, never an observed source-run path.
    pub fn workflow_path(&self, canonical: &str) -> Result<String> {
        ensure!(
            matches!(self.workflow_prefix.as_str(), "" | "testing-"),
            "workflow prefix must be empty or testing-"
        );
        let name = canonical
            .strip_prefix(".github/workflows/")
            .context("canonical workflow path must be under .github/workflows")?;
        let stem = name
            .strip_suffix(".yml")
            .context("canonical workflow path must end in .yml")?;
        ensure!(
            !stem.is_empty()
                && stem
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)),
            "invalid canonical workflow name"
        );
        let prefix = if name.starts_with("testing-") {
            ""
        } else {
            &self.workflow_prefix
        };
        Ok(format!(".github/workflows/{prefix}{name}"))
    }

    /// Render a canonical workflow definition while preserving pin comments.
    /// This is for generated definitions, never for normalizing run evidence.
    pub fn render_workflow(&self, source: &str) -> Result<String> {
        if self.workflow_prefix.is_empty() {
            return Ok(source.to_owned());
        }
        ensure!(
            self.workflow_prefix == "testing-",
            "invalid workflow prefix"
        );
        let yaml: serde_yaml::Value = serde_yaml::from_str(source)?;
        let name = yaml["name"].as_str().context("workflow name missing")?;
        let names = source
            .lines()
            .filter(|line| line.starts_with("name:"))
            .count();
        ensure!(names == 1, "workflow name source anchor is ambiguous");
        let name = if name.starts_with("testing-") {
            name.to_owned()
        } else {
            format!("testing-{name}")
        };
        let mut rendered = String::new();
        for line in source.split_inclusive('\n') {
            if line.starts_with("name:") {
                rendered.push_str(&format!("name: {}", serde_json::to_string(&name)?));
                if line.ends_with('\n') {
                    rendered.push('\n');
                }
            } else {
                rendered.push_str(line);
            }
        }
        // Preserve literal pins and comments; external workflow authorities are
        // not part of this deployment's namespace.
        let mut output = String::new();
        let mut remaining = rendered.as_str();
        while let Some(start) = remaining.find(".github/workflows/") {
            let before = &remaining[..start];
            let external = before.ends_with('/')
                && !before.ends_with("./")
                && !before.ends_with(&format!("{}/", self.server.repository));
            output.push_str(&remaining[..start]);
            remaining = &remaining[start..];
            let rest = &remaining[".github/workflows/".len()..];
            let length = rest
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || b"-_.".contains(b))
                .count();
            ensure!(
                external || !rest[length..].starts_with('/'),
                "workflow reference is not a canonical file path"
            );
            let path_length = ".github/workflows/".len() + length;
            let path = &remaining[..path_length];
            if path.ends_with(".yml") && !external {
                output.push_str(&self.workflow_path(path)?);
            } else {
                output.push_str(path);
            }
            remaining = &remaining[path_length..];
        }
        output.push_str(remaining);
        Ok(output)
    }
}

pub fn workflow_path(canonical: &str) -> Result<String> {
    trusted()?.deployment.workflow_path(canonical)
}

pub fn validate_branch(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 255
            && !value.starts_with('/')
            && !value.ends_with('/')
            && !value.contains(['\\', ':', '?', '#', '%', '@', '~', '^', '*', '['])
            && !value.bytes().any(|b| b.is_ascii_control() || b == b' ')
            && !value.contains("..")
            && value.split('/').all(|p| !p.is_empty()
                && !p.starts_with('.')
                && !p.ends_with('.')
                && !p.ends_with(".lock")),
        "invalid configured branch"
    );
    Ok(())
}

#[derive(Debug, Clone)]
pub struct TrustedConfig {
    pub owner_id: u64,
    pub client_bot_id: u64,
    pub server_bot_id: u64,
    pub renovate_merge_bot: Option<Principal>,
    pub deployment: Deployment,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenovateMergePolicy {
    #[serde(default)]
    renovate_merge_bot: Option<Principal>,
}

fn renovate_merge_policy(bytes: &[u8]) -> Result<Option<Principal>> {
    ensure!(bytes.len() <= 1024, "Renovate merge policy is oversized");
    Ok(serde_json::from_slice::<RenovateMergePolicy>(bytes)?.renovate_merge_bot)
}

static TRUSTED: OnceLock<std::result::Result<(TrustedConfig, Vec<u8>), String>> = OnceLock::new();

fn path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("SECUREFIX_POLICY_PATH") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(test)]
    return Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/policy.json"));
    #[cfg(not(test))]
    Ok(std::env::current_exe()?
        .parent()
        .context("runtime executable has no directory")?
        .join("policy.json"))
}

fn loaded() -> Result<&'static (TrustedConfig, Vec<u8>)> {
    TRUSTED
        .get_or_init(|| {
            (|| {
                let path = path()?;
                let bytes = std::fs::read(&path)
                    .with_context(|| format!("read trusted policy {}", path.display()))?;
                // This source-bound policy is embedded in the attested binary.
                // Keep policy.json readable by the predecessor controller that
                // validates a successor before activating its new authority.
                let policy = crate::policy::Policy::parse(&bytes)?.with_renovate_merge_bot(
                    renovate_merge_policy(include_bytes!("renovate_merge_policy.json"))?,
                )?;
                Ok((
                    TrustedConfig {
                        owner_id: policy.owner_id,
                        client_bot_id: policy.client_bot_id,
                        server_bot_id: policy.server_bot_id,
                        renovate_merge_bot: policy.renovate_merge_bot,
                        deployment: policy.deployment,
                    },
                    bytes,
                ))
            })()
            .map_err(|error: anyhow::Error| format!("{error:#}"))
        })
        .as_ref()
        .map_err(|error| anyhow::anyhow!("{error}"))
}

pub fn trusted() -> Result<&'static TrustedConfig> {
    Ok(&loaded()?.0)
}
pub fn trusted_policy_bytes() -> Result<Vec<u8>> {
    Ok(loaded()?.1.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_workflow_namespace_preserves_pins_and_is_idempotent() {
        let mut deployment = crate::config::trusted().unwrap().deployment.clone();
        deployment.server.repository = "owner/server".into();
        let source = "# source comment\nname: Merge Request\non: workflow_dispatch\njobs:\n  runtime:\n    uses: ./.github/workflows/load-cli.yml\n  request:\n    uses: owner/server/.github/workflows/reusable-merge-request.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v0.2.33\n";
        assert_eq!(deployment.render_workflow(source).unwrap(), source);
        deployment.workflow_prefix = "testing-".into();
        let rendered = deployment.render_workflow(source).unwrap();
        assert!(rendered.starts_with("# source comment\nname: \"testing-Merge Request\"\n"));
        assert!(rendered.contains("./.github/workflows/testing-load-cli.yml"));
        assert!(rendered.contains("owner/server/.github/workflows/testing-reusable-merge-request.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v0.2.33"));
        assert_eq!(deployment.render_workflow(&rendered).unwrap(), rendered);
        let external = "name: External\njobs:\n  baseline:\n    uses: other/server/.github/workflows/publish-runtime.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # pinned baseline\n";
        assert!(deployment.render_workflow(external).unwrap().contains("other/server/.github/workflows/publish-runtime.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # pinned baseline"));
        assert!(deployment.render_workflow("jobs: {}\n").is_err());
        assert!(
            deployment
                .render_workflow("name: one\nname: two\njobs: {}\n")
                .is_err()
        );
        assert!(
            deployment
                .render_workflow(
                    "name: Invalid\njobs:\n  bad:\n    uses: ./.github/workflows/../merge.yml\n"
                )
                .is_err()
        );
    }

    #[test]
    fn separate_control_storage_preserves_the_workflow_host_and_reviewer() {
        let mut deployment =
            crate::policy::Policy::parse(include_bytes!("../tests/fixtures/policy.json"))
                .unwrap()
                .deployment;
        let original = deployment.clone();
        assert_eq!(deployment.control_repository(), &deployment.server);
        assert!(
            serde_json::to_value(&deployment)
                .unwrap()
                .get("control_repository")
                .is_none()
        );
        deployment.control_repository = Some(deployment.integration.clone());
        assert!(deployment.validate().is_err());
        deployment.workflow_prefix = "testing-".into();
        deployment.validate().unwrap();
        assert_eq!(deployment.control_repository(), &deployment.integration);
        assert_eq!(deployment.server, original.server);
        assert_eq!(deployment.approval_reviewer, original.approval_reviewer);
        for field in ["repository", "id", "default_branch"] {
            let mut altered = serde_json::to_value(&deployment).unwrap();
            altered["control_repository"][field] = match field {
                "id" => serde_json::json!(123),
                "repository" => serde_json::json!("civitaspo/other-test"),
                _ => serde_json::json!("other"),
            };
            assert!(
                serde_json::from_value::<Deployment>(altered)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        deployment.control_repository = Some(original.server);
        assert!(deployment.validate().is_err());
    }

    #[test]
    fn workflow_namespace_is_one_exact_trusted_deployment_choice() {
        let mut deployment =
            crate::policy::Policy::parse(include_bytes!("../tests/fixtures/policy.json"))
                .unwrap()
                .deployment;
        assert!(deployment.workflow_prefix.is_empty());
        assert!(
            serde_json::to_value(&deployment)
                .unwrap()
                .get("workflow_prefix")
                .is_none()
        );
        let canonical = ".github/workflows/merge-caller-migration.yml";
        assert_eq!(deployment.workflow_path(canonical).unwrap(), canonical);
        for label in [
            "approve-request-7",
            "merge-request-7",
            "policy-request-7",
            "release-request-7",
            "securefix-7-abcd",
        ] {
            assert_eq!(deployment.label_prefix(label), label);
        }
        deployment.workflow_prefix = "testing-".into();
        deployment.validate().unwrap();
        for (label, testing_label) in [
            ("approve-request-7", "testing-approve-request-7"),
            ("merge-request-7", "testing-merge-request-7"),
            ("policy-request-7", "testing-policy-request-7"),
            ("release-request-7", "testing-release-request-7"),
            ("securefix-7-abcd", "testing-securefix-7-abcd"),
        ] {
            assert_eq!(deployment.label_prefix(label), testing_label);
        }
        assert_eq!(
            deployment.workflow_path(canonical).unwrap(),
            ".github/workflows/testing-merge-caller-migration.yml"
        );
        assert_ne!(deployment.workflow_path(canonical).unwrap(), canonical);
        let existing = ".github/workflows/testing-securefix-server.yml";
        assert_eq!(deployment.workflow_path(existing).unwrap(), existing);
        for invalid in ["test-", "../", "testing-/", "Testing-", "testing-\n"] {
            deployment.workflow_prefix = invalid.into();
            assert!(deployment.validate().is_err());
            assert!(deployment.workflow_path(canonical).is_err());
        }
    }

    #[test]
    fn expected_workflow_mapping_rejects_paths_refs_and_traversal() {
        let deployment =
            crate::policy::Policy::parse(include_bytes!("../tests/fixtures/policy.json"))
                .unwrap()
                .deployment;
        for invalid in [
            "merge.yml",
            ".github/workflows/../merge.yml",
            ".github/workflows/nested/merge.yml",
            ".github/workflows/merge.yml@main",
            ".github/workflows/merge.yml?ref=main",
            ".github/workflows/.yml",
        ] {
            assert!(deployment.workflow_path(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn embedded_renovate_policy_is_optional_strict_and_separate_from_base_policy() {
        assert!(renovate_merge_policy(b"{}").unwrap().is_none());
        assert!(
            renovate_merge_policy(br#"{"renovate_merge_bot":null}"#)
                .unwrap()
                .is_none()
        );
        for invalid in [
            br#"{"extra":true}"#.as_slice(),
            br#"{"renovate_merge_bot":{"id":43,"login":"updater[bot]","extra":true}}"#,
            &[b' '; 1025],
        ] {
            assert!(renovate_merge_policy(invalid).is_err());
        }
        let policy = crate::policy::Policy::parse(include_bytes!("../policy.json")).unwrap();
        assert!(policy.renovate_merge_bot.is_none());
        let bot = renovate_merge_policy(include_bytes!("renovate_merge_policy.json")).unwrap();
        let configured = policy.with_renovate_merge_bot(bot.clone()).unwrap();
        assert_eq!(configured.renovate_merge_bot, bot);
        assert!(
            serde_json::to_value(configured)
                .unwrap()
                .get("renovate_merge_bot")
                .is_none()
        );
    }
}
