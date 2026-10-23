use anyhow::{Context, Result, bail};
use semver::Version;
use serde::{Deserialize, Serialize};

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
    /// Source package version when it differs from the release tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_version: Option<String>,
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
        if let Some(package_version) = &self.package_version {
            Version::parse(package_version)
                .context("release manifest package version is invalid")?;
        }
        if self.source_run_id.0 == 0
            || self.run_attempt == 0
            || self.release_pr_number == 0
            || self.artifact_id == Some(0)
        {
            bail!("release manifest contains an empty numeric identifier");
        }
        Ok(())
    }

    pub fn package_version(&self) -> &str {
        self.package_version
            .as_deref()
            .unwrap_or_else(|| self.tag.version())
    }
}
