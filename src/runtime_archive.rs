//! Bounded inspection of candidate archives as data; never executes or extracts them.
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeSet, io::Read};

const MAX_ARCHIVE: usize = 128 * 1024 * 1024;
const MAX_UNPACKED: u64 = 512 * 1024 * 1024;
const MAX_MEMBERS: usize = 4096;

pub struct Contents {
    pub policy: Vec<u8>,
    pub binary: Option<Vec<u8>>,
}

pub fn policy(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(contents(bytes)?.policy)
}

pub fn contents(bytes: &[u8]) -> Result<Contents> {
    ensure!(bytes.len() <= MAX_ARCHIVE, "candidate archive is oversized");
    let decoder = flate2::read::MultiGzDecoder::new(bytes);
    let mut bounded = decoder.take(MAX_UNPACKED + MAX_MEMBERS as u64 * 512 + 1024 * 1024 + 1);
    let mut seen = BTreeSet::new();
    let mut policy = None;
    let mut binary = None;
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
            } else if normalized == "securefix" {
                ensure!(
                    kind.is_file() && size > 0 && size <= MAX_ARCHIVE as u64,
                    "candidate archive binary is missing, empty or oversized"
                );
                let mut raw = Vec::new();
                entry
                    .by_ref()
                    .take(MAX_ARCHIVE as u64 + 1)
                    .read_to_end(&mut raw)?;
                ensure!(
                    raw.len() as u64 == size,
                    "candidate archive binary size mismatch"
                );
                binary = Some(raw);
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
    Ok(Contents {
        policy: policy.context("candidate archive is missing policy.json")?,
        binary,
    })
}
