pub mod api;
pub mod attestation;
pub mod config;
pub mod control;
#[cfg(test)]
mod fixtures;
pub mod instance_config;
pub mod package;
pub mod policy;
pub mod runtime_archive;
pub mod workflow;

use anyhow::{Result, ensure};
use std::{fs::OpenOptions, io::Write};

pub fn output(name: &str, value: impl AsRef<str>) -> Result<()> {
    let value = value.as_ref();
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "invalid output name"
    );
    ensure!(
        !value.contains(['\r', '\n']),
        "output must be a single line"
    );
    if let Ok(path) = std::env::var("GITHUB_OUTPUT") {
        writeln!(
            OpenOptions::new().append(true).open(path)?,
            "{name}={value}"
        )?;
    } else {
        println!("{name}={value}");
    }
    Ok(())
}

pub fn event() -> Result<serde_json::Value> {
    let path = std::env::var("GITHUB_EVENT_PATH")?;
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

pub fn output_multiline(name: &str, value: &str) -> Result<()> {
    use sha2::{Digest, Sha256};
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "invalid output name"
    );
    ensure!(
        value.len() <= 1024 * 1024 && !value.contains('\r'),
        "invalid multiline output"
    );
    let delimiter = format!(
        "securefix_{}",
        crate::hex_encode(Sha256::digest(value.as_bytes()))
    );
    ensure!(
        !value.lines().any(|line| line == delimiter),
        "multiline output delimiter collision"
    );
    if let Ok(path) = std::env::var("GITHUB_OUTPUT") {
        writeln!(
            OpenOptions::new().append(true).open(path)?,
            "{name}<<{delimiter}\n{value}\n{delimiter}"
        )?;
    } else {
        println!("{name}<<{delimiter}\n{value}\n{delimiter}");
    }
    Ok(())
}

pub fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod hex_tests {
    #[test]
    fn sha256_encoding_preserves_canonical_lowercase_hex() {
        use sha2::{Digest, Sha256};
        assert_eq!(
            super::hex_encode(Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(super::hex_encode([0, 1, 15, 255]), "00010fff");
    }
}
