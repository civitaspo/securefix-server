pub mod api;
#[cfg(test)]
mod fixtures;
pub mod policy;
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
