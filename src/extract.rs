use anyhow::{Result, bail};
use binwalk::{Binwalk, extractors::common::ExtractionResult, signatures::common::SignatureResult};
use std::collections::HashMap;
use std::path::Path;

const EXTRACT_DIR: &str = "./extracted";

pub fn scan(firmware: &[u8]) -> Option<Vec<SignatureResult>> {
    let binwalker = Binwalk::new();
    let findings = binwalker.scan(firmware);
    if findings.is_empty() {
        println!("No known signatures found.");
        return None;
    }
    Some(findings)
}

pub fn unpack(
    filepath: String,
    firmware: &[u8],
    findings: &Vec<SignatureResult>,
) -> Result<HashMap<String, ExtractionResult>> {
    // Binwalk does not error when its output directory already exists; it just
    // writes into it, silently merging/overwriting whatever a previous run left
    // behind. Refuse up front so an earlier extraction can't be clobbered
    // without the user knowing.
    if Path::new(EXTRACT_DIR).exists() {
        bail!(
            "output directory `{EXTRACT_DIR}` already exists; \
             move or remove it before extracting again"
        );
    }

    let x_binwalker = Binwalk::configure(
        Some(filepath),
        Some(EXTRACT_DIR.to_string()),
        None,
        None,
        None,
        false,
    )
    .map_err(|e| anyhow::anyhow!("failed to configure binwalk: {e:?}"))?;

    Ok(x_binwalker.extract(firmware, &x_binwalker.base_target_file, findings))
}
