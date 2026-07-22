use binwalk::{Binwalk, extractors::common::ExtractionResult, signatures::common::SignatureResult};
use std::collections::HashMap;

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
) -> HashMap<String, ExtractionResult> {
    let x_binwalker = Binwalk::configure(
        Some(filepath),
        Some(String::from("./extracted")),
        None,
        None,
        None,
        false,
    )
    .expect("failed to configure binwalk");

    x_binwalker.extract(firmware, &x_binwalker.base_target_file, findings)
}
