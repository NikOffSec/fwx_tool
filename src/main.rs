mod type_identify;
mod verify;

use crate::type_identify::{Finding, identify};
use anyhow::{Context, Result, bail};
use std::{env, fs};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let [_, filepath] = args.as_slice() else {
        bail!("Expected two arguments.\nUsage: fwx <filepath>")
    };

    let firmware = fs::read(filepath).with_context(|| format!("reading {filepath}"))?;

    let identified = scan_image(&firmware);

    Ok(())
}

fn scan_image(image: &[u8]) -> Vec<Finding> {
    let mut detections: Vec<Finding> = Vec::new();
    for (offset, _byte) in image.iter().enumerate() {
        if let Some(filetype) = identify(image, offset) {
            if !filetype.verify_file(&image[offset..]) {
                continue;
            }
            detections.push(Finding { filetype, offset });
        }
    }
    detections
}
