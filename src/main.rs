use anyhow::{Context, Result, bail};
use binwalk::Binwalk;
use std::{env, fs};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let [_, filepath] = args.as_slice() else {
        bail!("Expected two arguments.\nUsage: fwx <filepath>")
    };

    let firmware = fs::read(filepath).with_context(|| format!("reading {filepath}"))?;

    let binwalker = Binwalk::new();
    let findings = binwalker.scan(&firmware);

    if findings.is_empty() {
        println!("No known signatures found.");
        return Ok(());
    }

    for finding in &findings {
        // size is 0 when the signature parser can't determine a length
        let size = if finding.size > 0 {
            format!(" ({} bytes)", finding.size)
        } else {
            String::new()
        };
        println!("0x{:08X}  {}{}", finding.offset, finding.description, size);
    }

    Ok(())
}
