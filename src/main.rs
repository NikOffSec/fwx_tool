mod disassemble;
mod extract;
mod metadata;

use anyhow::{Context, Result, bail};
use std::{env, fs};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let [_, filepath] = args.as_slice() else {
        bail!("Expected two arguments.\nUsage: fwx <filepath>")
    };

    let firmware = fs::read(filepath).with_context(|| format!("reading {filepath}"))?;
    println!("== Loaded firmware ==");
    println!("path: {filepath}");
    println!("size: {} bytes\n", firmware.len());

    println!("== Signature scan (extract::scan) ==");
    let findings = extract::scan(&firmware);
    match &findings {
        Some(sigs) => {
            println!("{} signature(s) found:", sigs.len());
            for sig in sigs {
                println!(
                    "  offset=0x{:x} size={} name={} desc={}",
                    sig.offset, sig.size, sig.name, sig.description
                );
            }
        }
        None => println!("(no findings)"),
    }
    println!();

    println!("== Extraction (extract::unpack) ==");
    match &findings {
        Some(sigs) => {
            let results = extract::unpack(filepath.clone(), &firmware, sigs);
            if results.is_empty() {
                println!("(nothing extracted)");
            } else {
                println!("{} extraction result(s):", results.len());
                for (key, res) in &results {
                    println!("  {key} -> {res:?}");
                }
            }
        }
        None => println!("(skipped: no signatures to extract)"),
    }
    println!();

    println!("== Strings (metadata::extract_strings) ==");
    match metadata::extract_strings(&firmware) {
        Ok(strs) => {
            println!("{} string(s) found. First 20:", strs.len());
            for (s, off) in strs.iter().take(20) {
                println!("  0x{off:x}: {s}");
            }
        }
        Err(e) => println!("error extracting strings: {e}"),
    }
    println!();

    println!("== Entropy scan (metadata::entropy_scan) ==");
    const BLOCK_SIZE: usize = 1024;
    let entropy = metadata::entropy_scan(&firmware, BLOCK_SIZE);
    println!(
        "{} block(s) of {BLOCK_SIZE} bytes. First 20:",
        entropy.len()
    );
    for (off, e) in entropy.iter().take(20) {
        println!("  0x{off:x}: {e:.4} bits");
    }
    if !entropy.is_empty() {
        let avg: f64 = entropy.iter().map(|(_, e)| e).sum::<f64>() / entropy.len() as f64;
        println!("average entropy: {avg:.4} bits");
    }
    println!();

    println!("== Disassembler == ");
    let listing = disassemble::disassembler(&firmware);
    for instruction in listing {
        println!("{:?}", instruction);
    }

    Ok(())
}
