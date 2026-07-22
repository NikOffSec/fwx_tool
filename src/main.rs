mod disassemble;
mod extract;
mod metadata;
mod ui;

use anyhow::{Context, Result, bail};
use std::{env, fs};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let [_, filepath] = args.as_slice() else {
        bail!("Expected two arguments.\nUsage: fwx <filepath>")
    };

    let firmware = fs::read(filepath).with_context(|| format!("reading {filepath}"))?;

    ui::run(firmware, filepath.clone())
}
