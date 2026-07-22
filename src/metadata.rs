use rust_strings::{BytesConfig, strings};

pub fn extract_strings(firmware: &[u8]) -> Result<Vec<(String, u64)>, Box<dyn std::error::Error>> {
    let config = BytesConfig::new(firmware.to_vec()).with_min_length(4);
    Ok(strings(&config)?)
}

/// Shannon entropy (0.0–8.0 bits) of one block.
fn shannon_entropy(block: &[u8]) -> f64 {
    if block.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in block {
        counts[b as usize] += 1;
    }
    let len = block.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// (offset, entropy) per block.
pub fn entropy_scan(firmware: &[u8], block_size: usize) -> Vec<(usize, f64)> {
    firmware
        .chunks(block_size)
        .enumerate()
        .map(|(i, chunk)| (i * block_size, shannon_entropy(chunk)))
        .collect()
}
