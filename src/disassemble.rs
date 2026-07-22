use capstone::prelude::*;
use object::{Architecture, Endianness, Object};
use std::io;

fn detect_arch(firmware: &[u8]) -> Option<(Architecture, Endianness)> {
    let file = object::File::parse(firmware).ok()?;
    Some((file.architecture(), file.endianness()))
}

fn build_capstone(archv: Architecture, endian: Endianness) -> Result<Capstone, &'static str> {
    let big = matches!(endian, Endianness::Big);

    let cs = match archv {
        Architecture::X86_64 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build(),
        Architecture::I386 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .detail(true)
            .build(),

        Architecture::Aarch64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build(),
        Architecture::Arm => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .endian(if big {
                arch::Endian::Big
            } else {
                arch::Endian::Little
            })
            .detail(true)
            .build(),

        Architecture::Mips64 => Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips64)
            .endian(if big {
                arch::Endian::Big
            } else {
                arch::Endian::Little
            })
            .detail(true)
            .build(),
        Architecture::Mips => Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips32)
            .endian(if big {
                arch::Endian::Big
            } else {
                arch::Endian::Little
            })
            .detail(true)
            .build(),

        Architecture::PowerPc64 => Capstone::new()
            .ppc()
            .mode(arch::ppc::ArchMode::Mode64)
            .detail(true)
            .build(),
        Architecture::Riscv64 => Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV64)
            .detail(true)
            .build(),
        Architecture::Riscv32 => Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV32)
            .detail(true)
            .build(),

        _ => return Err("unsupported architecture"),
    };

    cs.map_err(|_| "failed to initialize capstone")
}

pub fn disassembler(firmware: &[u8], base_addr: u64) -> Vec<(u64, String, String, String)> {
    let (archv, end) = match detect_arch(firmware) {
        Some(pair) => pair,
        None => {
            println!(
                "architecture could not be identified\nplease specify the firmware's architecture and endianness"
            );
            // TODO: take user input for arch and end and parse it to Architecture and Endianness objects
            return Vec::new();
        }
    };

    let cs = match build_capstone(archv, end) {
        Ok(cs) => cs,
        Err(e) => {
            println!("disassembly unavailable: {e}");
            return Vec::new();
        }
    };

    let insns = match cs.disasm_all(firmware, base_addr) {
        Ok(insns) => insns,
        Err(_) => return Vec::new(),
    };

    insns
        .iter()
        .map(|i| {
            let addr = i.address();
            let bytes = i
                .bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            let mnem = i.mnemonic().unwrap_or("").to_string();
            let ops = i.op_str().unwrap_or("").to_string();
            (addr, bytes, mnem, ops)
        })
        .collect()
}
