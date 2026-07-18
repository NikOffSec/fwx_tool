pub struct Magic {
    pub filetype: FileType,
    // [offset, bytes]
    pub patterns: &'static [(usize, &'static [u8])],
    pub validate: Option<fn(data: &[u8], off: usize) -> bool>,
}

pub const MAGIC_NUMBERS: &[Magic] = &[
    // Boot images
    Magic {
        filetype: FileType::UBootUImage,
        patterns: &[(0, &[0x27, 0x05, 0x19, 0x56])],
        validate: None,
    },
    Magic {
        filetype: FileType::DeviceTreeBlob,
        // Note: FIT images share this same magic; distinguish via validate
        patterns: &[(0, &[0xd0, 0x0d, 0xfe, 0xed])],
        validate: None,
    },
    Magic {
        filetype: FileType::AndroidBoot,
        patterns: &[(0, b"ANDROID!")],
        validate: None,
    },
    Magic {
        filetype: FileType::BroadcomTrx,
        patterns: &[(0, b"HDR0")],
        validate: None,
    },
    // Record Formats
    Magic {
        filetype: FileType::IntelHex,
        patterns: &[(0, &[0x3a])],
        validate: None,
    },
    Magic {
        filetype: FileType::SRecord,
        patterns: &[(0, b"S0"), (0, b"S1"), (0, b"S3")],
        validate: None,
    },
    // Compression
    Magic {
        filetype: FileType::Gzip,
        patterns: &[(0, &[0x1f, 0x8b, 0x08])],
        validate: None,
    },
    Magic {
        filetype: FileType::Zlib,
        patterns: &[
            (0, &[0x78, 0x01]), // no/low compression
            (0, &[0x78, 0x5e]), // fast compression
            (0, &[0x78, 0x9c]), // default compression
            (0, &[0x78, 0xda]), // best compression
        ],
        validate: None,
    },
    Magic {
        filetype: FileType::Bzip2,
        patterns: &[(0, &[0x42, 0x5a, 0x68])],
        validate: None,
    },
    Magic {
        filetype: FileType::Xz,
        patterns: &[(0, &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])],
        validate: None,
    },
    Magic {
        filetype: FileType::Lzma,
        patterns: &[(0, &[0x5d, 0x00, 0x00, 0x80, 0x00])],
        validate: None,
    },
    Magic {
        filetype: FileType::Lz4,
        patterns: &[(0, &[0x04, 0x22, 0x4d, 0x18])],
        validate: None,
    },
    Magic {
        filetype: FileType::Lzop,
        patterns: &[(0, &[0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a])],
        validate: None,
    },
    Magic {
        filetype: FileType::Zstd,
        patterns: &[(0, &[0x28, 0xb5, 0x2f, 0xfd])],
        validate: None,
    },
    //  Filesystems
    Magic {
        filetype: FileType::SquashFs,
        patterns: &[
            (0, b"hsqs"), // little-endian
            (0, b"sqsh"), // big-endian
            (0, b"shsq"), // LZMA variant (DD-WRT)
            (0, b"qshs"), // LZMA variant alt
        ],
        validate: None,
    },
    Magic {
        filetype: FileType::CramFs,
        patterns: &[
            (0, &[0x45, 0x3d, 0xcd, 0x28]), // little-endian
            (0, &[0x28, 0xcd, 0x3d, 0x45]), // big-endian
        ],
        validate: None,
    },
    Magic {
        filetype: FileType::Ext,
        patterns: &[(0x438, &[0x53, 0xef])],
        validate: None,
    },
    Magic {
        filetype: FileType::Iso9660,
        patterns: &[(0x8001, b"CD001")],
        validate: None,
    },
    // Archives
    Magic {
        filetype: FileType::Tar,
        patterns: &[
            (257, b"ustar\x00"), // POSIX
            (257, b"ustar "),    // GNU
        ],
        validate: None,
    },
    Magic {
        filetype: FileType::Zip,
        patterns: &[
            (0, &[0x50, 0x4b, 0x03, 0x04]), // local file header
            (0, &[0x50, 0x4b, 0x05, 0x06]), // end of central dir
            (0, &[0x50, 0x4b, 0x07, 0x08]), // spanned archive
        ],
        validate: None,
    },
    Magic {
        filetype: FileType::SevenZ,
        patterns: &[(0, &[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])],
        validate: None,
    },
    Magic {
        filetype: FileType::Cpio,
        patterns: &[
            (0, b"070701"),     // newc (no CRC)
            (0, b"070702"),     // newc (CRC)
            (0, &[0xc7, 0x71]), // binary little-endian
            (0, &[0x71, 0xc7]), // binary big-endian
        ],
        validate: None,
    },
    Magic {
        filetype: FileType::Ar,
        patterns: &[(0, b"!<arch>\n")],
        validate: None,
    },
    // Executables
    Magic {
        filetype: FileType::Elf,
        patterns: &[(0, &[0x7f, 0x45, 0x4c, 0x46])],
        validate: None,
    },
    Magic {
        filetype: FileType::PeCoff,
        patterns: &[(0, &[0x4d, 0x5a])],
        validate: None,
    },
    Magic {
        filetype: FileType::MachO,
        patterns: &[
            (0, &[0xfe, 0xed, 0xfa, 0xce]), // 32-bit BE
            (0, &[0xce, 0xfa, 0xed, 0xfe]), // 32-bit LE
            (0, &[0xfe, 0xed, 0xfa, 0xcf]), // 64-bit BE
            (0, &[0xcf, 0xfa, 0xed, 0xfe]), // 64-bit LE
        ],
        validate: None,
    },
    Magic {
        filetype: FileType::MachOUniversal,
        patterns: &[
            (0, &[0xca, 0xfe, 0xba, 0xbe]),
            (0, &[0xbe, 0xba, 0xfe, 0xca]),
        ],
        validate: None,
    },
    // Keys
    Magic {
        filetype: FileType::DerAsn1,
        patterns: &[(0, &[0x30, 0x82])],
        validate: None,
    },
    Magic {
        filetype: FileType::Pem,
        patterns: &[(0, b"-----BEGIN ")],
        validate: None,
    },
];

pub struct Finding {
    pub filetype: FileType,
    pub offset: usize, // Offset in file, not filetype specific
}

pub fn identify(data: &[u8], offset: usize) -> Option<FileType> {
    for magic in MAGIC_NUMBERS {
        for &(pat_off, pattern) in magic.patterns {
            let start = offset.checked_add(pat_off)?;
            let end = start.checked_add(pattern.len())?;
            if data.get(start..end) == Some(pattern) {
                let valid = magic.validate.map_or(true, |check| check(data, offset));
                if valid {
                    return Some(magic.filetype);
                }
            }
        }
    }
    None
}

use std::fmt;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    // Boot / firmware images
    UBootUImage,
    DeviceTreeBlob,
    AndroidBoot,
    BroadcomTrx,
    // Record formats
    IntelHex,
    SRecord,
    // Compression
    Gzip,
    Zlib,
    Bzip2,
    Xz,
    Lzma,
    Lz4,
    Lzop,
    Zstd,
    // Filesystems
    SquashFs,
    CramFs,
    Jffs2,
    UbiEc,
    Ubifs,
    RomFs,
    Ext,
    Iso9660,
    // Archives
    Tar,
    Zip,
    SevenZ,
    Cpio,
    Ar,
    // Executables
    Elf,
    PeCoff,
    MachO,
    MachOUniversal,
    // Certificates / keys
    DerAsn1,
    Pem,
}

pub enum Category {
    Firmware,
    Record,
    Compression,
    Filesystem,
    Archive,
    Executable,
    Crypto,
}

impl FileType {
    pub fn category(self) -> Category {
        use FileType::*;
        match self {
            UBootUImage | DeviceTreeBlob | AndroidBoot | BroadcomTrx => Category::Firmware,
            IntelHex | SRecord => Category::Record,
            Gzip | Zlib | Bzip2 | Xz | Lzma | Lz4 | Lzop | Zstd => Category::Compression,
            SquashFs | CramFs | Jffs2 | UbiEc | Ubifs | RomFs | Ext | Iso9660 => {
                Category::Filesystem
            }
            Tar | Zip | SevenZ | Cpio | Ar => Category::Archive,
            Elf | PeCoff | MachO | MachOUniversal => Category::Executable,
            DerAsn1 | Pem => Category::Crypto,
        }
    }
}

impl FileType {
    pub fn is_weak_signature(&self) -> bool {
        use FileType::*;
        matches!(
            self,
            DerAsn1
                | IntelHex
                | SRecord
                | Zlib
                | Lzma
                | Jffs2
                | Gzip
                | Tar
                | Ext
                | PeCoff
                | Zip
                | Cpio
                | Lz4
                | Zstd
                | SquashFs
                | CramFs
                | BroadcomTrx
                | UBootUImage
                | DeviceTreeBlob
                | MachO
        )
    }
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FileType::*;
        let name = match self {
            UBootUImage => "U-Boot uImage",
            DeviceTreeBlob => "Flattened Device Tree Blob (FDTB)",
            AndroidBoot => "Android boot image",
            BroadcomTrx => "Broadcom TRX",
            IntelHex => "Intel HEX",
            SRecord => "Motorola S-Record",
            Gzip => "gzip",
            Zlib => "zlib",
            Bzip2 => "bzip2",
            Xz => "xz",
            Lzma => "LZMA",
            Lz4 => "LZ4",
            Lzop => "LZOP",
            Zstd => "Zstandard",
            SquashFs => "SquashFS",
            CramFs => "CRAMFS",
            Jffs2 => "JFFS2",
            UbiEc => "UBI EC header",
            Ubifs => "UBIFS",
            RomFs => "ROMFS",
            Ext => "ext2/3/4",
            Iso9660 => "ISO 9660",
            Tar => "tar",
            Zip => "zip",
            SevenZ => "7z",
            Cpio => "cpio",
            Ar => "AR archive",
            Elf => "ELF",
            PeCoff => "PE/COFF",
            MachO => "Mach-O",
            MachOUniversal => "Mach-O Universal Binary",
            DerAsn1 => "DER/ASN.1",
            Pem => "PEM",
        };
        write!(f, "{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_gzip_at_offset() {
        let mut blob = vec![0u8; 64];
        blob.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00]);
        assert_eq!(identify(&blob, 64), Some(FileType::Gzip));
    }

    #[test]
    fn ext_magic_is_offset_relative() {
        let mut blob = vec![0u8; 0x500];
        blob[0x438] = 0x53;
        blob[0x439] = 0xef;
        assert_eq!(identify(&blob, 0), Some(FileType::Ext));
    }

    #[test]
    fn display_matches_old_strings() {
        assert_eq!(FileType::SquashFs.to_string(), "SquashFS");
        assert_eq!(
            FileType::DeviceTreeBlob.to_string(),
            "Flattened Device Tree Blob (FDTB)"
        );
    }

    #[test]
    fn unsupported_extraction_is_an_error() {
        let err = FileType::Pem.extract(&[], 0).unwrap_err();
        assert!(matches!(err, ExtractError::Unsupported(FileType::Pem)));
    }
}
