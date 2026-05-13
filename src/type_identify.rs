pub struct Magic {
    pub filetype: &'static str,
    pub patterns: &'static [(usize, &'static [u8])],
    pub validate: Option<fn(data: &[u8], off: usize) -> bool>,
}

static MAGIC_NUMBERS: &[Magic] = &[
    // ──── Boot / Firmware Images ────
    Magic {
        filetype: "U-Boot uImage",
        patterns: &[(0, &[0x27, 0x05, 0x19, 0x56])],
        validate: None,
    },
    Magic {
        filetype: "Flattened Device Tree Blob (FDTB)",
        // Note: FIT images share this same magic; distinguish via validate
        patterns: &[(0, &[0xd0, 0x0d, 0xfe, 0xed])],
        validate: None,
    },
    Magic {
        filetype: "Android boot image",
        patterns: &[(0, b"ANDROID!")],
        validate: None,
    },
    Magic {
        filetype: "Broadcom TRX",
        patterns: &[(0, b"HDR0")],
        validate: None,
    },

    // ──── Record Formats ────
    Magic {
        filetype: "Intel HEX",
        patterns: &[(0, &[0x3a])],
        validate: None,
    },
    Magic {
        filetype: "Motorola S-Record",
        patterns: &[
            (0, b"S0"),
            (0, b"S1"),
            (0, b"S3"),
        ],
        validate: None,
    },

    // ──── Compression ────
    Magic {
        filetype: "gzip",
        patterns: &[(0, &[0x1f, 0x8b, 0x08])],
        validate: None,
    },
    Magic {
        filetype: "zlib",
        patterns: &[
            (0, &[0x78, 0x01]),  // no/low compression
            (0, &[0x78, 0x5e]),  // fast compression
            (0, &[0x78, 0x9c]),  // default compression
            (0, &[0x78, 0xda]),  // best compression
        ],
        validate: None,
    },
    Magic {
        filetype: "bzip2",
        patterns: &[(0, &[0x42, 0x5a, 0x68])],
        validate: None,
    },
    Magic {
        filetype: "xz",
        patterns: &[(0, &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])],
        validate: None,
    },
    Magic {
        filetype: "LZMA",
        patterns: &[(0, &[0x5d, 0x00, 0x00, 0x80, 0x00])],
        validate: None,
    },
    Magic {
        filetype: "LZ4",
        patterns: &[(0, &[0x04, 0x22, 0x4d, 0x18])],
        validate: None,
    },
    Magic {
        filetype: "LZOP",
        patterns: &[(0, &[0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a])],
        validate: None,
    },
    Magic {
        filetype: "Zstandard",
        patterns: &[(0, &[0x28, 0xb5, 0x2f, 0xfd])],
        validate: None,
    },

    // ──── Filesystems ────
    Magic {
        filetype: "SquashFS",
        patterns: &[
            (0, b"hsqs"),                          // little-endian
            (0, b"sqsh"),                          // big-endian
            (0, b"shsq"),                          // LZMA variant (DD-WRT)
            (0, b"qshs"),                          // LZMA variant alt
        ],
        validate: None,
    },
    Magic {
        filetype: "CRAMFS",
        patterns: &[
            (0, &[0x45, 0x3d, 0xcd, 0x28]),       // little-endian
            (0, &[0x28, 0xcd, 0x3d, 0x45]),        // big-endian
        ],
        validate: None,
    },
    Magic {
        filetype: "JFFS2",
        patterns: &[
            (0, &[0x85, 0x19]),                    // little-endian
            (0, &[0x19, 0x85]),                    // big-endian
        ],
        validate: None,
    },
    Magic {
        filetype: "UBI EC header",
        patterns: &[(0, &[0x55, 0x42, 0x49, 0x23])],
        validate: None,
    },
    Magic {
        filetype: "UBIFS",
        patterns: &[(0, &[0x31, 0x18, 0x10, 0x06])],
        validate: None,
    },
    Magic {
        filetype: "ROMFS",
        patterns: &[(0, b"-rom1fs-")],
        validate: None,
    },
    Magic {
        filetype: "ext2/3/4",
        patterns: &[(0x438, &[0x53, 0xef])],
        validate: None,
    },
    Magic {
        filetype: "ISO 9660",
        patterns: &[(0x8001, b"CD001")],
        validate: None,
    },

    // ──── Archives ────
    Magic {
        filetype: "tar",
        patterns: &[
            (257, b"ustar\x00"),                   // POSIX
            (257, b"ustar "),                      // GNU
        ],
        validate: None,
    },
    Magic {
        filetype: "zip",
        patterns: &[
            (0, &[0x50, 0x4b, 0x03, 0x04]),       // local file header
            (0, &[0x50, 0x4b, 0x05, 0x06]),        // end of central dir
            (0, &[0x50, 0x4b, 0x07, 0x08]),        // spanned archive
        ],
        validate: None,
    },
    Magic {
        filetype: "7z",
        patterns: &[(0, &[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])],
        validate: None,
    },
    Magic {
        filetype: "cpio",
        patterns: &[
            (0, b"070701"),                        // newc (no CRC)
            (0, b"070702"),                        // newc (CRC)
            (0, &[0xc7, 0x71]),                    // binary little-endian
            (0, &[0x71, 0xc7]),                    // binary big-endian
        ],
        validate: None,
    },
    Magic {
        filetype: "AR archive",
        patterns: &[(0, b"!<arch>\n")],
        validate: None,
    },

    // ──── Executables ────
    Magic {
        filetype: "ELF",
        patterns: &[(0, &[0x7f, 0x45, 0x4c, 0x46])],
        validate: None,
    },
    Magic {
        filetype: "PE/COFF",
        patterns: &[(0, &[0x4d, 0x5a])],
        validate: None,
    },
    Magic {
        filetype: "Mach-O",
        patterns: &[
            (0, &[0xfe, 0xed, 0xfa, 0xce]),       // 32-bit BE
            (0, &[0xce, 0xfa, 0xed, 0xfe]),        // 32-bit LE
            (0, &[0xfe, 0xed, 0xfa, 0xcf]),        // 64-bit BE
            (0, &[0xcf, 0xfa, 0xed, 0xfe]),        // 64-bit LE
        ],
        validate: None,
    },
    Magic {
        filetype: "Mach-O Universal Binary",
        patterns: &[
            (0, &[0xca, 0xfe, 0xba, 0xbe]),
            (0, &[0xbe, 0xba, 0xfe, 0xca]),
        ],
        validate: None,
    },

    // ──── Certificates / Keys ────
    Magic {
        filetype: "DER/ASN.1",
        patterns: &[(0, &[0x30, 0x82])],
        validate: None,
    },
    Magic {
        filetype: "PEM",
        patterns: &[(0, b"-----BEGIN ")],
        validate: None,
    },
];