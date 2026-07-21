// CRC helpers

fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    crc
}

fn crc32(data: &[u8]) -> u32 {
    crc32_update(0xFFFF_FFFF, data) ^ 0xFFFF_FFFF
}

fn crc32_jffs2(data: &[u8]) -> u32 {
    crc32_update(0, data)
}

// parsing helpers

fn hex_swap(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// for Intel HEX and Motorola S Record
fn hex_byte(s: &[u8], i: usize) -> Option<u8> {
    Some(hex_swap(*s.get(2 * i)?)? << 4 | hex_swap(*s.get(2 * i + 1)?)?)
}

fn u16_le(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*d.get(o)?, *d.get(o + 1)?]))
}

fn u16_be(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(o)?, *d.get(o + 1)?]))
}

fn u32_le(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *d.get(o)?,
        *d.get(o + 1)?,
        *d.get(o + 2)?,
        *d.get(o + 3)?,
    ]))
}

fn u32_be(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *d.get(o)?,
        *d.get(o + 1)?,
        *d.get(o + 2)?,
        *d.get(o + 3)?,
    ]))
}

fn u64_le(d: &[u8], o: usize) -> Option<u64> {
    let lo = u32_le(d, o)? as u64;
    let hi = u32_le(d, o + 4)? as u64;
    Some(hi << 32 | lo)
}

// verify functions

// Magic == 1F 8B, CM (BYTE 2) == 8 (deflate) and FLG (BYTE 3) bits 5-7 == 0
pub fn gzip(data: &[u8]) -> bool {
    data.len() >= 10 && data[0] == 0x1F && data[1] == 0x8B && data[2] == 0x08 && data[3] & 0xE0 == 0
}

// Two header bytes CMF and FLG: (CMF * 256 + FLG) MUST be divisible by 31
// CM == 8 (deflate) and CINFO <= 7 (max format allows)
pub fn zlib(data: &[u8]) -> bool {
    let (Some(&cmf), Some(&flg)) = (data.first(), data.get(1)) else {
        return false;
    };
    cmf & 0x0F == 8 && cmf >> 4 <= 7 && (u16::from(cmf) * 256 + u16::from(flg)) == 0
}

/// header: props byte, u32 LE dictionary size, u64 LE uncompressed size.
/// props = lc + lp*9 + pb*45 with lc<=8, lp<=4, pb<=4, so props < 225.
/// (The common default 0x5D encodes lc=3, lp=0, pb=2.)
/// Dictionary sizes in real files are 4 KiB … 512 MiB.
/// Uncompressed size is either the sentinel `u64::MAX` ("unknown,
///   streamed") or something plausibly small (< 16 GiB here).
pub fn lzma(data: &[u8]) -> bool {
    let (Some(&props), Some(dict), Some(usize_field)) =
        (data.first(), u32_le(data, 1), u64_le(data, 5))
    else {
        return false;
    };
    props < 225
        && (0x1000..=0x2000_0000).contains(&dict)
        && (usize_field == u64::MAX || usize_field < 1 << 34)
}

/// FLG bits 7–6 (version) must be `01`; bit 1 is reserved-zero.
/// BD bit 7 and bits 3–0 are reserved-zero;
/// bits 6–4 (block max size) may only be 4..=7 (64 KB … 4 MB).
pub fn lz4(data: &[u8]) -> bool {
    let (Some(&flg), Some(&bd)) = (data.get(4), data.get(5)) else {
        return false;
    };
    data.len() >= 7
        && data[..4] == [0x04, 0x22, 0x4D, 0x18]
        && flg >> 6 == 0b01
        && flg & 0b0000_0010 == 0
        && bd & 0b1000_1111 == 0
        && (4..=7).contains(&(bd >> 4 & 0b111))
}

/// Frame_Header_Descriptor bit 3 is reserved and must be 0.
/// If Single_Segment isn't set, a Window_Descriptor follows whose
/// implied window log (10 + exponent) must be within the format's maximum of 41.
pub fn zstd(data: &[u8]) -> bool {
    let Some(&fhd) = data.get(4) else {
        return false;
    };
    if data[..4] != [0x28, 0xB5, 0x2F, 0xFD] || fhd & 0b0000_1000 != 0 {
        return false;
    }
    if fhd & 0b0010_0000 != 0 {
        return true;
    }
    let Some(&wd) = data.get(5) else { return false };
    10 + u32::from(wd >> 3) <= 41
}

/// POSIX tars have "ustar" at 257 and pre-POSIX tars have nothing
/// tar header has a checksum field at bytes 148..156: the unsigned sum of all 512 header
/// bytes with the checksum field itself counted as ASCII spaces, stored as octal text
pub fn tar(data: &[u8]) -> bool {
    let Some(hdr) = data.get(..512) else {
        return false;
    };
    if &hdr[257..262] != b"ustar" {
        return false;
    }
    let Some(stored) = parse_octal(&hdr[148..156]) else {
        return false;
    };
    let sum: u32 = hdr
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                0x20
            } else {
                u32::from(b)
            }
        })
        .sum();
    sum == stored
}

/// Helper for tar octal checksum
fn parse_octal(field: &[u8]) -> Option<u32> {
    let mut val: u32 = 0;
    let mut seen = false;
    for &b in field {
        match b {
            b'0'..=b'7' => {
                val = val.checked_mul(8)?.checked_add(u32::from(b - b'0'))?;
                seen = true;
            }
            b' ' | 0 => {
                if seen {
                    break;
                }
            }
            _ => return None,
        }
    }
    seen.then_some(val)
}

/// Magic is a single ":" but a record is `:llaaaatt(dd...)cc` in ASCII hex,
/// and the checksum byte `cc` is chosen so that all decoded bytes
/// (count, address, type, data, checksum) sum to 0 mod 256
pub fn intel_hex(data: &[u8]) -> bool {
    fn inner(data: &[u8]) -> Option<bool> {
        if *data.first()? != b':' {
            return Some(false);
        }
        let hex = &data[1..];
        let count = hex_byte(hex, 0)?;
        let rectype = hex_byte(hex, 3)?;
        if rectype > 0x05 {
            return Some(false);
        }
        // count + addr(2) + type + data(count) + checksum
        let total = 5 + count as usize;
        let mut sum: u8 = 0;
        for i in 0..total {
            sum = sum.wrapping_add(hex_byte(hex, i)?);
        }
        Some(sum == 0)
    }
    inner(data) == Some(true)
}

/// Magic is just ASCII `S` + a digit. Structure:
/// `Stccaaaa...kk` where `cc` is a byte count covering address+data+checksum
/// and `kk` is the one's complement of the sum of count/address/data — so
/// count byte + all counted bytes must sum to 0xFF mod 256. 'S4' is undefined
pub fn srecord(data: &[u8]) -> bool {
    fn inner(data: &[u8]) -> Option<bool> {
        if *data.first()? != b'S' {
            return Some(false);
        }
        let t = *data.get(1)?;
        if !t.is_ascii_digit() || t == b'4' {
            return Some(false);
        }
        let hex = &data[2..];
        let count = hex_byte(hex, 0)?;
        if count < 3 {
            // must at least hold a 2-byte address + checksum
            return Some(false);
        }
        let mut sum: u8 = count;
        for i in 1..=count as usize {
            sum = sum.wrapping_add(hex_byte(hex, i)?);
        }
        Some(sum == 0xFF)
    }
    inner(data) == Some(true)
}

/// cpio. The portable variants are pure ASCII: after the 6-char magic,
/// "newc"/"crc" archives (`070701`/`070702`) have 13 fields of exactly
/// 8 hex digits each, and the old portable format (`070707`) has 66 octal
/// digits. Requiring every one of those characters to be a valid digit is
/// a very strong filter against the magic appearing inside ordinary text.
pub fn cpio(data: &[u8]) -> bool {
    let Some(magic) = data.get(..6) else {
        return false;
    };
    match magic {
        b"070701" | b"070702" => data
            .get(6..110)
            .is_some_and(|f| f.iter().all(u8::is_ascii_hexdigit)),
        b"070707" => data
            .get(6..76)
            .is_some_and(|f| f.iter().all(|b| (b'0'..=b'7').contains(b))),
        _ => false,
    }
}

/// zip local file header. `PK\x03\x04` is respectable, but zip magics recur
/// throughout archives and inside jar/apk/docx containers, so for firmware
/// scanning we sanity-check the header fields:
/// - "version needed" low byte is a realistic value (<= 63 covers every
///   feature ever defined; 0x14/0x2D in practice),
/// - compression method is one of the registered identifiers,
/// - filename/extra lengths fit within the data we can see.
pub fn zip(data: &[u8]) -> bool {
    const METHODS: &[u16] = &[
        0, 1, 2, 3, 4, 5, 6, 8, 9, 12, 14, 20, 93, 94, 95, 96, 97, 98, 99,
    ];
    let (Some(version), Some(method), Some(name_len), Some(extra_len)) = (
        u16_le(data, 4),
        u16_le(data, 8),
        u16_le(data, 26),
        u16_le(data, 28),
    ) else {
        return false;
    };
    data[..4] == *b"PK\x03\x04"
        && version & 0xFF <= 63
        && METHODS.contains(&method)
        && 30 + name_len as usize + extra_len as usize <= data.len()
}

// ---------------------------------------------------------------------------
// Verifiers — filesystems
// ---------------------------------------------------------------------------

/// JFFS2. The magic `0x1985` is two bytes, but every node header carries a
/// CRC of its own first 8 bytes (magic, nodetype, totlen) using the kernel's
/// `crc32(0, ...)` variant. Recomputing it is definitive. We additionally
/// require a known nodetype and a minimally sane total length. Both
/// endiannesses are handled.
pub fn jffs2(data: &[u8]) -> bool {
    const NODETYPES: &[u16] = &[
        0xE001, // dirent
        0xE002, // inode
        0x2003, // cleanmarker
        0x2004, // padding
        0x2006, // summary
        0xE008, // xattr
        0xE009, // xref
    ];
    fn check(
        data: &[u8],
        magic: u16,
        rd16: fn(&[u8], usize) -> Option<u16>,
        rd32: fn(&[u8], usize) -> Option<u32>,
    ) -> bool {
        let (Some(m), Some(nodetype), Some(totlen), Some(stored)) =
            (rd16(data, 0), rd16(data, 2), rd32(data, 4), rd32(data, 8))
        else {
            return false;
        };
        m == magic
            && NODETYPES.contains(&nodetype)
            && totlen >= 12
            && crc32_jffs2(&data[..8]) == stored
    }
    check(data, 0x1985, u16_le, u32_le) || check(data, 0x1985, u16_be, u32_be)
}

/// ext2/3/4. The magic `0xEF53` is two bytes and lives *inside* the
/// superblock, which itself sits 1024 bytes into the filesystem. Given a
/// slice starting at the filesystem start, we check the magic at its true
/// location plus superblock fields that can't be nonsense in a real fs:
/// nonzero inode/block counts, nonzero inodes-per-group, and a block size
/// exponent of at most 6 (64 KiB, the largest ext4 supports).
pub fn ext(data: &[u8]) -> bool {
    const SB: usize = 1024;
    let (Some(magic), Some(inodes), Some(blocks), Some(log_bs), Some(per_group)) = (
        u16_le(data, SB + 56),
        u32_le(data, SB),
        u32_le(data, SB + 4),
        u32_le(data, SB + 24),
        u32_le(data, SB + 40),
    ) else {
        return false;
    };
    magic == 0xEF53 && inodes != 0 && blocks != 0 && per_group != 0 && log_bs <= 6
}

/// SquashFS v4 (also tolerates v1–3 with weaker checks, since their
/// superblock layouts differ). Checks beyond the 4-byte magic:
/// the version-major field (same offset across versions) must be 1..=4,
/// and for v4 the redundant pair `block_size == 1 << block_log` must agree,
/// with the block size in the legal 4 KiB..=1 MiB range. Handles the
/// byte-swapped `sqsh` magic used by opposite-endian images.
pub fn squashfs(data: &[u8]) -> bool {
    let Some(magic) = data.get(..4) else {
        return false;
    };
    let (rd16, rd32): (
        fn(&[u8], usize) -> Option<u16>,
        fn(&[u8], usize) -> Option<u32>,
    ) = match magic {
        b"hsqs" => (u16_le, u32_le),
        b"sqsh" => (u16_be, u32_be),
        _ => return false,
    };
    let (Some(major), Some(block_size), Some(block_log)) =
        (rd16(data, 28), rd32(data, 12), rd16(data, 22))
    else {
        return false;
    };
    match major {
        4 => (12..=20).contains(&block_log) && block_size == 1u32 << block_log,
        1..=3 => true, // different layout; version check is all we do cheaply
        _ => false,
    }
}

/// CramFS. The 4-byte magic `0x28CD3D45` is decent, but the format hands us
/// something better: the literal ASCII signature "Compressed ROMFS" at
/// offset 16. Sixteen fixed bytes is effectively unforgeable by accident.
pub fn cramfs(data: &[u8]) -> bool {
    data.get(16..32) == Some(b"Compressed ROMFS".as_slice())
}

// ---------------------------------------------------------------------------
// Verifiers — firmware containers & executables
// ---------------------------------------------------------------------------

/// U-Boot uImage. The 64-byte header stores a CRC-32 of itself (standard
/// zlib CRC) at offset 4, computed with that field zeroed. Recomputing it
/// is proof positive — this is exactly the check U-Boot itself performs
/// before booting an image.
pub fn uimage(data: &[u8]) -> bool {
    let Some(hdr_slice) = data.get(..64) else {
        return false;
    };
    if hdr_slice[..4] != [0x27, 0x05, 0x19, 0x56] {
        return false;
    }
    let stored = u32::from_be_bytes([hdr_slice[4], hdr_slice[5], hdr_slice[6], hdr_slice[7]]);
    let mut hdr = [0u8; 64];
    hdr.copy_from_slice(hdr_slice);
    hdr[4..8].fill(0);
    crc32(&hdr) == stored
}

/// Broadcom TRX. After the "HDR0" magic: total length, a CRC, a
/// flags/version word, and three partition offsets. We verify structure:
/// length covers at least the 28-byte header, version is 1 or 2, and every
/// nonzero partition offset points inside the stated image. (The stored CRC
/// spans the whole image from offset 12, so recomputing it on a large blob
/// is possible but expensive; the structural check is usually sufficient.)
pub fn trx(data: &[u8]) -> bool {
    let (Some(len), Some(flag_version)) = (u32_le(data, 4), u32_le(data, 12)) else {
        return false;
    };
    if data[..4] != *b"HDR0" {
        return false;
    }
    let version = flag_version >> 16;
    if len < 28 || !(1..=2).contains(&version) {
        return false;
    }
    (0..3).all(|i| {
        u32_le(data, 16 + 4 * i)
            .map(|off| off == 0 || (28..len).contains(&off))
            .unwrap_or(false)
    })
}

/// Flattened Device Tree blob. Beyond the 4-byte big-endian magic, the
/// header's internal geometry must be self-consistent: total size covers at
/// least the header, the struct/strings/memreserve offsets all point inside
/// the blob, and the version pair satisfies `last_comp_version <= version`
/// (current blobs are version 17, last-compatible 16).
pub fn dtb(data: &[u8]) -> bool {
    let (
        Some(magic),
        Some(total),
        Some(off_struct),
        Some(off_strings),
        Some(off_rsvmap),
        Some(version),
        Some(last_comp),
    ) = (
        u32_be(data, 0),
        u32_be(data, 4),
        u32_be(data, 8),
        u32_be(data, 12),
        u32_be(data, 16),
        u32_be(data, 20),
        u32_be(data, 24),
    )
    else {
        return false;
    };
    magic == 0xD00D_FEED
        && total >= 40
        && version >= last_comp
        && version <= 32
        && off_struct < total
        && off_strings < total
        && off_rsvmap < total
}

/// PE/COFF. `MZ` alone is two bytes and ubiquitous in random data. The real
/// test, per the spec: read `e_lfanew` at 0x3C, find `PE\0\0` there, then
/// confirm the COFF machine type is a registered value and the optional
/// header (if present) starts with the PE32/PE32+/ROM magic. Chaining an
/// interior pointer to a second magic like this is about as strong as
/// verification gets without parsing sections.
pub fn pe(data: &[u8]) -> bool {
    const MACHINES: &[u16] = &[
        0x0000, 0x014C, 0x0166, 0x0169, 0x01C0, 0x01C2, 0x01C4, 0x0266, 0x0284, 0x0366, 0x0466,
        0x01F0, 0x01F1, 0x0EBC, 0x5032, 0x5064, 0x6232, 0x6264, 0x8664, 0xAA64,
    ];
    if data.len() < 0x40 || data[..2] != *b"MZ" {
        return false;
    }
    let Some(e_lfanew) = u32_le(data, 0x3C).map(|v| v as usize) else {
        return false;
    };
    // Sane e_lfanew: past the DOS header, before anything absurd.
    if !(0x40..0x10_0000).contains(&e_lfanew) {
        return false;
    }
    let (Some(sig), Some(machine), Some(opt_size)) = (
        data.get(e_lfanew..e_lfanew + 4),
        u16_le(data, e_lfanew + 4),
        u16_le(data, e_lfanew + 20),
    ) else {
        return false;
    };
    if sig != b"PE\0\0" || !MACHINES.contains(&machine) {
        return false;
    }
    // If an optional header exists, its magic must be PE32 / PE32+ / ROM.
    if opt_size >= 2 {
        matches!(u16_le(data, e_lfanew + 24), Some(0x010B | 0x020B | 0x0107))
    } else {
        true
    }
}

/// Mach-O, both thin and fat (universal). For thin images we check a known
/// CPU type, a defined file type (1..=11), and a plausible load-command
/// count. For fat images the header is big-endian `0xCAFEBABE` — which
/// collides with Java class files! The disambiguator: the next u32 is
/// `nfat_arch`, tiny in real binaries (<= ~18 slices ever shipped), whereas
/// in a class file those bytes are minor/major version, decoding to 45+.
pub fn macho(data: &[u8]) -> bool {
    const CPUS: &[u32] = &[
        7,           // x86
        0x0100_0007, // x86_64
        12,          // arm
        0x0100_000C, // arm64
        18,          // ppc
        0x0100_0012, // ppc64
    ];
    let Some(magic) = u32_be(data, 0) else {
        return false;
    };
    match magic {
        // Thin, big-endian on disk
        0xFEED_FACE | 0xFEED_FACF => thin_macho(data, u32_be, CPUS),
        // Thin, little-endian on disk (magic appears byte-swapped)
        0xCEFA_EDFE | 0xCFFA_EDFE => thin_macho(data, u32_le, CPUS),
        // Fat / universal (always big-endian)
        0xCAFE_BABE | 0xCAFE_BABF => {
            let Some(nfat) = u32_be(data, 4) else {
                return false;
            };
            (1..=30).contains(&nfat)
                && (0..nfat as usize).all(|i| {
                    u32_be(data, 8 + i * 20)
                        .map(|cpu| CPUS.contains(&cpu))
                        .unwrap_or(false)
                })
        }
        _ => false,
    }
}

fn thin_macho(data: &[u8], rd32: fn(&[u8], usize) -> Option<u32>, cpus: &[u32]) -> bool {
    let (Some(cputype), Some(filetype), Some(ncmds)) =
        (rd32(data, 4), rd32(data, 12), rd32(data, 16))
    else {
        return false;
    };
    cpus.contains(&cputype) && (1..=11).contains(&filetype) && (1..10_000).contains(&ncmds)
}

// ---------------------------------------------------------------------------
// Verifiers — encoded data
// ---------------------------------------------------------------------------

/// DER-encoded ASN.1 — the weakest signature of all: a single `0x30`
/// (SEQUENCE tag, which is also ASCII '0'). We parse the length field per
/// DER's rules and demand full consistency:
/// - Short form (< 0x80): the length is the byte itself.
/// - Long form (0x81..=0x84): that many big-endian length bytes follow;
///   DER additionally requires *minimal* encoding (no leading zero byte,
///   and the value must not have fit in short form).
/// - `0x80` (indefinite length) is BER-only — invalid in DER.
/// Finally the declared content must actually fit in the data we have,
/// and be nonempty (real certs/keys are never an empty SEQUENCE).
pub fn der(data: &[u8]) -> bool {
    let (Some(&tag), Some(&lb)) = (data.first(), data.get(1)) else {
        return false;
    };
    if tag != 0x30 {
        return false;
    }
    let (len, hdr_len) = match lb {
        0x00 => return false, // empty SEQUENCE: legal but never a real file
        l @ 0x01..=0x7F => (l as usize, 2),
        0x80 => return false, // indefinite: BER, not DER
        l @ 0x81..=0x84 => {
            let n = (l & 0x7F) as usize;
            let Some(bytes) = data.get(2..2 + n) else {
                return false;
            };
            if bytes[0] == 0 {
                return false; // non-minimal: leading zero
            }
            let mut v: usize = 0;
            for &b in bytes {
                v = v << 8 | b as usize;
            }
            if v < 0x80 {
                return false; // non-minimal: should've used short form
            }
            (v, 2 + n)
        }
        _ => return false, // >4 length bytes: nothing real is that big
    };
    hdr_len + len <= data.len()
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_vector() {
        // The canonical CRC-32 check value.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn gzip_header() {
        let good = [0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0x03];
        assert!(gzip(&good));
        let bad_cm = [0x1F, 0x8B, 0x07, 0x00, 0, 0, 0, 0, 0x00, 0x03];
        assert!(!gzip(&bad_cm));
        let bad_flg = [0x1F, 0x8B, 0x08, 0xE0, 0, 0, 0, 0, 0x00, 0x03];
        assert!(!gzip(&bad_flg));
    }

    #[test]
    fn zlib_header() {
        assert!(zlib(&[0x78, 0x9C])); // default compression
        assert!(zlib(&[0x78, 0x01])); // fastest
        assert!(zlib(&[0x78, 0xDA])); // best
        assert!(!zlib(&[0x78, 0x00])); // fails the %31 rule
        assert!(!zlib(&[0x79, 0x9C])); // CM != 8 pattern
    }

    #[test]
    fn intel_hex_records() {
        assert!(intel_hex(b":00000001FF")); // EOF record
        assert!(intel_hex(b":0300300002337A1E")); // data record w/ checksum
        assert!(!intel_hex(b":00000001FE")); // corrupted checksum
        assert!(!intel_hex(b":00000009F7")); // undefined record type
    }

    #[test]
    fn srecord_records() {
        assert!(srecord(b"S0030000FC")); // header record
        assert!(srecord(b"S9030000FC")); // termination record
        assert!(!srecord(b"S0030000FB")); // corrupted checksum
        assert!(!srecord(b"S4030000FC")); // S4 undefined
    }

    #[test]
    fn tar_header_checksum() {
        let mut hdr = vec![0u8; 512];
        hdr[..5].copy_from_slice(b"hello");
        // compute checksum with field as spaces
        hdr[148..156].fill(b' ');
        let sum: u32 = hdr.iter().map(|&b| u32::from(b)).sum();
        let field = format!("{:06o}\0 ", sum);
        hdr[148..156].copy_from_slice(field.as_bytes());
        assert!(tar(&hdr));
        hdr[0] ^= 0xFF; // corrupt a byte
        assert!(!tar(&hdr));
    }

    #[test]
    fn jffs2_node() {
        // Build a cleanmarker node: magic, nodetype 0x2003, totlen 12, then CRC.
        let mut node = Vec::new();
        node.extend_from_slice(&0x1985u16.to_le_bytes());
        node.extend_from_slice(&0x2003u16.to_le_bytes());
        node.extend_from_slice(&12u32.to_le_bytes());
        let crc = crc32_jffs2(&node);
        node.extend_from_slice(&crc.to_le_bytes());
        assert!(jffs2(&node));
        node[3] ^= 0xFF;
        assert!(!jffs2(&node));
    }

    #[test]
    fn uimage_header_crc() {
        let mut hdr = [0u8; 64];
        hdr[..4].copy_from_slice(&[0x27, 0x05, 0x19, 0x56]);
        hdr[32] = 5; // arbitrary field content
        let crc = crc32(&hdr); // hcrc field currently zero
        hdr[4..8].copy_from_slice(&crc.to_be_bytes());
        assert!(uimage(&hdr));
        hdr[32] = 6;
        assert!(!uimage(&hdr));
    }

    #[test]
    fn der_lengths() {
        assert!(der(&[0x30, 0x03, 0x02, 0x01, 0x05])); // SEQUENCE { INTEGER 5 }
        assert!(!der(&[0x30, 0x80])); // indefinite length
        assert!(!der(&[0x30, 0x81, 0x05])); // non-minimal long form
        assert!(!der(&[0x30, 0x05, 0x02])); // declared length overruns data
        assert!(der(&[0x30, 0x81, 0x80 /* len=128 */]
            .iter()
            .copied()
            .chain(std::iter::repeat(0u8).take(128))
            .collect::<Vec<_>>()
            .as_slice()));
    }

    #[test]
    fn cpio_ascii() {
        let mut newc = b"070701".to_vec();
        newc.extend_from_slice(&[b'0'; 104]);
        assert!(cpio(&newc));
        newc[10] = b'X';
        assert!(!cpio(&newc));
    }

    #[test]
    fn lz4_descriptor() {
        // magic + FLG(version=01) + BD(block max size = 4) + dummy HC byte
        assert!(lz4(&[
            0x04,
            0x22,
            0x4D,
            0x18,
            0b0100_0000,
            0b0100_0000,
            0x00
        ]));
        // reserved FLG bit set
        assert!(!lz4(&[
            0x04,
            0x22,
            0x4D,
            0x18,
            0b0100_0010,
            0b0100_0000,
            0x00
        ]));
        // invalid block max size (3)
        assert!(!lz4(&[
            0x04,
            0x22,
            0x4D,
            0x18,
            0b0100_0000,
            0b0011_0000,
            0x00
        ]));
    }

    #[test]
    fn fat_macho_vs_java_class() {
        // Fat Mach-O: 2 arches, first is arm64
        let mut fat = Vec::new();
        fat.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
        fat.extend_from_slice(&2u32.to_be_bytes());
        for cpu in [0x0100_000Cu32, 0x0100_0007] {
            fat.extend_from_slice(&cpu.to_be_bytes());
            fat.extend_from_slice(&[0u8; 16]);
        }
        assert!(macho(&fat));
        // Java class file: CAFEBABE, minor 0, major 52 (Java 8)
        let mut class = Vec::new();
        class.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
        class.extend_from_slice(&[0x00, 0x00, 0x00, 0x34]);
        class.extend_from_slice(&[0u8; 40]);
        assert!(!macho(&class));
    }
}
