//! Strict TriCore executable ELF to Motorola S-record firmware measurement.
//!
//! This module deliberately reads program headers rather than sections: a
//! TRACE32 data-load image is defined by the loadable bytes and their physical
//! addresses (LMA), not by the linker-facing virtual layout (VMA).

use sha2::{Digest as _, Sha256};
use t32perf_model::Sha256Digest;
use thiserror::Error;

/// Largest ELF byte sequence accepted by [`measure_tricore_elf_to_s3`].
pub const MAX_TRICORE_FIRMWARE_ELF_BYTES: usize = 256 * 1024 * 1024;
/// Largest number of program headers accepted by [`measure_tricore_elf_to_s3`].
pub const MAX_TRICORE_PROGRAM_HEADERS: usize = 65_536;
/// Largest S-record output accepted by [`measure_tricore_elf_to_s3`].
pub const MAX_TRICORE_S3_OUTPUT_BYTES: usize = 512 * 1024 * 1024;
/// Fixed maximum data payload in every S3 record.
pub const TRICORE_S3_RECORD_PAYLOAD_BYTES: usize = 32;

const ELF_HEADER_BYTES: usize = 52;
const ELF_PROGRAM_HEADER_BYTES: usize = 32;
const ELF_MACHINE_TRICORE: u16 = 44;
const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_PROGRAM_TYPE_LOAD: u32 = 1;

/// One file-backed physical load range from the source ELF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareImageSegment {
    /// First physical address included in the segment.
    pub physical_address: u32,
    /// Exclusive physical end address of the segment.
    pub physical_end_address: u64,
    /// Byte offset in the source ELF.
    pub file_offset: u64,
    /// Number of source bytes included in the segment.
    pub size: u64,
}

/// Deterministic firmware image representation suitable for TRACE32 loading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareImageMeasurement {
    /// Complete LF-terminated Motorola S0/S3/S7 stream.
    pub s3_bytes: Vec<u8>,
    /// SHA-256 of [`Self::s3_bytes`].
    pub s3_sha256: Sha256Digest,
    /// SHA-256 of the exact source ELF byte sequence.
    pub source_elf_sha256: Sha256Digest,
    /// Executable entry point emitted in the terminating S7 record.
    pub entry_point: u32,
    /// File-backed physical load coverage, sorted by physical address.
    pub segments: Vec<FirmwareImageSegment>,
}

/// A strictly parsed, source-independent TriCore S3 image.
///
/// This deliberately accepts only the canonical S0/S3/S7 representation
/// emitted by [`measure_tricore_elf_to_s3`], rather than generic S-record
/// syntax. A controller must not load an alternative representation of the
/// firmware it has registered and measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTricoreS3Image {
    /// SHA-256 of the exact LF-terminated S-record byte stream.
    pub s3_sha256: Sha256Digest,
    /// Entry point carried by the unique terminal S7 record.
    pub entry_point: u32,
    /// S3 data records in strict ascending physical-address order.
    pub records: Vec<TricoreS3DataRecord>,
}

/// One parsed canonical S3 data record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TricoreS3DataRecord {
    /// First physical address represented by this record.
    pub physical_address: u32,
    /// Data bytes decoded from the record.
    pub payload: Vec<u8>,
}

/// Failure while validating or encoding a TriCore firmware ELF.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FirmwareImageError {
    /// The source ELF exceeds the immutable admission limit.
    #[error("TriCore firmware ELF exceeds {limit} bytes")]
    InputTooLarge {
        /// Admission limit.
        limit: usize,
    },
    /// ELF identification or header data is malformed.
    #[error("invalid TriCore ELF: {message}")]
    InvalidElf {
        /// Diagnostic without untrusted byte content.
        message: String,
    },
    /// The ELF class, byte order, machine, or type is not supported.
    #[error("UNSUPPORTED: {message}")]
    Unsupported {
        /// Stable rejection reason.
        message: String,
    },
    /// A file-backed load segment did not supply a physical LMA.
    #[error("PT_LOAD program header {index} has zero p_paddr; VMA fallback is forbidden")]
    MissingPhysicalAddress {
        /// Zero-based program header index.
        index: usize,
    },
    /// Two physical ranges overlap.
    #[error(
        "PT_LOAD program header {index} overlaps program header {previous_index} in physical address space"
    )]
    OverlappingLoadSegments {
        /// Earlier program-header index.
        previous_index: usize,
        /// Later program-header index.
        index: usize,
    },
    /// No file-backed PT_LOAD range exists.
    #[error("TriCore ELF has no file-backed PT_LOAD coverage")]
    NoLoadCoverage,
    /// Exact S-record encoding would exceed its immutable quota.
    #[error("TriCore S3 output exceeds {limit} bytes")]
    OutputTooLarge {
        /// Output ceiling.
        limit: usize,
    },
    /// Source bytes differ from the registered firmware artifact digest.
    #[error("registered firmware ELF digest does not match supplied source bytes")]
    SourceDigestMismatch,
    /// S3 bytes differ from the registered measurement artifact digest.
    #[error("registered TriCore S3 digest does not match supplied measurement bytes")]
    S3DigestMismatch,
    /// A syntactically valid S3 image differs from the canonical ELF derivation.
    #[error("TriCore S3 stream does not exactly match the canonical ELF-derived measurement")]
    S3EncodingMismatch,
}

#[derive(Debug)]
struct LoadSegment<'a> {
    index: usize,
    physical_address: u32,
    file_offset: u64,
    bytes: &'a [u8],
}

/// Validates an exact TriCore ELF32 executable and encodes its `PT_LOAD` bytes.
///
/// Only little-endian `e_machine = 44` files are accepted. Each file-backed
/// load segment must supply a nonzero `p_paddr`; silently using `p_vaddr`
/// would change an LMA measurement into a VMA measurement. The returned S3
/// stream is independent of program-header order and uses 32-byte S3 records.
pub fn measure_tricore_elf_to_s3(
    elf_bytes: &[u8],
) -> Result<FirmwareImageMeasurement, FirmwareImageError> {
    if elf_bytes.len() > MAX_TRICORE_FIRMWARE_ELF_BYTES {
        return Err(FirmwareImageError::InputTooLarge {
            limit: MAX_TRICORE_FIRMWARE_ELF_BYTES,
        });
    }
    validate_identification(elf_bytes)?;
    let entry_point = read_u32(elf_bytes, 24, "e_entry")?;
    let program_offset = read_u32(elf_bytes, 28, "e_phoff")? as usize;
    let header_size = read_u16(elf_bytes, 40, "e_ehsize")? as usize;
    let program_entry_size = read_u16(elf_bytes, 42, "e_phentsize")? as usize;
    let program_count = read_u16(elf_bytes, 44, "e_phnum")? as usize;
    if header_size != ELF_HEADER_BYTES {
        return Err(invalid("e_ehsize is not ELF32 header size"));
    }
    if program_entry_size != ELF_PROGRAM_HEADER_BYTES {
        return Err(invalid("e_phentsize is not ELF32 program-header size"));
    }
    if program_count == 0 || program_count == usize::from(u16::MAX) {
        return Err(invalid("e_phnum must be a nonzero non-extended count"));
    }
    if program_count > MAX_TRICORE_PROGRAM_HEADERS {
        return Err(invalid("e_phnum exceeds program-header limit"));
    }
    let table_bytes = program_count
        .checked_mul(program_entry_size)
        .ok_or_else(|| invalid("program-header table length overflows"))?;
    checked_range(
        elf_bytes,
        program_offset,
        table_bytes,
        "program-header table",
    )?;

    let mut loads = Vec::new();
    for index in 0..program_count {
        let offset = program_offset
            .checked_add(
                index
                    .checked_mul(program_entry_size)
                    .ok_or_else(|| invalid("program-header offset overflows"))?,
            )
            .ok_or_else(|| invalid("program-header offset overflows"))?;
        if read_u32(elf_bytes, offset, "p_type")? != ELF_PROGRAM_TYPE_LOAD {
            continue;
        }
        let file_offset = read_u32(elf_bytes, offset + 4, "p_offset")? as usize;
        let physical_address = read_u32(elf_bytes, offset + 12, "p_paddr")?;
        let file_size = read_u32(elf_bytes, offset + 16, "p_filesz")? as usize;
        let memory_size = read_u32(elf_bytes, offset + 20, "p_memsz")? as usize;
        if memory_size < file_size {
            return Err(invalid("PT_LOAD p_memsz is smaller than p_filesz"));
        }
        if file_size == 0 {
            continue;
        }
        if physical_address == 0 {
            return Err(FirmwareImageError::MissingPhysicalAddress { index });
        }
        let bytes = checked_range(elf_bytes, file_offset, file_size, "PT_LOAD file range")?;
        let physical_end = u64::from(physical_address)
            .checked_add(file_size as u64)
            .ok_or_else(|| invalid("PT_LOAD physical address range overflows"))?;
        if physical_end > (u64::from(u32::MAX) + 1) {
            return Err(invalid(
                "PT_LOAD physical address range exceeds S3 address space",
            ));
        }
        loads.push(LoadSegment {
            index,
            physical_address,
            file_offset: file_offset as u64,
            bytes,
        });
    }
    if loads.is_empty() {
        return Err(FirmwareImageError::NoLoadCoverage);
    }
    loads.sort_unstable_by_key(|segment| segment.physical_address);
    for pair in loads.windows(2) {
        let previous_end = u64::from(pair[0].physical_address) + pair[0].bytes.len() as u64;
        if previous_end > u64::from(pair[1].physical_address) {
            return Err(FirmwareImageError::OverlappingLoadSegments {
                previous_index: pair[0].index,
                index: pair[1].index,
            });
        }
    }

    let encoded_size = estimate_s3_output_bytes(&loads)?;
    if encoded_size > MAX_TRICORE_S3_OUTPUT_BYTES {
        return Err(FirmwareImageError::OutputTooLarge {
            limit: MAX_TRICORE_S3_OUTPUT_BYTES,
        });
    }

    let mut s3_bytes = Vec::with_capacity(encoded_size);
    append_record(&mut s3_bytes, b'0', 0, b"T32PERF")?;
    for segment in &loads {
        for (chunk_index, chunk) in segment
            .bytes
            .chunks(TRICORE_S3_RECORD_PAYLOAD_BYTES)
            .enumerate()
        {
            let byte_offset = chunk_index
                .checked_mul(TRICORE_S3_RECORD_PAYLOAD_BYTES)
                .ok_or_else(|| invalid("S3 record offset overflows"))?;
            let address = segment
                .physical_address
                .checked_add(byte_offset as u32)
                .ok_or_else(|| invalid("S3 record address overflows"))?;
            append_record(&mut s3_bytes, b'3', address, chunk)?;
        }
    }
    append_record(&mut s3_bytes, b'7', entry_point, &[])?;
    let segments = loads
        .iter()
        .map(|segment| FirmwareImageSegment {
            physical_address: segment.physical_address,
            physical_end_address: u64::from(segment.physical_address) + segment.bytes.len() as u64,
            file_offset: segment.file_offset,
            size: segment.bytes.len() as u64,
        })
        .collect();
    Ok(FirmwareImageMeasurement {
        s3_sha256: digest(&s3_bytes),
        source_elf_sha256: digest(elf_bytes),
        s3_bytes,
        entry_point,
        segments,
    })
}

/// Derives the canonical S3 image after binding the exact registered ELF bytes.
///
/// `registered_elf_sha256` must be copied from the immutable Session artifact
/// record before target control begins. The digest is checked before any ELF
/// parsing so a caller cannot accidentally derive a target-load image from a
/// different byte sequence.
pub fn measure_registered_tricore_elf_to_s3(
    elf_bytes: &[u8],
    registered_elf_sha256: &Sha256Digest,
) -> Result<FirmwareImageMeasurement, FirmwareImageError> {
    if digest(elf_bytes) != *registered_elf_sha256 {
        return Err(FirmwareImageError::SourceDigestMismatch);
    }
    measure_tricore_elf_to_s3(elf_bytes)
}

/// Parses a canonical, LF-terminated TriCore S0/S3/S7 stream.
///
/// The parser rejects lower-case hexadecimal input, CRLF, empty records,
/// unsupported record types, non-canonical headers, unordered or overlapping
/// S3 ranges, payloads larger than the fixed encoder chunk, and anything after
/// the single S7 terminator.
pub fn parse_tricore_s3_image(s3_bytes: &[u8]) -> Result<ParsedTricoreS3Image, FirmwareImageError> {
    if s3_bytes.len() > MAX_TRICORE_S3_OUTPUT_BYTES {
        return Err(FirmwareImageError::OutputTooLarge {
            limit: MAX_TRICORE_S3_OUTPUT_BYTES,
        });
    }
    if s3_bytes.is_empty() || !s3_bytes.ends_with(b"\n") || s3_bytes.contains(&b'\r') {
        return Err(invalid(
            "S3 stream must be nonempty and use LF line endings",
        ));
    }
    let mut lines = s3_bytes[..s3_bytes.len() - 1].split(|byte| *byte == b'\n');
    let header = lines
        .next()
        .ok_or_else(|| invalid("S3 stream has no header"))?;
    let header = parse_srecord(header, b'0')?;
    if header.address != 0 || header.payload != b"T32PERF" {
        return Err(invalid("S0 header is not the fixed T32PERF marker"));
    }

    let mut records: Vec<TricoreS3DataRecord> = Vec::new();
    let mut entry_point = None;
    for line in lines {
        if line.is_empty() {
            return Err(invalid("S3 stream contains an empty record"));
        }
        if entry_point.is_some() {
            return Err(invalid("S3 stream contains data after its S7 terminator"));
        }
        match line.get(1).copied() {
            Some(b'3') => {
                let record = parse_srecord(line, b'3')?;
                if record.address == 0
                    || record.payload.is_empty()
                    || record.payload.len() > TRICORE_S3_RECORD_PAYLOAD_BYTES
                {
                    return Err(invalid(
                        "S3 record address or payload is outside canonical bounds",
                    ));
                }
                let end = u64::from(record.address)
                    .checked_add(record.payload.len() as u64)
                    .ok_or_else(|| invalid("S3 record address range overflows"))?;
                if end > u64::from(u32::MAX) + 1 {
                    return Err(invalid("S3 record exceeds 32-bit address space"));
                }
                if let Some(previous) = records.last() {
                    let previous_end = u64::from(previous.physical_address)
                        .checked_add(previous.payload.len() as u64)
                        .ok_or_else(|| invalid("S3 record address range overflows"))?;
                    if previous_end > u64::from(record.address) {
                        return Err(invalid(
                            "S3 records are not strictly non-overlapping and ascending",
                        ));
                    }
                }
                records.push(TricoreS3DataRecord {
                    physical_address: record.address,
                    payload: record.payload,
                });
            }
            Some(b'7') => {
                let terminator = parse_srecord(line, b'7')?;
                if !terminator.payload.is_empty() {
                    return Err(invalid("S7 terminator contains payload bytes"));
                }
                entry_point = Some(terminator.address);
            }
            _ => return Err(invalid("S3 stream contains an unsupported record type")),
        }
    }
    if records.is_empty() {
        return Err(FirmwareImageError::NoLoadCoverage);
    }
    let entry_point = entry_point.ok_or_else(|| invalid("S3 stream has no S7 terminator"))?;
    Ok(ParsedTricoreS3Image {
        s3_sha256: digest(s3_bytes),
        entry_point,
        records,
    })
}

/// Verifies a registered ELF and S3 artifact as one canonical image.
///
/// Both artifact digests are checked before accepting the measurement. The S3
/// representation must parse strictly and equal a fresh deterministic
/// derivation byte-for-byte; another valid S-record spelling is not accepted.
pub fn verify_registered_tricore_elf_s3_measurement(
    elf_bytes: &[u8],
    registered_elf_sha256: &Sha256Digest,
    s3_bytes: &[u8],
    registered_s3_sha256: &Sha256Digest,
) -> Result<FirmwareImageMeasurement, FirmwareImageError> {
    let measurement = measure_registered_tricore_elf_to_s3(elf_bytes, registered_elf_sha256)?;
    if digest(s3_bytes) != *registered_s3_sha256 {
        return Err(FirmwareImageError::S3DigestMismatch);
    }
    parse_tricore_s3_image(s3_bytes)?;
    if s3_bytes != measurement.s3_bytes {
        return Err(FirmwareImageError::S3EncodingMismatch);
    }
    Ok(measurement)
}

fn estimate_s3_output_bytes(loads: &[LoadSegment<'_>]) -> Result<usize, FirmwareImageError> {
    // `S0` with two-byte address and seven identifier bytes, plus an `S7`.
    let mut total = srecord_text_size(2, 7)?
        .checked_add(srecord_text_size(4, 0)?)
        .ok_or_else(|| invalid("S3 output length overflows"))?;
    for load in loads {
        let complete_records = load.bytes.len() / TRICORE_S3_RECORD_PAYLOAD_BYTES;
        let remainder = load.bytes.len() % TRICORE_S3_RECORD_PAYLOAD_BYTES;
        total = total
            .checked_add(
                complete_records
                    .checked_mul(srecord_text_size(4, TRICORE_S3_RECORD_PAYLOAD_BYTES)?)
                    .ok_or_else(|| invalid("S3 output length overflows"))?,
            )
            .ok_or_else(|| invalid("S3 output length overflows"))?;
        if remainder != 0 {
            total = total
                .checked_add(srecord_text_size(4, remainder)?)
                .ok_or_else(|| invalid("S3 output length overflows"))?;
        }
    }
    Ok(total)
}

fn srecord_text_size(
    address_bytes: usize,
    payload_bytes: usize,
) -> Result<usize, FirmwareImageError> {
    let count = address_bytes
        .checked_add(payload_bytes)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| invalid("S-record byte count overflows"))?;
    if count > usize::from(u8::MAX) {
        return Err(invalid("S-record byte count exceeds u8"));
    }
    2usize
        .checked_add(
            count
                .checked_add(1)
                .and_then(|value| value.checked_mul(2))
                .ok_or_else(|| invalid("S-record text length overflows"))?,
        )
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| invalid("S-record text length overflows"))
}

fn validate_identification(bytes: &[u8]) -> Result<(), FirmwareImageError> {
    if bytes.len() < ELF_HEADER_BYTES {
        return Err(invalid("file is shorter than the ELF32 header"));
    }
    if bytes.get(0..4) != Some(b"\x7fELF") {
        return Err(FirmwareImageError::Unsupported {
            message: "firmware image is not ELF".to_owned(),
        });
    }
    if bytes[4] != 1 || bytes[5] != 1 || bytes[6] != 1 {
        return Err(FirmwareImageError::Unsupported {
            message: "firmware image must be ELF32 little-endian version 1".to_owned(),
        });
    }
    if read_u16(bytes, 16, "e_type")? != ELF_TYPE_EXECUTABLE {
        return Err(FirmwareImageError::Unsupported {
            message: "firmware image must be an executable ELF".to_owned(),
        });
    }
    if read_u16(bytes, 18, "e_machine")? != ELF_MACHINE_TRICORE {
        return Err(FirmwareImageError::Unsupported {
            message: "firmware image must use TriCore e_machine 44".to_owned(),
        });
    }
    if read_u32(bytes, 20, "e_version")? != 1 {
        return Err(invalid("e_version is not 1"));
    }
    Ok(())
}

fn checked_range<'a>(
    bytes: &'a [u8],
    offset: usize,
    length: usize,
    field: &str,
) -> Result<&'a [u8], FirmwareImageError> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| invalid(format!("{field} offset plus length overflows")))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| invalid(format!("{field} exceeds file length")))
}

fn read_u16(bytes: &[u8], offset: usize, field: &str) -> Result<u16, FirmwareImageError> {
    let value = checked_range(bytes, offset, 2, field)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize, field: &str) -> Result<u32, FirmwareImageError> {
    let value = checked_range(bytes, offset, 4, field)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn append_record(
    output: &mut Vec<u8>,
    record_type: u8,
    address: u32,
    payload: &[u8],
) -> Result<(), FirmwareImageError> {
    let address_bytes: usize = if record_type == b'0' { 2 } else { 4 };
    let count = address_bytes
        .checked_add(payload.len())
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| invalid("S-record byte count overflows"))?;
    let count = u8::try_from(count).map_err(|_| invalid("S-record byte count exceeds u8"))?;
    let extra = srecord_text_size(address_bytes, payload.len())?;
    if output
        .len()
        .checked_add(extra)
        .is_none_or(|size| size > MAX_TRICORE_S3_OUTPUT_BYTES)
    {
        return Err(FirmwareImageError::OutputTooLarge {
            limit: MAX_TRICORE_S3_OUTPUT_BYTES,
        });
    }
    output.extend_from_slice(b"S");
    output.push(record_type);
    write_hex_byte(output, count);
    let mut checksum = count;
    let address_width = address_bytes;
    for shift in (0..address_width).rev() {
        let byte = ((address >> (shift * 8)) & 0xff) as u8;
        checksum = checksum.wrapping_add(byte);
        write_hex_byte(output, byte);
    }
    for &byte in payload {
        checksum = checksum.wrapping_add(byte);
        write_hex_byte(output, byte);
    }
    write_hex_byte(output, !checksum);
    output.push(b'\n');
    Ok(())
}

#[derive(Debug)]
struct ParsedSRecord {
    address: u32,
    payload: Vec<u8>,
}

fn parse_srecord(line: &[u8], expected_type: u8) -> Result<ParsedSRecord, FirmwareImageError> {
    if line.len() < 4 || line[0] != b'S' || line[1] != expected_type {
        return Err(invalid("S-record header is malformed"));
    }
    let count = parse_hex_byte(&line[2..4])?;
    let expected_length = 4usize
        .checked_add(
            usize::from(count)
                .checked_mul(2)
                .ok_or_else(|| invalid("S-record length overflows"))?,
        )
        .ok_or_else(|| invalid("S-record length overflows"))?;
    if line.len() != expected_length {
        return Err(invalid("S-record byte count does not match line length"));
    }
    let mut encoded = Vec::with_capacity(usize::from(count));
    for pair in line[4..].as_chunks::<2>().0 {
        encoded.push(parse_hex_byte(pair)?);
    }
    let address_bytes = if expected_type == b'0' { 2 } else { 4 };
    if encoded.len() < address_bytes + 1
        || encoded.iter().copied().fold(count, u8::wrapping_add) != u8::MAX
    {
        return Err(invalid("S-record checksum or byte count is invalid"));
    }
    let mut address = 0_u32;
    for byte in &encoded[..address_bytes] {
        address = (address << 8) | u32::from(*byte);
    }
    let payload_end = encoded.len() - 1;
    Ok(ParsedSRecord {
        address,
        payload: encoded[address_bytes..payload_end].to_vec(),
    })
}

fn parse_hex_byte(bytes: &[u8]) -> Result<u8, FirmwareImageError> {
    if bytes.len() != 2 {
        return Err(invalid("S-record hexadecimal byte is truncated"));
    }
    let high = parse_upper_hex_nibble(bytes[0])?;
    let low = parse_upper_hex_nibble(bytes[1])?;
    Ok((high << 4) | low)
}

fn parse_upper_hex_nibble(byte: u8) -> Result<u8, FirmwareImageError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(invalid("S-record contains non-uppercase hexadecimal data")),
    }
}

fn write_hex_byte(output: &mut Vec<u8>, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    output.push(HEX[usize::from(byte >> 4)]);
    output.push(HEX[usize::from(byte & 0x0f)]);
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(hex_encode(&Sha256::digest(bytes))).expect("SHA-256 output is valid")
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn invalid(message: impl Into<String>) -> FirmwareImageError {
    FirmwareImageError::InvalidElf {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_output_quota_is_detectable_without_allocating_image() {
        let complete_records = MAX_TRICORE_S3_OUTPUT_BYTES / 79 + 1;
        let stream_size = srecord_text_size(2, 7).unwrap()
            + srecord_text_size(4, 0).unwrap()
            + complete_records * srecord_text_size(4, TRICORE_S3_RECORD_PAYLOAD_BYTES).unwrap();
        assert!(stream_size > MAX_TRICORE_S3_OUTPUT_BYTES);
    }
}
