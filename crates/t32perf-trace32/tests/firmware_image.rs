use sha2::{Digest as _, Sha256};
use t32perf_trace32::{
    FirmwareImageError, MAX_TRICORE_FIRMWARE_ELF_BYTES, MAX_TRICORE_S3_OUTPUT_BYTES,
    measure_registered_tricore_elf_to_s3, measure_tricore_elf_to_s3, parse_tricore_s3_image,
    verify_registered_tricore_elf_s3_measurement,
};

const HEADER: usize = 52;
const PROGRAM_HEADER: usize = 32;

#[derive(Clone, Copy)]
struct Load<'a> {
    vaddr: u32,
    paddr: u32,
    memsz: u32,
    bytes: &'a [u8],
}

fn executable_elf(entry: u32, loads: &[Load<'_>]) -> Vec<u8> {
    let table_end = HEADER + loads.len() * PROGRAM_HEADER;
    let payload_start = (table_end + 15) & !15;
    let payload_bytes = loads.iter().map(|load| load.bytes.len()).sum::<usize>();
    let mut elf = vec![0_u8; payload_start + payload_bytes];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 1; // ELF32
    elf[5] = 1; // little endian
    elf[6] = 1; // EI_VERSION
    put_u16(&mut elf, 16, 2); // ET_EXEC
    put_u16(&mut elf, 18, 44); // EM_TRICORE
    put_u32(&mut elf, 20, 1);
    put_u32(&mut elf, 24, entry);
    put_u32(&mut elf, 28, HEADER as u32);
    put_u16(&mut elf, 40, HEADER as u16);
    put_u16(&mut elf, 42, PROGRAM_HEADER as u16);
    put_u16(&mut elf, 44, loads.len() as u16);

    let mut file_offset = payload_start;
    for (index, load) in loads.iter().enumerate() {
        let header = HEADER + index * PROGRAM_HEADER;
        put_u32(&mut elf, header, 1); // PT_LOAD
        put_u32(&mut elf, header + 4, file_offset as u32);
        put_u32(&mut elf, header + 8, load.vaddr);
        put_u32(&mut elf, header + 12, load.paddr);
        put_u32(&mut elf, header + 16, load.bytes.len() as u32);
        put_u32(&mut elf, header + 20, load.memsz);
        put_u32(&mut elf, header + 24, 5); // PF_R|PF_X
        put_u32(&mut elf, header + 28, 4);
        elf[file_offset..file_offset + load.bytes.len()].copy_from_slice(load.bytes);
        file_offset += load.bytes.len();
    }
    elf
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn load(vaddr: u32, paddr: u32, memsz: u32, bytes: &[u8]) -> Load<'_> {
    Load {
        vaddr,
        paddr,
        memsz,
        bytes,
    }
}

#[test]
fn tricore_executable_uses_physical_lma_not_virtual_address() {
    let elf = executable_elf(0x8000_0000, &[load(0x8000_0000, 0xa000_0000, 2, &[1, 2])]);
    let image = measure_tricore_elf_to_s3(&elf).unwrap();

    assert_eq!(
        std::str::from_utf8(&image.s3_bytes).unwrap(),
        "S00A0000543332504552460F\nS307A0000000010255\nS705800000007A\n"
    );
    assert_eq!(image.entry_point, 0x8000_0000);
    assert_eq!(image.segments.len(), 1);
    assert_eq!(image.segments[0].physical_address, 0xa000_0000);
    assert_eq!(image.segments[0].physical_end_address, 0xa000_0002);
    assert_eq!(image.segments[0].file_offset, 96);
    assert_eq!(image.segments[0].size, 2);
    assert_eq!(image.source_elf_sha256.as_str(), hex_sha256(&elf));
    assert_eq!(image.s3_sha256.as_str(), hex_sha256(&image.s3_bytes));
}

#[test]
fn output_is_sorted_by_lma_and_deterministic_across_program_header_order() {
    let early = load(0x8000_0040, 0xa000_0040, 1, &[0xbb]);
    let late = load(0x8000_0000, 0xa000_0000, 1, &[0xaa]);
    let first = measure_tricore_elf_to_s3(&executable_elf(0x8000_0000, &[early, late])).unwrap();
    let second = measure_tricore_elf_to_s3(&executable_elf(0x8000_0000, &[late, early])).unwrap();

    let first_text = std::str::from_utf8(&first.s3_bytes).unwrap();
    assert!(
        first_text.find("S306A0000000AA").unwrap() < first_text.find("S306A0000040BB").unwrap()
    );
    assert_eq!(first.s3_bytes, second.s3_bytes);
    assert_eq!(first.s3_sha256, second.s3_sha256);
    assert_ne!(first.source_elf_sha256, second.source_elf_sha256);
    assert_eq!(first.segments[0].physical_address, 0xa000_0000);
}

#[test]
fn splits_payload_at_fixed_s3_record_size_and_checks_every_record() {
    let payload: Vec<u8> = (0..33).collect();
    let image = measure_tricore_elf_to_s3(&executable_elf(
        0x8000_0000,
        &[load(0x8000_0000, 0xa000_0000, 33, &payload)],
    ))
    .unwrap();
    let lines: Vec<_> = std::str::from_utf8(&image.s3_bytes)
        .unwrap()
        .lines()
        .collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[0], "S00A0000543332504552460F");
    assert!(lines[1].starts_with("S325A0000000"));
    assert_eq!(lines[2], "S306A00000202019");
    assert_eq!(lines[3], "S705800000007A");
    for line in lines {
        assert_srecord_checksum(line);
    }
}

#[test]
fn rejects_zero_or_missing_file_backed_lma_and_no_coverage() {
    let zero = executable_elf(0, &[load(0x1234, 0, 1, &[1])]);
    assert_eq!(
        measure_tricore_elf_to_s3(&zero),
        Err(FirmwareImageError::MissingPhysicalAddress { index: 0 })
    );

    let mut no_coverage = executable_elf(0, &[load(0, 0xa000_0000, 1, &[1])]);
    put_u32(&mut no_coverage, HEADER, 0); // PT_NULL
    assert_eq!(
        measure_tricore_elf_to_s3(&no_coverage),
        Err(FirmwareImageError::NoLoadCoverage)
    );
}

#[test]
fn zero_sized_load_does_not_require_lma_or_contribute_coverage() {
    let elf = executable_elf(0, &[load(0x1234, 0, 0, &[])]);
    assert_eq!(
        measure_tricore_elf_to_s3(&elf),
        Err(FirmwareImageError::NoLoadCoverage)
    );
}

#[test]
fn rejects_overlapping_loads_and_invalid_load_sizes() {
    let overlapping = executable_elf(
        0,
        &[
            load(0, 0xa000_0000, 2, &[1, 2]),
            load(0, 0xa000_0001, 1, &[3]),
        ],
    );
    assert_eq!(
        measure_tricore_elf_to_s3(&overlapping),
        Err(FirmwareImageError::OverlappingLoadSegments {
            previous_index: 0,
            index: 1,
        })
    );

    let mut memsmaller = executable_elf(0, &[load(0, 0xa000_0000, 2, &[1, 2])]);
    put_u32(&mut memsmaller, HEADER + 20, 1);
    assert_invalid(measure_tricore_elf_to_s3(&memsmaller), "p_memsz is smaller");
}

#[test]
fn rejects_truncated_ranges_and_arithmetic_boundaries() {
    let mut truncated = executable_elf(0, &[load(0, 0xa000_0000, 1, &[1])]);
    put_u32(&mut truncated, HEADER + 4, u32::MAX);
    assert_invalid(measure_tricore_elf_to_s3(&truncated), "PT_LOAD file range");

    let too_high = executable_elf(0, &[load(0, u32::MAX, 2, &[1, 2])]);
    assert_invalid(
        measure_tricore_elf_to_s3(&too_high),
        "exceeds S3 address space",
    );

    let mut bad_table = executable_elf(0, &[load(0, 0xa000_0000, 1, &[1])]);
    put_u32(&mut bad_table, 28, u32::MAX);
    assert_invalid(
        measure_tricore_elf_to_s3(&bad_table),
        "program-header table",
    );
}

#[test]
fn rejects_unsupported_and_malformed_elf_headers() {
    assert!(matches!(
        measure_tricore_elf_to_s3(b"not an elf"),
        Err(FirmwareImageError::InvalidElf { .. })
    ));

    let mut elf = executable_elf(0, &[load(0, 0xa000_0000, 1, &[1])]);
    elf[4] = 2;
    assert_unsupported(measure_tricore_elf_to_s3(&elf));
    elf[4] = 1;
    put_u16(&mut elf, 16, 1);
    assert_unsupported(measure_tricore_elf_to_s3(&elf));
    put_u16(&mut elf, 16, 2);
    put_u16(&mut elf, 18, 40);
    assert_unsupported(measure_tricore_elf_to_s3(&elf));
}

#[test]
fn rejects_extended_and_excessive_program_header_counts() {
    let mut extended = executable_elf(0, &[load(0, 0xa000_0000, 1, &[1])]);
    put_u16(&mut extended, 44, u16::MAX);
    assert_invalid(measure_tricore_elf_to_s3(&extended), "e_phnum");

    let mut table_overflow = executable_elf(0, &[load(0, 0xa000_0000, 1, &[1])]);
    put_u16(&mut table_overflow, 42, u16::MAX);
    assert_invalid(measure_tricore_elf_to_s3(&table_overflow), "e_phentsize");
}

#[test]
fn input_and_output_quotas_fail_before_output_allocation() {
    let too_large = vec![0_u8; MAX_TRICORE_FIRMWARE_ELF_BYTES + 1];
    assert_eq!(
        measure_tricore_elf_to_s3(&too_large),
        Err(FirmwareImageError::InputTooLarge {
            limit: MAX_TRICORE_FIRMWARE_ELF_BYTES,
        })
    );

    // A maximum-sized accepted input can encode to more than the immutable
    // output quota. This source has one file-backed load and fails during the
    // size estimate, before the S-record Vec is reserved.
    let bytes = vec![0x5a_u8; MAX_TRICORE_FIRMWARE_ELF_BYTES - 96];
    let elf = executable_elf(0, &[load(0, 0xa000_0000, bytes.len() as u32, &bytes)]);
    assert!(elf.len() <= MAX_TRICORE_FIRMWARE_ELF_BYTES);
    assert_eq!(
        measure_tricore_elf_to_s3(&elf),
        Err(FirmwareImageError::OutputTooLarge {
            limit: MAX_TRICORE_S3_OUTPUT_BYTES,
        })
    );
}

#[test]
fn registered_measurement_and_canonical_s3_verification_bind_both_digests() {
    let elf = executable_elf(0x8000_0000, &[load(0x8000_0000, 0xa000_0000, 2, &[1, 2])]);
    let measurement = measure_tricore_elf_to_s3(&elf).unwrap();
    let parsed = parse_tricore_s3_image(&measurement.s3_bytes).unwrap();
    assert_eq!(parsed.s3_sha256, measurement.s3_sha256);
    assert_eq!(parsed.entry_point, measurement.entry_point);
    assert_eq!(parsed.records.len(), 1);
    assert_eq!(parsed.records[0].physical_address, 0xa000_0000);
    assert_eq!(parsed.records[0].payload, vec![1, 2]);
    assert_eq!(
        measure_registered_tricore_elf_to_s3(&elf, &measurement.source_elf_sha256).unwrap(),
        measurement
    );
    assert_eq!(
        verify_registered_tricore_elf_s3_measurement(
            &elf,
            &measurement.source_elf_sha256,
            &measurement.s3_bytes,
            &measurement.s3_sha256,
        )
        .unwrap(),
        measurement
    );

    let wrong_digest = measure_tricore_elf_to_s3(&executable_elf(
        0x8000_0000,
        &[load(0x8000_0000, 0xa000_0000, 2, &[3, 4])],
    ))
    .unwrap()
    .source_elf_sha256;
    assert_eq!(
        measure_registered_tricore_elf_to_s3(&elf, &wrong_digest),
        Err(FirmwareImageError::SourceDigestMismatch)
    );
    assert_eq!(
        verify_registered_tricore_elf_s3_measurement(
            &elf,
            &measurement.source_elf_sha256,
            &measurement.s3_bytes,
            &wrong_digest,
        ),
        Err(FirmwareImageError::S3DigestMismatch)
    );
}

#[test]
fn s3_parser_rejects_noncanonical_or_tampered_streams() {
    let elf = executable_elf(0x8000_0000, &[load(0x8000_0000, 0xa000_0000, 2, &[1, 2])]);
    let measurement = measure_tricore_elf_to_s3(&elf).unwrap();

    let mut lowercase = measurement.s3_bytes.clone();
    let upper_a = lowercase.iter().position(|byte| *byte == b'A').unwrap();
    lowercase[upper_a] = b'a';
    assert_invalid(parse_tricore_s3_image(&lowercase), "uppercase");
    let mut crlf = Vec::new();
    for byte in &measurement.s3_bytes {
        if *byte == b'\n' {
            crlf.push(b'\r');
        }
        crlf.push(*byte);
    }
    assert_invalid(parse_tricore_s3_image(&crlf), "LF line endings");
    let mut checksum = measurement.s3_bytes.clone();
    let position = checksum.iter().position(|byte| *byte == b'5').unwrap();
    checksum[position] = b'4';
    assert_invalid(parse_tricore_s3_image(&checksum), "checksum");

    let mut altered = measurement.s3_bytes.clone();
    let terminator = b"S705800000007A\n";
    let offset = altered.len() - terminator.len();
    altered[offset..].copy_from_slice(b"S7058000000179\n");
    let altered_digest = t32perf_model::Sha256Digest::new(hex_sha256(&altered)).unwrap();
    assert_eq!(
        verify_registered_tricore_elf_s3_measurement(
            &elf,
            &measurement.source_elf_sha256,
            &altered,
            &altered_digest,
        ),
        Err(FirmwareImageError::S3EncodingMismatch)
    );
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn assert_invalid(result: Result<impl std::fmt::Debug, FirmwareImageError>, needle: &str) {
    match result {
        Err(FirmwareImageError::InvalidElf { message }) => {
            assert!(message.contains(needle), "{message}")
        }
        other => panic!("expected invalid ELF containing {needle:?}, got {other:?}"),
    }
}

fn assert_unsupported(result: Result<impl std::fmt::Debug, FirmwareImageError>) {
    assert!(matches!(
        result,
        Err(FirmwareImageError::Unsupported { .. })
    ));
}

fn assert_srecord_checksum(line: &str) {
    assert!(line.starts_with('S'));
    let data = &line[2..];
    assert_eq!(data.len() % 2, 0);
    let bytes: Vec<u8> = (0..data.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&data[offset..offset + 2], 16).unwrap())
        .collect();
    assert_eq!(usize::from(bytes[0]) + 1, bytes.len());
    assert_eq!(bytes.into_iter().fold(0_u8, u8::wrapping_add), u8::MAX);
}
