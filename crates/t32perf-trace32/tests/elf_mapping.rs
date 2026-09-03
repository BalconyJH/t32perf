use object::{Architecture, BinaryFormat, Endianness, SectionKind, write::Object};
use sha2::{Digest as _, Sha256};
use t32perf_trace32::{
    ElfExecutableRange, ElfFunctionRange, ElfMappingError, executable_scope_from_elf,
    function_ranges_from_elf, sampling_function_ranges_from_elf, validate_sampling_function_elf,
};

const ARM_THUMB_EXECUTABLE: &[u8] = include_bytes!("fixtures/elf/arm-thumb-et-exec.elf");
const ARM_THUMB_EXECUTABLE_SHA256: &str =
    "466facf0c04484b88d07e7c33dac47cc049e154b8741bd8f5dd18a1d0ea49baf";

fn relocatable_elf_fixture() -> Vec<u8> {
    let mut object = Object::new(BinaryFormat::Elf, Architecture::Arm, Endianness::Little);
    let section = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    object.append_section_data(section, &[0_u8; 4], 2);
    object.write().unwrap()
}

#[test]
fn only_executable_elf_images_are_accepted() {
    let bytes = relocatable_elf_fixture();
    assert!(matches!(
        executable_scope_from_elf(&bytes),
        Err(ElfMappingError::RequiresExecutableElf)
    ));
    assert!(matches!(
        function_ranges_from_elf(&bytes, "firmware", 1),
        Err(ElfMappingError::RequiresExecutableElf)
    ));
}

#[test]
fn maps_real_arm_thumb_executable_segments_functions_and_aliases() {
    assert_eq!(
        hex_sha256(ARM_THUMB_EXECUTABLE),
        ARM_THUMB_EXECUTABLE_SHA256
    );
    assert_eq!(
        executable_scope_from_elf(ARM_THUMB_EXECUTABLE)
            .unwrap()
            .ranges,
        [ElfExecutableRange {
            start: 0x100,
            end: 0x10c,
        }]
    );
    assert_eq!(
        function_ranges_from_elf(ARM_THUMB_EXECUTABLE, "fixture", 3).unwrap(),
        [
            ElfFunctionRange {
                function_id: "elf:fixture:0000000000000100-0000000000000102".to_owned(),
                display_name: "_start".to_owned(),
                start: 0x100,
                end: 0x102,
            },
            ElfFunctionRange {
                function_id: "elf:fixture:0000000000000102-0000000000000106".to_owned(),
                display_name: "first".to_owned(),
                start: 0x102,
                end: 0x106,
            },
            ElfFunctionRange {
                function_id: "elf:fixture:0000000000000106-000000000000010c".to_owned(),
                display_name: "second".to_owned(),
                start: 0x106,
                end: 0x10c,
            },
        ]
    );
}

#[test]
fn sampling_function_validation_accepts_real_arm_thumb_elf() {
    validate_sampling_function_elf(ARM_THUMB_EXECUTABLE).unwrap();
    assert_eq!(
        sampling_function_ranges_from_elf(ARM_THUMB_EXECUTABLE, "fixture", 3).unwrap(),
        function_ranges_from_elf(ARM_THUMB_EXECUTABLE, "fixture", 3).unwrap()
    );
}

#[test]
fn sampling_function_validation_rejects_other_elf_abis_without_changing_generic_mapping() {
    let big_endian_arm = executable_elf32(Architecture::Arm, Endianness::Big);
    assert!(executable_scope_from_elf(&big_endian_arm).is_ok());
    assert!(matches!(
        validate_sampling_function_elf(&big_endian_arm),
        Err(ElfMappingError::SamplingRequiresLittleEndian)
    ));

    let x86 = executable_elf32(Architecture::I386, Endianness::Little);
    assert!(executable_scope_from_elf(&x86).is_ok());
    assert!(matches!(
        validate_sampling_function_elf(&x86),
        Err(ElfMappingError::SamplingRequiresArmArchitecture)
    ));

    let elf64_arm = executable_elf64_arm();
    assert!(executable_scope_from_elf(&elf64_arm).is_ok());
    assert!(matches!(
        validate_sampling_function_elf(&elf64_arm),
        Err(ElfMappingError::SamplingRequiresElf32)
    ));
}

fn executable_elf32(architecture: Architecture, endian: Endianness) -> Vec<u8> {
    let machine = match architecture {
        Architecture::Arm => 40_u16,
        Architecture::I386 => 3_u16,
        _ => unreachable!(),
    };
    let mut bytes = vec![0_u8; 84];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 1;
    bytes[5] = if endian == Endianness::Little { 1 } else { 2 };
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 2, endian);
    put_u16(&mut bytes, 18, machine, endian);
    put_u32(&mut bytes, 20, 1, endian);
    put_u32(&mut bytes, 28, 52, endian);
    put_u16(&mut bytes, 40, 52, endian);
    put_u16(&mut bytes, 42, 32, endian);
    put_u16(&mut bytes, 44, 1, endian);
    put_u32(&mut bytes, 52, 1, endian);
    put_u32(&mut bytes, 60, 0x100, endian);
    put_u32(&mut bytes, 64, 4, endian);
    put_u32(&mut bytes, 68, 4, endian);
    put_u32(&mut bytes, 72, 4, endian);
    put_u32(&mut bytes, 76, 1, endian);
    put_u32(&mut bytes, 80, 4, endian);
    bytes
}

fn executable_elf64_arm() -> Vec<u8> {
    let mut bytes = vec![0_u8; 120];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 2, Endianness::Little);
    put_u16(&mut bytes, 18, 40, Endianness::Little);
    put_u32(&mut bytes, 20, 1, Endianness::Little);
    put_u64(&mut bytes, 32, 64, Endianness::Little);
    put_u16(&mut bytes, 52, 64, Endianness::Little);
    put_u16(&mut bytes, 54, 56, Endianness::Little);
    put_u16(&mut bytes, 56, 1, Endianness::Little);
    put_u32(&mut bytes, 64, 1, Endianness::Little);
    put_u32(&mut bytes, 68, 5, Endianness::Little);
    put_u64(&mut bytes, 80, 0x100, Endianness::Little);
    put_u64(&mut bytes, 96, 4, Endianness::Little);
    put_u64(&mut bytes, 104, 4, Endianness::Little);
    put_u64(&mut bytes, 112, 4, Endianness::Little);
    bytes
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16, endian: Endianness) {
    let encoded = if endian == Endianness::Little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    bytes[offset..offset + 2].copy_from_slice(&encoded);
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32, endian: Endianness) {
    let encoded = if endian == Endianness::Little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    bytes[offset..offset + 4].copy_from_slice(&encoded);
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64, endian: Endianness) {
    let encoded = if endian == Endianness::Little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    bytes[offset..offset + 8].copy_from_slice(&encoded);
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
