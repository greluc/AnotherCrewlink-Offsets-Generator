//! End-to-end test of the part that had no predecessor: turning a type-info
//! slot into a byte signature the client can resolve.
//!
//! It runs against a synthetic PE rather than a 49 MB game file, so it works in
//! CI and on a machine with no Among Us installed. The fixture reproduces the
//! properties that make the real problem hard:
//!
//!   * several instructions reference the same slot, so the first anchor found
//!     is not automatically usable;
//!   * one of them is followed by identical code, so the shortest possible
//!     signature is ambiguous and has to grow;
//!   * every absolute address is covered by a base relocation, so a correct
//!     signature must wildcard all of them -- including ones belonging to
//!     *other* globals that happen to sit inside the pattern.

use acl_offsetgen::pattern::Pattern;
use acl_offsetgen::pe::{Arch, Image};
use acl_offsetgen::siggen::{Resolution, SignatureGenerator};

const IMAGE_BASE: u32 = 0x1000_0000;
const TEXT_RVA: usize = 0x1000;
const SLOT_RVA: u32 = 0x2_0100;
const OTHER_SLOT_RVA: u32 = 0x2_0200;

/// Builds a 32-bit PE with one code section, one relocation block, and the
/// given code at `TEXT_RVA`.
fn build_pe(code: &[u8], relocation_offsets: &[u16]) -> Vec<u8> {
    let optional_size: u16 = 0xe0;
    let pe = 0x80usize;
    let table = pe + 24 + optional_size as usize;
    let headers_size = 0x400usize;
    let text_raw = 0x400usize;
    let reloc_raw = 0x800usize;

    let mut file = vec![0u8; 0xc00];
    file[0] = b'M';
    file[1] = b'Z';
    file[0x3c..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
    file[pe..pe + 4].copy_from_slice(b"PE\0\0");
    file[pe + 6..pe + 8].copy_from_slice(&2u16.to_le_bytes());
    file[pe + 20..pe + 22].copy_from_slice(&optional_size.to_le_bytes());

    let opt = pe + 24;
    file[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
    file[opt + 28..opt + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    // Large enough that the type-info slots below sit inside the module; the
    // resolver rejects anything that lands outside it.
    file[opt + 56..opt + 60].copy_from_slice(&0x3_0000u32.to_le_bytes()); // SizeOfImage
    file[opt + 60..opt + 64].copy_from_slice(&(headers_size as u32).to_le_bytes());
    file[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
    let dir = opt + 96;
    file[dir + 40..dir + 44].copy_from_slice(&0x2000u32.to_le_bytes()); // reloc rva
    file[dir + 44..dir + 48].copy_from_slice(&0x40u32.to_le_bytes()); // reloc size

    // .text
    file[table..table + 5].copy_from_slice(b".text");
    file[table + 8..table + 12].copy_from_slice(&0x400u32.to_le_bytes());
    file[table + 12..table + 16].copy_from_slice(&(TEXT_RVA as u32).to_le_bytes());
    file[table + 16..table + 20].copy_from_slice(&0x400u32.to_le_bytes());
    file[table + 20..table + 24].copy_from_slice(&(text_raw as u32).to_le_bytes());
    file[table + 36..table + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    // .reloc
    let second = table + 40;
    file[second..second + 6].copy_from_slice(b".reloc");
    file[second + 8..second + 12].copy_from_slice(&0x100u32.to_le_bytes());
    file[second + 12..second + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    file[second + 16..second + 20].copy_from_slice(&0x200u32.to_le_bytes());
    file[second + 20..second + 24].copy_from_slice(&(reloc_raw as u32).to_le_bytes());
    file[second + 36..second + 40].copy_from_slice(&0x4200_0040u32.to_le_bytes());

    file[text_raw..text_raw + code.len()].copy_from_slice(code);

    // One relocation block covering page 0x1000.
    let block_size = 8 + relocation_offsets.len() * 2;
    file[reloc_raw..reloc_raw + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    file[reloc_raw + 4..reloc_raw + 8].copy_from_slice(&(block_size as u32).to_le_bytes());
    for (index, offset) in relocation_offsets.iter().enumerate() {
        let entry = (3u16 << 12) | *offset;
        let at = reloc_raw + 8 + index * 2;
        file[at..at + 2].copy_from_slice(&entry.to_le_bytes());
    }

    file
}

/// `mov eax, [abs32]`
fn mov_eax_abs(target: u32) -> Vec<u8> {
    let mut bytes = vec![0xA1];
    bytes.extend_from_slice(&(IMAGE_BASE + target).to_le_bytes());
    bytes
}

#[test]
fn generates_a_unique_signature_that_resolves_back_to_the_slot() {
    // Two identical loads of the slot, distinguished only by what follows.
    // A one-instruction signature matches both, so the generator has to grow.
    let mut code = Vec::new();
    let mut relocations = Vec::new();

    let push =
        |code: &mut Vec<u8>, relocations: &mut Vec<u16>, bytes: &[u8], reloc_at: Option<usize>| {
            if let Some(offset) = reloc_at {
                relocations.push((code.len() + offset) as u16);
            }
            code.extend_from_slice(bytes);
        };

    // site 1: mov eax,[slot] ; mov eax,[eax+0x5C] ; mov ecx,[eax]
    push(&mut code, &mut relocations, &mov_eax_abs(SLOT_RVA), Some(1));
    push(&mut code, &mut relocations, &[0x8B, 0x40, 0x5C], None);
    push(&mut code, &mut relocations, &[0x8B, 0x08], None);
    // site 2: same first two instructions, then something else
    push(&mut code, &mut relocations, &mov_eax_abs(SLOT_RVA), Some(1));
    push(&mut code, &mut relocations, &[0x8B, 0x40, 0x5C], None);
    push(&mut code, &mut relocations, &[0x90, 0x90, 0x90], None);
    // a load of a different global, to be sure we do not latch onto it
    push(
        &mut code,
        &mut relocations,
        &mov_eax_abs(OTHER_SLOT_RVA),
        Some(1),
    );
    push(&mut code, &mut relocations, &[0xC3], None);

    let file = build_pe(&code, &relocations);
    let image = Image::parse(&file).expect("synthetic PE should parse");
    assert_eq!(image.arch, Arch::X86);

    let generated = SignatureGenerator::new(&image)
        .generate(SLOT_RVA as u64)
        .expect("a signature should be generated");

    // Unique in the whole mapped image.
    let matches = generated.pattern.find_all(image.mapped(), 8);
    assert_eq!(
        matches.len(),
        1,
        "signature '{}' matched {} times",
        generated.pattern,
        matches.len()
    );

    // And it resolves to the slot with the client's arithmetic.
    assert_eq!(
        generated.resolves_to,
        Resolution::Slot(SLOT_RVA as u64),
        "the signature must resolve back to the slot it was built from"
    );
    assert_eq!(
        generated.address_offset, 0,
        "x86 signatures resolve by subtracting the module base, so nothing is added"
    );

    // It had to grow past a single instruction to become unique.
    assert!(
        generated.pattern.len() > 5,
        "expected the ambiguous first instruction to be extended, got '{}'",
        generated.pattern
    );
}

#[test]
fn absolute_addresses_are_wildcarded_so_the_signature_survives_aslr() {
    // A signature containing a literal absolute address only matches a process
    // that loaded at the preferred base. The relocation table says which bytes
    // those are, and all of them must come out as wildcards -- including the
    // unrelated global in the trailing instruction.
    let mut code = Vec::new();
    let mut relocations = Vec::new();

    relocations.push(1u16);
    code.extend_from_slice(&mov_eax_abs(SLOT_RVA));
    code.extend_from_slice(&[0x8B, 0x40, 0x5C]);
    relocations.push((code.len() + 1) as u16);
    code.extend_from_slice(&mov_eax_abs(OTHER_SLOT_RVA));
    code.extend_from_slice(&[0xC3]);

    let file = build_pe(&code, &relocations);
    let image = Image::parse(&file).expect("parse");
    let generated = SignatureGenerator::new(&image)
        .generate(SLOT_RVA as u64)
        .expect("generate");

    let text = generated.pattern.to_string();
    let literal_bytes: Vec<u8> = generated
        .pattern
        .bytes()
        .iter()
        .filter_map(|byte| *byte)
        .collect();

    for address in [IMAGE_BASE + SLOT_RVA, IMAGE_BASE + OTHER_SLOT_RVA] {
        let encoded = address.to_le_bytes();
        assert!(
            !literal_bytes.windows(4).any(|window| window == encoded),
            "signature '{text}' still spells out the relocated address 0x{address:X}"
        );
    }
}

#[test]
fn a_slot_nothing_references_is_an_error_rather_than_a_bad_signature() {
    let code = [0x90u8, 0x90, 0x90, 0xC3];
    let file = build_pe(&code, &[]);
    let image = Image::parse(&file).expect("parse");

    let error = SignatureGenerator::new(&image)
        .generate(0x2_9999)
        .expect_err("an unreferenced slot cannot produce a signature");
    assert!(error.to_string().contains("no instruction"));
}

#[test]
fn an_unrelocated_constant_that_looks_like_the_address_is_not_taken_as_an_anchor() {
    // The same 4 bytes as the slot address, but with no relocation covering
    // them: that is data, not a pointer load, and anchoring there would produce
    // a signature that breaks the moment the module is rebased.
    let mut code = Vec::new();
    code.extend_from_slice(&mov_eax_abs(SLOT_RVA)); // no relocation recorded
    code.extend_from_slice(&[0xC3]);

    let file = build_pe(&code, &[]);
    let image = Image::parse(&file).expect("parse");
    assert!(SignatureGenerator::new(&image)
        .generate(SLOT_RVA as u64)
        .is_err());
}

/// `mov eax, imm32`
fn mov_eax_imm(value: i32) -> Vec<u8> {
    let mut bytes = vec![0xB8];
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes
}

#[test]
fn generates_a_signature_over_a_literal_and_reads_it_back() {
    // The broadcast-version case: a value baked into the code rather than an
    // address, reached through a method whose RVA the dump reports.
    const VERSION: i32 = 50_663_350;
    let mut code = Vec::new();
    code.extend_from_slice(&[0x90, 0x51, 0x52, 0x53]); // distinguishing prefix
    let method = TEXT_RVA + code.len();
    code.extend_from_slice(&mov_eax_imm(VERSION));
    code.extend_from_slice(&[0xC3]);
    code.extend_from_slice(&[0xCC; 8]);

    let file = build_pe(&code, &[]);
    let image = Image::parse(&file).expect("parse");
    let generated = SignatureGenerator::new(&image)
        .generate_immediate(method as u64)
        .expect("generate");

    assert_eq!(generated.resolves_to, Resolution::Immediate(VERSION));
    assert_eq!(generated.immediate(), Some(VERSION));
    // The literal is one byte into `mov eax, imm32`, and the client reads it
    // where it lies rather than turning it into an address.
    assert_eq!(generated.pattern_offset, 1);
    assert_eq!(generated.address_offset, 0);

    let matches = generated.pattern.find_all(image.mapped(), 4);
    assert_eq!(matches.len(), 1);
    let location = matches[0] + generated.pattern_offset as usize;
    assert_eq!(image.read_i32(location), Some(VERSION));
}

#[test]
fn a_literal_signature_grows_backwards_when_forward_says_nothing() {
    // Two tiny functions that are byte-identical from the opcode onwards --
    // only what precedes them differs. Growing forward can never separate
    // them, so the generator has to extend the other way.
    let mut code = Vec::new();
    code.extend_from_slice(&[0x90, 0x90, 0x90, 0x90]); // prefix of the decoy
    code.extend_from_slice(&mov_eax_imm(1111));
    code.extend_from_slice(&[0xC3]);
    code.extend_from_slice(&[0xCC; 4]);

    code.extend_from_slice(&[0x51, 0x52, 0x53, 0x54]); // prefix of the target
    let method = TEXT_RVA + code.len();
    code.extend_from_slice(&mov_eax_imm(2222));
    code.extend_from_slice(&[0xC3]);
    code.extend_from_slice(&[0xCC; 4]);

    let file = build_pe(&code, &[]);
    let image = Image::parse(&file).expect("parse");
    let generated = SignatureGenerator::new(&image)
        .generate_immediate(method as u64)
        .expect("a backwards-grown signature should still be possible");

    assert_eq!(generated.resolves_to, Resolution::Immediate(2222));
    assert!(
        generated.pattern_offset > 1,
        "growing backwards has to move the literal further into the pattern, got {}",
        generated.pattern_offset
    );

    let matches = generated.pattern.find_all(image.mapped(), 4);
    assert_eq!(
        matches.len(),
        1,
        "signature '{}' is ambiguous",
        generated.pattern
    );
    let location = matches[0] + generated.pattern_offset as usize;
    assert_eq!(
        image.read_i32(location),
        Some(2222),
        "the shifted patternOffset must still land on the literal"
    );
}

#[test]
fn a_method_without_a_literal_is_an_error() {
    let mut code = Vec::new();
    let method = TEXT_RVA + code.len();
    code.extend_from_slice(&[0x33, 0xC0]); // xor eax, eax
    code.extend_from_slice(&[0xC3]);

    let file = build_pe(&code, &[]);
    let image = Image::parse(&file).expect("parse");
    let error = SignatureGenerator::new(&image)
        .generate_immediate(method as u64)
        .expect_err("nothing to anchor on");
    assert!(error.to_string().contains("32-bit literal"));
}

#[test]
fn the_clients_resolution_arithmetic_is_reproduced_exactly() {
    let mut code = Vec::new();
    code.extend_from_slice(&mov_eax_abs(SLOT_RVA));
    code.extend_from_slice(&[0x8B, 0x40, 0x5C, 0xC3]);
    let file = build_pe(&code, &[1]);
    let image = Image::parse(&file).expect("parse");

    let generated = SignatureGenerator::new(&image)
        .generate(SLOT_RVA as u64)
        .expect("generate");

    // Re-derive by hand, the way GameReader.findPattern does on x86:
    //   location = match + patternOffset
    //   value    = int32 at location            (already rebased at runtime)
    //   result   = value - moduleBase
    let pattern = Pattern::parse(&generated.pattern.to_string()).expect("round trip");
    let position = pattern.find_all(image.mapped(), 2)[0];
    let location = position + generated.pattern_offset as usize;
    let raw = image.read_u32(location).expect("read");
    assert_eq!(u64::from(raw) - image.image_base, SLOT_RVA as u64);
}
