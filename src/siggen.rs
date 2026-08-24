//! Generates the byte signatures the client uses to locate static classes.
//!
//! This is the piece the old generator never had. Its base files carried the
//! signatures as literals, so every Among Us rebuild meant a disassembler
//! session by hand -- which is why the automated pipeline stopped producing
//! anything after August 2024 while the offsets repo carried on by hand.
//!
//! # How it works
//!
//! For each type, `script.json` gives the RVA of the global slot holding its
//! `Il2CppClass*`. Any instruction in the binary that loads that slot is a
//! usable anchor, so we do not need to recognise a particular accessor method:
//!
//!   1. find every instruction whose memory operand resolves to the slot;
//!   2. take one, and start the signature at that instruction with the
//!      address field wildcarded;
//!   3. append whole instructions until the pattern matches exactly once in
//!      the mapped image;
//!   4. resolve the finished signature the way the client will, and check it
//!      lands back on the slot we started from.
//!
//! Step 4 is what makes the output trustworthy: a signature is only emitted
//! after it has been shown to produce the right address by the same arithmetic
//! `GameReader.findPattern` performs.
//!
//! # Wildcarding
//!
//! Anything the loader or linker may rewrite has to be a wildcard, or the
//! signature only matches the one process that happened to load at the
//! preferred image base:
//!
//!   * bytes covered by a base relocation (this is every absolute address on
//!     x86, taken from the PE's own `.reloc` table rather than guessed);
//!   * RIP-relative displacements on x64;
//!   * branch and call targets.
//!
//! Everything else stays literal, because literal bytes are what make a
//! signature specific.

use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind};

use crate::error::{Error, Result};
use crate::pattern::Pattern;
use crate::pe::{Arch, Image};

/// Longest signature we are willing to emit. Past this the pattern is covering
/// so much code that the next game build is bound to shift something inside it.
const MAX_SIGNATURE_BYTES: usize = 96;

/// How many anchor instructions to try before giving up on a type.
const MAX_CANDIDATES: usize = 24;

/// Bytes prepended per step when a signature has to grow backwards.
const BACKWARD_STEP: usize = 4;

/// Cap on match positions collected while probing.
///
/// The growth loop only ever filters this set, so it has to start out complete
/// -- a truncated set could shrink to one entry while other matches sat beyond
/// the cut and the signature would look unique when it is not. Hitting the cap
/// is therefore treated as an error, not as a result. Real anchors land in the
/// low hundreds of thousands at worst (a one-literal-byte opcode across 33 MB
/// of code), so this is a guard against pathology rather than a working limit.
const MATCH_PROBE_CAP: usize = 2_000_000;

/// What a signature is supposed to point at, and therefore how it is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expectation {
    /// A global holding an `Il2CppClass*`. The client turns the field into an
    /// address (RIP-relative on x64, absolute minus module base on x86).
    Slot(u64),
    /// A literal baked into the code. The client reads the field as an `int`
    /// and uses the value directly -- `findPattern`'s `getLocation` path.
    Immediate(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    Slot(u64),
    Immediate(i32),
}

#[derive(Debug, Clone)]
pub struct GeneratedSignature {
    pub pattern: Pattern,
    pub pattern_offset: i64,
    pub address_offset: i64,
    /// What the finished signature actually produced, recomputed with the
    /// client's arithmetic rather than taken on trust.
    pub resolves_to: Resolution,
    /// RVA of the anchor instruction, for diagnostics.
    pub anchor_rva: u64,
    pub literal_bytes: usize,
}

impl GeneratedSignature {
    pub fn describe(&self) -> String {
        format!(
            "{} bytes ({} literal) anchored at 0x{:X}",
            self.pattern.len(),
            self.literal_bytes,
            self.anchor_rva
        )
    }

    pub fn immediate(&self) -> Option<i32> {
        match self.resolves_to {
            Resolution::Immediate(value) => Some(value),
            Resolution::Slot(_) => None,
        }
    }
}

pub struct SignatureGenerator<'a> {
    image: &'a Image,
}

impl<'a> SignatureGenerator<'a> {
    pub fn new(image: &'a Image) -> Self {
        Self { image }
    }

    /// Builds a signature that resolves to `slot_rva`.
    pub fn generate(&self, slot_rva: u64) -> Result<GeneratedSignature> {
        let candidates = self.find_anchors(slot_rva);
        if candidates.is_empty() {
            return Err(Error::malformed(format!(
                "no instruction in any code section loads the type-info slot at 0x{slot_rva:X}; \
                 the type exists in the metadata but its class pointer is never read, so there \
                 is nothing to anchor a signature to"
            )));
        }

        let mut best: Option<GeneratedSignature> = None;
        let mut last_error = None;

        for anchor in candidates.into_iter().take(MAX_CANDIDATES) {
            match self.grow(&anchor, Expectation::Slot(slot_rva)) {
                Ok(signature) => {
                    let better = best
                        .as_ref()
                        .is_none_or(|current| signature.pattern.len() < current.pattern.len());
                    if better {
                        best = Some(signature);
                    }
                    // A short unique signature is as good as this gets; stop
                    // rather than disassembling another twenty candidates.
                    if best.as_ref().is_some_and(|found| found.pattern.len() <= 24) {
                        break;
                    }
                }
                Err(error) => last_error = Some(error),
            }
        }

        best.ok_or_else(|| {
            last_error.unwrap_or_else(|| {
                Error::malformed(format!(
                    "could not build a unique signature for the slot at 0x{slot_rva:X} \
                     within {MAX_SIGNATURE_BYTES} bytes"
                ))
            })
        })
    }

    /// Builds a signature over a 32-bit literal inside a known method.
    ///
    /// This is how the broadcast-version pattern is produced. It cannot be
    /// anchored on a type-info slot -- there is no metadata object involved,
    /// only a number the compiler baked into the code -- but the method that
    /// returns it does have an address, and `dump.cs` reports it.
    /// `Constants.GetBroadcastVersion` compiles to `mov eax, <version>; ret` on
    /// both architectures, so the literal is one byte into the method.
    ///
    /// Such a method is tiny and followed by alignment padding, so the pattern
    /// almost always has to grow backwards into whatever precedes it; see
    /// [`Self::grow`].
    pub fn generate_immediate(&self, method_rva: u64) -> Result<GeneratedSignature> {
        let start = method_rva as usize;
        let mut cursor = start;

        // Scan a few instructions rather than only the first: a different
        // compiler could emit a prologue before loading the constant.
        for _ in 0..8 {
            let Some(instruction) = self.decode_at(cursor) else {
                break;
            };
            let length = instruction.len();
            if length == 0 {
                break;
            }

            if let Some(value) = immediate32(&instruction) {
                let bytes = &self.image.mapped()[cursor..cursor + length];
                if let Some(field_offset) = find_immediate_field(bytes, length, value) {
                    let anchor = Anchor {
                        start: cursor,
                        length,
                        field_offset,
                        quality: 0,
                    };
                    return self.grow(&anchor, Expectation::Immediate(value));
                }
            }
            cursor += length;
        }

        Err(Error::malformed(format!(
            "the method at 0x{method_rva:X} does not start with an instruction carrying a \
             32-bit literal, so there is nothing to anchor a signature on"
        )))
    }

    /// Instruction starts whose memory operand points at `slot_rva`.
    ///
    /// Found by locating the address field first and then decoding backwards,
    /// which is far cheaper and more reliable than a linear sweep of 32 MB of
    /// code that has data interleaved in it.
    fn find_anchors(&self, slot_rva: u64) -> Vec<Anchor> {
        let mapped = self.image.mapped();
        let mut anchors = Vec::new();

        for section in self.image.code_sections() {
            let start = section.virtual_address as usize;
            let end = (start + section.virtual_size as usize).min(mapped.len());
            if end <= start + 4 {
                continue;
            }

            for field in start..end - 4 {
                if !self.field_points_at(field, slot_rva) {
                    continue;
                }
                if let Some(anchor) = self.decode_backwards(field, slot_rva) {
                    anchors.push(anchor);
                    if anchors.len() >= MAX_CANDIDATES * 4 {
                        return self.rank(anchors);
                    }
                }
            }
        }
        self.rank(anchors)
    }

    fn field_points_at(&self, field_rva: usize, slot_rva: u64) -> bool {
        match self.image.arch {
            Arch::X86 => {
                // Absolute address, and the loader must be rewriting it --
                // an unrelocated dword that happens to equal the address is a
                // constant, not a pointer load.
                let Some(value) = self.image.read_u32(field_rva) else {
                    return false;
                };
                value as u64 == self.image.image_base + slot_rva
                    && self.image.is_relocated(field_rva)
            }
            Arch::X64 => {
                let Some(displacement) = self.image.read_i32(field_rva) else {
                    return false;
                };
                let end = field_rva as i64 + 4;
                end + displacement as i64 == slot_rva as i64
            }
        }
    }

    /// Finds the instruction that owns the address field at `field_rva`.
    fn decode_backwards(&self, field_rva: usize, slot_rva: u64) -> Option<Anchor> {
        let mapped = self.image.mapped();
        // x86/x64 instructions top out at 15 bytes, and the field is the last
        // thing in the encoding for the loads we want, so the start is within
        // 15 bytes before it.
        let earliest = field_rva.saturating_sub(15);
        for start in (earliest..field_rva).rev() {
            let mut decoder = Decoder::with_ip(
                self.image.arch.bitness(),
                &mapped[start..(start + 16).min(mapped.len())],
                start as u64,
                DecoderOptions::NONE,
            );
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                continue;
            }
            // Require the address to be the instruction's final field. That
            // rules out forms with a trailing immediate (`mov [addr], imm32`)
            // and keeps us on plain loads, which are both the common case and
            // the stable one.
            if instruction.next_ip() != (field_rva + 4) as u64 {
                continue;
            }
            if !self.instruction_targets(&instruction, slot_rva) {
                continue;
            }
            return Some(Anchor {
                start,
                length: instruction.len(),
                field_offset: field_rva - start,
                quality: anchor_quality(&instruction),
            });
        }
        None
    }

    fn instruction_targets(&self, instruction: &Instruction, slot_rva: u64) -> bool {
        match self.image.arch {
            Arch::X86 => {
                instruction.memory_displacement64() == self.image.image_base + slot_rva
                    && instruction.memory_base() == iced_x86::Register::None
                    && instruction.memory_index() == iced_x86::Register::None
            }
            Arch::X64 => {
                instruction.is_ip_rel_memory_operand()
                    && instruction.ip_rel_memory_address() == slot_rva
            }
        }
    }

    fn rank(&self, mut anchors: Vec<Anchor>) -> Vec<Anchor> {
        anchors.sort_by_key(|anchor| (anchor.quality, anchor.start));
        anchors
    }

    /// Grows a signature from `anchor` until it matches exactly once.
    fn grow(&self, anchor: &Anchor, expected: Expectation) -> Result<GeneratedSignature> {
        let mapped = self.image.mapped();
        let target = describe_expectation(expected);

        let mut pattern = Pattern::new(self.mask_instruction(
            anchor.start,
            anchor.length,
            Some(anchor.field_offset),
        ));

        let mut positions = pattern.find_all(mapped, MATCH_PROBE_CAP);
        if positions.len() >= MATCH_PROBE_CAP {
            return Err(Error::malformed(format!(
                "the anchor instruction at 0x{:X} is too generic to start a signature from \
                 ({MATCH_PROBE_CAP}+ matches)",
                anchor.start
            )));
        }

        let mut start = anchor.start;
        let mut cursor = anchor.start + anchor.length;
        let mut field_offset = anchor.field_offset;

        while positions.len() != 1 {
            if positions.is_empty() {
                // Cannot happen -- the anchor itself matches -- but never loop
                // on a contradiction.
                return Err(Error::malformed(format!(
                    "signature for {target} stopped matching its own anchor"
                )));
            }
            if pattern.len() >= MAX_SIGNATURE_BYTES {
                return Err(Error::malformed(format!(
                    "signature for {target} was still ambiguous after {MAX_SIGNATURE_BYTES} \
                     bytes ({} candidate sites remained)",
                    positions.len()
                )));
            }

            // Forward first: appending whole instructions keeps the pattern
            // readable and leaves patternOffset where it started.
            let before = positions.len();
            if let Some(next) = self.decode_at(cursor) {
                let length = next.len();
                if length > 0 && cursor + length <= mapped.len() {
                    for byte in self.mask_instruction(cursor, length, None) {
                        pattern.push(byte);
                    }
                    pattern.retain_matches(mapped, &mut positions);
                    cursor += length;
                    if positions.len() < before {
                        continue;
                    }
                    // Appending that instruction ruled nothing out. Carrying on
                    // forward would spend the whole length budget on bytes the
                    // other candidates share, so try the other direction.
                }
            }

            // Either nothing decodable ahead, or what is ahead does not
            // distinguish this site from the others. Both are normal for a tiny
            // function such as `mov eax, imm32; ret` followed by alignment
            // padding: every other tiny function looks identical from there on.
            //
            // Extending backwards is the way out -- the pattern is matched as
            // bytes, so it need not begin on an instruction boundary -- but it
            // is only worth it when there is no alternative anchor. Reaching
            // back past the start of a function couples the signature to
            // whatever the linker happened to place before it, and for a
            // type-info slot there are usually dozens of other sites to try
            // instead. So a slot gives up here and lets the next candidate run;
            // a literal, which has exactly one anchor, reaches backwards.
            if !allows_backward_growth(expected) {
                return Err(Error::malformed(format!(
                    "the anchor at 0x{:X} cannot be made unique by growing forwards \
                     ({} candidate sites remained)",
                    anchor.start,
                    positions.len()
                )));
            }

            let step = BACKWARD_STEP.min(start);
            if step == 0 {
                return Err(Error::malformed(format!(
                    "signature for {target} is ambiguous and cannot be extended in either \
                     direction ({} candidate sites)",
                    positions.len()
                )));
            }
            start -= step;
            field_offset += step;
            let mut prefix = self.mask_bytes(start, step);
            prefix.extend(pattern.bytes().iter().copied());
            pattern = Pattern::new(prefix);

            // Candidate starts move with the pattern; anything that would run
            // off the front of the image is not a candidate any more.
            positions = positions
                .into_iter()
                .filter_map(|position| position.checked_sub(step))
                .filter(|position| pattern.matches_at(mapped, *position))
                .collect();
        }

        let match_start = positions[0];
        let pattern_offset = field_offset as i64;
        let address_offset = match expected {
            // The client adds the field value to (match + patternOffset) and
            // then this, so it has to complete the instruction: RIP-relative
            // displacements are measured from the end of the instruction, four
            // bytes past the start of the displacement. On x86 it subtracts the
            // module base from the absolute value instead, so nothing is added.
            Expectation::Slot(_) => match self.image.arch {
                Arch::X64 => 4,
                Arch::X86 => 0,
            },
            // The immediate is read where it lies, on both architectures.
            Expectation::Immediate(_) => 0,
        };

        let resolves_to = match expected {
            Expectation::Slot(slot_rva) => {
                let resolved =
                    self.resolve_like_the_client(match_start, pattern_offset, address_offset)?;
                if resolved != slot_rva {
                    return Err(Error::malformed(format!(
                        "generated signature resolves to 0x{resolved:X} but the slot is at \
                         0x{slot_rva:X} -- refusing to emit it"
                    )));
                }
                Resolution::Slot(resolved)
            }
            Expectation::Immediate(value) => {
                let read = self.read_immediate(match_start, pattern_offset, address_offset)?;
                if read != value {
                    return Err(Error::malformed(format!(
                        "generated signature reads {read} but the immediate is {value} -- \
                         refusing to emit it"
                    )));
                }
                Resolution::Immediate(read)
            }
        };

        Ok(GeneratedSignature {
            literal_bytes: pattern.literal_count(),
            pattern,
            pattern_offset,
            address_offset,
            resolves_to,
            anchor_rva: anchor.start as u64,
        })
    }

    /// The `getLocation` path of `findPattern`: the field is read as an `int`
    /// at `match + patternOffset + addressOffset` and used as-is.
    pub fn read_immediate(
        &self,
        match_start: usize,
        pattern_offset: i64,
        address_offset: i64,
    ) -> Result<i32> {
        let location = match_start as i64 + pattern_offset + address_offset;
        if location < 0 {
            return Err(Error::malformed(
                "signature location is before the start of the module",
            ));
        }
        self.image
            .read_i32(location as usize)
            .ok_or_else(|| Error::malformed("signature match points outside the image"))
    }

    /// Raw bytes with relocated ones wildcarded, without decoding.
    ///
    /// Used when extending backwards, where instruction boundaries are unknown.
    /// Relocations are the only thing that has to be masked for correctness --
    /// they are what the loader rewrites when the module is rebased. Everything
    /// else is stable for the lifetime of the build the signature was made for.
    fn mask_bytes(&self, rva: usize, length: usize) -> Vec<Option<u8>> {
        self.image.mapped()[rva..rva + length]
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                if self.image.is_relocated(rva + index) {
                    None
                } else {
                    Some(*byte)
                }
            })
            .collect()
    }

    /// Reproduces `GameReader.findPattern` exactly, as an independent check.
    pub fn resolve_like_the_client(
        &self,
        match_start: usize,
        pattern_offset: i64,
        address_offset: i64,
    ) -> Result<u64> {
        let location = match_start as i64 + pattern_offset;
        let raw = self
            .image
            .read_u32(location as usize)
            .ok_or_else(|| Error::malformed("signature match points outside the image"))?;

        let resolved = match self.image.arch {
            Arch::X64 => raw as i32 as i64 + location + address_offset,
            Arch::X86 => raw as i64 - self.image.image_base as i64,
        };
        if resolved < 0 || resolved as u64 >= self.image.size_of_image as u64 {
            return Err(Error::malformed(format!(
                "signature resolves to 0x{resolved:X}, which is outside the module"
            )));
        }
        Ok(resolved as u64)
    }

    fn decode_at(&self, rva: usize) -> Option<Instruction> {
        let mapped = self.image.mapped();
        if rva >= mapped.len() {
            return None;
        }
        let mut decoder = Decoder::with_ip(
            self.image.arch.bitness(),
            &mapped[rva..(rva + 16).min(mapped.len())],
            rva as u64,
            DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            None
        } else {
            Some(instruction)
        }
    }

    /// Instruction bytes with everything load-time-variable wildcarded.
    fn mask_instruction(
        &self,
        rva: usize,
        length: usize,
        force_wildcard_at: Option<usize>,
    ) -> Vec<Option<u8>> {
        let mapped = self.image.mapped();
        let mut bytes: Vec<Option<u8>> = mapped[rva..rva + length]
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                if self.image.is_relocated(rva + index) {
                    None
                } else {
                    Some(*byte)
                }
            })
            .collect();

        if let Some(offset) = force_wildcard_at {
            for slot in bytes.iter_mut().skip(offset).take(4) {
                *slot = None;
            }
        }

        if let Some(instruction) = self.decode_at(rva) {
            if instruction.len() == length {
                for field in variable_fields(&instruction, &mapped[rva..rva + length], rva) {
                    for slot in bytes.iter_mut().skip(field.0).take(field.1) {
                        *slot = None;
                    }
                }
            }
        }
        bytes
    }
}

#[derive(Debug, Clone, Copy)]
struct Anchor {
    start: usize,
    length: usize,
    field_offset: usize,
    quality: u8,
}

/// Lower is better. A plain register load is the shape the hand-written
/// signatures used and the one least likely to be reshuffled by the optimiser.
fn anchor_quality(instruction: &Instruction) -> u8 {
    let is_mov = instruction.mnemonic() == iced_x86::Mnemonic::Mov;
    let loads_into_register = instruction.op0_kind() == OpKind::Register
        && instruction.op_count() == 2
        && instruction.op1_kind() == OpKind::Memory;
    match (is_mov, loads_into_register) {
        (true, true) => 0,
        (false, true) => 1,
        (true, false) => 2,
        _ => 3,
    }
}

/// Byte ranges inside one instruction that a different build may change:
/// RIP-relative displacements and branch/call targets. Returned as
/// `(offset, length)` pairs relative to the instruction start.
///
/// The field is located by arithmetic rather than by asking the decoder for an
/// encoding offset: try each candidate position and keep the one that
/// reproduces the target the decoder reported. That is exact, and it does not
/// depend on how the instruction happens to be encoded.
fn variable_fields(instruction: &Instruction, bytes: &[u8], rva: usize) -> Vec<(usize, usize)> {
    let mut fields = Vec::new();
    let length = instruction.len();
    let end = (rva + length) as i64;

    if instruction.is_ip_rel_memory_operand() {
        let target = instruction.ip_rel_memory_address() as i64;
        if let Some(offset) = find_relative_field(bytes, length, 4, end, target) {
            fields.push((offset, 4));
        }
    }

    let branch_target = match instruction.op0_kind() {
        OpKind::NearBranch16 => Some(instruction.near_branch16() as i64),
        OpKind::NearBranch32 => Some(instruction.near_branch32() as i64),
        OpKind::NearBranch64 => Some(instruction.near_branch64() as i64),
        _ => None,
    };
    if let Some(target) = branch_target {
        for width in [4usize, 2, 1] {
            if let Some(offset) = find_relative_field(bytes, length, width, end, target) {
                fields.push((offset, width));
                break;
            }
        }
    }

    fields
}

/// Whether a stuck signature may reach back before its anchor.
///
/// Only when there is no second anchor to fall back on. See the comment at the
/// call site for why that distinction matters.
fn allows_backward_growth(expected: Expectation) -> bool {
    match expected {
        Expectation::Slot(_) => false,
        Expectation::Immediate(_) => true,
    }
}

fn describe_expectation(expected: Expectation) -> String {
    match expected {
        Expectation::Slot(rva) => format!("the slot at 0x{rva:X}"),
        Expectation::Immediate(value) => format!("the literal {value}"),
    }
}

/// The 32-bit literal an instruction carries, if it has exactly one.
fn immediate32(instruction: &Instruction) -> Option<i32> {
    for index in 0..instruction.op_count() {
        if instruction.op_kind(index) == OpKind::Immediate32 {
            return Some(instruction.immediate32() as i32);
        }
    }
    None
}

/// Byte offset of a literal inside an instruction's encoding.
///
/// Searched from the back because immediates are encoded last; an earlier
/// coincidental match would point at the wrong bytes.
fn find_immediate_field(bytes: &[u8], length: usize, value: i32) -> Option<usize> {
    if length < 4 {
        return None;
    }
    let encoded = value.to_le_bytes();
    (0..=length - 4)
        .rev()
        .find(|offset| bytes[*offset..*offset + 4] == encoded)
}

fn find_relative_field(
    bytes: &[u8],
    length: usize,
    width: usize,
    end: i64,
    target: i64,
) -> Option<usize> {
    if length < width {
        return None;
    }
    // Search from the back: displacements and relatives sit late in the
    // encoding, and the last match is the real field if an earlier byte
    // sequence coincidentally works out.
    for offset in (0..=length - width).rev() {
        let slice = &bytes[offset..offset + width];
        let value = match width {
            1 => slice[0] as i8 as i64,
            2 => i16::from_le_bytes([slice[0], slice[1]]) as i64,
            4 => i32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]) as i64,
            _ => return None,
        };
        if end + value == target {
            return Some(offset);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locates_a_rel32_branch_field() {
        // E8 rel32: call from rva 0x1000, length 5, target 0x1100.
        let bytes = [0xE8, 0xFB, 0x00, 0x00, 0x00];
        let end = 0x1005i64;
        assert_eq!(find_relative_field(&bytes, 5, 4, end, 0x1100), Some(1));
    }

    #[test]
    fn locates_a_rel8_branch_field() {
        // EB 10: jmp short from 0x2000, length 2, target 0x2012.
        let bytes = [0xEB, 0x10];
        assert_eq!(find_relative_field(&bytes, 2, 1, 0x2002, 0x2012), Some(1));
    }

    #[test]
    fn reports_no_field_when_nothing_fits() {
        let bytes = [0x90, 0x90, 0x90, 0x90];
        assert_eq!(find_relative_field(&bytes, 4, 4, 0x1004, 0x9999), None);
    }
}
