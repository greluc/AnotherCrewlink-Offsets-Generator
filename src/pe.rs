//! Minimal PE reader.
//!
//! We need four things out of `GameAssembly.dll`: whether it is 32- or 64-bit,
//! the preferred image base, the section table, and the base relocation table.
//! That is a few hundred lines of well-specified header walking, so it is done
//! here rather than by taking on an object-file crate.
//!
//! The important product is [`Image::mapped`]: the sections laid out at their
//! virtual addresses, which is what the game process sees and therefore what a
//! byte signature has to match. Scanning the raw file instead would give
//! offsets that mean nothing to the client.

use std::fmt;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86,
    X64,
}

impl Arch {
    pub fn pointer_size(self) -> u64 {
        match self {
            Arch::X86 => 4,
            Arch::X64 => 8,
        }
    }

    pub fn bitness(self) -> u32 {
        match self {
            Arch::X86 => 32,
            Arch::X64 => 64,
        }
    }

    pub fn dir_name(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X64 => "x64",
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.dir_name())
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_pointer: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl Section {
    pub fn is_executable(&self) -> bool {
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    pub fn contains(&self, rva: u32) -> bool {
        rva >= self.virtual_address && rva < self.virtual_address + self.virtual_size.max(1)
    }
}

pub struct Image {
    pub arch: Arch,
    pub image_base: u64,
    pub size_of_image: u32,
    pub sections: Vec<Section>,
    /// Sections laid out at their RVAs, i.e. what the loader produces.
    mapped: Vec<u8>,
    /// One bit per byte of `mapped`: set when a base relocation covers it.
    relocated: Vec<u64>,
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    data.get(offset..offset + 2)
        .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
        .ok_or_else(|| Error::malformed(format!("PE truncated reading u16 at 0x{offset:x}")))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    data.get(offset..offset + 4)
        .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
        .ok_or_else(|| Error::malformed(format!("PE truncated reading u32 at 0x{offset:x}")))
}

fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    data.get(offset..offset + 8)
        .map(|slice| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(slice);
            u64::from_le_bytes(bytes)
        })
        .ok_or_else(|| Error::malformed(format!("PE truncated reading u64 at 0x{offset:x}")))
}

impl Image {
    pub fn parse(file: &[u8]) -> Result<Self> {
        if file.get(..2) != Some(b"MZ") {
            return Err(Error::malformed("not a PE file: missing MZ signature"));
        }
        let pe_offset = u32_at(file, 0x3c)? as usize;
        if file.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
            return Err(Error::malformed("not a PE file: missing PE signature"));
        }

        let section_count = u16_at(file, pe_offset + 6)? as usize;
        let optional_size = u16_at(file, pe_offset + 20)? as usize;
        let optional = pe_offset + 24;
        let magic = u16_at(file, optional)?;

        let (arch, image_base) = match magic {
            0x10b => (Arch::X86, u32_at(file, optional + 28)? as u64),
            0x20b => (Arch::X64, u64_at(file, optional + 24)?),
            other => {
                return Err(Error::malformed(format!(
                    "unsupported PE optional header magic 0x{other:x}"
                )))
            }
        };

        // SizeOfImage and SizeOfHeaders sit at the same place in both variants.
        let size_of_image = u32_at(file, optional + 56)?;
        let size_of_headers = u32_at(file, optional + 60)?;

        // Data directory 5 is the base relocation table.
        let (dir_count_off, dir_base) = match arch {
            Arch::X86 => (optional + 92, optional + 96),
            Arch::X64 => (optional + 108, optional + 112),
        };
        let dir_count = u32_at(file, dir_count_off)? as usize;
        let reloc_dir = if dir_count > 5 {
            let entry = dir_base + 5 * 8;
            Some((u32_at(file, entry)?, u32_at(file, entry + 4)?))
        } else {
            None
        };

        let table = optional + optional_size;
        let mut sections = Vec::with_capacity(section_count);
        for index in 0..section_count {
            let base = table + index * 40;
            let raw_name = file
                .get(base..base + 8)
                .ok_or_else(|| Error::malformed("PE truncated in section table"))?;
            let name =
                String::from_utf8_lossy(raw_name.split(|byte| *byte == 0).next().unwrap_or(&[]))
                    .into_owned();
            sections.push(Section {
                name,
                virtual_size: u32_at(file, base + 8)?,
                virtual_address: u32_at(file, base + 12)?,
                raw_size: u32_at(file, base + 16)?,
                raw_pointer: u32_at(file, base + 20)?,
                characteristics: u32_at(file, base + 36)?,
            });
        }

        if size_of_image as usize > 512 * 1024 * 1024 {
            return Err(Error::malformed(format!(
                "SizeOfImage of {size_of_image} bytes is implausible for GameAssembly.dll"
            )));
        }

        let mut mapped = vec![0u8; size_of_image as usize];
        let header_bytes = (size_of_headers as usize).min(file.len()).min(mapped.len());
        mapped[..header_bytes].copy_from_slice(&file[..header_bytes]);

        for section in &sections {
            let copy = (section.raw_size as usize).min(if section.virtual_size == 0 {
                section.raw_size as usize
            } else {
                section.virtual_size as usize
            });
            let start = section.virtual_address as usize;
            let raw_start = section.raw_pointer as usize;
            let available = file.len().saturating_sub(raw_start);
            let copy = copy.min(available).min(mapped.len().saturating_sub(start));
            if copy == 0 {
                continue;
            }
            mapped[start..start + copy].copy_from_slice(&file[raw_start..raw_start + copy]);
        }

        let mut image = Self {
            arch,
            image_base,
            size_of_image,
            sections,
            mapped,
            relocated: Vec::new(),
        };
        image.relocated = image.build_relocation_bitmap(reloc_dir)?;
        Ok(image)
    }

    /// Marks every byte covered by a base relocation.
    ///
    /// This is what makes generated signatures survive ASLR. A `HIGHLOW`
    /// relocation means the loader rewrites those four bytes at load time, so a
    /// signature that spelled them out would only ever match the one process
    /// that happened to load at the preferred base. Masking exactly the
    /// relocated dwords -- rather than guessing which immediates look like
    /// addresses -- is both correct and provable from the file itself.
    fn build_relocation_bitmap(&self, dir: Option<(u32, u32)>) -> Result<Vec<u64>> {
        let words = self.mapped.len().div_ceil(64);
        let mut bitmap = vec![0u64; words];
        let Some((rva, size)) = dir else {
            return Ok(bitmap);
        };
        if rva == 0 || size == 0 {
            return Ok(bitmap);
        }

        let mut cursor = rva as usize;
        let end = (rva as usize)
            .saturating_add(size as usize)
            .min(self.mapped.len());
        while cursor + 8 <= end {
            let page_rva = u32_at(&self.mapped, cursor)?;
            let block_size = u32_at(&self.mapped, cursor + 4)? as usize;
            if block_size < 8 || cursor + block_size > end {
                break;
            }
            let entries = (block_size - 8) / 2;
            for index in 0..entries {
                let entry = u16_at(&self.mapped, cursor + 8 + index * 2)?;
                let kind = entry >> 12;
                let offset = (entry & 0x0fff) as u32;
                // 3 = HIGHLOW (4 bytes, x86), 10 = DIR64 (8 bytes, x64).
                let width = match kind {
                    3 => 4usize,
                    10 => 8usize,
                    _ => continue,
                };
                let target = page_rva as usize + offset as usize;
                for byte in target..(target + width).min(self.mapped.len()) {
                    bitmap[byte / 64] |= 1u64 << (byte % 64);
                }
            }
            cursor += block_size;
        }
        Ok(bitmap)
    }

    pub fn mapped(&self) -> &[u8] {
        &self.mapped
    }

    pub fn is_relocated(&self, rva: usize) -> bool {
        self.relocated
            .get(rva / 64)
            .is_some_and(|word| word & (1u64 << (rva % 64)) != 0)
    }

    /// True when any byte of `[rva, rva+len)` is subject to a relocation.
    pub fn range_relocated(&self, rva: usize, len: usize) -> bool {
        (rva..rva + len).any(|byte| self.is_relocated(byte))
    }

    pub fn read_u32(&self, rva: usize) -> Option<u32> {
        self.mapped
            .get(rva..rva + 4)
            .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    pub fn read_i32(&self, rva: usize) -> Option<i32> {
        self.read_u32(rva).map(|value| value as i32)
    }

    pub fn section_of(&self, rva: u32) -> Option<&Section> {
        self.sections.iter().find(|section| section.contains(rva))
    }

    /// Executable sections, in file order. For Among Us this is `.text` (the
    /// IL2CPP runtime) and `il2cpp` (the compiled game code) -- the game's own
    /// static accesses live almost entirely in the latter, which is why
    /// searching only `.text` finds nothing.
    pub fn code_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections
            .iter()
            .filter(|section| section.is_executable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a tiny but structurally valid 32-bit PE with one code section and
    /// one relocation, so the mapping and bitmap logic can be tested without a
    /// 49 MB game file.
    pub(crate) fn synthetic_x86() -> Vec<u8> {
        let mut file = vec![0u8; 0x600];
        file[0] = b'M';
        file[1] = b'Z';
        let pe = 0x80usize;
        file[0x3c..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
        file[pe..pe + 4].copy_from_slice(b"PE\0\0");
        file[pe + 6..pe + 8].copy_from_slice(&2u16.to_le_bytes()); // sections
        let optional_size = 0xe0u16;
        file[pe + 20..pe + 22].copy_from_slice(&optional_size.to_le_bytes());
        let opt = pe + 24;
        file[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        file[opt + 28..opt + 32].copy_from_slice(&0x1000_0000u32.to_le_bytes()); // ImageBase
        file[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
        file[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        file[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        let dir = opt + 96;
        file[dir + 5 * 8..dir + 5 * 8 + 4].copy_from_slice(&0x2000u32.to_le_bytes()); // reloc rva
        file[dir + 5 * 8 + 4..dir + 5 * 8 + 8].copy_from_slice(&0x10u32.to_le_bytes()); // reloc size

        let table = opt + optional_size as usize;
        // .text at rva 0x1000, raw 0x200
        file[table..table + 5].copy_from_slice(b".text");
        file[table + 8..table + 12].copy_from_slice(&0x100u32.to_le_bytes()); // vsize
        file[table + 12..table + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // rva
        file[table + 16..table + 20].copy_from_slice(&0x200u32.to_le_bytes()); // rawsize
        file[table + 20..table + 24].copy_from_slice(&0x200u32.to_le_bytes()); // rawptr
        file[table + 36..table + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        // .reloc at rva 0x2000, raw 0x400
        let second = table + 40;
        file[second..second + 6].copy_from_slice(b".reloc");
        file[second + 8..second + 12].copy_from_slice(&0x100u32.to_le_bytes());
        file[second + 12..second + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        file[second + 16..second + 20].copy_from_slice(&0x200u32.to_le_bytes());
        file[second + 20..second + 24].copy_from_slice(&0x400u32.to_le_bytes());
        file[second + 36..second + 40].copy_from_slice(&0x4200_0040u32.to_le_bytes());

        // Code: mov eax, [0x10001040]  (A1 40 10 00 10) at rva 0x1000
        file[0x200..0x205].copy_from_slice(&[0xA1, 0x40, 0x10, 0x00, 0x10]);

        // Relocation block: page 0x1000, one HIGHLOW at offset 1 (the abs32).
        file[0x400..0x404].copy_from_slice(&0x1000u32.to_le_bytes());
        file[0x404..0x408].copy_from_slice(&10u32.to_le_bytes()); // block size
        file[0x408..0x40a].copy_from_slice(&((3u16 << 12) | 1u16).to_le_bytes());

        file
    }

    #[test]
    fn parses_and_maps() {
        let image = Image::parse(&synthetic_x86()).expect("parse");
        assert_eq!(image.arch, Arch::X86);
        assert_eq!(image.image_base, 0x1000_0000);
        assert_eq!(image.sections.len(), 2);
        assert_eq!(
            &image.mapped()[0x1000..0x1005],
            &[0xA1, 0x40, 0x10, 0x00, 0x10]
        );
        assert_eq!(image.code_sections().count(), 1);
    }

    #[test]
    fn relocation_bitmap_covers_the_abs32() {
        let image = Image::parse(&synthetic_x86()).expect("parse");
        assert!(
            !image.is_relocated(0x1000),
            "opcode byte must not be marked"
        );
        for byte in 0x1001..0x1005 {
            assert!(
                image.is_relocated(byte),
                "byte 0x{byte:x} should be relocated"
            );
        }
        assert!(!image.is_relocated(0x1005));
        assert!(image.range_relocated(0x1000, 5));
        assert!(!image.range_relocated(0x1005, 4));
    }

    #[test]
    fn rejects_non_pe() {
        assert!(Image::parse(b"not a pe at all").is_err());
    }
}
