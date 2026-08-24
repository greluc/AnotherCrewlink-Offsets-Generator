//! Works out `Il2CppClass::static_fields` from the `il2cpp.h` the dumper writes.
//!
//! Every chain the client walks to reach a static class goes
//! `slot -> +static_fields -> deref -> +field`. That middle number was a magic
//! constant in the old generator's base files (184 on x64, 92 on x86). It is
//! not arbitrary: it is `sizeof(Il2CppClass_1)`, which Unity changes when it
//! changes the runtime. Deriving it from the header the dumper just produced
//! means a Unity upgrade shifts the number instead of silently corrupting every
//! offset in the file.
//!
//! The parser handles exactly the subset of C that Il2CppDumper emits: flat
//! structs of scalars, pointers, and other structs declared earlier.

use std::collections::HashMap;

use crate::error::{read_to_string_lossy, Error, Result};
use crate::pe::Arch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Layout {
    size: u64,
    align: u64,
}

pub struct HeaderLayout {
    arch: Arch,
    structs: HashMap<String, Vec<(String, String)>>,
}

impl HeaderLayout {
    pub fn load(path: impl AsRef<std::path::Path>, arch: Arch) -> Result<Self> {
        let text = read_to_string_lossy(path)?;
        Ok(Self::parse(&text, arch))
    }

    pub fn parse(text: &str, arch: Arch) -> Self {
        let mut structs: HashMap<String, Vec<(String, String)>> = HashMap::new();
        let mut current: Option<(String, Vec<(String, String)>)> = None;

        for raw in text.lines() {
            let line = raw.trim();
            if let Some((name, has_body)) = struct_header(line) {
                if !has_body {
                    continue; // forward declaration
                }
                if let Some((previous, members)) = current.take() {
                    structs.insert(previous, members);
                }
                current = Some((name, Vec::new()));
                continue;
            }
            if line == "};" {
                if let Some((name, members)) = current.take() {
                    structs.insert(name, members);
                }
                continue;
            }
            if let Some((_, members)) = current.as_mut() {
                if let Some(member) = parse_member(line) {
                    members.push(member);
                }
            }
        }
        if let Some((name, members)) = current.take() {
            structs.insert(name, members);
        }

        Self { arch, structs }
    }

    /// Byte offset of `Il2CppClass::static_fields`.
    pub fn static_fields_offset(&self) -> Result<u64> {
        let offset = self
            .member_offset("Il2CppClass", "static_fields")
            .ok_or_else(|| {
                Error::malformed(
                    "il2cpp.h has no Il2CppClass::static_fields -- the dumper's header format \
                 changed and the static-field chains can no longer be derived",
                )
            })?;

        // Sanity band. Every IL2CPP version since Unity 5 lands between these,
        // and a value outside would mean the parse went wrong rather than that
        // Unity moved something.
        let pointer = self.arch.pointer_size();
        let (low, high) = (10 * pointer, 40 * pointer);
        if !(low..=high).contains(&offset) {
            return Err(Error::malformed(format!(
                "computed Il2CppClass::static_fields = {offset}, which is outside the \
                 plausible range {low}..={high} for {} -- refusing to build chains on it",
                self.arch
            )));
        }
        Ok(offset)
    }

    fn member_offset(&self, struct_name: &str, member_name: &str) -> Option<u64> {
        let members = self.structs.get(struct_name)?;
        let mut offset = 0u64;
        for (type_name, name) in members {
            let layout = self.layout_of(type_name, 0)?;
            offset = align_up(offset, layout.align);
            if name == member_name {
                return Some(offset);
            }
            offset += layout.size;
        }
        None
    }

    fn layout_of(&self, type_name: &str, depth: usize) -> Option<Layout> {
        if depth > 8 {
            return None; // cycle guard; the real header is only two levels deep
        }
        let pointer = self.arch.pointer_size();
        let type_name = type_name.trim();

        if type_name.ends_with('*') {
            return Some(Layout {
                size: pointer,
                align: pointer,
            });
        }

        let scalar = match type_name {
            "uint8_t" | "int8_t" | "char" | "bool" | "unsigned char" => Some(1),
            "uint16_t" | "int16_t" | "short" | "unsigned short" => Some(2),
            "uint32_t" | "int32_t" | "int" | "unsigned int" | "float" => Some(4),
            "uint64_t" | "int64_t" | "double" | "long long" | "unsigned long long" => Some(8),
            "size_t" | "intptr_t" | "uintptr_t" => Some(pointer),
            _ => None,
        };
        if let Some(size) = scalar {
            return Some(Layout { size, align: size });
        }

        let members = self.structs.get(type_name)?;
        let mut size = 0u64;
        let mut align = 1u64;
        for (member_type, _) in members {
            let layout = self.layout_of(member_type, depth + 1)?;
            align = align.max(layout.align);
            size = align_up(size, layout.align) + layout.size;
        }
        Some(Layout {
            size: align_up(size, align),
            align,
        })
    }
}

fn align_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    value.div_ceil(align) * align
}

/// `struct Foo` / `struct Foo;` / `union Foo`, returning whether a body follows.
fn struct_header(line: &str) -> Option<(String, bool)> {
    let rest = line
        .strip_prefix("struct ")
        .or_else(|| line.strip_prefix("union "))?;
    let name = rest
        .trim_end_matches('{')
        .trim()
        .trim_end_matches(';')
        .trim();
    if name.is_empty() || name.contains(' ') {
        return None;
    }
    Some((name.to_string(), !line.ends_with(';')))
}

/// `Il2CppClass* parent;` -> ("Il2CppClass*", "parent")
fn parse_member(line: &str) -> Option<(String, String)> {
    let line = line.split("//").next()?.trim();
    let declaration = line.strip_suffix(';')?;
    if declaration.is_empty() || declaration.contains('(') || declaration.contains('{') {
        return None;
    }
    // Arrays such as "VirtualInvokeData vtable[255]" sit after static_fields and
    // never need sizing, so they are skipped rather than modelled.
    if declaration.contains('[') {
        return None;
    }
    let declaration = declaration.strip_prefix("const ").unwrap_or(declaration);

    // Pointer stars can bind either way: "void *monitor" and "void* monitor".
    let (type_part, name_part) = declaration.rsplit_once(' ')?;
    let stars = name_part.chars().take_while(|c| *c == '*').count();
    let name = name_part.trim_start_matches('*').trim();
    if name.is_empty() {
        return None;
    }
    let mut type_name = type_part.trim().to_string();
    for _ in 0..stars {
        type_name.push('*');
    }
    Some((type_name, name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim excerpt of the header Il2CppDumper 6.7.46 writes for Among Us
    /// 2026.8.18 (metadata v31), trimmed to the structs that matter.
    const REAL_HEADER: &str = r#"
struct Il2CppType
{
    void* data;
    unsigned int bits;
};

struct Il2CppClass;

struct Il2CppObject
{
    Il2CppClass *klass;
    void *monitor;
};

struct Il2CppRuntimeInterfaceOffsetPair
{
    Il2CppClass* interfaceType;
    int32_t offset;
};
struct Il2CppClass_1
{
    void* image;
    void* gc_desc;
    const char* name;
    const char* namespaze;
    Il2CppType byval_arg;
    Il2CppType this_arg;
    Il2CppClass* element_class;
    Il2CppClass* castClass;
    Il2CppClass* declaringType;
    Il2CppClass* parent;
    void *generic_class;
    void* typeMetadataHandle;
    void* interopData;
    Il2CppClass* klass;
    void* fields;
    void* events;
    void* properties;
    void* methods;
    Il2CppClass** nestedTypes;
    Il2CppClass** implementedInterfaces;
    Il2CppRuntimeInterfaceOffsetPair* interfaceOffsets;
};

struct Il2CppClass_2
{
    Il2CppClass** typeHierarchy;
    void *unity_user_data;
    uint32_t initializationExceptionGCHandle;
};

struct Il2CppClass
{
    Il2CppClass_1 _1;
    void* static_fields;
    Il2CppRGCTXData* rgctx_data;
    Il2CppClass_2 _2;
    VirtualInvokeData vtable[255];
};
"#;

    #[test]
    fn derives_the_x86_static_fields_offset() {
        let layout = HeaderLayout::parse(REAL_HEADER, Arch::X86);
        // 19 pointers (4 before the two Il2CppTypes, 15 after) at 4 bytes, plus
        // two 8-byte Il2CppType values = 92. This is the number the working
        // hand-written x86 offsets use.
        assert_eq!(layout.static_fields_offset().expect("offset"), 92);
    }

    #[test]
    fn derives_the_x64_static_fields_offset() {
        let layout = HeaderLayout::parse(REAL_HEADER, Arch::X64);
        // Same 19 pointers at 8 bytes, plus two Il2CppType values padded to 16 = 184.
        assert_eq!(layout.static_fields_offset().expect("offset"), 184);
    }

    #[test]
    fn pointer_star_binding_does_not_matter() {
        assert_eq!(
            parse_member("Il2CppClass *klass;"),
            Some(("Il2CppClass*".into(), "klass".into()))
        );
        assert_eq!(
            parse_member("Il2CppClass* klass;"),
            Some(("Il2CppClass*".into(), "klass".into()))
        );
        assert_eq!(
            parse_member("Il2CppClass** nestedTypes;"),
            Some(("Il2CppClass**".into(), "nestedTypes".into()))
        );
    }

    #[test]
    fn arrays_and_functions_are_skipped() {
        assert_eq!(parse_member("VirtualInvokeData vtable[255];"), None);
        assert_eq!(parse_member("void (*invoke)(void);"), None);
    }

    #[test]
    fn a_header_without_the_struct_fails_loudly() {
        let layout = HeaderLayout::parse("struct Something { int x; };", Arch::X64);
        assert!(layout.static_fields_offset().is_err());
    }

    #[test]
    fn an_implausible_result_is_rejected() {
        // static_fields as the very first member would be offset 0, far below
        // the plausible band -- better to stop than to emit chains of zeroes.
        let header = "struct Il2CppClass\n{\n    void* static_fields;\n};";
        let layout = HeaderLayout::parse(header, Arch::X64);
        assert!(layout.static_fields_offset().is_err());
    }
}
