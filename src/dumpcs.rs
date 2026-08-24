//! Index of `dump.cs`: every class, every field, every offset.
//!
//! Replaces the old "find the line saying `class Foo `, then look at the next
//! 200 lines" approach. That window silently returned -1 for anything further
//! down, and Among Us classes have outgrown it -- in the 2026.8.18 dump
//! `PlayerControl` spans 597 lines, `CosmeticsLayer` 445, `InnerNetClient` 434.
//! Here the whole file is read once into a map, so a field is either found or
//! genuinely absent.
//!
//! Two details the format forces on us:
//!
//!   * Nested types appear as their own top-level blocks named `Outer.Inner`
//!     (`Il2CppExecutor::GetTypeDefName` prefixes the declaring type), which is
//!     why `NetworkedPlayerInfo.PlayerOutfit` is a valid lookup key.
//!   * Static and instance fields live in the same block but in *different*
//!     offset spaces -- static offsets are relative to the class's
//!     `static_fields` block. `GameData` has a static `RoundsPlayedInSession`
//!     at +16 and an instance `AllPlayers` also at +16. Asking for the wrong
//!     one gives a plausible number that points at nothing.

use std::collections::HashMap;

use crate::error::{read_to_string_lossy, Result};

#[derive(Debug, Clone)]
pub struct Field {
    pub offset: i64,
    pub is_static: bool,
    pub type_name: String,
}

#[derive(Debug, Default, Clone)]
pub struct Class {
    /// Declaration order preserved: useful when reporting near-misses.
    pub fields: Vec<(String, Field)>,
    pub line_span: usize,
}

impl Class {
    /// Instance field by name, falling back to a static of the same name.
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields
            .iter()
            .find(|(field_name, field)| field_name == name && !field.is_static)
            .or_else(|| {
                self.fields
                    .iter()
                    .find(|(field_name, _)| field_name == name)
            })
            .map(|(_, field)| field)
    }

    pub fn static_field(&self, name: &str) -> Option<&Field> {
        self.fields
            .iter()
            .find(|(field_name, field)| field_name == name && field.is_static)
            .map(|(_, field)| field)
    }

    pub fn field_names(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().map(|(name, _)| name.as_str())
    }
}

#[derive(Debug, Default)]
pub struct Dump {
    classes: HashMap<String, Class>,
}

impl Dump {
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let text = read_to_string_lossy(path)?;
        Ok(Self::parse(&text))
    }

    pub fn parse(text: &str) -> Self {
        let mut classes: HashMap<String, Class> = HashMap::new();
        let mut current: Option<(String, Class)> = None;

        for line in text.lines() {
            if let Some(name) = parse_type_declaration(line) {
                if let Some((previous_name, previous)) = current.take() {
                    classes.insert(previous_name, previous);
                }
                current = Some((name, Class::default()));
                continue;
            }
            if let Some((_, class)) = current.as_mut() {
                class.line_span += 1;
                if let Some((name, field)) = parse_field(line) {
                    class.fields.push((name, field));
                }
            }
        }
        if let Some((name, class)) = current.take() {
            classes.insert(name, class);
        }

        Self { classes }
    }

    pub fn class(&self, name: &str) -> Option<&Class> {
        self.classes.get(name)
    }

    pub fn class_count(&self) -> usize {
        self.classes.len()
    }

    /// First matching `class.field` from the candidates, as `(offset, which)`.
    ///
    /// Callers pass several names because Among Us renames fields without
    /// moving them: in 2026.8.18 `InnerNetClient.GameMode` became
    /// `NetworkMode`, same offset 40. The old generator looked for one name,
    /// got -1, and wrote that -1 straight into the published offsets.
    pub fn find_field(&self, class: &str, candidates: &[&str]) -> Option<(i64, String)> {
        let class_info = self.classes.get(class)?;
        for candidate in candidates {
            if let Some(field) = class_info.field(candidate) {
                return Some((field.offset, format!("{class}.{candidate}")));
            }
        }
        None
    }

    pub fn find_static_field(&self, class: &str, candidates: &[&str]) -> Option<(i64, String)> {
        let class_info = self.classes.get(class)?;
        for candidate in candidates {
            if let Some(field) = class_info.static_field(candidate) {
                return Some((field.offset, format!("{class}.{candidate} (static)")));
            }
        }
        None
    }
}

/// Recognises the type-declaration lines Il2CppDumper emits at column 0.
fn parse_type_declaration(line: &str) -> Option<String> {
    if line.starts_with('\t') || line.starts_with(' ') || line.is_empty() {
        return None;
    }
    // Strip the trailing "// TypeDefIndex: n" comment before looking at bases.
    let body = line.split("//").next().unwrap_or(line).trim_end();
    let mut rest = body;
    for modifier in [
        "public ",
        "private ",
        "internal ",
        "protected internal ",
        "protected ",
    ] {
        if let Some(stripped) = rest.strip_prefix(modifier) {
            rest = stripped;
            break;
        }
    }
    loop {
        let mut advanced = false;
        for modifier in ["static ", "abstract ", "sealed ", "readonly ", "unsafe "] {
            if let Some(stripped) = rest.strip_prefix(modifier) {
                rest = stripped;
                advanced = true;
            }
        }
        if !advanced {
            break;
        }
    }
    let rest = ["class ", "struct ", "interface ", "enum "]
        .iter()
        .find_map(|keyword| rest.strip_prefix(keyword))?;

    let name = rest
        .split(" : ")
        .next()
        .unwrap_or(rest)
        .trim()
        .trim_end_matches('{')
        .trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Recognises `\t<modifiers><type> <name>; // 0xNN`.
fn parse_field(line: &str) -> Option<(String, Field)> {
    let body = line.strip_prefix('\t')?;
    if body.starts_with('\t') || body.starts_with("//") || body.starts_with('[') {
        return None;
    }

    let (declaration, comment) = body.rsplit_once("; // ")?;
    let hex = comment.trim().strip_prefix("0x")?;
    let offset = i64::from_str_radix(hex, 16).ok()?;

    // A static field with a default value reads "public int X = 5; // 0x0";
    // cut the initialiser off so the name is still the last token.
    let declaration = declaration.split(" = ").next().unwrap_or(declaration);

    let mut rest = declaration;
    for modifier in [
        "public ",
        "private ",
        "internal ",
        "protected internal ",
        "protected ",
    ] {
        if let Some(stripped) = rest.strip_prefix(modifier) {
            rest = stripped;
            break;
        }
    }
    let mut is_static = false;
    loop {
        let mut advanced = false;
        for modifier in ["static ", "readonly ", "const ", "volatile ", "unsafe "] {
            if let Some(stripped) = rest.strip_prefix(modifier) {
                if modifier == "static " {
                    is_static = true;
                }
                rest = stripped;
                advanced = true;
            }
        }
        if !advanced {
            break;
        }
    }

    // Split on the last space: field names never contain one, but generic type
    // arguments do ("Dictionary<PlayerOutfitType, PlayerOutfit> Outfits").
    let (type_name, name) = rest.rsplit_once(' ')?;
    let name = name.trim();
    if name.is_empty() || type_name.trim().is_empty() {
        return None;
    }

    Some((
        name.to_string(),
        Field {
            offset,
            is_static,
            type_name: type_name.trim().to_string(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
// Namespace:
public class PlayerControl : InnerNetObject // TypeDefIndex: 1234
{
\t// Fields
\tpublic byte PlayerId; // 0x28
\tpublic CosmeticsLayer cosmetics; // 0x3C
\tpublic static PlayerControl LocalPlayer; // 0x0
\tpublic const int Magic = 7;
\tpublic Dictionary<PlayerOutfitType, NetworkedPlayerInfo.PlayerOutfit> Outfits; // 0x40
\tpublic static int Counter = 5; // 0x8

\t// Methods
\t// RVA: 0x100 Offset: 0x100 VA: 0x100
\tpublic void Update() { }
}

// Namespace:
public sealed class NetworkedPlayerInfo.PlayerOutfit : Object // TypeDefIndex: 99
{
\t// Fields
\tpublic int ColorId; // 0x8
\tpublic string PlayerName; // 0x20
}

public enum RoleTeamTypes // TypeDefIndex: 5
{
\tpublic int value__; // 0x0
}
";

    fn dump() -> Dump {
        Dump::parse(SAMPLE)
    }

    #[test]
    fn indexes_every_class_including_nested_and_enums() {
        let dump = dump();
        assert_eq!(dump.class_count(), 3);
        assert!(dump.class("PlayerControl").is_some());
        assert!(dump.class("NetworkedPlayerInfo.PlayerOutfit").is_some());
        assert!(dump.class("RoleTeamTypes").is_some());
    }

    #[test]
    fn reads_instance_field_offsets() {
        let dump = dump();
        assert_eq!(
            dump.find_field("PlayerControl", &["cosmetics"]).unwrap().0,
            0x3C
        );
        assert_eq!(
            dump.find_field("NetworkedPlayerInfo.PlayerOutfit", &["ColorId"])
                .unwrap()
                .0,
            8
        );
    }

    #[test]
    fn generic_types_with_commas_do_not_break_the_name() {
        let dump = dump();
        assert_eq!(
            dump.find_field("PlayerControl", &["Outfits"]).unwrap().0,
            0x40
        );
    }

    #[test]
    fn separates_static_from_instance_space() {
        let dump = dump();
        let class = dump.class("PlayerControl").expect("class");
        assert!(class.static_field("LocalPlayer").is_some());
        assert_eq!(class.static_field("LocalPlayer").unwrap().offset, 0);
        assert!(class.static_field("cosmetics").is_none());
        // A static with an initialiser still parses, name intact.
        assert_eq!(class.static_field("Counter").unwrap().offset, 8);
    }

    #[test]
    fn skips_consts_which_have_no_offset() {
        let dump = dump();
        assert!(dump.find_field("PlayerControl", &["Magic"]).is_none());
    }

    #[test]
    fn candidate_list_handles_renames() {
        let dump = dump();
        // First name missing, second present: this is the GameMode/NetworkMode case.
        let (offset, which) = dump
            .find_field("PlayerControl", &["NotAField", "cosmetics"])
            .expect("fallback should hit");
        assert_eq!(offset, 0x3C);
        assert_eq!(which, "PlayerControl.cosmetics");
    }

    #[test]
    fn missing_class_and_field_are_distinguishable_from_zero() {
        let dump = dump();
        assert!(dump.find_field("NoSuchClass", &["x"]).is_none());
        assert!(dump.find_field("PlayerControl", &["nope"]).is_none());
    }

    #[test]
    fn method_bodies_and_comments_are_not_mistaken_for_fields() {
        let dump = dump();
        let class = dump.class("PlayerControl").expect("class");
        assert!(class.field_names().all(|name| name != "Update"));
    }
}
