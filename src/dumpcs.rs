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
    /// Namespace the type was declared in. Empty for Among Us's own code, which
    /// is what makes it a usable tie-breaker against bundled third-party types.
    pub namespace: String,
    /// Declaration order preserved: useful when reporting near-misses.
    pub fields: Vec<(String, Field)>,
    /// Method name to RVA, in declaration order. Overloads keep the first.
    pub methods: Vec<(String, u64)>,
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

/// All types sharing one simple name, in lookup order.
///
/// A dump of Among Us contains nine classes called `Constants`: the game's own
/// plus ones from Steamworks, Discord, Sentry and Unity Services. Keeping only
/// one of them is how a lookup ends up silently answering from the wrong type,
/// so they are all kept and searched in turn.
#[derive(Debug, Default)]
pub struct Dump {
    classes: HashMap<String, Vec<Class>>,
}

impl Dump {
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let text = read_to_string_lossy(path)?;
        Ok(Self::parse(&text))
    }

    pub fn parse(text: &str) -> Self {
        let mut classes: HashMap<String, Vec<Class>> = HashMap::new();
        let mut current: Option<(String, Class)> = None;
        // Both of these describe the *next* line, so they are held until it
        // arrives: the namespace comment precedes a type declaration, the RVA
        // comment precedes a method.
        let mut pending_namespace = String::new();
        let mut pending_rva: Option<u64> = None;

        for line in text.lines() {
            if let Some(namespace) = parse_namespace_comment(line) {
                pending_namespace = namespace;
                continue;
            }
            if let Some(name) = parse_type_declaration(line) {
                if let Some((previous_name, previous)) = current.take() {
                    classes.entry(previous_name).or_default().push(previous);
                }
                current = Some((
                    name,
                    Class {
                        namespace: std::mem::take(&mut pending_namespace),
                        ..Class::default()
                    },
                ));
                pending_rva = None;
                continue;
            }
            if let Some((_, class)) = current.as_mut() {
                class.line_span += 1;
                if let Some((name, field)) = parse_field(line) {
                    class.fields.push((name, field));
                    pending_rva = None;
                    continue;
                }
                if let Some(rva) = parse_rva_comment(line) {
                    pending_rva = rva;
                    continue;
                }
                if let Some(rva) = pending_rva.take() {
                    if let Some(name) = parse_method_name(line) {
                        class.methods.push((name, rva));
                    }
                }
            }
        }
        if let Some((name, class)) = current.take() {
            classes.entry(name).or_default().push(class);
        }

        Self { classes }
    }

    /// Candidate types for a simple name, most likely first.
    ///
    /// Among Us declares its own types in the global namespace, so those are
    /// tried before anything a bundled SDK contributed.
    fn candidates(&self, name: &str) -> impl Iterator<Item = &Class> {
        let all = self.classes.get(name).map(Vec::as_slice).unwrap_or(&[]);
        all.iter()
            .filter(|class| class.namespace.is_empty())
            .chain(all.iter().filter(|class| !class.namespace.is_empty()))
    }

    /// First candidate for `name`, for diagnostics and tests.
    pub fn class(&self, name: &str) -> Option<&Class> {
        self.candidates(name).next()
    }

    pub fn class_count(&self) -> usize {
        self.classes.values().map(Vec::len).sum()
    }

    /// First matching `class.field` from the candidates, as `(offset, which)`.
    ///
    /// Callers pass several names because Among Us renames fields without
    /// moving them: in 2026.8.18 `InnerNetClient.GameMode` became
    /// `NetworkMode`, same offset 40. The old generator looked for one name,
    /// got -1, and wrote that -1 straight into the published offsets.
    pub fn find_field(&self, class: &str, candidates: &[&str]) -> Option<(i64, String)> {
        for candidate in candidates {
            for class_info in self.candidates(class) {
                if let Some(field) = class_info.field(candidate) {
                    return Some((field.offset, format!("{class}.{candidate}")));
                }
            }
        }
        None
    }

    /// RVA of the first method named by one of `candidates`.
    ///
    /// Used to anchor signatures on a known function rather than on a
    /// hand-picked byte pattern: `Constants.GetBroadcastVersion` compiles to
    /// `mov eax, <version>; ret`, so its RVA plus one is the version itself.
    pub fn find_method(&self, class: &str, candidates: &[&str]) -> Option<(u64, String)> {
        for candidate in candidates {
            for class_info in self.candidates(class) {
                if let Some((_, rva)) = class_info
                    .methods
                    .iter()
                    .find(|(name, _)| name == candidate)
                {
                    return Some((*rva, format!("{class}.{candidate}")));
                }
            }
        }
        None
    }

    pub fn find_static_field(&self, class: &str, candidates: &[&str]) -> Option<(i64, String)> {
        for candidate in candidates {
            for class_info in self.candidates(class) {
                if let Some(field) = class_info.static_field(candidate) {
                    return Some((field.offset, format!("{class}.{candidate} (static)")));
                }
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

/// Recognises `// Namespace: Steamworks` and the empty form the game's own
/// types carry.
fn parse_namespace_comment(line: &str) -> Option<String> {
    let rest = line.strip_prefix("// Namespace:")?;
    Some(rest.trim().to_string())
}

/// Recognises `\t// RVA: 0x6CA4A0 Offset: 0x6C92A0 VA: 0x106CA4A0`.
///
/// Returns `Some(None)` for the `RVA: -1` form the dumper writes for abstract
/// and unimplemented methods, so the caller drops the pending comment instead
/// of attaching a bogus address to the next line.
fn parse_rva_comment(line: &str) -> Option<Option<u64>> {
    let rest = line.trim_start().strip_prefix("// RVA: ")?;
    let value = rest.split_whitespace().next()?;
    match value.strip_prefix("0x") {
        Some(hex) => Some(u64::from_str_radix(hex, 16).ok()),
        None => Some(None),
    }
}

/// Recognises a method declaration and returns its name.
fn parse_method_name(line: &str) -> Option<String> {
    let body = line.strip_prefix('\t')?;
    if body.starts_with("//") || body.starts_with('[') {
        return None;
    }
    let before_params = body.split('(').next()?;
    if before_params.len() == body.len() {
        return None; // no parentheses: not a method
    }
    let name = before_params.rsplit_once(' ').map(|(_, name)| name)?.trim();
    // Generic methods carry their parameters in the name: "Foo<T>".
    let name = name.split('<').next().unwrap_or(name);
    if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    Some(name.to_string())
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

    const METHODS: &str = "\
public class Constants // TypeDefIndex: 42
{
\t// Fields
\tpublic static int Version; // 0x0

\t// Methods
\t// RVA: 0x6CA4A0 Offset: 0x6C92A0 VA: 0x106CA4A0
\tinternal static int GetBroadcastVersion() { }

\t// RVA: 0x6CA450 Offset: 0x6C9250 VA: 0x106CA450
\tinternal static byte[] GetBroadcastVersionBytes() { }

\t// RVA: -1 Offset: -1 VA: 0x0
\tpublic abstract void NotCompiled() { }

\t// RVA: 0x1234 Offset: 0x1000 VA: 0x101234
\tpublic static void Generic<T>(T value) { }
}
";

    #[test]
    fn reads_method_rvas() {
        let dump = Dump::parse(METHODS);
        assert_eq!(
            dump.find_method("Constants", &["GetBroadcastVersion"]),
            Some((0x6CA4A0, "Constants.GetBroadcastVersion".to_string()))
        );
        assert_eq!(
            dump.find_method("Constants", &["GetBroadcastVersionBytes"])
                .map(|(rva, _)| rva),
            Some(0x6CA450)
        );
    }

    #[test]
    fn methods_without_an_address_are_skipped() {
        // "RVA: -1" means the method was never compiled. Attaching that comment
        // to the following declaration would hand the disassembler address 0.
        let dump = Dump::parse(METHODS);
        assert_eq!(dump.find_method("Constants", &["NotCompiled"]), None);
    }

    #[test]
    fn generic_methods_keep_their_bare_name() {
        let dump = Dump::parse(METHODS);
        assert_eq!(
            dump.find_method("Constants", &["Generic"])
                .map(|(rva, _)| rva),
            Some(0x1234)
        );
    }

    #[test]
    fn fields_are_not_mistaken_for_methods_and_vice_versa() {
        let dump = Dump::parse(METHODS);
        assert!(dump.find_method("Constants", &["Version"]).is_none());
        assert!(dump
            .find_field("Constants", &["GetBroadcastVersion"])
            .is_none());
    }

    #[test]
    fn a_missing_method_is_reported_rather_than_guessed() {
        let dump = Dump::parse(METHODS);
        assert!(dump.find_method("Constants", &["NoSuchMethod"]).is_none());
        assert!(dump
            .find_method("NoSuchClass", &["GetBroadcastVersion"])
            .is_none());
    }

    /// A dump of Among Us has nine classes called `Constants`: the game's own
    /// in the global namespace, plus Steamworks, Discord, Sentry and Unity
    /// Services. Only one of them has the method we want.
    const COLLIDING: &str = "\
// Namespace: Steamworks
public static class Constants // TypeDefIndex: 4972
{
\t// Fields
\tpublic static int Version; // 0x10

\t// Methods
\t// RVA: 0x111111 Offset: 0x1 VA: 0x1
\tpublic static int Unrelated() { }
}

// Namespace:
public static class Constants // TypeDefIndex: 238
{
\t// Fields
\tpublic static int Version; // 0x20

\t// Methods
\t// RVA: 0x6CA4A0 Offset: 0x6C92A0 VA: 0x106CA4A0
\tinternal static int GetBroadcastVersion() { }
}

// Namespace: Unity.Services.LevelPlay
internal static class Constants // TypeDefIndex: 17758
{
\t// Fields
\tpublic static int Version; // 0x30
}
";

    #[test]
    fn colliding_type_names_are_all_kept() {
        let dump = Dump::parse(COLLIDING);
        assert_eq!(dump.class_count(), 3);
    }

    #[test]
    fn the_games_own_namespace_wins_a_name_collision() {
        // Declaration order puts Steamworks first and Unity Services last, so
        // neither "first wins" nor "last wins" would pick the right one.
        let dump = Dump::parse(COLLIDING);
        assert_eq!(
            dump.find_field("Constants", &["Version"])
                .map(|(offset, _)| offset),
            Some(0x20)
        );
        assert_eq!(
            dump.class("Constants")
                .map(|class| class.namespace.as_str()),
            Some("")
        );
    }

    #[test]
    fn a_member_only_a_later_namespace_has_is_still_found() {
        // Preference is not exclusion: if the preferred type does not carry the
        // member, the others are still searched.
        let dump = Dump::parse(COLLIDING);
        assert_eq!(
            dump.find_method("Constants", &["Unrelated"])
                .map(|(rva, _)| rva),
            Some(0x111111)
        );
        assert_eq!(
            dump.find_method("Constants", &["GetBroadcastVersion"])
                .map(|(rva, _)| rva),
            Some(0x6CA4A0)
        );
    }
}
