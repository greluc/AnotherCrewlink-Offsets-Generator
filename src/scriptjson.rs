//! The `_TypeInfo` slot addresses out of Il2CppDumper's `script.json`.
//!
//! For every IL2CPP type the compiled binary keeps one global slot holding its
//! `Il2CppClass*`, and `script.json` names them `<Type>_TypeInfo`. That slot is
//! the anchor for everything the client reads about a static class, so this is
//! where signature generation starts. Addresses in this file are RVAs (verified
//! against the game: `PlayerControl_TypeInfo` at 0x2ADC244 is referenced as
//! `ImageBase + 0x2ADC244` throughout the code sections).
//!
//! The file is ~95 MB for Among Us. Only `ScriptMetadata` is deserialised;
//! every other member is parsed and dropped rather than turned into a
//! `serde_json::Value`.

use std::collections::HashMap;

use serde::Deserialize;

use crate::error::{read_to_string_lossy, Error, Result};

#[derive(Debug, Deserialize)]
struct ScriptFile {
    #[serde(rename = "ScriptMetadata", default)]
    script_metadata: Vec<MetadataEntry>,
}

#[derive(Debug, Deserialize)]
struct MetadataEntry {
    #[serde(rename = "Address")]
    address: u64,
    #[serde(rename = "Name")]
    name: String,
}

#[derive(Debug, Default)]
pub struct TypeInfoTable {
    slots: HashMap<String, u64>,
}

impl TypeInfoTable {
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let text = read_to_string_lossy(path)?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let parsed: ScriptFile = serde_json::from_str(text)
            .map_err(|error| Error::malformed(format!("script.json is not readable: {error}")))?;

        let mut slots = HashMap::new();
        for entry in parsed.script_metadata {
            if let Some(type_name) = entry.name.strip_suffix("_TypeInfo") {
                // Generic instantiations produce several entries that differ only
                // in mangling; keep the first, which is the plain type.
                slots.entry(type_name.to_string()).or_insert(entry.address);
            }
        }

        if slots.is_empty() {
            return Err(Error::malformed(
                "script.json contains no _TypeInfo entries -- was the dumper run with \
                 GenerateStruct enabled?",
            ));
        }
        Ok(Self { slots })
    }

    /// Slot RVA for `type_name`, e.g. `PlayerControl`.
    pub fn slot(&self, type_name: &str) -> Option<u64> {
        self.slots.get(type_name).copied()
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_type_info_slots_and_ignores_everything_else() {
        let text = r#"{
          "ScriptMethod": [ { "Address": 1, "Name": "a", "Signature": "x", "TypeSignature": "i" } ],
          "ScriptString": [ { "Address": 2, "Value": "hello" } ],
          "ScriptMetadata": [
            { "Address": 44941892, "Name": "PlayerControl_TypeInfo", "Signature": "PlayerControl_c*" },
            { "Address": 44857460, "Name": "AmongUsClient_TypeInfo", "Signature": "AmongUsClient_c*" },
            { "Address": 999, "Name": "SomeMethod_MethodInfo", "Signature": "x" }
          ],
          "Addresses": [ 1, 2, 3 ]
        }"#;
        let table = TypeInfoTable::parse(text).expect("parse");
        assert_eq!(table.len(), 2);
        assert_eq!(table.slot("PlayerControl"), Some(44_941_892));
        assert_eq!(table.slot("AmongUsClient"), Some(44_857_460));
        assert_eq!(table.slot("SomeMethod"), None);
    }

    #[test]
    fn first_entry_wins_for_duplicate_names() {
        let text = r#"{"ScriptMetadata":[
          {"Address":10,"Name":"Foo_TypeInfo"},
          {"Address":20,"Name":"Foo_TypeInfo"}]}"#;
        let table = TypeInfoTable::parse(text).expect("parse");
        assert_eq!(table.slot("Foo"), Some(10));
    }

    #[test]
    fn a_dump_without_struct_generation_is_an_error_not_an_empty_table() {
        let text = r#"{"ScriptMethod":[],"ScriptMetadata":[]}"#;
        assert!(TypeInfoTable::parse(text).is_err());
    }

    #[test]
    fn malformed_json_is_reported() {
        assert!(TypeInfoTable::parse("{ not json").is_err());
    }
}
