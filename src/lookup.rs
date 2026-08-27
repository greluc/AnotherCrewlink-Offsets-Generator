//! `lookup.json`: the index the client reads before it fetches any offsets.
//!
//! The client keys it by the game's broadcast version, and caches the fetched
//! offsets under `(filename, architecture)` while comparing
//! `cached >= offsetsVersion`. Two consequences shape this module:
//!
//!   * `offsetsVersion` has to be counted **per file**. The old generator wrote
//!     one global constant for everything, so republishing a corrected file
//!     under the same name left every existing client on its cached, broken
//!     copy. The hand-maintained repository worked around this by bumping by
//!     hand -- V17.4.0 went 1, 2, 3, 4, 5 over four days of fixes.
//!   * the counter only needs to move when the content moves, so an unchanged
//!     regeneration must not churn it.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{read_to_string_lossy, Error, Result};
use crate::offsets::Signature;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lookup {
    /// Top-level keys this generator does not model, kept verbatim.
    ///
    /// `lookup.json` is authored by more than this tool. The sync workflow adds
    /// `upstream_commit`, and the client reads `bundle_version` for replay
    /// detection and `min_client_version` to refuse a bundle it is too old for.
    /// Deserialising into a struct that only knew `patterns` and `versions`
    /// would have dropped all three the next time the generator wrote the file
    /// -- silently, and taking the client's rollback protection with it.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
    #[serde(rename = "patterns")]
    pub patterns: Patterns,
    #[serde(rename = "versions")]
    pub versions: serde_json::Map<String, serde_json::Value>,
}

/// Key the client uses to reject a replayed older bundle.
const BUNDLE_VERSION: &str = "bundle_version";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patterns {
    pub x64: BroadcastPattern,
    pub x86: BroadcastPattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastPattern {
    #[serde(rename = "broadcastVersion")]
    pub broadcast_version: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionEntry {
    pub version: String,
    pub file: String,
    #[serde(rename = "offsetsVersion")]
    pub offsets_version: i64,
}

/// What changed relative to the file already on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentChange {
    New,
    Changed,
    Identical,
}

impl Lookup {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let text = read_to_string_lossy(&path)?;
        serde_json::from_str(&text).map_err(|error| {
            Error::malformed(format!(
                "{}: not a usable lookup.json: {error}",
                path.as_ref().display()
            ))
        })
    }

    fn entry(&self, key: &str) -> Option<VersionEntry> {
        serde_json::from_value(self.versions.get(key)?.clone()).ok()
    }

    fn entries(&self) -> impl Iterator<Item = (String, VersionEntry)> + '_ {
        self.versions.iter().filter_map(|(key, value)| {
            serde_json::from_value::<VersionEntry>(value.clone())
                .ok()
                .map(|entry| (key.clone(), entry))
        })
    }

    /// Highest `offsetsVersion` currently published for `file`.
    fn published_version_for(&self, file: &str) -> Option<i64> {
        self.entries()
            .filter(|(_, entry)| entry.file == file)
            .map(|(_, entry)| entry.offsets_version)
            .max()
    }

    /// Records `broadcast_version -> file`, choosing an `offsetsVersion` that
    /// makes existing clients refetch exactly when the content changed.
    pub fn upsert(
        &mut self,
        broadcast_version: i32,
        game_version: &str,
        file: &str,
        change: ContentChange,
    ) -> Result<i64> {
        let published = self.published_version_for(file);
        let offsets_version = match (change, published) {
            // Nothing on the client can be stale for a file that has never
            // been published.
            (_, None) => 1,
            // Same bytes as what is already out there: leave the counter alone
            // so a rerun produces no diff.
            (ContentChange::Identical, Some(current)) => current,
            (_, Some(current)) => current + 1,
        };

        let entry = VersionEntry {
            version: format!("V{game_version}"),
            file: file.to_string(),
            offsets_version,
        };

        // Every key pointing at this file moves together -- they all serve the
        // same bytes, so they must all invalidate together.
        let keys: Vec<String> = self
            .entries()
            .filter(|(key, existing)| existing.file == file && key != "default")
            .map(|(key, _)| key)
            .collect();
        for key in keys {
            self.set(&key, &entry)?;
        }
        self.set(&broadcast_version.to_string(), &entry)?;
        self.refresh_default()?;
        Ok(offsets_version)
    }

    fn set(&mut self, key: &str, entry: &VersionEntry) -> Result<()> {
        let value = serde_json::to_value(entry)
            .map_err(|error| Error::malformed(format!("cannot serialise lookup entry: {error}")))?;
        self.versions.insert(key.to_string(), value);
        Ok(())
    }

    /// Points `default` at the newest build we know about.
    ///
    /// The old generator picked it with `Skip(1).FirstOrDefault()`, i.e. by
    /// whatever position the dictionary happened to put things in. Sorting by
    /// broadcast version says what was actually meant: a client running a build
    /// nobody has published offsets for gets the most recent ones rather than
    /// an arbitrary entry.
    fn refresh_default(&mut self) -> Result<()> {
        let newest = self
            .entries()
            .filter_map(|(key, entry)| key.parse::<i64>().ok().map(|number| (number, entry)))
            .max_by_key(|(number, _)| *number);

        if let Some((_, entry)) = newest {
            self.set("default", &entry)?;
        }
        Ok(())
    }

    /// Sorted newest-first, with `default` on top, so the file reads like a
    /// changelog and diffs stay local.
    pub fn to_json(&self) -> Result<String> {
        let mut ordered = serde_json::Map::new();
        if let Some(default) = self.versions.get("default") {
            ordered.insert("default".to_string(), default.clone());
        }
        let mut numeric: Vec<(i64, String)> = self
            .versions
            .keys()
            .filter(|key| key.as_str() != "default")
            .filter_map(|key| key.parse::<i64>().ok().map(|number| (number, key.clone())))
            .collect();
        numeric.sort_by_key(|(number, _)| std::cmp::Reverse(*number));
        for (_, key) in numeric {
            if let Some(value) = self.versions.get(&key) {
                ordered.insert(key, value.clone());
            }
        }
        // Anything non-numeric that we did not recognise is kept rather than
        // dropped; losing a hand-added key would be worse than odd ordering.
        let mut leftovers: Vec<&String> = self
            .versions
            .keys()
            .filter(|key| key.as_str() != "default" && key.parse::<i64>().is_err())
            .collect();
        leftovers.sort();
        for key in leftovers {
            if let Some(value) = self.versions.get(key) {
                ordered.insert(key.clone(), value.clone());
            }
        }

        let rendered = Lookup {
            extra: self.extra.clone(),
            patterns: self.patterns.clone(),
            versions: ordered,
        };
        serde_json::to_string_pretty(&rendered)
            .map(|text| text + "\n")
            .map_err(|error| Error::malformed(format!("cannot render lookup.json: {error}")))
    }

    /// Current `bundle_version`, if the file carries one.
    pub fn bundle_version(&self) -> Option<i64> {
        self.extra
            .get(BUNDLE_VERSION)
            .and_then(|value| value.as_i64())
    }

    /// Moves `bundle_version` on, so a client cannot be handed the previous
    /// bundle in place of this one.
    ///
    /// The client keeps the highest version it has seen and rejects anything
    /// lower, so this has to advance whenever the contents do. Leaving it alone
    /// after changing an offsets file would let the pre-change bundle be
    /// replayed at a client that had already accepted the new one, with nothing
    /// to tell them apart. Only called when something actually changed, so a
    /// rerun that produces identical output does not churn it.
    pub fn bump_bundle_version(&mut self) -> Option<i64> {
        let next = self.bundle_version()? + 1;
        self.extra
            .insert(BUNDLE_VERSION.to_string(), serde_json::json!(next));
        Some(next)
    }

    pub fn lookup_entry(&self, broadcast_version: i32) -> Option<VersionEntry> {
        self.entry(&broadcast_version.to_string())
    }
}

/// Compares freshly generated JSON against what is already on disk.
pub fn classify_change(path: &Path, generated: &str) -> ContentChange {
    match std::fs::read_to_string(path) {
        Err(_) => ContentChange::New,
        Ok(existing) => {
            if normalise(&existing) == normalise(generated) {
                ContentChange::Identical
            } else {
                ContentChange::Changed
            }
        }
    }
}

/// Line endings and trailing whitespace are not content.
fn normalise(text: &str) -> String {
    text.replace("\r\n", "\n").trim_end().to_string()
}

/// Broadcast-version keys grouped by the file they serve, for the run report.
pub fn versions_serving(lookup: &Lookup, file: &str) -> BTreeMap<String, String> {
    lookup
        .entries()
        .filter(|(_, entry)| entry.file == file)
        .map(|(key, entry)| (key, entry.version))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup_with(entries: &[(&str, &str, &str, i64)]) -> Lookup {
        let signature = Signature {
            sig: Some("6A 00 68 ? ? ? ?".to_string()),
            pattern_offset: Some(3),
            address_offset: Some(0),
        };
        let mut versions = serde_json::Map::new();
        for (key, version, file, offsets_version) in entries {
            versions.insert(
                (*key).to_string(),
                serde_json::to_value(VersionEntry {
                    version: (*version).to_string(),
                    file: (*file).to_string(),
                    offsets_version: *offsets_version,
                })
                .expect("value"),
            );
        }
        Lookup {
            extra: serde_json::Map::new(),
            patterns: Patterns {
                x64: BroadcastPattern {
                    broadcast_version: signature.clone(),
                },
                x86: BroadcastPattern {
                    broadcast_version: signature,
                },
            },
            versions,
        }
    }

    #[test]
    fn a_brand_new_file_starts_at_one() {
        let mut lookup = lookup_with(&[]);
        let version = lookup
            .upsert(
                50_663_350,
                "2026.8.18",
                "V2026.8.18/offsets.json",
                ContentChange::New,
            )
            .expect("upsert");
        assert_eq!(version, 1);
        assert_eq!(
            lookup.lookup_entry(50_663_350).unwrap().version,
            "V2026.8.18"
        );
    }

    #[test]
    fn changed_content_bumps_so_cached_clients_refetch() {
        let mut lookup = lookup_with(&[("50656300", "V17.4.0", "V17.4.0/offsets.json", 5)]);
        let version = lookup
            .upsert(
                50_656_300,
                "17.4.0",
                "V17.4.0/offsets.json",
                ContentChange::Changed,
            )
            .expect("upsert");
        assert_eq!(version, 6, "a corrected file has to invalidate the cache");
    }

    #[test]
    fn identical_content_does_not_churn_the_counter() {
        let mut lookup = lookup_with(&[("50656300", "V17.4.0", "V17.4.0/offsets.json", 5)]);
        let version = lookup
            .upsert(
                50_656_300,
                "17.4.0",
                "V17.4.0/offsets.json",
                ContentChange::Identical,
            )
            .expect("upsert");
        assert_eq!(version, 5);
    }

    #[test]
    fn every_key_serving_a_file_moves_together() {
        // Three builds share one offsets file; correcting it must invalidate
        // the cache for all three, not just the one being regenerated.
        let mut lookup = lookup_with(&[
            ("50638350", "V2025.9.9", "V2025.9.9/offsets.json", 8),
            ("50641800", "V17.0.1s", "V2025.9.9/offsets.json", 8),
            ("50643450", "V17.1.0s", "V2025.9.9/offsets.json", 8),
        ]);
        lookup
            .upsert(
                50_643_450,
                "17.1.0",
                "V2025.9.9/offsets.json",
                ContentChange::Changed,
            )
            .expect("upsert");
        for key in ["50638350", "50641800", "50643450"] {
            assert_eq!(lookup.entry(key).unwrap().offsets_version, 9, "key {key}");
        }
    }

    #[test]
    fn default_points_at_the_newest_build() {
        let mut lookup = lookup_with(&[
            ("50607250", "V2024.8.13", "V2024.8.13/offsets.json", 15),
            ("50656300", "V17.4.0", "V17.4.0/offsets.json", 5),
        ]);
        lookup
            .upsert(
                50_663_350,
                "2026.8.18",
                "V2026.8.18/offsets.json",
                ContentChange::New,
            )
            .expect("upsert");
        let default = lookup.entry("default").expect("default");
        assert_eq!(default.file, "V2026.8.18/offsets.json");
    }

    #[test]
    fn rendering_sorts_newest_first_and_keeps_unknown_keys() {
        let mut lookup = lookup_with(&[
            ("50607250", "V2024.8.13", "V2024.8.13/offsets.json", 15),
            ("50656300", "V17.4.0", "V17.4.0/offsets.json", 5),
        ]);
        lookup.versions.insert(
            "notes".to_string(),
            serde_json::Value::String("kept".to_string()),
        );
        lookup.refresh_default().expect("default");
        let json = lookup.to_json().expect("render");
        let default_at = json.find("\"default\"").expect("default present");
        let newest_at = json.find("\"50656300\"").expect("newest present");
        let oldest_at = json.find("\"50607250\"").expect("oldest present");
        assert!(default_at < newest_at && newest_at < oldest_at);
        assert!(json.contains("\"notes\""));
    }

    #[test]
    fn unknown_top_level_keys_survive_a_round_trip() {
        // lookup.json is authored by more than this tool: the sync workflow adds
        // upstream_commit, and the client reads bundle_version and
        // min_client_version. Dropping them on write would take the client's
        // replay protection with them.
        let source = r#"{
  "bundle_version": 7,
  "min_client_version": "1.0.0",
  "upstream_commit": "abc123",
  "patterns": {
    "x64": { "broadcastVersion": { "sig": "33 D2", "patternOffset": 3, "addressOffset": 0 } },
    "x86": { "broadcastVersion": { "sig": "6A 00", "patternOffset": 3, "addressOffset": 0 } }
  },
  "versions": {
    "default": { "version": "V1", "file": "V1/offsets.json", "offsetsVersion": 1 },
    "100": { "version": "V1", "file": "V1/offsets.json", "offsetsVersion": 1 }
  }
}"#;
        let lookup: Lookup = serde_json::from_str(source).expect("parse");
        assert_eq!(lookup.bundle_version(), Some(7));

        let rendered = lookup.to_json().expect("render");
        let back: serde_json::Value = serde_json::from_str(&rendered).expect("reparse");
        assert_eq!(back["bundle_version"], 7);
        assert_eq!(back["min_client_version"], "1.0.0");
        assert_eq!(back["upstream_commit"], "abc123");
        assert!(back["patterns"].is_object());
        assert_eq!(back["versions"].as_object().unwrap().len(), 2);
    }

    #[test]
    fn bundle_version_only_moves_forward() {
        let mut lookup = lookup_with(&[]);
        // Absent: nothing to bump, and nothing invented.
        assert_eq!(lookup.bundle_version(), None);
        assert_eq!(lookup.bump_bundle_version(), None);

        lookup
            .extra
            .insert("bundle_version".to_string(), serde_json::json!(4));
        assert_eq!(lookup.bump_bundle_version(), Some(5));
        assert_eq!(lookup.bump_bundle_version(), Some(6));
        assert_eq!(lookup.bundle_version(), Some(6));
    }

    #[test]
    fn change_detection_ignores_line_endings() {
        let dir = std::env::temp_dir().join("acl-offsetgen-lookup-test");
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("offsets.json");
        std::fs::write(&path, "{\r\n  \"a\": 1\r\n}\r\n").expect("write");
        assert_eq!(
            classify_change(&path, "{\n  \"a\": 1\n}\n"),
            ContentChange::Identical
        );
        assert_eq!(
            classify_change(&path, "{\n  \"a\": 2\n}\n"),
            ContentChange::Changed
        );
        assert_eq!(
            classify_change(&dir.join("missing.json"), "{}"),
            ContentChange::New
        );
        let _ = std::fs::remove_file(&path);
    }
}
