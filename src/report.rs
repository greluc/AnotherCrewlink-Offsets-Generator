//! What changed, and where every number came from.
//!
//! A generator that only writes a file leaves the reviewer to eyeball 300 lines
//! of numbers. The diff below is the practical regression check: after a game
//! update the interesting output is not the file, it is the four fields that
//! moved.

use crate::generate::Provenance;
use crate::offsets::Offsets;

/// One field whose value differs between two offsets files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Difference {
    pub path: String,
    pub before: String,
    pub after: String,
}

/// Field-by-field comparison of two offsets files.
///
/// Signature strings are compared too, but reported as "changed" rather than
/// spelled out -- a 60-byte pattern on a diff line helps nobody.
pub fn diff(before: &Offsets, after: &Offsets) -> Vec<Difference> {
    let (Ok(before), Ok(after)) = (serde_json::to_value(before), serde_json::to_value(after))
    else {
        return Vec::new();
    };
    let mut differences = Vec::new();
    walk(&before, &after, String::new(), &mut differences);
    differences
}

fn walk(
    before: &serde_json::Value,
    after: &serde_json::Value,
    path: String,
    out: &mut Vec<Difference>,
) {
    match (before, after) {
        (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                match (a.get(key), b.get(key)) {
                    (Some(left), Some(right)) => walk(left, right, child, out),
                    (Some(left), None) => out.push(Difference {
                        path: child,
                        before: render(left),
                        after: "(removed)".to_string(),
                    }),
                    (None, Some(right)) => out.push(Difference {
                        path: child,
                        before: "(absent)".to_string(),
                        after: render(right),
                    }),
                    (None, None) => {}
                }
            }
        }
        (serde_json::Value::Array(a), serde_json::Value::Array(b)) => {
            if a == b {
                return;
            }
            // Whole-array reporting: a chain that gained a hop is one change,
            // not four.
            out.push(Difference {
                path,
                before: render(before),
                after: render(after),
            });
            let _ = (a, b);
        }
        (left, right) => {
            if left != right {
                out.push(Difference {
                    path,
                    before: render(left),
                    after: render(right),
                });
            }
        }
    }
}

fn render(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) if text.len() > 24 => {
            format!("<{} byte pattern>", (text.split_whitespace().count()))
        }
        other => serde_json::to_string(other).unwrap_or_else(|_| "?".to_string()),
    }
}

/// Human-readable summary of a run.
pub fn render_provenance(entries: &[(String, Provenance)]) -> String {
    let mut derived = 0;
    let mut layout = 0;
    let mut signatures = 0;
    let mut carried = Vec::new();

    for (label, provenance) in entries {
        match provenance {
            Provenance::Derived(_) => derived += 1,
            Provenance::Layout(_) => layout += 1,
            Provenance::SignatureFor(_) => signatures += 1,
            Provenance::Carried(why) => carried.push(format!("{label} -- {why}")),
        }
    }

    let mut text = format!(
        "  {derived} values read from the dump, {layout} derived from the pointer size, \
         {signatures} signatures generated"
    );
    if carried.is_empty() {
        text.push_str("\n  nothing carried from the base file");
    } else {
        text.push_str(&format!(
            "\n  {} value(s) carried from the base file, because no dump describes them:",
            carried.len()
        ));
        for entry in carried {
            text.push_str(&format!("\n    - {entry}"));
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reports_a_scalar_change_with_its_path() {
        let before = json!({"player": {"roleTeam": 76}});
        let after = json!({"player": {"roleTeam": 80}});
        let mut out = Vec::new();
        walk(&before, &after, String::new(), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path, "player.roleTeam");
        assert_eq!(out[0].before, "76");
        assert_eq!(out[0].after, "80");
    }

    #[test]
    fn a_chain_that_grew_is_one_entry_not_four() {
        let before = json!({"localX": [200, 108]});
        let after = json!({"localX": [224, 64, 16, 176]});
        let mut out = Vec::new();
        walk(&before, &after, String::new(), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path, "localX");
    }

    #[test]
    fn identical_files_produce_nothing() {
        let value = json!({"a": [1, 2], "b": {"c": 3}});
        let mut out = Vec::new();
        walk(&value, &value, String::new(), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn added_and_removed_keys_are_both_reported() {
        let before = json!({"kept": 1, "gone": 2});
        let after = json!({"kept": 1, "fresh": 3});
        let mut out = Vec::new();
        walk(&before, &after, String::new(), &mut out);
        assert_eq!(out.len(), 2);
        assert!(out
            .iter()
            .any(|d| d.path == "gone" && d.after == "(removed)"));
        assert!(out
            .iter()
            .any(|d| d.path == "fresh" && d.before == "(absent)"));
    }

    #[test]
    fn long_signatures_are_summarised() {
        let before = json!({"sig": "48 8B 05 ? ? ? ? 48 8B 88 B8 00 00 00 48 8B 09"});
        let after = json!({"sig": "48 8B 05 ? ? ? ? 48 8B 80 B8 00 00 00 48 8B 08"});
        let mut out = Vec::new();
        walk(&before, &after, String::new(), &mut out);
        assert_eq!(out.len(), 1);
        assert!(out[0].after.contains("byte pattern"));
    }
}
