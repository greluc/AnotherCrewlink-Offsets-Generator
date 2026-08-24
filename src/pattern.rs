//! Byte signatures: the `"48 8B 05 ? ? ? ?"` strings the client scans for.
//!
//! Match semantics are copied from what `memoryjs.findPattern` does inside
//! AnotherCrewLink, because a signature that is unique under different rules is
//! not unique where it counts:
//!
//!   * the search runs over the module as it is mapped in memory, not the file;
//!   * `?` matches any single byte;
//!   * the reported location is the module-relative address of the match plus
//!     `patternOffset`.

use std::fmt;

use crate::error::{Error, Result};

/// `None` is a wildcard byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    bytes: Vec<Option<u8>>,
}

impl Pattern {
    pub fn new(bytes: Vec<Option<u8>>) -> Self {
        Self { bytes }
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut bytes = Vec::new();
        for token in text.split_whitespace() {
            if token == "?" || token == "??" {
                bytes.push(None);
            } else {
                let value = u8::from_str_radix(token, 16).map_err(|_| {
                    Error::malformed(format!(
                        "'{token}' is not a hex byte or wildcard in signature"
                    ))
                })?;
                bytes.push(Some(value));
            }
        }
        if bytes.is_empty() {
            return Err(Error::malformed("signature is empty"));
        }
        Ok(Self { bytes })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn bytes(&self) -> &[Option<u8>] {
        &self.bytes
    }

    pub fn push(&mut self, byte: Option<u8>) {
        self.bytes.push(byte);
    }

    pub fn truncate(&mut self, len: usize) {
        self.bytes.truncate(len);
    }

    /// Number of literal (non-wildcard) bytes. A signature that is mostly
    /// wildcards may be unique today by luck; this is what tells us so.
    pub fn literal_count(&self) -> usize {
        self.bytes.iter().filter(|byte| byte.is_some()).count()
    }

    pub fn matches_at(&self, haystack: &[u8], position: usize) -> bool {
        let Some(window) = haystack.get(position..position + self.bytes.len()) else {
            return false;
        };
        self.bytes
            .iter()
            .zip(window)
            .all(|(expected, actual)| expected.is_none_or(|byte| byte == *actual))
    }

    /// All match positions, stopping once `cap` have been found.
    ///
    /// Skips ahead on the first literal byte, which turns a 48 MB scan from
    /// "compare everything" into "look at the few hundred thousand places the
    /// first opcode byte occurs".
    pub fn find_all(&self, haystack: &[u8], cap: usize) -> Vec<usize> {
        let mut found = Vec::new();
        if self.bytes.len() > haystack.len() {
            return found;
        }
        let last_start = haystack.len() - self.bytes.len();

        let anchor = self
            .bytes
            .iter()
            .position(|byte| byte.is_some())
            .map(|index| (index, self.bytes[index].expect("anchor is literal")));

        match anchor {
            Some((anchor_index, anchor_byte)) => {
                let mut cursor = anchor_index;
                while cursor < haystack.len() {
                    let Some(hit) = haystack[cursor..]
                        .iter()
                        .position(|byte| *byte == anchor_byte)
                        .map(|offset| cursor + offset)
                    else {
                        break;
                    };
                    if hit >= anchor_index {
                        let start = hit - anchor_index;
                        if start <= last_start && self.matches_at(haystack, start) {
                            found.push(start);
                            if found.len() >= cap {
                                return found;
                            }
                        }
                    }
                    cursor = hit + 1;
                }
            }
            None => {
                // All wildcards: matches everywhere. Never useful, but do not lie.
                for start in 0..=last_start {
                    found.push(start);
                    if found.len() >= cap {
                        return found;
                    }
                }
            }
        }
        found
    }

    /// Keeps only those `positions` where this pattern still matches.
    ///
    /// Extending a signature can only ever shrink the candidate set, so the
    /// growth loop filters instead of rescanning the image on every step.
    pub fn retain_matches(&self, haystack: &[u8], positions: &mut Vec<usize>) {
        positions.retain(|position| self.matches_at(haystack, *position));
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for byte in &self.bytes {
            if !first {
                f.write_str(" ")?;
            }
            first = false;
            match byte {
                Some(value) => write!(f, "{value:02X}")?,
                None => f.write_str("?")?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_text() {
        let pattern = Pattern::parse("48 8B 05 ? ? ? ? 48 8B 88").expect("parse");
        assert_eq!(pattern.len(), 10);
        assert_eq!(pattern.literal_count(), 6);
        assert_eq!(pattern.to_string(), "48 8B 05 ? ? ? ? 48 8B 88");
    }

    #[test]
    fn accepts_double_question_wildcards() {
        let pattern = Pattern::parse("A1 ?? ?? ?? ??").expect("parse");
        assert_eq!(pattern.len(), 5);
        assert_eq!(pattern.literal_count(), 1);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Pattern::parse("").is_err());
        assert!(Pattern::parse("zz 01").is_err());
    }

    #[test]
    fn finds_every_occurrence() {
        let haystack = [0x00, 0xA1, 0x11, 0x22, 0x33, 0x00, 0xA1, 0x44, 0x55, 0x66];
        let pattern = Pattern::parse("A1 ? ? ?").expect("parse");
        assert_eq!(pattern.find_all(&haystack, 16), vec![1, 6]);
    }

    #[test]
    fn honours_the_cap() {
        let haystack = vec![0xCCu8; 64];
        let pattern = Pattern::parse("CC CC").expect("parse");
        assert_eq!(pattern.find_all(&haystack, 3).len(), 3);
    }

    #[test]
    fn anchor_is_not_required_to_be_the_first_byte() {
        // Leading wildcard: the scan must still anchor on the 0xE8 and find the
        // match that starts one byte earlier.
        let haystack = [0x00, 0x90, 0xE8, 0x01, 0x02, 0x03, 0x04];
        let pattern = Pattern::parse("? E8 ? ? ? ?").expect("parse");
        assert_eq!(pattern.find_all(&haystack, 8), vec![1]);
    }

    #[test]
    fn does_not_run_past_the_end() {
        let haystack = [0xA1, 0x00];
        let pattern = Pattern::parse("A1 ? ? ? ?").expect("parse");
        assert!(pattern.find_all(&haystack, 8).is_empty());
    }

    #[test]
    fn retain_matches_narrows_candidates() {
        let haystack = [
            0xA1, 0x01, 0x02, 0x03, 0x04, 0x8B, 0xA1, 0x09, 0x08, 0x07, 0x06, 0x33,
        ];
        let short = Pattern::parse("A1 ? ? ? ?").expect("parse");
        let mut positions = short.find_all(&haystack, 32);
        assert_eq!(positions, vec![0, 6]);
        let long = Pattern::parse("A1 ? ? ? ? 8B").expect("parse");
        long.retain_matches(&haystack, &mut positions);
        assert_eq!(positions, vec![0]);
    }
}
