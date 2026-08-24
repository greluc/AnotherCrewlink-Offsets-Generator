//! Facts about a game build: which version it is and what it broadcasts.

use crate::error::{Error, Result};
use crate::pattern::Pattern;
use crate::pe::Image;

/// Version strings pulled out of `globalgamemanagers`.
#[derive(Debug, Clone)]
pub struct GameVersion {
    /// The game's own version, e.g. `2026.8.18` or `17.4.0`.
    pub game: String,
    /// The Unity version the build was made with, e.g. `2022.3.44f1`.
    pub unity: Option<String>,
}

impl GameVersion {
    /// Name used for the offsets directory: `V` + version, matching the layout
    /// the client fetches from (`offsets/x86/V2026.8.18/offsets.json`).
    pub fn directory_name(&self) -> String {
        format!("V{}", self.game)
    }
}

/// Extracts the game version from a `globalgamemanagers` file.
///
/// The old generator read a fixed window (`skip 0xFF0, take 1200`) and looked
/// for bytes spelling "202". Unity 2022.3 moved the string: in Among Us
/// 2026.8.18 it sits at 0x7A8, outside that window, so the search returned
/// nothing, the version came back null, and the build was silently dropped from
/// the run. It would also have matched the Unity version string, and it stops
/// working in 2030.
///
/// Instead the whole file is scanned for Unity's own encoding -- a 32-bit
/// little-endian length followed by that many ASCII bytes -- and the candidates
/// are filtered by shape. That is what the format actually guarantees, so it
/// survives the next layout change.
pub fn read_game_version(global_game_managers: &[u8]) -> Result<GameVersion> {
    let mut candidates = Vec::new();

    let limit = global_game_managers.len().saturating_sub(4);
    for position in 0..limit {
        let length = u32::from_le_bytes([
            global_game_managers[position],
            global_game_managers[position + 1],
            global_game_managers[position + 2],
            global_game_managers[position + 3],
        ]) as usize;
        if !(3..=24).contains(&length) {
            continue;
        }
        let start = position + 4;
        let Some(raw) = global_game_managers.get(start..start + length) else {
            continue;
        };
        if !raw.iter().all(|byte| byte.is_ascii_graphic()) {
            continue;
        }
        let Ok(text) = std::str::from_utf8(raw) else {
            continue;
        };
        if looks_like_a_version(text) {
            candidates.push((start, text.to_string()));
        }
    }

    let unity = candidates
        .iter()
        .find(|(_, text)| is_unity_version(text))
        .map(|(_, text)| text.clone());

    let game = candidates
        .iter()
        .find(|(_, text)| !is_unity_version(text))
        .map(|(_, text)| text.clone())
        .ok_or_else(|| {
            Error::malformed(format!(
                "no game version string found in globalgamemanagers ({} bytes scanned{}). \
                 Either the file is not from Among Us or Unity changed how the build version \
                 is stored.",
                global_game_managers.len(),
                match &unity {
                    Some(version) => format!(", Unity version {version} was found"),
                    None => String::new(),
                }
            ))
        })?;

    Ok(GameVersion { game, unity })
}

/// `2026.8.18`, `17.4.0`, `2022.3.44f1` -- digits and dots, at least two dots,
/// optionally a Unity-style build suffix.
fn looks_like_a_version(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    // Three components for 2026.8.18 and 17.4.0, four for hotfixes such as
    // 2023.3.28.1, which the offsets repository already carries.
    if !(3..=4).contains(&parts.len()) {
        return false;
    }
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return false;
        }
        let leading_digits = part.chars().take_while(char::is_ascii_digit).count();
        if leading_digits == 0 {
            return false;
        }
        let is_last = index == parts.len() - 1;
        if is_last {
            // Only the final component may carry a build suffix, as in "44f1".
            if !part[leading_digits..]
                .chars()
                .all(|c| c.is_ascii_alphanumeric())
            {
                return false;
            }
        } else if leading_digits != part.len() {
            return false;
        }
    }
    true
}

fn is_unity_version(text: &str) -> bool {
    // Unity tags releases as <year>.<minor>.<patch><f|b|a|p><build>.
    text.rsplit('.')
        .next()
        .is_some_and(|last| last.contains(['f', 'b', 'a', 'p']))
}

/// Reads the broadcast version -- the integer the client uses as the lookup key.
///
/// `patternOffset` points at the immediate holding the value; the client reads
/// it with `getLocation`, so this is a straight `int` read at that RVA rather
/// than a pointer walk.
pub fn read_broadcast_version(
    image: &Image,
    pattern: &Pattern,
    pattern_offset: i64,
    address_offset: i64,
) -> Result<i32> {
    let matches = pattern.find_all(image.mapped(), 8);
    let first = matches.first().copied().ok_or_else(|| {
        Error::malformed(format!(
            "the broadcast-version signature for {} did not match this build. It is stored in \
             lookup.json rather than generated, so it has to be refreshed by hand when the \
             game's version check is recompiled.",
            image.arch
        ))
    })?;

    let location = first as i64 + pattern_offset + address_offset;
    let value = image
        .read_i32(location as usize)
        .ok_or_else(|| Error::malformed("broadcast-version signature points outside the image"))?;

    if value <= 0 {
        return Err(Error::malformed(format!(
            "broadcast version read as {value}, which cannot be right"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduces the shape of a real `globalgamemanagers`: Unity version near
    /// the front, game version further in, both length-prefixed.
    fn synthetic_ggm(unity: &str, game: &str) -> Vec<u8> {
        let mut file = vec![0u8; 0x900];
        let put = |offset: usize, text: &str, file: &mut Vec<u8>| {
            file[offset..offset + 4].copy_from_slice(&(text.len() as u32).to_le_bytes());
            file[offset + 4..offset + 4 + text.len()].copy_from_slice(text.as_bytes());
        };
        put(0x2c, unity, &mut file);
        put(0x7a4, game, &mut file);
        file
    }

    #[test]
    fn finds_the_current_layout() {
        let file = synthetic_ggm("2022.3.44f1", "2026.8.18");
        let version = read_game_version(&file).expect("version");
        assert_eq!(version.game, "2026.8.18");
        assert_eq!(version.unity.as_deref(), Some("2022.3.44f1"));
        assert_eq!(version.directory_name(), "V2026.8.18");
    }

    #[test]
    fn handles_the_new_short_version_scheme() {
        // Among Us moved from date-style versions to 17.x in 2025.
        let file = synthetic_ggm("2022.3.44f1", "17.4.0");
        let version = read_game_version(&file).expect("version");
        assert_eq!(version.game, "17.4.0");
        assert_eq!(version.directory_name(), "V17.4.0");
    }

    #[test]
    fn does_not_mistake_the_unity_version_for_the_game_version() {
        let file = synthetic_ggm("2020.3.45f1", "2021.6.30");
        let version = read_game_version(&file).expect("version");
        assert_eq!(version.game, "2021.6.30");
    }

    #[test]
    fn survives_a_layout_move() {
        // Same content, different position: the old fixed window would miss this.
        let mut file = vec![0u8; 0x4000];
        let unity = "2022.3.44f1";
        let game = "2027.1.1";
        file[0x30..0x34].copy_from_slice(&(unity.len() as u32).to_le_bytes());
        file[0x34..0x34 + unity.len()].copy_from_slice(unity.as_bytes());
        file[0x3000..0x3004].copy_from_slice(&(game.len() as u32).to_le_bytes());
        file[0x3004..0x3004 + game.len()].copy_from_slice(game.as_bytes());
        assert_eq!(read_game_version(&file).expect("version").game, "2027.1.1");
    }

    #[test]
    fn a_file_without_a_version_is_an_error_not_a_silent_none() {
        let file = vec![0u8; 4096];
        let error = read_game_version(&file).expect_err("should fail");
        assert!(error.to_string().contains("no game version string"));
    }

    #[test]
    fn does_not_read_past_the_end() {
        // A length prefix at the very end promising more bytes than exist.
        let mut file = vec![0u8; 8];
        file[4..8].copy_from_slice(&9999u32.to_le_bytes());
        assert!(read_game_version(&file).is_err());
    }

    #[test]
    fn version_shape_filter() {
        assert!(looks_like_a_version("2026.8.18"));
        assert!(looks_like_a_version("17.4.0"));
        assert!(looks_like_a_version("2022.3.44f1"));
        assert!(!looks_like_a_version("hello.world.here"));
        assert!(!looks_like_a_version("1.2"));
        assert!(!looks_like_a_version(""));
        assert!(is_unity_version("2022.3.44f1"));
        assert!(!is_unity_version("2026.8.18"));
    }
}
