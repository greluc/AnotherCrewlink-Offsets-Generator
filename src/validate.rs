//! The gate between "generated" and "published".
//!
//! The old generator had nothing here. When a lookup failed it wrote `-1` into
//! the offsets file and printed a line nobody read, so a half-resolved build
//! looked exactly like a good one and the client dereferenced whatever `-1`
//! pointed at. Every check below is cheap and runs on every generated file; if
//! any of them fails, nothing is written.
//!
//! The strongest check is [`check_signatures`]: each generated signature is
//! scanned for in the mapped image and resolved with the client's own
//! arithmetic, and the result has to be the type-info slot it was built from.
//! That verifies the signature end to end rather than trusting the code that
//! produced it.

use crate::offsets::{Offsets, Signature, SIGNATURE_RESOLVED};
use crate::pattern::Pattern;
use crate::pe::{Arch, Image};
use crate::scriptjson::TypeInfoTable;
use crate::siggen::SignatureGenerator;

/// Largest offset we believe in. Real ones are in the hundreds; a value in the
/// millions means an address leaked into a field slot.
const MAX_PLAUSIBLE_OFFSET: i64 = 65_536;

pub struct Report {
    pub problems: Vec<String>,
    /// Things that are not wrong but that a maintainer should see. A stale
    /// write-path signature is the motivating case: harmless while writing is
    /// off, and a live hazard the moment it is turned on.
    pub warnings: Vec<String>,
    pub checks_run: usize,
}

impl Report {
    pub fn is_ok(&self) -> bool {
        self.problems.is_empty()
    }
}

pub fn validate(offsets: &Offsets, image: &Image, types: &TypeInfoTable) -> Report {
    let mut problems = Vec::new();
    let mut warnings = Vec::new();
    let mut checks = 0usize;

    checks += check_no_sentinels(offsets, &mut problems);
    checks += check_chain_shapes(offsets, &mut problems);
    checks += check_player_struct(offsets, &mut problems);
    checks += check_signatures(offsets, image, types, &mut problems);
    checks += check_write_path(offsets, image, &mut problems, &mut warnings);

    Report {
        problems,
        warnings,
        checks_run: checks,
    }
}

/// The subset of checks that need only the file, not the game binary.
///
/// Useful for linting an offsets file in CI, where no Among Us install exists.
pub fn structural_problems(offsets: &Offsets) -> Vec<String> {
    let mut problems = Vec::new();
    check_no_sentinels(offsets, &mut problems);
    check_chain_shapes(offsets, &mut problems);
    check_player_struct(offsets, &mut problems);
    problems
}

/// No unresolved values anywhere. Slot 0 of a signature-backed chain is the one
/// legitimate negative number in the file.
fn check_no_sentinels(offsets: &Offsets, problems: &mut Vec<String>) -> usize {
    let mut checks = 0;
    let json = match serde_json::to_value(offsets) {
        Ok(value) => value,
        Err(error) => {
            problems.push(format!("offsets could not be serialised: {error}"));
            return 1;
        }
    };

    let signature_heads: Vec<String> = offsets
        .signature_backed_chains()
        .iter()
        .map(|(name, _, _)| (*name).to_string())
        .chain(std::iter::once("playerControl_GameOptions".to_string()))
        .collect();

    walk(&json, String::new(), &mut |path, value| {
        checks += 1;
        // Signatures are checked properly further down. Their numbers are
        // instruction-encoding adjustments, not field offsets: `addressOffset`
        // is legitimately negative when a signature anchors after the field it
        // describes, which several of the carried write-path ones do.
        if path.starts_with("signatures.") {
            return;
        }
        let Some(number) = value.as_i64() else {
            return;
        };
        // Slot 0 of a signature-backed chain holds nothing meaningful: the
        // client replaces it with a pattern scan before use, and the existing
        // files put -1, 65535 or a stale address there. Skip it entirely rather
        // than pick a favourite.
        // `signature_backed_chains` already names the nested one
        // "innerNetClient.base", which is exactly the path walk() produces.
        if signature_heads
            .iter()
            .any(|head| path == format!("{head}[0]"))
        {
            return;
        }

        if number == SIGNATURE_RESOLVED {
            problems.push(format!(
                "{path} is {SIGNATURE_RESOLVED}, which is the marker for \"resolved by \
                 signature at runtime\". Outside slot 0 of a signature-backed chain that means \
                 a lookup failed"
            ));
        } else if number < 0 {
            problems.push(format!("{path} is negative ({number})"));
        } else if number > MAX_PLAUSIBLE_OFFSET {
            problems.push(format!(
                "{path} is {number}, far past any plausible field offset"
            ));
        }
    });

    checks
}

fn walk(value: &serde_json::Value, path: String, visit: &mut impl FnMut(&str, &serde_json::Value)) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                walk(child, child_path, visit);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                walk(child, format!("{path}[{index}]"), visit);
            }
        }
        other => visit(&path, other),
    }
}

/// Every signature-backed chain must start with the marker and continue with
/// the same `static_fields` offset. A mismatch means one of them was built from
/// a stale constant.
fn check_chain_shapes(offsets: &Offsets, problems: &mut Vec<String>) -> usize {
    let mut checks = 0;
    let mut static_fields: Option<i64> = None;

    for (name, chain, signature) in offsets.signature_backed_chains() {
        checks += 1;
        if chain.len() < 2 {
            problems.push(format!(
                "{name} has {} element(s); a signature-backed chain needs at least the \
                 slot and static_fields",
                chain.len()
            ));
            continue;
        }
        // Slot 0 is deliberately not checked. The client overwrites it from
        // this chain's signature before reading anything, so its value carries
        // no meaning -- the hand-written files variously use -1, 65535, and
        // stale real addresses. Insisting on one of them would make `verify`
        // reject perfectly good files over a cosmetic difference, and the check
        // that matters (does the signature resolve to the right slot?) is
        // further down.
        match static_fields {
            None => static_fields = Some(chain[1]),
            Some(expected) if expected != chain[1] => problems.push(format!(
                "{name}[1] is {} but other chains use {expected} for Il2CppClass::static_fields",
                chain[1]
            )),
            _ => {}
        }
        if !signature.is_present() {
            problems.push(format!(
                "{name} is resolved by signature at runtime but its signature is empty"
            ));
        }
    }
    checks
}

fn check_player_struct(offsets: &Offsets, problems: &mut Vec<String>) -> usize {
    let player = &offsets.player;
    let total: i64 = player
        .struct_layout
        .iter()
        .map(|member| member.size())
        .sum();

    if total != player.buffer_length {
        problems.push(format!(
            "player.struct describes {total} bytes but player.bufferLength is {}; the client \
             reads bufferLength bytes and parses them with the struct, so the two have to agree",
            player.buffer_length
        ));
    }
    if player.struct_layout.iter().any(|member| member.size() <= 0) {
        problems.push("player.struct contains a member of zero or negative size".to_string());
    }
    // Every member GameReader looks up by name. `getOffsetByName` returns
    // undefined for one that is not there, which turns into a NaN address and
    // a read that quietly yields nothing -- so a file missing one of these
    // produces no player data at all, without any error.
    //
    // This is not hypothetical. Eight files in the offsets repository predate
    // the switch from GameData.PlayerInfo to NetworkedPlayerInfo and carry the
    // older layout, with `color`, `hat` and `impostor` as direct members and no
    // `outfitsPtr` or `rolePtr`. They stayed mapped for years while being
    // unreadable, because nothing checked the shape.
    for required in [
        "id",
        "outfitsPtr",
        "rolePtr",
        "taskPtr",
        "dead",
        "objectPtr",
    ] {
        if !player
            .struct_layout
            .iter()
            .any(|member| member.name == required)
        {
            problems.push(format!(
                "player.struct is missing '{required}', which GameReader reads by name -- \
                 the client would get no player data from this file"
            ));
        }
    }
    4
}

/// Checks the signatures the generator cannot produce.
///
/// `showModStamp`, `connectFunc`, `fixedUpdateFunc`, `modLateUpdate` and
/// `pingMessageString` do not point at a type-info slot. They are hook points
/// for the shellcode `GameReader` writes into the running game, which is why it
/// computes things like `relativeConnectJMP` and lands five bytes into a
/// function. Which function to detour and where inside it is a decision encoded
/// in those patterns, not something metadata can answer, so they are carried
/// from the base file rather than generated.
///
/// What can be checked is whether they still mean anything on this build, and
/// what happens if they do not:
///
///   * with `disableWriting` off, the client patches the game using these
///     addresses. A signature that does not match resolves to something
///     arbitrary and the client writes shellcode there. That is a failure.
///   * with `disableWriting` on, nothing reads them. That is a warning, so the
///     staleness stays visible instead of being discovered by whoever turns
///     writing back on.
fn check_write_path(
    offsets: &Offsets,
    image: &Image,
    problems: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> usize {
    // GameReader only scans for these inside an `if (!is_64bit)` branch.
    if image.arch != Arch::X86 {
        return 0;
    }

    let entries: [(&str, &Signature); 5] = [
        ("showModStamp", &offsets.signatures.show_mod_stamp),
        ("connectFunc", &offsets.signatures.connect_func),
        ("fixedUpdateFunc", &offsets.signatures.fixed_update_func),
        ("modLateUpdate", &offsets.signatures.mod_late_update),
        ("pingMessageString", &offsets.signatures.ping_message_string),
    ];

    let mut checks = 0;
    let mut stale = Vec::new();

    for (name, signature) in entries {
        checks += 1;
        let matches = signature
            .sig
            .as_deref()
            .and_then(|text| Pattern::parse(text).ok())
            .map(|pattern| pattern.find_all(image.mapped(), 2).len());

        let usable = match matches {
            Some(1) => true,
            // The client takes the first match, so several is not fatal on its
            // own -- but it is a coin flip, and worth naming.
            Some(count) if count > 1 => {
                stale.push(format!("{name} matches more than once"));
                true
            }
            Some(_) => {
                stale.push(format!("{name} does not match this build"));
                false
            }
            None => {
                stale.push(format!("{name} is missing or unparseable"));
                false
            }
        };

        if !usable && !offsets.disable_writing {
            problems.push(format!(
                "signatures.{name} does not resolve on this build, and disableWriting is \
                 false. The client patches the running game with this address -- writing \
                 shellcode to whatever it resolves to instead is not something to ship."
            ));
        }
    }

    if !stale.is_empty() && offsets.disable_writing {
        warnings.push(format!(
            "write-path signatures are stale ({}). Harmless while disableWriting is true, \
             since nothing reads them -- but they have to be refreshed by hand before it is \
             turned off. They are hook points for injected shellcode and cannot be generated.",
            stale.join(", ")
        ));
    }

    checks
}

/// Resolves every generated signature the way the client will, and checks it
/// lands on the right type-info slot.
fn check_signatures(
    offsets: &Offsets,
    image: &Image,
    types: &TypeInfoTable,
    problems: &mut Vec<String>,
) -> usize {
    let generator = SignatureGenerator::new(image);
    let expectations: [(&str, &Signature, &str); 9] = [
        (
            "innerNetClient",
            &offsets.signatures.inner_net_client,
            "AmongUsClient",
        ),
        ("meetingHud", &offsets.signatures.meeting_hud, "MeetingHud"),
        ("gameData", &offsets.signatures.game_data, "GameData"),
        ("shipStatus", &offsets.signatures.ship_status, "ShipStatus"),
        ("miniGame", &offsets.signatures.mini_game, "Minigame"),
        ("palette", &offsets.signatures.palette, "Palette"),
        (
            "playerControl",
            &offsets.signatures.player_control,
            "PlayerControl",
        ),
        (
            "serverManager",
            &offsets.signatures.server_manager,
            "ServerManager",
        ),
        (
            "gameOptionsManager",
            &offsets.signatures.game_options_manager,
            "GameOptionsManager",
        ),
    ];

    let mut checks = 0;
    for (name, signature, type_name) in expectations {
        checks += 1;
        let Some(text) = signature.sig.as_ref() else {
            problems.push(format!("signatures.{name} is missing"));
            continue;
        };
        let pattern = match Pattern::parse(text) {
            Ok(pattern) => pattern,
            Err(error) => {
                problems.push(format!("signatures.{name} does not parse: {error}"));
                continue;
            }
        };

        let matches = pattern.find_all(image.mapped(), 4);
        if matches.len() != 1 {
            problems.push(format!(
                "signatures.{name} matches {} times in the module; the client takes the first \
                 match, so anything but exactly one is a coin flip on the next build",
                if matches.len() >= 4 {
                    "4 or more".to_string()
                } else {
                    matches.len().to_string()
                }
            ));
            continue;
        }

        let expected = types.slot(type_name);
        let resolved = generator.resolve_like_the_client(
            matches[0],
            signature.pattern_offset.unwrap_or(0),
            signature.address_offset.unwrap_or(0),
        );
        match (resolved, expected) {
            (Ok(actual), Some(want)) if actual == want => {}
            (Ok(actual), Some(want)) => problems.push(format!(
                "signatures.{name} resolves to 0x{actual:X} but {type_name}_TypeInfo is at \
                 0x{want:X}"
            )),
            (Ok(_), None) => problems.push(format!(
                "signatures.{name}: {type_name}_TypeInfo is not in script.json, so the \
                 signature cannot be checked"
            )),
            (Err(error), _) => {
                problems.push(format!("signatures.{name} does not resolve: {error}"))
            }
        }
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offsets::{InnerNetClient, Outfit, Player, Signatures, StructMember};

    fn minimal_offsets() -> Offsets {
        let sig = |text: &str| Signature {
            sig: Some(text.to_string()),
            pattern_offset: Some(3),
            address_offset: Some(0),
        };
        Offsets {
            meeting_hud: vec![SIGNATURE_RESOLVED, 92, 0],
            object_cache_ptr: vec![8],
            meeting_hud_state: vec![136],
            all_players_ptr: vec![SIGNATURE_RESOLVED, 92, 0, 16],
            all_players: vec![8],
            player_count: vec![12],
            player_addr_ptr: 16,
            ship_status: vec![SIGNATURE_RESOLVED, 92, 0],
            ship_status_systems: vec![160],
            ship_status_map: vec![256],
            shipstatus_all_doors: vec![148],
            door_door_id: 16,
            door_is_open: 24,
            decon_door_upper_open: vec![16, 24],
            decon_door_lower_open: vec![20, 24],
            hq_hud_completed_consoles: vec![12, 16],
            hud_override_is_active: vec![8],
            mini_game: vec![SIGNATURE_RESOLVED, 92, 0],
            planet_surveillance_current_camera: vec![136],
            planet_surveillance_camaras_count: vec![116, 12],
            surveillance_filtered_rooms_count: vec![92, 12],
            light_radius: vec![140, 16],
            palette: vec![SIGNATURE_RESOLVED, 92],
            palette_playercolor: vec![644],
            palette_shadow_color: vec![648],
            player_control_game_options: vec![SIGNATURE_RESOLVED, 92, 20],
            gameoptions_data: vec![SIGNATURE_RESOLVED, 92, 0, 20],
            game_options_map_id: vec![20],
            game_options_max_players: vec![12],
            server_manager_current_server: vec![SIGNATURE_RESOLVED, 92, 4, 20, 8],
            connect_func: 4095,
            show_mod_stamp_func: 4095,
            mod_late_update_func: 255,
            fixed_update_func: 4095,
            ping_message_string: 4095,
            inner_net_client: InnerNetClient {
                base: vec![SIGNATURE_RESOLVED, 92, 0],
                network_address: 20,
                network_port: 24,
                game_mode: 40,
                game_id: 44,
                host_id: 48,
                client_id: 52,
                game_state: 100,
                online_scene: 176,
                main_menu_scene: 180,
            },
            player: Player {
                struct_layout: vec![
                    StructMember::padding(40),
                    StructMember::value("UINT", "id"),
                    StructMember::padding(20),
                    StructMember::value("UINT", "outfitsPtr"),
                    StructMember::value("UINT", "playerLevel"),
                    StructMember::value("UINT", "disconnected"),
                    StructMember::value("UINT", "rolePtr"),
                    StructMember::value("UINT", "taskPtr"),
                    StructMember::value("BYTE", "dead"),
                    StructMember::padding(3),
                    StructMember::value("UINT", "objectPtr"),
                ],
                is_dummy: vec![184],
                is_local: vec![60, 132],
                local_x: vec![152, 44, 8, 124],
                local_y: vec![152, 44, 8, 128],
                remote_x: vec![152, 44, 8, 124],
                remote_y: vec![152, 44, 8, 128],
                buffer_length: 92,
                offsets: vec![0, 0],
                in_vent: vec![72],
                client_id: vec![32],
                current_outfit: vec![68],
                role_team: vec![80],
                name_text: vec![60, 52, 132],
                outfit: Outfit {
                    color_id: vec![8],
                    hat_id: vec![12],
                    skin_id: vec![20],
                    visor_id: vec![24],
                    player_name: vec![32],
                },
            },
            signatures: Signatures {
                inner_net_client: sig("8B 0D ? ? ? ?"),
                meeting_hud: sig("8B 0D ? ? ? ?"),
                game_data: sig("8B 0D ? ? ? ?"),
                ship_status: sig("8B 0D ? ? ? ?"),
                mini_game: sig("8B 0D ? ? ? ?"),
                palette: sig("8B 0D ? ? ? ?"),
                player_control: sig("8B 0D ? ? ? ?"),
                show_mod_stamp: Signature::default(),
                connect_func: Signature::default(),
                fixed_update_func: Signature::default(),
                ping_message_string: Signature::default(),
                mod_late_update: Signature::default(),
                server_manager: sig("8B 0D ? ? ? ?"),
                game_options_manager: sig("8B 0D ? ? ? ?"),
            },
            old_meeting_hud: false,
            disable_writing: true,
            new_game_options: true,
        }
    }

    #[test]
    fn a_clean_file_has_no_structural_problems() {
        let offsets = minimal_offsets();
        let mut problems = Vec::new();
        check_no_sentinels(&offsets, &mut problems);
        check_chain_shapes(&offsets, &mut problems);
        check_player_struct(&offsets, &mut problems);
        assert!(problems.is_empty(), "unexpected problems: {problems:?}");
    }

    #[test]
    fn a_stray_minus_one_is_caught() {
        let mut offsets = minimal_offsets();
        offsets.player.role_team = vec![SIGNATURE_RESOLVED];
        let mut problems = Vec::new();
        check_no_sentinels(&offsets, &mut problems);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("player.roleTeam[0]"));
    }

    #[test]
    fn an_address_leaking_into_a_field_slot_is_caught() {
        let mut offsets = minimal_offsets();
        offsets.player.in_vent = vec![44_941_892];
        let mut problems = Vec::new();
        check_no_sentinels(&offsets, &mut problems);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("plausible"));
    }

    #[test]
    fn inconsistent_static_fields_offsets_are_caught() {
        let mut offsets = minimal_offsets();
        offsets.ship_status = vec![SIGNATURE_RESOLVED, 184, 0];
        let mut problems = Vec::new();
        check_chain_shapes(&offsets, &mut problems);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("static_fields"));
    }

    #[test]
    fn a_missing_signature_for_a_signature_backed_chain_is_caught() {
        let mut offsets = minimal_offsets();
        offsets.signatures.palette = Signature::default();
        let mut problems = Vec::new();
        check_chain_shapes(&offsets, &mut problems);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("signature is empty"));
    }

    #[test]
    fn struct_and_buffer_length_must_agree() {
        let mut offsets = minimal_offsets();
        offsets.player.buffer_length = 136;
        let mut problems = Vec::new();
        check_player_struct(&offsets, &mut problems);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("bufferLength"));
    }

    #[test]
    fn a_struct_missing_object_ptr_is_caught() {
        let mut offsets = minimal_offsets();
        offsets
            .player
            .struct_layout
            .retain(|m| m.name != "objectPtr");
        offsets.player.buffer_length = 88;
        let mut problems = Vec::new();
        check_player_struct(&offsets, &mut problems);
        assert!(problems.iter().any(|p| p.contains("objectPtr")));
    }
}
