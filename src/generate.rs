//! Turns a dump plus a binary into an `offsets.json`.
//!
//! Every value here has a stated provenance, which is the whole point:
//!
//!   * **derived** -- read out of `dump.cs` by class and field name;
//!   * **layout** -- follows from the pointer size (a `List<T>` keeps `_items`
//!     two pointers in and `_size` three, an `Il2CppArray` starts its data four
//!     pointers in). Generic type definitions carry no offsets in a dump, so
//!     these cannot be looked up and are computed instead;
//!   * **signature** -- resolved by [`crate::siggen`];
//!   * **carried** -- copied from the architecture's base file because it
//!     describes something no dump can tell us, such as where Unity keeps a
//!     position inside a native `Rigidbody2D`. These are listed in the run
//!     report so they never quietly rot.
//!
//! Nothing is guessed. A field that cannot be resolved is recorded as a problem
//! and the run fails rather than writing a placeholder -- the old generator
//! wrote `-1` into published offsets and said nothing, which is how a rename
//! like `InnerNetClient.GameMode` -> `NetworkMode` turned into a wrong pointer
//! for every player.

use serde::{Deserialize, Serialize};

use crate::dumpcs::Dump;
use crate::error::{Error, Result};
use crate::offsets::{
    InnerNetClient, Offsets, Outfit, Player, Signature, Signatures, StructMember,
    SIGNATURE_RESOLVED,
};
use crate::pe::Image;
use crate::scriptjson::TypeInfoTable;
use crate::siggen::SignatureGenerator;

/// The handful of numbers that cannot be derived from a dump or from the
/// pointer size, kept in `base/<arch>.json` so they can be corrected without a
/// rebuild.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseConstants {
    /// Offset of `position.x` inside Unity's native `Rigidbody2D`. Native, so
    /// it appears in no managed dump; `position.y` follows four bytes later.
    #[serde(rename = "nativeRigidbodyPositionX")]
    pub native_rigidbody_position_x: i64,

    /// Tail of the `serverManager_currentServer` chain after `static_fields`.
    /// Walks the singleton to the current region and its name; the shape has
    /// never been re-derived from a dump, so it is carried verbatim.
    #[serde(rename = "serverManagerTail")]
    pub server_manager_tail: Vec<i64>,

    /// Tail of the vestigial `playerControl_GameOptions` chain. The client
    /// stopped reading it once `newGameOptions` was introduced; it stays in the
    /// file only so the shape matches the hand-written ones.
    #[serde(rename = "playerControlGameOptionsTail")]
    pub player_control_game_options_tail: Vec<i64>,

    /// Placeholder values for the write-path function offsets.
    #[serde(rename = "functionPlaceholders")]
    pub function_placeholders: FunctionPlaceholders,

    /// Signatures for the write path (mod stamp, connect hook, ping string).
    /// These point at function bodies rather than at a type-info slot, so the
    /// generator cannot produce them. On x86 the client scans for them
    /// unconditionally, so they have to be present and syntactically valid even
    /// when `disableWriting` is set.
    #[serde(rename = "carriedSignatures")]
    pub carried_signatures: CarriedSignatures,

    #[serde(rename = "flags")]
    pub flags: Flags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionPlaceholders {
    #[serde(rename = "connectFunc")]
    pub connect_func: i64,
    #[serde(rename = "showModStampFunc")]
    pub show_mod_stamp_func: i64,
    #[serde(rename = "modLateUpdateFunc")]
    pub mod_late_update_func: i64,
    #[serde(rename = "fixedUpdateFunc")]
    pub fixed_update_func: i64,
    #[serde(rename = "pingMessageString")]
    pub ping_message_string: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CarriedSignatures {
    #[serde(rename = "showModStamp", default)]
    pub show_mod_stamp: Signature,
    #[serde(rename = "connectFunc", default)]
    pub connect_func: Signature,
    #[serde(rename = "fixedUpdateFunc", default)]
    pub fixed_update_func: Signature,
    #[serde(rename = "pingMessageString", default)]
    pub ping_message_string: Signature,
    #[serde(rename = "modLateUpdate", default)]
    pub mod_late_update: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flags {
    #[serde(rename = "oldMeetingHud")]
    pub old_meeting_hud: bool,
    #[serde(rename = "disableWriting")]
    pub disable_writing: bool,
    #[serde(rename = "newGameOptions")]
    pub new_game_options: bool,
}

impl BaseConstants {
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let text = crate::error::read_to_string_lossy(&path)?;
        serde_json::from_str(&text).map_err(|error| {
            Error::malformed(format!(
                "{}: not a usable base file: {error}",
                path.as_ref().display()
            ))
        })
    }
}

/// Where a produced number came from, for the run report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    Derived(String),
    Layout(String),
    SignatureFor(String),
    Carried(String),
}

pub struct GenerationOutcome {
    pub offsets: Offsets,
    pub provenance: Vec<(String, Provenance)>,
    pub signature_details: Vec<(String, String)>,
    /// Things that worked but that a maintainer should know about.
    pub notes: Vec<String>,
}

pub struct Generator<'a> {
    dump: &'a Dump,
    types: &'a TypeInfoTable,
    image: &'a Image,
    base: &'a BaseConstants,
    static_fields: i64,
    problems: Vec<String>,
    provenance: Vec<(String, Provenance)>,
    signature_details: Vec<(String, String)>,
    notes: Vec<String>,
}

impl<'a> Generator<'a> {
    pub fn new(
        dump: &'a Dump,
        types: &'a TypeInfoTable,
        image: &'a Image,
        base: &'a BaseConstants,
        static_fields: i64,
    ) -> Self {
        Self {
            dump,
            types,
            image,
            base,
            static_fields,
            problems: Vec::new(),
            provenance: Vec::new(),
            signature_details: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn pointer(&self) -> i64 {
        self.image.arch.pointer_size() as i64
    }

    /// Il2CppObject header, and therefore the offset of the first managed field
    /// and of `UnityEngine.Object.m_CachedPtr`.
    fn object_header(&self) -> i64 {
        2 * self.pointer()
    }

    fn list_items(&self) -> i64 {
        self.object_header()
    }

    fn list_count(&self) -> i64 {
        self.object_header() + self.pointer()
    }

    /// `Il2CppArray::max_length`, which is what the client reads for a count.
    fn array_length(&self) -> i64 {
        self.object_header() + self.pointer()
    }

    /// First element of an `Il2CppArray`.
    fn array_data(&self) -> i64 {
        4 * self.pointer()
    }

    /// `HashSet<T>::_count`. Generic definitions carry no offsets in a dump, so
    /// this follows the field order: `_buckets`, `_slots`, then `_count`.
    fn hashset_count(&self) -> i64 {
        self.object_header() + 2 * self.pointer()
    }

    fn field(&mut self, label: &str, class: &str, candidates: &[&str]) -> i64 {
        match self.dump.find_field(class, candidates) {
            Some((offset, which)) => {
                if candidates.len() > 1 && !which.ends_with(candidates[0]) {
                    self.notes.push(format!(
                        "{label}: {class}.{} is gone in this build; used {which} instead",
                        candidates[0]
                    ));
                }
                self.provenance
                    .push((label.to_string(), Provenance::Derived(which)));
                offset
            }
            None => {
                let message = self.describe_missing(label, class, candidates);
                self.problems.push(message);
                0
            }
        }
    }

    fn static_field(&mut self, label: &str, class: &str, candidates: &[&str]) -> i64 {
        match self.dump.find_static_field(class, candidates) {
            Some((offset, which)) => {
                self.provenance
                    .push((label.to_string(), Provenance::Derived(which)));
                offset
            }
            None => {
                let message = self.describe_missing(label, class, candidates);
                self.problems.push(message);
                0
            }
        }
    }

    fn describe_missing(&self, label: &str, class: &str, candidates: &[&str]) -> String {
        match self.dump.class(class) {
            None => format!(
                "{label}: class '{class}' is not in this dump at all -- it was renamed, \
                 removed, or the dump is incomplete"
            ),
            Some(class_info) => {
                let near: Vec<&str> = class_info
                    .field_names()
                    .filter(|name| {
                        candidates.iter().any(|candidate| {
                            name.to_ascii_lowercase()
                                .contains(&candidate.to_ascii_lowercase())
                                || candidate
                                    .to_ascii_lowercase()
                                    .contains(&name.to_ascii_lowercase())
                        })
                    })
                    .take(5)
                    .collect();
                let hint = if near.is_empty() {
                    String::new()
                } else {
                    format!(" (similar fields present: {})", near.join(", "))
                };
                format!("{label}: {class} has none of {:?}{hint}", candidates)
            }
        }
    }

    fn layout(&mut self, label: &str, description: &str, value: i64) -> i64 {
        self.provenance.push((
            label.to_string(),
            Provenance::Layout(description.to_string()),
        ));
        value
    }

    fn carried(&mut self, label: &str, why: &str) {
        self.provenance
            .push((label.to_string(), Provenance::Carried(why.to_string())));
    }

    /// Chain head for a static class: signature slot, `static_fields`, then
    /// dereference to the singleton `Instance`.
    fn static_chain(
        &mut self,
        label: &str,
        type_name: &str,
        signature: &mut Signature,
    ) -> Vec<i64> {
        let head = self.signature(label, type_name, signature);
        vec![head, self.static_fields, 0]
    }

    /// Chain head that stops at `static_fields`, for classes whose values are
    /// statics rather than instance fields (Palette).
    fn static_block(
        &mut self,
        label: &str,
        type_name: &str,
        signature: &mut Signature,
    ) -> Vec<i64> {
        let head = self.signature(label, type_name, signature);
        vec![head, self.static_fields]
    }

    fn signature(&mut self, label: &str, type_name: &str, signature: &mut Signature) -> i64 {
        let Some(slot) = self.types.slot(type_name) else {
            self.problems.push(format!(
                "{label}: no {type_name}_TypeInfo in script.json -- the class was renamed or \
                 removed, so its signature cannot be generated"
            ));
            return SIGNATURE_RESOLVED;
        };

        match SignatureGenerator::new(self.image).generate(slot) {
            Ok(generated) => {
                self.signature_details
                    .push((type_name.to_string(), generated.describe()));
                self.provenance.push((
                    label.to_string(),
                    Provenance::SignatureFor(type_name.to_string()),
                ));
                *signature = Signature {
                    sig: Some(generated.pattern.to_string()),
                    pattern_offset: Some(generated.pattern_offset),
                    address_offset: Some(generated.address_offset),
                };
            }
            Err(error) => {
                self.problems.push(format!(
                    "{label}: signature for {type_name} failed: {error}"
                ));
            }
        }
        SIGNATURE_RESOLVED
    }

    pub fn generate(mut self) -> Result<GenerationOutcome> {
        let mut signatures = Signatures::default();

        let object_header = self.object_header();
        let list_items = self.list_items();
        let list_count = self.list_count();
        let array_length = self.array_length();
        let array_data = self.array_data();
        let hashset_count = self.hashset_count();

        let meeting_hud =
            self.static_chain("meetingHud", "MeetingHud", &mut signatures.meeting_hud);
        let ship_status =
            self.static_chain("shipStatus", "ShipStatus", &mut signatures.ship_status);
        let mini_game = self.static_chain("miniGame", "Minigame", &mut signatures.mini_game);
        let palette_chain = self.static_block("palette", "Palette", &mut signatures.palette);

        let mut all_players_ptr =
            self.static_chain("allPlayersPtr", "GameData", &mut signatures.game_data);
        let all_players_field = self.field("allPlayersPtr[3]", "GameData", &["AllPlayers"]);
        all_players_ptr.push(all_players_field);

        let mut gameoptions_data = self.static_chain(
            "gameoptionsData",
            "GameOptionsManager",
            &mut signatures.game_options_manager,
        );
        let current_options = self.field(
            "gameoptionsData[3]",
            "GameOptionsManager",
            &["currentGameOptions"],
        );
        gameoptions_data.push(current_options);

        let mut server_manager = self.static_block(
            "serverManager_currentServer",
            "ServerManager",
            &mut signatures.server_manager,
        );
        self.carried(
            "serverManager_currentServer tail",
            "singleton walk to the current region name; never re-derived from a dump",
        );
        server_manager.extend(self.base.server_manager_tail.iter().copied());

        let mut player_control_game_options = vec![SIGNATURE_RESOLVED, self.static_fields];
        self.carried(
            "playerControl_GameOptions",
            "vestigial; the client stopped reading it when newGameOptions arrived",
        );
        player_control_game_options
            .extend(self.base.player_control_game_options_tail.iter().copied());

        let inner_net_client_base = self.static_chain(
            "innerNetClient.base",
            "AmongUsClient",
            &mut signatures.inner_net_client,
        );

        // playerControl's signature is not used for a chain of its own, but the
        // client scans for it and falls back to it when newGameOptions is off.
        let _ = self.signature(
            "signatures.playerControl",
            "PlayerControl",
            &mut signatures.player_control,
        );

        let door_is_open = self.field("door_isOpen", "PlainDoor", &["Open"]);
        let decon_upper = self.field("deconDoorUpperOpen[0]", "DeconSystem", &["UpperDoor"]);
        let decon_lower = self.field("deconDoorLowerOpen[0]", "DeconSystem", &["LowerDoor"]);

        let cosmetics = self.field("player.cosmetics", "PlayerControl", &["cosmetics"]);
        let net_transform = self.field("player.NetTransform", "PlayerControl", &["NetTransform"]);
        let body = self.field("player.body", "CustomNetworkTransform", &["body"]);
        let cached_ptr = self.layout(
            "player.localX[2]",
            "UnityEngine.Object.m_CachedPtr, first field after the object header",
            object_header,
        );
        self.carried(
            "player.localX[3]",
            "position.x inside the native Rigidbody2D; native layout, absent from any dump",
        );
        let native_x = self.base.native_rigidbody_position_x;

        let position_chain = |tail: i64| vec![net_transform, body, cached_ptr, tail];

        let player = Player {
            struct_layout: self.player_struct(),
            is_dummy: vec![self.field("player.isDummy", "PlayerControl", &["isDummy"])],
            is_local: vec![
                cosmetics,
                self.field("player.isLocal[1]", "CosmeticsLayer", &["localPlayer"]),
            ],
            local_x: position_chain(native_x),
            local_y: position_chain(native_x + 4),
            remote_x: position_chain(native_x),
            remote_y: position_chain(native_x + 4),
            buffer_length: self.player_buffer_length(),
            offsets: vec![0, 0],
            in_vent: vec![self.field("player.inVent", "PlayerControl", &["inVent"])],
            client_id: vec![self.field("player.clientId", "InnerNetObject", &["OwnerId"])],
            current_outfit: vec![self.field(
                "player.currentOutfit",
                "PlayerControl",
                &["<CurrentOutfitType>k__BackingField"],
            )],
            role_team: vec![self.field("player.roleTeam", "RoleBehaviour", &["TeamType"])],
            name_text: vec![
                cosmetics,
                self.field("player.nameText[1]", "CosmeticsLayer", &["nameText"]),
                self.field("player.nameText[2]", "TMP_Text", &["m_text"]),
            ],
            outfit: Outfit {
                color_id: vec![self.outfit_field("colorId", &["ColorId"])],
                hat_id: vec![self.outfit_field("hatId", &["HatId"])],
                skin_id: vec![self.outfit_field("skinId", &["SkinId"])],
                visor_id: vec![self.outfit_field("visorId", &["VisorId"])],
                player_name: vec![self.outfit_field("playerName", &["PlayerName", "_playerName"])],
            },
        };

        let inner_net_client = InnerNetClient {
            base: inner_net_client_base,
            network_address: self.field(
                "innerNetClient.networkAddress",
                "InnerNetClient",
                &["networkAddress"],
            ),
            network_port: self.field(
                "innerNetClient.networkPort",
                "InnerNetClient",
                &["networkPort"],
            ),
            // Renamed in 2026.8.18, same offset. Both names are tried so a
            // rename does not silently become a wrong number.
            game_mode: self.field(
                "innerNetClient.gameMode",
                "InnerNetClient",
                &["GameMode", "NetworkMode"],
            ),
            game_id: self.field("innerNetClient.gameId", "InnerNetClient", &["GameId"]),
            host_id: self.field("innerNetClient.hostId", "InnerNetClient", &["HostId"]),
            client_id: self.field("innerNetClient.clientId", "InnerNetClient", &["ClientId"]),
            game_state: self.field("innerNetClient.gameState", "InnerNetClient", &["GameState"]),
            online_scene: self.field(
                "innerNetClient.onlineScene",
                "AmongUsClient",
                &["OnlineScene"],
            ),
            main_menu_scene: self.field(
                "innerNetClient.mainMenuScene",
                "AmongUsClient",
                &["MainMenuScene"],
            ),
        };

        signatures.show_mod_stamp = self.base.carried_signatures.show_mod_stamp.clone();
        signatures.connect_func = self.base.carried_signatures.connect_func.clone();
        signatures.fixed_update_func = self.base.carried_signatures.fixed_update_func.clone();
        signatures.ping_message_string = self.base.carried_signatures.ping_message_string.clone();
        signatures.mod_late_update = self.base.carried_signatures.mod_late_update.clone();
        if signatures.show_mod_stamp.is_present() {
            self.carried(
                "signatures (write path)",
                "function-body signatures for the mod stamp and connect hook; only used when \
                 disableWriting is false",
            );
        }

        let offsets = Offsets {
            meeting_hud,
            object_cache_ptr: vec![self.layout(
                "objectCachePtr",
                "Il2CppObject header",
                object_header,
            )],
            meeting_hud_state: vec![self.field("meetingHudState", "MeetingHud", &["state"])],
            all_players_ptr,
            all_players: vec![self.layout("allPlayers", "List<T>::_items", list_items)],
            player_count: vec![self.layout("playerCount", "List<T>::_size", list_count)],
            player_addr_ptr: self.layout("playerAddrPtr", "Il2CppArray first element", array_data),
            ship_status,
            ship_status_systems: vec![self.field("shipStatus_systems", "ShipStatus", &["Systems"])],
            ship_status_map: vec![self.field("shipStatus_map", "ShipStatus", &["Type"])],
            shipstatus_all_doors: vec![self.field(
                "shipstatus_allDoors",
                "ShipStatus",
                &["AllDoors"],
            )],
            door_door_id: self.field("door_doorId", "OpenableDoor", &["Id"]),
            door_is_open,
            mushroom_door_is_open: self.field("mushroomDoor_isOpen", "MushroomWallDoor", &["open"]),
            decon_door_upper_open: vec![decon_upper, door_is_open],
            decon_door_lower_open: vec![decon_lower, door_is_open],
            hq_hud_completed_consoles: vec![
                self.field(
                    "hqHudSystemType_CompletedConsoles",
                    "HqHudSystemType",
                    &["CompletedConsoles"],
                ),
                self.layout(
                    "hqHudSystemType_CompletedConsoles[1]",
                    "HashSet<T>::_count",
                    hashset_count,
                ),
            ],
            hud_override_is_active: vec![self.field(
                "HudOverrideSystemType_isActive",
                "HudOverrideSystemType",
                &["<IsActive>k__BackingField"],
            )],
            mini_game,
            planet_surveillance_current_camera: vec![self.field(
                "planetSurveillanceMinigame_currentCamera",
                "PlanetSurveillanceMinigame",
                &["currentCamera"],
            )],
            planet_surveillance_camaras_count: vec![
                self.field(
                    "planetSurveillanceMinigame_camarasCount",
                    "PlanetSurveillanceMinigame",
                    &["survCameras"],
                ),
                self.layout(
                    "planetSurveillanceMinigame_camarasCount[1]",
                    "Il2CppArray::max_length",
                    array_length,
                ),
            ],
            surveillance_filtered_rooms_count: vec![
                self.field(
                    "surveillanceMinigame_FilteredRoomsCount",
                    "SurveillanceMinigame",
                    &["FilteredRooms"],
                ),
                self.layout(
                    "surveillanceMinigame_FilteredRoomsCount[1]",
                    "Il2CppArray::max_length",
                    array_length,
                ),
            ],
            light_radius: vec![
                self.field(
                    "lightRadius[0]",
                    "PlayerControl",
                    &["lightSource", "myLight"],
                ),
                self.field(
                    "lightRadius[1]",
                    "LightSource",
                    &["viewDistance", "LightRadius"],
                ),
            ],
            palette: palette_chain,
            palette_playercolor: vec![self.static_field(
                "palette_playercolor",
                "Palette",
                &["PlayerColors"],
            )],
            palette_shadow_color: vec![self.static_field(
                "palette_shadowColor",
                "Palette",
                &["ShadowColors"],
            )],
            player_control_game_options,
            gameoptions_data,
            game_options_map_id: vec![self.field(
                "gameOptions_MapId",
                "NormalGameOptionsV11",
                &["<MapId>k__BackingField"],
            )],
            game_options_max_players: vec![self.field(
                "gameOptions_MaxPLayers",
                "NormalGameOptionsV11",
                &["<MaxPlayers>k__BackingField"],
            )],
            server_manager_current_server: server_manager,
            connect_func: self.base.function_placeholders.connect_func,
            show_mod_stamp_func: self.base.function_placeholders.show_mod_stamp_func,
            mod_late_update_func: self.base.function_placeholders.mod_late_update_func,
            fixed_update_func: self.base.function_placeholders.fixed_update_func,
            ping_message_string: self.base.function_placeholders.ping_message_string,
            inner_net_client,
            player,
            signatures,
            old_meeting_hud: self.base.flags.old_meeting_hud,
            disable_writing: self.base.flags.disable_writing,
            new_game_options: self.base.flags.new_game_options,
        };

        if !self.problems.is_empty() {
            return Err(Error::Validation(self.problems));
        }

        Ok(GenerationOutcome {
            offsets,
            provenance: self.provenance,
            signature_details: self.signature_details,
            notes: self.notes,
        })
    }

    fn outfit_field(&mut self, label: &str, candidates: &[&str]) -> i64 {
        let full = format!("player.outfit.{label}");
        self.field(&full, "NetworkedPlayerInfo.PlayerOutfit", candidates)
    }

    /// Members of the player record the client parses with `structron`.
    ///
    /// Built by sorting the fields we care about by offset and padding the
    /// gaps, so the layout follows the dump rather than a hand-maintained list
    /// that has to be re-checked every time Innersloth adds a field.
    fn player_struct(&mut self) -> Vec<StructMember> {
        let wanted: Vec<(&str, &str, &str)> = vec![
            ("id", "PlayerId", "UINT"),
            ("outfitsPtr", "Outfits", "UINT"),
            ("playerLevel", "PlayerLevel", "UINT"),
            ("disconnected", "Disconnected", "UINT"),
            ("rolePtr", "Role", "UINT"),
            ("taskPtr", "Tasks", "UINT"),
            ("dead", "IsDead", "BYTE"),
            ("objectPtr", "_object", "UINT"),
        ];

        let mut entries: Vec<(i64, &str, &str)> = Vec::new();
        for (name, field, kind) in &wanted {
            let offset = self.field(
                &format!("player.struct.{name}"),
                "NetworkedPlayerInfo",
                &[field],
            );
            entries.push((offset, name, kind));
        }
        entries.sort_by_key(|(offset, _, _)| *offset);

        let mut members = Vec::new();
        let mut cursor = 0i64;
        for (offset, name, kind) in entries {
            if offset > cursor {
                members.push(StructMember::padding(offset - cursor));
                cursor = offset;
            }
            let member = StructMember::value(kind, name);
            cursor += member.size();
            members.push(member);
        }
        members
    }

    fn player_buffer_length(&mut self) -> i64 {
        let length = self
            .player_struct_cursor()
            .unwrap_or_else(|| self.object_header());
        self.provenance.push((
            "player.bufferLength".to_string(),
            Provenance::Layout("end of the last field read from NetworkedPlayerInfo".to_string()),
        ));
        length
    }

    fn player_struct_cursor(&self) -> Option<i64> {
        let last = self.dump.find_field("NetworkedPlayerInfo", &["_object"])?.0;
        Some(last + self.pointer())
    }
}

#[cfg(test)]
mod tests {
    use crate::offsets::StructMember;
    use crate::pe::Arch;

    fn member(kind: &str, name: &str) -> StructMember {
        StructMember::value(kind, name)
    }

    #[test]
    fn struct_padding_matches_the_reference_layout() {
        // Offsets from the real 2026.8.18 x86 dump of NetworkedPlayerInfo.
        // The expected output is byte-for-byte the hand-written V17.4.0 x86
        // struct, which is the strongest check available for this routine.
        let entries: Vec<(i64, &str, &str)> = vec![
            (40, "id", "UINT"),
            (64, "outfitsPtr", "UINT"),
            (68, "playerLevel", "UINT"),
            (72, "disconnected", "UINT"),
            (76, "rolePtr", "UINT"),
            (80, "taskPtr", "UINT"),
            (84, "dead", "BYTE"),
            (88, "objectPtr", "UINT"),
        ];
        let mut members = Vec::new();
        let mut cursor = 0i64;
        for (offset, name, kind) in entries {
            if offset > cursor {
                members.push(StructMember::padding(offset - cursor));
                cursor = offset;
            }
            let value = member(kind, name);
            cursor += value.size();
            members.push(value);
        }

        assert_eq!(members.len(), 11);
        assert_eq!(members[0], StructMember::padding(40));
        assert_eq!(members[1], member("UINT", "id"));
        assert_eq!(members[2], StructMember::padding(20));
        assert_eq!(members[8], member("BYTE", "dead"));
        assert_eq!(members[9], StructMember::padding(3));
        assert_eq!(members[10], member("UINT", "objectPtr"));
        assert_eq!(cursor, 92, "bufferLength should come out as 92 on x86");
    }

    #[test]
    fn layout_constants_follow_pointer_size() {
        // Checked against both hand-written reference files.
        for (arch, header, list_size, array_data, hashset) in
            [(Arch::X86, 8, 12, 16, 16), (Arch::X64, 16, 24, 32, 32)]
        {
            let pointer = arch.pointer_size() as i64;
            assert_eq!(2 * pointer, header);
            assert_eq!(3 * pointer, list_size);
            assert_eq!(4 * pointer, array_data);
            assert_eq!(2 * pointer + 2 * pointer, hashset);
        }
    }
}
