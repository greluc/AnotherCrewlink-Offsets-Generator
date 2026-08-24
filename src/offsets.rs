//! The `offsets.json` schema, in the order the client's `IOffsets` declares it.
//!
//! Field order is deliberate: the offsets repository is reviewed as a git diff,
//! and keeping the generated file in the same shape as the hand-written ones
//! means a diff shows what actually changed instead of a reordering.

use serde::{Deserialize, Serialize};

/// Value written into chain slot 0 for anything the client resolves by
/// signature at runtime.
///
/// `GameReader.initializeoffsets` overwrites `meetingHud[0]`, `allPlayersPtr[0]`,
/// `shipStatus[0]`, `miniGame[0]`, `palette[0]`, `gameoptionsData[0]`,
/// `serverManager_currentServer[0]` and `innerNetClient.base[0]` with the result
/// of a pattern scan before reading anything, so whatever we put there is never
/// used. Emitting a fixed marker rather than the build's real RVA keeps those
/// eight lines out of every diff, which is what makes a version-to-version diff
/// worth reading. The real addresses go in the run report instead.
pub const SIGNATURE_RESOLVED: i64 = -1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Offsets {
    #[serde(rename = "meetingHud")]
    pub meeting_hud: Vec<i64>,
    #[serde(rename = "objectCachePtr")]
    pub object_cache_ptr: Vec<i64>,
    #[serde(rename = "meetingHudState")]
    pub meeting_hud_state: Vec<i64>,
    #[serde(rename = "allPlayersPtr")]
    pub all_players_ptr: Vec<i64>,
    #[serde(rename = "allPlayers")]
    pub all_players: Vec<i64>,
    #[serde(rename = "playerCount")]
    pub player_count: Vec<i64>,
    #[serde(rename = "playerAddrPtr")]
    pub player_addr_ptr: i64,
    #[serde(rename = "shipStatus")]
    pub ship_status: Vec<i64>,
    #[serde(rename = "shipStatus_systems")]
    pub ship_status_systems: Vec<i64>,
    #[serde(rename = "shipStatus_map")]
    pub ship_status_map: Vec<i64>,
    #[serde(rename = "shipstatus_allDoors")]
    pub shipstatus_all_doors: Vec<i64>,
    #[serde(rename = "door_doorId")]
    pub door_door_id: i64,
    #[serde(rename = "door_isOpen")]
    pub door_is_open: i64,
    // `mushroomDoor_isOpen` used to sit here. The client never read it: it is
    // absent from `IOffsets` and has no references anywhere in AnotherCrewLink.
    // What it did do was fail to resolve on every build made before the Fungle
    // added `MushroomWallDoor`, and get published as -1 in 28 of the 44 offsets
    // files -- the single largest source of unresolved values in the repository,
    // for a field nothing consumes.
    #[serde(rename = "deconDoorUpperOpen")]
    pub decon_door_upper_open: Vec<i64>,
    #[serde(rename = "deconDoorLowerOpen")]
    pub decon_door_lower_open: Vec<i64>,
    #[serde(rename = "hqHudSystemType_CompletedConsoles")]
    pub hq_hud_completed_consoles: Vec<i64>,
    #[serde(rename = "HudOverrideSystemType_isActive")]
    pub hud_override_is_active: Vec<i64>,
    #[serde(rename = "miniGame")]
    pub mini_game: Vec<i64>,
    #[serde(rename = "planetSurveillanceMinigame_currentCamera")]
    pub planet_surveillance_current_camera: Vec<i64>,
    #[serde(rename = "planetSurveillanceMinigame_camarasCount")]
    pub planet_surveillance_camaras_count: Vec<i64>,
    #[serde(rename = "surveillanceMinigame_FilteredRoomsCount")]
    pub surveillance_filtered_rooms_count: Vec<i64>,
    #[serde(rename = "lightRadius")]
    pub light_radius: Vec<i64>,
    #[serde(rename = "palette")]
    pub palette: Vec<i64>,
    #[serde(rename = "palette_playercolor")]
    pub palette_playercolor: Vec<i64>,
    #[serde(rename = "palette_shadowColor")]
    pub palette_shadow_color: Vec<i64>,
    #[serde(rename = "playerControl_GameOptions")]
    pub player_control_game_options: Vec<i64>,
    #[serde(rename = "gameoptionsData")]
    pub gameoptions_data: Vec<i64>,
    #[serde(rename = "gameOptions_MapId")]
    pub game_options_map_id: Vec<i64>,
    #[serde(rename = "gameOptions_MaxPLayers")]
    pub game_options_max_players: Vec<i64>,
    #[serde(rename = "serverManager_currentServer")]
    pub server_manager_current_server: Vec<i64>,
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
    #[serde(rename = "innerNetClient")]
    pub inner_net_client: InnerNetClient,
    #[serde(rename = "player")]
    pub player: Player,
    #[serde(rename = "signatures")]
    pub signatures: Signatures,
    #[serde(rename = "oldMeetingHud")]
    pub old_meeting_hud: bool,
    #[serde(rename = "disableWriting")]
    pub disable_writing: bool,
    #[serde(rename = "newGameOptions")]
    pub new_game_options: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InnerNetClient {
    #[serde(rename = "base")]
    pub base: Vec<i64>,
    #[serde(rename = "networkAddress")]
    pub network_address: i64,
    #[serde(rename = "networkPort")]
    pub network_port: i64,
    #[serde(rename = "gameMode")]
    pub game_mode: i64,
    #[serde(rename = "gameId")]
    pub game_id: i64,
    #[serde(rename = "hostId")]
    pub host_id: i64,
    #[serde(rename = "clientId")]
    pub client_id: i64,
    #[serde(rename = "gameState")]
    pub game_state: i64,
    #[serde(rename = "onlineScene")]
    pub online_scene: i64,
    #[serde(rename = "mainMenuScene")]
    pub main_menu_scene: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Player {
    #[serde(rename = "struct")]
    pub struct_layout: Vec<StructMember>,
    #[serde(rename = "isDummy")]
    pub is_dummy: Vec<i64>,
    #[serde(rename = "isLocal")]
    pub is_local: Vec<i64>,
    #[serde(rename = "localX")]
    pub local_x: Vec<i64>,
    #[serde(rename = "localY")]
    pub local_y: Vec<i64>,
    #[serde(rename = "remoteX")]
    pub remote_x: Vec<i64>,
    #[serde(rename = "remoteY")]
    pub remote_y: Vec<i64>,
    #[serde(rename = "bufferLength")]
    pub buffer_length: i64,
    #[serde(rename = "offsets")]
    pub offsets: Vec<i64>,
    #[serde(rename = "inVent")]
    pub in_vent: Vec<i64>,
    #[serde(rename = "clientId")]
    pub client_id: Vec<i64>,
    #[serde(rename = "currentOutfit")]
    pub current_outfit: Vec<i64>,
    #[serde(rename = "roleTeam")]
    pub role_team: Vec<i64>,
    #[serde(rename = "nameText")]
    pub name_text: Vec<i64>,
    #[serde(rename = "outfit")]
    pub outfit: Outfit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Outfit {
    #[serde(rename = "colorId")]
    pub color_id: Vec<i64>,
    #[serde(rename = "hatId")]
    pub hat_id: Vec<i64>,
    #[serde(rename = "skinId")]
    pub skin_id: Vec<i64>,
    #[serde(rename = "visorId")]
    pub visor_id: Vec<i64>,
    #[serde(rename = "playerName")]
    pub player_name: Vec<i64>,
}

/// One entry of the `structron` layout the client builds for a player record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StructMember {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(rename = "skip", skip_serializing_if = "Option::is_none")]
    pub skip: Option<i64>,
    #[serde(rename = "name")]
    pub name: String,
}

impl StructMember {
    pub fn value(kind: &str, name: &str) -> Self {
        Self {
            kind: kind.to_string(),
            skip: None,
            name: name.to_string(),
        }
    }

    pub fn padding(bytes: i64) -> Self {
        Self {
            kind: "SKIP".to_string(),
            skip: Some(bytes),
            name: "unused".to_string(),
        }
    }

    pub fn size(&self) -> i64 {
        match self.kind.as_str() {
            "SKIP" => self.skip.unwrap_or(0),
            "BYTE" | "CHAR" => 1,
            "SHORT" | "SHORT_BE" | "USHORT" | "USHORT_BE" => 2,
            _ => 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Signatures {
    #[serde(rename = "innerNetClient")]
    pub inner_net_client: Signature,
    #[serde(rename = "meetingHud")]
    pub meeting_hud: Signature,
    #[serde(rename = "gameData")]
    pub game_data: Signature,
    #[serde(rename = "shipStatus")]
    pub ship_status: Signature,
    #[serde(rename = "miniGame")]
    pub mini_game: Signature,
    #[serde(rename = "palette")]
    pub palette: Signature,
    #[serde(rename = "playerControl")]
    pub player_control: Signature,
    #[serde(rename = "showModStamp")]
    pub show_mod_stamp: Signature,
    #[serde(rename = "connectFunc")]
    pub connect_func: Signature,
    #[serde(rename = "fixedUpdateFunc")]
    pub fixed_update_func: Signature,
    #[serde(rename = "pingMessageString")]
    pub ping_message_string: Signature,
    #[serde(rename = "modLateUpdate")]
    pub mod_late_update: Signature,
    #[serde(rename = "serverManager")]
    pub server_manager: Signature,
    #[serde(rename = "gameOptionsManager")]
    pub game_options_manager: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Signature {
    #[serde(rename = "sig", skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    #[serde(rename = "patternOffset", skip_serializing_if = "Option::is_none")]
    pub pattern_offset: Option<i64>,
    #[serde(rename = "addressOffset", skip_serializing_if = "Option::is_none")]
    pub address_offset: Option<i64>,
}

impl Signature {
    pub fn is_present(&self) -> bool {
        self.sig.as_ref().is_some_and(|sig| !sig.trim().is_empty())
    }
}

impl Offsets {
    /// Every static chain whose first element the client replaces at runtime,
    /// paired with the signature that replaces it. Used by validation so the
    /// two can never drift apart.
    pub fn signature_backed_chains(&self) -> Vec<(&'static str, &Vec<i64>, &Signature)> {
        vec![
            (
                "meetingHud",
                &self.meeting_hud,
                &self.signatures.meeting_hud,
            ),
            (
                "allPlayersPtr",
                &self.all_players_ptr,
                &self.signatures.game_data,
            ),
            (
                "shipStatus",
                &self.ship_status,
                &self.signatures.ship_status,
            ),
            ("miniGame", &self.mini_game, &self.signatures.mini_game),
            ("palette", &self.palette, &self.signatures.palette),
            (
                "gameoptionsData",
                &self.gameoptions_data,
                &self.signatures.game_options_manager,
            ),
            (
                "serverManager_currentServer",
                &self.server_manager_current_server,
                &self.signatures.server_manager,
            ),
            (
                "innerNetClient.base",
                &self.inner_net_client.base,
                &self.signatures.inner_net_client,
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_member_sizes() {
        assert_eq!(StructMember::value("UINT", "id").size(), 4);
        assert_eq!(StructMember::value("BYTE", "dead").size(), 1);
        assert_eq!(StructMember::padding(20).size(), 20);
    }

    #[test]
    fn padding_is_serialised_with_skip_and_values_without() {
        let padding = serde_json::to_string(&StructMember::padding(20)).expect("json");
        assert!(padding.contains("\"skip\":20"));
        let value = serde_json::to_string(&StructMember::value("UINT", "id")).expect("json");
        assert!(!value.contains("skip"));
    }

    #[test]
    fn an_absent_signature_serialises_as_an_empty_object() {
        let json = serde_json::to_string(&Signature::default()).expect("json");
        assert_eq!(json, "{}");
        assert!(!Signature::default().is_present());
    }
}
