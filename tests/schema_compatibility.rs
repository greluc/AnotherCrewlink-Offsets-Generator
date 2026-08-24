//! Guards the contract with the client.
//!
//! `offsets.json` is consumed by `IOffsets` in AnotherCrewLink's
//! `src/main/offsetStore.ts`. Nothing in this repository can compile-check that
//! relationship, so instead the real files that client is known to accept are
//! checked in as fixtures and parsed with our own types. If a key is renamed,
//! dropped, or changes shape on either side, one of these fails.
//!
//! `generated-x86-V2026.8.18.json` is the first file this generator produced
//! for a live build. It is here as a golden copy: a change to it should be a
//! deliberate, reviewed diff, not a surprise.

use acl_offsetgen::offsets::Offsets;
use acl_offsetgen::validate;

const REFERENCE_X86: &str = include_str!("fixtures/reference-x86-V17.4.0.json");
const REFERENCE_X64: &str = include_str!("fixtures/reference-x64-V17.4.0.json");
const GENERATED_X86: &str = include_str!("fixtures/generated-x86-V2026.8.18.json");

fn parse(label: &str, text: &str) -> Offsets {
    serde_json::from_str(text).unwrap_or_else(|error| {
        panic!("{label} no longer matches the Offsets type: {error}");
    })
}

#[test]
fn hand_written_reference_files_parse_with_our_types() {
    let x86 = parse("reference x86", REFERENCE_X86);
    let x64 = parse("reference x64", REFERENCE_X64);

    // Spot-check values that exercise the awkward parts of the schema: an
    // optional signature, a chain with a nested object, and the struct list.
    assert_eq!(x86.player.buffer_length, 92);
    assert_eq!(x64.player.buffer_length, 136);
    assert!(x86.signatures.show_mod_stamp.is_present());
    assert!(
        !x64.signatures.show_mod_stamp.is_present(),
        "x64 leaves the write-path signatures empty"
    );
    assert_eq!(x86.inner_net_client.network_port, 24);
}

#[test]
fn round_tripping_a_reference_file_preserves_every_field() {
    // Serialising and re-parsing must be lossless, or regenerating a version
    // would quietly drop something the client reads.
    for (label, text) in [("x86", REFERENCE_X86), ("x64", REFERENCE_X64)] {
        let original = parse(label, text);
        let rendered = serde_json::to_string(&original).expect("serialise");
        let reparsed: Offsets = serde_json::from_str(&rendered).expect("reparse");
        assert_eq!(original, reparsed, "{label} did not survive a round trip");
    }
}

#[test]
fn generated_output_keeps_the_key_order_of_the_hand_written_files() {
    // The offsets repository is reviewed as a git diff. If our key order drifts
    // from the existing files, the first regenerated version shows up as a
    // rewrite of the whole file and the real change is lost in the noise.
    let reference: serde_json::Value =
        serde_json::from_str(REFERENCE_X86).expect("reference parses");
    let generated: serde_json::Value =
        serde_json::from_str(GENERATED_X86).expect("generated parses");

    let keys = |value: &serde_json::Value| -> Vec<String> {
        value.as_object().expect("object").keys().cloned().collect()
    };
    assert_eq!(keys(&reference), keys(&generated));
    assert_eq!(
        keys(&reference["player"]),
        keys(&generated["player"]),
        "player block key order drifted"
    );
    assert_eq!(
        keys(&reference["signatures"]),
        keys(&generated["signatures"]),
        "signatures block key order drifted"
    );
}

#[test]
fn the_golden_generated_file_still_passes_structural_validation() {
    // Runs the checks that do not need the game binary. The signature checks
    // are covered by `signature_generation.rs`; this is about shape.
    let generated = parse("generated x86", GENERATED_X86);
    let problems = validate::structural_problems(&generated);
    assert!(
        problems.is_empty(),
        "the golden file no longer validates: {problems:?}"
    );
}

#[test]
fn the_known_defects_in_the_hand_written_x86_file_are_still_defects() {
    // Three values in the shipping x86 file are wrong, and the generator
    // disagrees with all three. Pinning them here means that if someone later
    // "fixes" the generator to reproduce the reference exactly, this test says
    // why that would be a regression.
    let reference = parse("reference x86", REFERENCE_X86);
    let generated = parse("generated x86", GENERATED_X86);

    // The Instance dereference is missing from the reference chain; the x64
    // file has it, which is what shows the shape is wrong rather than clever.
    assert_eq!(reference.gameoptions_data, vec![-1, 92, 24]);
    assert_eq!(generated.gameoptions_data, vec![-1, 92, 0, 20]);

    // 8 is HashSet<T>::_buckets on x86; the count is at 16. The x64 reference
    // uses 32, which is the same field at 8-byte pointers.
    assert_eq!(reference.hq_hud_completed_consoles, vec![12, 8]);
    assert_eq!(generated.hq_hud_completed_consoles, vec![12, 16]);

    // Not a defect but a real game change: RoleBehaviour.TeamType moved when
    // MaxCount was inserted before it, between 17.4.0 and 2026.8.18.
    assert_eq!(reference.player.role_team, vec![76]);
    assert_eq!(generated.player.role_team, vec![80]);
}
