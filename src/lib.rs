//! Generates AnotherCrewLink offsets and signatures from Among Us game files.
//!
//! The pipeline, in order:
//!
//! ```text
//!   game files ─► Il2CppDumper (external, pinned) ─► dump.cs + script.json + il2cpp.h
//!                                                       │
//!   GameAssembly.dll ─► PE image (mapped, relocations) ──┤
//!                                                       ▼
//!                                    field offsets + generated signatures
//!                                                       │
//!                                                   validation
//!                                                       │
//!                                          offsets.json + lookup.json
//! ```
//!
//! Exposed as a library so the integration tests can drive the same code the
//! binary does.

pub mod dumpcs;
pub mod error;
pub mod gameinfo;
pub mod generate;
pub mod il2cpph;
pub mod lookup;
pub mod offsets;
pub mod pattern;
pub mod pe;
pub mod report;
pub mod scriptjson;
pub mod sha256;
pub mod siggen;
pub mod tools;
pub mod validate;

pub use error::{Error, Result};
