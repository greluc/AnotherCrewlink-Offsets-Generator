//! Running Il2CppDumper as an external process, and refusing to if it is not
//! the build we pinned.
//!
//! Two things go wrong with vendoring a dumper, and both bit the old project:
//! the bundled copy silently went stale (the DLL it shipped predated metadata
//! v31 support by two weeks, which is why nothing has been generated since),
//! and a binary in the repository is a blob nobody reviews. Keeping it external
//! and pinned by digest fixes both -- upgrading is a one-line change to
//! `tools.lock.json` that shows up in review, and a binary that does not match
//! the pin never runs.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;

use crate::error::{read_file, read_to_string_lossy, Error, Result};
use crate::sha256::{to_hex, Sha256};

#[derive(Debug, Deserialize)]
struct ToolsLock {
    il2cppdumper: DumperPin,
}

#[derive(Debug, Deserialize)]
struct DumperPin {
    tag: String,
    #[serde(rename = "supported_metadata_versions")]
    supported_metadata_versions: String,
    binaries: Vec<PinnedBinary>,
}

#[derive(Debug, Deserialize)]
struct PinnedBinary {
    path: String,
    size: u64,
    sha256: String,
}

pub struct Dumper {
    executable: PathBuf,
    pub tag: String,
    pub supported_metadata_versions: String,
}

pub struct DumpArtifacts {
    pub dump_cs: PathBuf,
    pub script_json: PathBuf,
    pub il2cpp_h: PathBuf,
}

impl Dumper {
    /// Loads the pin, finds the installed dumper and verifies its digest.
    pub fn locate(repo_root: &Path, install_dir: Option<&Path>) -> Result<Self> {
        let lock_path = repo_root.join("tools.lock.json");
        let lock: ToolsLock = serde_json::from_str(&read_to_string_lossy(&lock_path)?)
            .map_err(|error| Error::malformed(format!("tools.lock.json is unusable: {error}")))?;
        let pin = lock.il2cppdumper;

        let dir = install_dir
            .map(Path::to_path_buf)
            .unwrap_or_else(|| repo_root.join("tools").join("il2cppdumper"));

        // Prefer the 64-bit dumper; the 32-bit one is only there for hosts that
        // cannot run it. Neither choice depends on the game's architecture.
        let mut last_error = None;
        for binary in &pin.binaries {
            let candidate = dir.join(&binary.path);
            if !candidate.is_file() {
                last_error = Some(format!("{} is not installed", candidate.display()));
                continue;
            }
            match verify_digest(&candidate, binary) {
                Ok(()) => {
                    return Ok(Self {
                        executable: candidate,
                        tag: pin.tag,
                        supported_metadata_versions: pin.supported_metadata_versions,
                    })
                }
                Err(error) => return Err(error),
            }
        }

        Err(Error::tool(format!(
            "Il2CppDumper {} is not installed in {} ({}).\n\
             Install it with:  pwsh tools/fetch-il2cppdumper.ps1",
            pin.tag,
            dir.display(),
            last_error.unwrap_or_else(|| "no candidate binaries found".to_string())
        )))
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Runs the dumper over one game build and returns the artefacts it wrote.
    pub fn dump(
        &self,
        game_assembly: &Path,
        metadata: &Path,
        output_dir: &Path,
    ) -> Result<DumpArtifacts> {
        for required in [game_assembly, metadata] {
            if !required.is_file() {
                return Err(Error::usage(format!(
                    "{} does not exist; point --game at an Among Us installation directory",
                    required.display()
                )));
            }
        }
        std::fs::create_dir_all(output_dir).map_err(|error| Error::io(output_dir, error))?;
        self.write_config()?;

        // The dumper runs with its own directory as the working directory (it
        // reads config.json from there), so every path handed to it has to be
        // absolute or it writes its output next to the executable.
        let game_assembly = absolute(game_assembly)?;
        let metadata = absolute(metadata)?;
        let output_absolute = absolute(output_dir)?;

        let output = Command::new(&self.executable)
            .arg(&game_assembly)
            .arg(&metadata)
            .arg(&output_absolute)
            // The dumper asks for keyboard input on several failure paths. With
            // no stdin it gets EOF and exits instead of waiting forever, which
            // is what made the old tool hang in CI.
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .current_dir(self.executable.parent().unwrap_or_else(|| Path::new(".")))
            .output()
            .map_err(|error| {
                Error::tool(format!(
                    "could not start {}: {error}",
                    self.executable.display()
                ))
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        if !output.status.success() {
            return Err(Error::tool(format!(
                "Il2CppDumper exited with {}.\n--- output ---\n{}{}",
                output.status,
                stdout.trim(),
                if stderr.trim().is_empty() {
                    String::new()
                } else {
                    format!("\n--- stderr ---\n{}", stderr.trim())
                }
            )));
        }

        // The dumper reports failures on stdout and still exits 0, so the exit
        // status alone is not enough. This is the check the old wrapper lacked:
        // it caught the exception, logged it, returned void, and the caller
        // carried on as if a dump existed.
        if stdout.contains("ERROR:") || stdout.contains("Exception") {
            return Err(Error::tool(format!(
                "Il2CppDumper reported a failure:\n{}\n\n\
                 If this says the metadata version is unsupported, the pinned dumper ({}) is \
                 older than the game. It supports metadata {}.",
                stdout.trim(),
                self.tag,
                self.supported_metadata_versions
            )));
        }

        let artifacts = DumpArtifacts {
            dump_cs: output_dir.join("dump.cs"),
            script_json: output_dir.join("script.json"),
            il2cpp_h: output_dir.join("il2cpp.h"),
        };
        for (name, path) in [
            ("dump.cs", &artifacts.dump_cs),
            ("script.json", &artifacts.script_json),
            ("il2cpp.h", &artifacts.il2cpp_h),
        ] {
            if !path.is_file() {
                return Err(Error::tool(format!(
                    "Il2CppDumper finished without writing {name}.\n--- output ---\n{}",
                    stdout.trim()
                )));
            }
        }

        Ok(artifacts)
    }

    /// The dumper reads `config.json` from its own directory.
    fn write_config(&self) -> Result<()> {
        let dir = self
            .executable
            .parent()
            .ok_or_else(|| Error::tool("dumper path has no parent directory"))?;
        // GenerateStruct is what produces script.json, which is where the
        // type-info slots come from -- without it no signature can be built.
        // The dummy DLL export costs minutes and is never read.
        let config = r#"{
  "DumpMethod": true,
  "DumpField": true,
  "DumpProperty": true,
  "DumpAttribute": false,
  "DumpFieldOffset": true,
  "DumpMethodOffset": true,
  "DumpTypeDefIndex": true,
  "GenerateDummyDll": false,
  "GenerateStruct": true,
  "DummyDllAddToken": false,
  "RequireAnyKey": false,
  "ForceIl2CppVersion": false,
  "ForceVersion": 16,
  "ForceDump": false,
  "NoRedirectedPointer": false
}
"#;
        crate::error::write_file(dir.join("config.json"), config)
    }
}

fn absolute(path: &Path) -> Result<PathBuf> {
    std::path::absolute(path).map_err(|error| Error::io(path, error))
}

fn verify_digest(path: &Path, expected: &PinnedBinary) -> Result<()> {
    let metadata = std::fs::metadata(path).map_err(|error| Error::io(path, error))?;
    if metadata.len() != expected.size {
        return Err(Error::tool(format!(
            "{} is {} bytes but tools.lock.json pins {}. Refusing to run an unpinned binary.",
            path.display(),
            metadata.len(),
            expected.size
        )));
    }

    let bytes = read_file(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let actual = to_hex(&hasher.finish());

    if actual != expected.sha256.to_ascii_lowercase() {
        return Err(Error::tool(format!(
            "{} does not match its pin.\n  expected {}\n  actual   {}\n\
             Refusing to run it. Re-install with tools/fetch-il2cppdumper.ps1, or update \
             tools.lock.json deliberately if you meant to change versions.",
            path.display(),
            expected.sha256,
            actual
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pin_file_in_this_repository_parses() {
        // Guards against a hand edit of tools.lock.json that would only be
        // noticed the next time someone tried to generate.
        let text = include_str!("../tools.lock.json");
        let lock: ToolsLock = serde_json::from_str(text).expect("tools.lock.json should parse");
        assert!(!lock.il2cppdumper.binaries.is_empty());
        for binary in &lock.il2cppdumper.binaries {
            assert_eq!(
                binary.sha256.len(),
                64,
                "{} has a malformed digest",
                binary.path
            );
            assert!(
                binary.sha256.chars().all(|c| c.is_ascii_hexdigit()),
                "{} has a non-hex digest",
                binary.path
            );
            assert!(binary.size > 0);
        }
    }

    #[test]
    fn a_size_mismatch_is_refused_before_hashing() {
        let dir = std::env::temp_dir().join("acl-offsetgen-tools-test");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("fake.exe");
        std::fs::write(&path, b"not the real dumper").expect("write");

        let pin = PinnedBinary {
            path: "fake.exe".to_string(),
            size: 999_999,
            sha256: "0".repeat(64),
        };
        let error = verify_digest(&path, &pin).expect_err("should refuse");
        assert!(error
            .to_string()
            .contains("Refusing to run an unpinned binary"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_digest_mismatch_is_refused() {
        let dir = std::env::temp_dir().join("acl-offsetgen-tools-test");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("fake2.exe");
        let contents = b"not the real dumper";
        std::fs::write(&path, contents).expect("write");

        let pin = PinnedBinary {
            path: "fake2.exe".to_string(),
            size: contents.len() as u64,
            sha256: "a".repeat(64),
        };
        let error = verify_digest(&path, &pin).expect_err("should refuse");
        assert!(error.to_string().contains("does not match its pin"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_matching_digest_is_accepted() {
        let dir = std::env::temp_dir().join("acl-offsetgen-tools-test");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("fake3.exe");
        let contents = b"hello";
        std::fs::write(&path, contents).expect("write");

        let pin = PinnedBinary {
            path: "fake3.exe".to_string(),
            size: contents.len() as u64,
            sha256: crate::sha256::hex_digest(contents),
        };
        assert!(verify_digest(&path, &pin).is_ok());
        let _ = std::fs::remove_file(&path);
    }
}
