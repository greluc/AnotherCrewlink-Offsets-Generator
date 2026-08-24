//! Command line entry point.

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use acl_offsetgen::dumpcs::Dump;
use acl_offsetgen::error::{read_file, write_file, Error, Result};
use acl_offsetgen::gameinfo::{read_broadcast_version, read_game_version, GameVersion};
use acl_offsetgen::generate::{BaseConstants, Generator};
use acl_offsetgen::il2cpph::HeaderLayout;
use acl_offsetgen::lookup::{classify_change, ContentChange, Lookup};
use acl_offsetgen::offsets::Offsets;
use acl_offsetgen::pattern::Pattern;
use acl_offsetgen::pe::{Arch, Image};
use acl_offsetgen::report;
use acl_offsetgen::scriptjson::TypeInfoTable;
use acl_offsetgen::tools::Dumper;
use acl_offsetgen::validate;

#[derive(Parser)]
#[command(
    name = "acl-offsetgen",
    version,
    about = "Generates AnotherCrewLink offsets and signatures from an Among Us build",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Reads a game installation and writes offsets.json and lookup.json.
    Generate(GenerateArgs),
    /// Checks an existing offsets.json against a game build without writing.
    ///
    /// Works on hand-written files too, which makes it usable as a gate on the
    /// offsets repository.
    Verify(VerifyArgs),
    /// Reports whether the pinned Il2CppDumper is installed and intact.
    Doctor(DoctorArgs),
}

#[derive(clap::Args)]
struct GenerateArgs {
    /// Among Us installation directory (the one holding GameAssembly.dll).
    #[arg(long)]
    game: PathBuf,
    /// Offsets repository to write into, laid out like AnotherCrewlink-Offsets.
    #[arg(long)]
    out: PathBuf,
    /// Scratch directory for dumper output. Reused between runs.
    #[arg(long, default_value = "work")]
    work: PathBuf,
    /// Print everything that would happen, write nothing.
    #[arg(long)]
    dry_run: bool,
    /// Re-run the dumper even if this build was already dumped.
    #[arg(long)]
    force_dump: bool,
    /// Directory holding the pinned Il2CppDumper.
    #[arg(long)]
    dumper: Option<PathBuf>,
}

#[derive(clap::Args)]
struct VerifyArgs {
    /// Among Us installation directory.
    #[arg(long)]
    game: PathBuf,
    /// offsets.json to check.
    #[arg(long)]
    offsets: PathBuf,
    #[arg(long, default_value = "work")]
    work: PathBuf,
    #[arg(long)]
    dumper: Option<PathBuf>,
}

#[derive(clap::Args)]
struct DoctorArgs {
    #[arg(long)]
    dumper: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Generate(args) => generate(args),
        Command::Verify(args) => verify(args),
        Command::Doctor(args) => doctor(args),
    };

    if let Err(error) = result {
        eprintln!("\nerror: {error}");
        std::process::exit(1);
    }
}

fn repo_root() -> PathBuf {
    // Runs from the repository during development and from next to the binary
    // once installed; try the executable's directory before giving up on ".".
    let current = PathBuf::from(".");
    if current.join("tools.lock.json").is_file() {
        return current;
    }
    if let Ok(exe) = std::env::current_exe() {
        for candidate in exe.ancestors().skip(1).take(4) {
            if candidate.join("tools.lock.json").is_file() {
                return candidate.to_path_buf();
            }
        }
    }
    current
}

struct GameFiles {
    game_assembly: PathBuf,
    metadata: PathBuf,
    global_game_managers: PathBuf,
}

fn locate_game(directory: &Path) -> Result<GameFiles> {
    let files = GameFiles {
        game_assembly: directory.join("GameAssembly.dll"),
        metadata: directory
            .join("Among Us_Data")
            .join("il2cpp_data")
            .join("Metadata")
            .join("global-metadata.dat"),
        global_game_managers: directory.join("Among Us_Data").join("globalgamemanagers"),
    };
    for (label, path) in [
        ("GameAssembly.dll", &files.game_assembly),
        ("global-metadata.dat", &files.metadata),
        ("globalgamemanagers", &files.global_game_managers),
    ] {
        if !path.is_file() {
            return Err(Error::usage(format!(
                "{} is missing under {}. Point --game at the folder that contains \
                 GameAssembly.dll.",
                label,
                directory.display()
            )));
        }
    }
    Ok(files)
}

/// Everything read off one build, before any offsets are produced.
struct Analysed {
    image: Image,
    dump: Dump,
    types: TypeInfoTable,
    static_fields: i64,
    version: GameVersion,
}

fn analyse(
    game_dir: &Path,
    work: &Path,
    dumper_dir: Option<&Path>,
    force_dump: bool,
) -> Result<Analysed> {
    let files = locate_game(game_dir)?;
    let root = repo_root();
    let dumper = Dumper::locate(&root, dumper_dir)?;
    println!(
        "Il2CppDumper {} verified at {}",
        dumper.tag,
        dumper.executable().display()
    );

    let assembly_bytes = read_file(&files.game_assembly)?;
    let image = Image::parse(&assembly_bytes)?;

    let ggm = read_file(&files.global_game_managers)?;
    let version = read_game_version(&ggm)?;
    println!(
        "Among Us {} ({}{})",
        version.game,
        image.arch,
        version
            .unity
            .as_ref()
            .map(|unity| format!(", Unity {unity}"))
            .unwrap_or_default()
    );

    let dump_dir = work
        .join("dumps")
        .join(format!("{}-{}", version.game, image.arch));
    let already = dump_dir.join("dump.cs").is_file()
        && dump_dir.join("script.json").is_file()
        && dump_dir.join("il2cpp.h").is_file();

    if already && !force_dump {
        println!("reusing dump in {}", dump_dir.display());
    } else {
        println!("dumping to {} ...", dump_dir.display());
        dumper.dump(&files.game_assembly, &files.metadata, &dump_dir)?;
    }

    let dump = Dump::load(dump_dir.join("dump.cs"))?;
    let types = TypeInfoTable::load(dump_dir.join("script.json"))?;
    let header = HeaderLayout::load(dump_dir.join("il2cpp.h"), image.arch)?;
    let static_fields = header.static_fields_offset()? as i64;
    println!(
        "  {} classes, {} type-info slots, Il2CppClass::static_fields at {}",
        dump.class_count(),
        types.len(),
        static_fields
    );

    Ok(Analysed {
        image,
        dump,
        types,
        static_fields,
        version,
    })
}

fn base_constants_path(root: &Path, arch: Arch) -> PathBuf {
    root.join("base").join(format!("{}.json", arch.dir_name()))
}

/// Resolves `--out` and checks it really is an offsets checkout.
///
/// Done before the dump rather than when the file is first read, so a mistyped
/// path fails in a moment instead of after a full run. Relative paths resolve
/// against the current directory while the generator's own `base/` and
/// `tools.lock.json` are found next to the executable, and that asymmetry is
/// easy to trip over -- so the message says what the path resolved to.
fn resolve_offsets_repo(out: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(out).map_err(|error| Error::io(out, error))?;
    if absolute.join("lookup.json").is_file() {
        return Ok(absolute);
    }
    Err(Error::usage(format!(
        "--out should point at a checkout of the offsets repository, but there is no \
         lookup.json in it.\n  given:      {}\n  resolved to: {}\n\
         Expected layout: <repo>/lookup.json and <repo>/offsets/x86/... . Relative paths \
         are resolved against the current directory, so running from target\\release needs \
         a different number of ..\\ than running from the project root.",
        out.display(),
        absolute.display()
    )))
}

fn generate(args: GenerateArgs) -> Result<()> {
    let root = repo_root();
    let out = resolve_offsets_repo(&args.out)?;
    let analysed = analyse(
        &args.game,
        &args.work,
        args.dumper.as_deref(),
        args.force_dump,
    )?;
    let arch = analysed.image.arch;

    let base = BaseConstants::load(base_constants_path(&root, arch))?;
    let outcome = Generator::new(
        &analysed.dump,
        &analysed.types,
        &analysed.image,
        &base,
        analysed.static_fields,
    )
    .generate()?;

    println!("\nprovenance");
    println!("{}", report::render_provenance(&outcome.provenance));
    for (type_name, detail) in &outcome.signature_details {
        println!("  signature {type_name}: {detail}");
    }
    for note in &outcome.notes {
        println!("  note: {note}");
    }

    println!("\nvalidation");
    let validation = validate::validate(&outcome.offsets, &analysed.image, &analysed.types);
    if !validation.is_ok() {
        return Err(Error::Validation(validation.problems));
    }
    println!("  {} checks passed", validation.checks_run);

    // The broadcast-version pattern lives in lookup.json rather than being
    // generated, because it points at an immediate rather than a type-info slot.
    let lookup_path = out.join("lookup.json");
    let mut lookup = Lookup::load(&lookup_path)?;
    let broadcast_pattern = match arch {
        Arch::X86 => &lookup.patterns.x86.broadcast_version,
        Arch::X64 => &lookup.patterns.x64.broadcast_version,
    };
    let pattern = Pattern::parse(
        broadcast_pattern
            .sig
            .as_deref()
            .ok_or_else(|| Error::malformed("lookup.json has no broadcastVersion signature"))?,
    )?;
    let broadcast = read_broadcast_version(
        &analysed.image,
        &pattern,
        broadcast_pattern.pattern_offset.unwrap_or(0),
        broadcast_pattern.address_offset.unwrap_or(0),
    )?;
    println!("\nbroadcast version {broadcast}");

    let directory = analysed.version.directory_name();
    let relative = format!("{directory}/offsets.json");
    let offsets_path = out
        .join("offsets")
        .join(arch.dir_name())
        .join(&directory)
        .join("offsets.json");

    let rendered = render_offsets(&outcome.offsets)?;
    let change = classify_change(&offsets_path, &rendered);

    if let Ok(previous_text) = std::fs::read_to_string(&offsets_path) {
        if let Ok(previous) = serde_json::from_str::<Offsets>(&previous_text) {
            let differences = report::diff(&previous, &outcome.offsets);
            println!("\nchanges against the file already in the repository");
            if differences.is_empty() {
                println!("  none");
            } else {
                for difference in &differences {
                    println!(
                        "  {}: {} -> {}",
                        difference.path, difference.before, difference.after
                    );
                }
            }
        }
    }

    let offsets_version = lookup.upsert(broadcast, &analysed.version.game, &relative, change)?;
    println!(
        "\nlookup: {broadcast} -> {relative} (offsetsVersion {offsets_version}, {})",
        match change {
            ContentChange::New => "new file",
            ContentChange::Changed => "content changed, clients will refetch",
            ContentChange::Identical => "unchanged",
        }
    );

    if args.dry_run {
        println!("\ndry run: nothing written");
        return Ok(());
    }

    write_file(&offsets_path, &rendered)?;
    write_file(&lookup_path, &lookup.to_json()?)?;
    println!("\nwrote {}", offsets_path.display());
    println!("wrote {}", lookup_path.display());
    Ok(())
}

fn verify(args: VerifyArgs) -> Result<()> {
    let analysed = analyse(&args.game, &args.work, args.dumper.as_deref(), false)?;
    let text = acl_offsetgen::error::read_to_string_lossy(&args.offsets)?;
    let offsets: Offsets = serde_json::from_str(&text)
        .map_err(|error| Error::malformed(format!("{}: {error}", args.offsets.display())))?;

    let validation = validate::validate(&offsets, &analysed.image, &analysed.types);
    if validation.is_ok() {
        println!(
            "\n{} passes all {} checks against Among Us {} ({})",
            args.offsets.display(),
            validation.checks_run,
            analysed.version.game,
            analysed.image.arch
        );
        return Ok(());
    }
    Err(Error::Validation(validation.problems))
}

fn doctor(args: DoctorArgs) -> Result<()> {
    let root = repo_root();
    println!("repository root: {}", root.display());
    match Dumper::locate(&root, args.dumper.as_deref()) {
        Ok(dumper) => {
            println!("Il2CppDumper {} ok", dumper.tag);
            println!("  {}", dumper.executable().display());
            println!("  supports metadata {}", dumper.supported_metadata_versions);
        }
        Err(error) => {
            println!("Il2CppDumper: {error}");
            return Err(error);
        }
    }
    for arch in [Arch::X86, Arch::X64] {
        let path = base_constants_path(&root, arch);
        match BaseConstants::load(&path) {
            Ok(_) => println!("base/{}.json ok", arch.dir_name()),
            Err(error) => println!("base/{}.json: {error}", arch.dir_name()),
        }
    }
    Ok(())
}

/// Two-space indent with a trailing newline, matching the hand-written files.
fn render_offsets(offsets: &Offsets) -> Result<String> {
    serde_json::to_string_pretty(offsets)
        .map(|text| text + "\n")
        .map_err(|error| Error::malformed(format!("cannot render offsets.json: {error}")))
}
