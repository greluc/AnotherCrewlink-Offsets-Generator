# acl-offsetgen

Generates the memory offsets and byte signatures [AnotherCrewLink](https://github.com/greluc/AnotherCrewLink)
needs to read Among Us, straight from an installed copy of the game.

Rust rewrite of the old `BCL-OffsetGenerator`. That tool had not produced
anything since August 2024 — every offsets file published after it was written
by hand — and it stopped for reasons the rewrite is built around.

```
acl-offsetgen generate --game "D:\SteamLibrary\steamapps\common\Among Us" --out ..\AnotherCrewlink-Offsets
```

```
Il2CppDumper v6.7.46 verified at .\tools\il2cppdumper\Il2CppDumper.exe
Among Us 2026.8.18 (x86, Unity 2022.3.44f1)
  18030 classes, 13642 type-info slots, Il2CppClass::static_fields at 92

provenance
  55 values read from the dump, 9 derived from the pointer size, 9 signatures generated
  4 value(s) carried from the base file, because no dump describes them:
    ...
  note: innerNetClient.gameMode: InnerNetClient.GameMode is gone in this build; used InnerNetClient.NetworkMode instead

validation
  198 checks passed

broadcast version 50663350
lookup: 50663350 -> V2026.8.18/offsets.json (offsetsVersion 1, new file)
```

## What was wrong, and what changed

**Signatures were never generated.** The client locates every static class
(`PlayerControl`, `GameData`, `ShipStatus`, …) with a byte pattern, and
`GameReader.initializeoffsets` overwrites slot 0 of each chain with the result.
The old generator kept those patterns as literals in its base files and copied
them through, so a game rebuild meant a session in a disassembler. That is why
the pipeline quietly became a manual process.

They are generated now. `script.json` gives the RVA of the global holding each
type's `Il2CppClass*`; any instruction that loads it is a usable anchor, so the
generator finds one, wildcards everything the loader may rewrite, and grows the
pattern instruction by instruction until it matches exactly once. Then it
resolves the finished pattern with the client's own arithmetic and checks it
lands back on the slot it started from. Nine signatures for Among Us 2026.8.18
come out between 8 and 30 bytes and take about a second, on both
architectures.

Which bytes get wildcarded is not guesswork: the PE's own `.reloc` table says
which ones the loader rewrites, and every one of them becomes a `?`. That is
what makes the pattern survive ASLR, and it also masks unrelated globals that
happen to sit inside the pattern.

The broadcast-version pattern is generated the same way, from a different kind
of anchor. It points at a literal rather than at a type-info slot, so there is
no metadata object to start from — but `Constants.GetBroadcastVersion` compiles
to `mov eax, <version>; ret` and `dump.cs` reports its address, so the literal
is one byte into a known method. That method is tiny and surrounded by padding,
so the pattern grows *backwards* into what precedes it until it is unique.

This one lives in `lookup.json` rather than in an offsets file, because the
client reads it before it knows which offsets to fetch — which makes it global
to every client and every build. So it is not replaced casually: the version is
established from the dump, and the pattern already in `lookup.json` is kept if
it still produces that value. Only when it does not is a generated one written
in, with a note that the older versions in the file need re-checking. Either
way it is now verified against the metadata on every run, which it never was.

**The base files had drifted three years out of date.** Chains had grown hops
the old code could not fill — it only ever wrote indices `[0]` and `[1]`, while
`player.localX` needs four. Field offsets are now read from the dump by class
and field name and assembled per architecture, and the handful of numbers no
dump can describe live in `base/x86.json` and `base/x64.json`, each with a note
saying why it is there. The run report lists them every time so they cannot rot
unnoticed.

**Nothing checked the output.** A failed lookup wrote `-1` into the published
file and printed a line nobody read. Now a failed lookup fails the run, and
before anything is written the result goes through ~270 checks: no unresolved
values, chain shapes consistent, the player struct's size matching
`bufferLength`, and every signature scanned for and resolved against the binary.
If a check fails, nothing is written.

Part of that gate mirrors the client's own contract. AnotherCrewLink validates
every bundle it fetches in `src/main/offsetsValidator.ts`, and a rejected bundle
does not merely look wrong -- it does not arrive, because the client falls back
to a cached or embedded one. Those bounds are duplicated in `validate.rs` under
`client_contract`, deliberately rather than approximately, so a file the client
would refuse fails here instead of at the far end of a fetch on someone else's
machine. If the client moves a bound, that module is what has to follow.

Some smaller things that were also wrong: the version search read a fixed byte
window that Unity 2022.3 moved out from under it (the string sits at 0x7A8 now,
the window looked at 0xFF0–0x14A0); the field search only looked 200 lines past
a class declaration, and `PlayerControl` alone spans 597; `default` in
`lookup.json` was picked by dictionary position rather than by version; and
`offsetsVersion` was one global constant, although the client compares it per
file, so republishing a corrected file left every client on its cached copy.

## Running it

Install the pinned dumper once:

```bash
pwsh tools/fetch-il2cppdumper.ps1
```

```bash
cargo run --release -- doctor
```

```bash
cargo run --release -- generate --game "<Among Us folder>" --out "<offsets repo>" --dry-run
```

`--dry-run` prints everything, including the diff against the file already in
the repository, and writes nothing. Drop it to publish.

`verify` checks an existing offsets file against a game build without writing —
it works on hand-written files too, so it can gate the offsets repository:

```bash
cargo run --release -- verify --game "<Among Us folder>" --offsets ../AnotherCrewlink-Offsets/offsets/x86/V17.4.0/offsets.json
```

The dump is cached under `work/dumps/<version>-<arch>`; `--force-dump` redoes it.

`lookup.json` is authored by more than this tool -- the sync workflow records
`upstream_commit`, and the client reads `bundle_version` for replay detection
and `min_client_version` to refuse a bundle it is too old for. Keys the
generator does not model are carried through untouched, and `bundle_version`
advances whenever the generator changes the bundle, because the client keeps the
highest it has seen and refuses anything lower.

## Supply chain

The generator is a build tool for files that end up on every user's machine, so
the things it trusts are kept few and pinned.

**Il2CppDumper stays external and pinned.** `tools.lock.json` records the
release tag, the archive's SHA-256 and size, and the digest of each extracted
binary. `tools/fetch-il2cppdumper.ps1` verifies the archive before extracting
and each binary afterwards; `acl-offsetgen` re-verifies the executable's digest
before every run and refuses to start it otherwise. Upgrading is a reviewed diff
to `tools.lock.json`, never something a script does on its own.

GitHub does not publish a digest for this asset, so the pin is trust-on-first-use:
downloaded once on 2026-08-24, digest recorded, verified ever since. CI re-fetches
and re-verifies on every run, which is the canary for the asset being replaced
upstream.

**The network lives in one script.** HTTP and unzip are in
`tools/fetch-il2cppdumper.ps1`, roughly a hundred readable lines, and not in the
Rust build at all. That keeps `reqwest`, a TLS stack, `zip` and `flate2` out of
the dependency graph — `deny.toml` bans them by name so they cannot come back as
a transitive dependency without someone noticing.

**Dependencies:** four direct (`clap`, `serde`, `serde_json`, `iced-x86`), 23
crates in the whole graph, every version pinned with `=`, `Cargo.lock` committed,
every CI command `--locked`. SHA-256 is vendored in `src/sha256.rs` rather than
pulled from a crate family, because it is the code that decides whether we are
willing to execute an external binary and it should be readable in one sitting.
`cargo deny` enforces crates.io as the only source, no git dependencies,
permissive licences only, no duplicate versions, and no known advisories. CI
fails if the graph grows past 40 crates.

**CI** uses exactly one action, `actions/checkout`, pinned to a commit rather
than a tag, with `persist-credentials: false` and `permissions: contents: read`.
The toolchain comes from `rust-toolchain.toml` via the runner's own rustup.

It also runs weekly, not only on push. Advisories are the one check whose result
changes without anyone touching the code, and this repository goes quiet between
game updates -- on push alone the first notice of a new advisory, or of the
pinned Il2CppDumper archive being replaced upstream, would arrive months late.

Everything being pinned is good for reproducibility and bad for staying current,
so Dependabot covers the other half: it turns "a newer version exists" into a
pull request that runs the full CI, rather than an update that is either applied
blindly or missed. A separate job builds against the `rust-version` in
`Cargo.toml`, because an MSRV nothing verifies is a claim with no consumer --
the declared one was wrong until that job existed.

## Regression testing

One hundred and five tests, none of which need Among Us installed.

The signature generator is tested end to end against a synthetic PE built in the
test: several instructions reference the same slot, one is followed by identical
code so the shortest pattern is ambiguous and has to grow, and every absolute
address is relocated so a correct signature has to wildcard all of them. The
tests assert the result is unique, resolves back to the slot, and does not spell
out a single relocated address.

`tests/fixtures/` holds the hand-written V17.4.0 offsets for both architectures
and the files this generator produced for 2026.8.18. They pin the contract with
the client: if a key is renamed or changes shape on either side, parsing fails;
key order is checked too, so a regenerated version shows up as a small diff
rather than a rewrite of the whole file.

Where the generated files disagree with the hand-written ones is pinned as
tests, because most of it is defects in the shipping files:

| field | shipping | generated | why |
|---|---|---|---|
| `innerNetClient.gameMode` (x64) | `-1` | `68` | a failed lookup written straight into a published file: the old generator searched for `InnerNetClient.GameMode`, the field is `NetworkMode` |
| `hqHudSystemType_CompletedConsoles` | `[12, 8]` / `[24, 16]` | `[12, 16]` / `[24, 32]` | that is `HashSet<T>::_buckets`; the count is one pointer further on |
| `planetSurveillanceMinigame_camarasCount` (x64) | `[216, 12]` | `[216, 24]` | `Il2CppArray::max_length` is 12 on x86 and 24 on x64; the x86 number was carried across |
| `surveillanceMinigame_FilteredRoomsCount` (x64) | `[168, 12]` | `[168, 24]` | same |
| `gameoptionsData` (x86) | `[-1, 92, 24]` | `[-1, 92, 0, 20]` | the `Instance` dereference is missing; the x64 file has it |
| `player.roleTeam` | `[76]` / `[108]` | `[80]` / `[116]` | a real game change — `MaxCount` was inserted before `RoleBehaviour.TeamType` after 17.4.0 |

Everything else matches: 64 of 68 fields on x86 and 53 of 68 on x64, where the
remaining x64 differences are the slot-0 placeholders the client overwrites
anyway.

One key is deliberately no longer emitted. `mushroomDoor_isOpen` has no
references anywhere in AnotherCrewLink and is absent from its `IOffsets`
interface, but it failed to resolve on every build older than the Fungle and
was published as `-1` in 28 of the 44 offsets files -- the single largest source
of unresolved values in the repository, for a field with no consumer. Dropping
it needs no client change, since nothing was reading it.

## Known limits

**The write path cannot be refreshed from here, and that is not a gap waiting
to be filled.** `showModStamp`, `connectFunc`, `fixedUpdateFunc`,
`modLateUpdate` and `pingMessageString` are hook sites for shellcode the client
injects into the running game. The client writes a five-byte jump over the site
and carries the instructions it displaced in its shellcode as literal bytes
(`0x55, 0x8b, 0xec, 0x56, 0x8b, 0x75, 0x08` for the fixedUpdate detour), so a
regenerated signature would point somewhere new while the shellcode kept
relocating the old build's instructions. Refreshing it is a change to
AnotherCrewLink, verified by injecting code into a live game. A matching
signature is necessary and nowhere near sufficient.

What is here is the safety property. Against 2026.8.18 two of the five no longer
match at all and `modLateUpdate` matches 162 times — it is a bare function
prologue, so "the client takes the first match" would patch a jump into an
arbitrary function. Anything other than exactly one match counts as unusable,
which fails the run outright if `disableWriting` is false and is reported as a
warning on every run while it is true. The numbers live in `base/x86.json` next
to the signatures.

**Steam downloading is gone.** The old tool drove a 2022 fork of DepotDownloader
whose Steam login flow Valve has retired, and scraped a SteamDB page that had to
be saved by hand and served from localhost. Generating from a local installation
covers the case that matters; building offsets for historical versions would need
a current DepotDownloader invoked as a separate tool.

## Layout

```
base/                     per-architecture constants no dump can provide
src/
  dumpcs.rs               dump.cs -> class and field index
  scriptjson.rs           script.json -> type-info slot RVAs
  il2cpph.rs              il2cpp.h -> Il2CppClass::static_fields offset
  pe.rs                   PE parsing, section mapping, relocation bitmap
  pattern.rs              byte signatures: parse, format, scan
  siggen.rs               signature generation
  gameinfo.rs             game version, broadcast version
  generate.rs             assembles offsets.json, records provenance
  validate.rs             the gate between generated and published
  lookup.rs               lookup.json, per-file offsetsVersion
  report.rs               diff against the previous version
  tools.rs                runs Il2CppDumper, enforces the digest pin
  sha256.rs               vendored, so the digest check has no dependencies
tools/                    fetch script and the installed dumper (gitignored)
```
