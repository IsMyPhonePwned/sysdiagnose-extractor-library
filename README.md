# sysdiagnose-extractor-library

**This project is based on [EC-DIGIT-CSIRC/sysdiagnose](https://github.com/EC-DIGIT-CSIRC/sysdiagnose)** (the Sysdiagnose Analysis Framework / SAF), developed by the European Commission DIGIT Cybersecurity Operation Centre. It is a Rust reimplementation of SAF’s parser and analyser modules for Apple sysdiagnose archives—not a fork of the Python tree, but deliberately aligned with that upstream project’s IDs, inputs, and output shapes.

Rust library and CLI to load Apple **sysdiagnose** archives (typically `sysdiagnose_*.tar.gz`) and run the same **parser modules** as the Python SAF. The workflow mirrors **[bugreport-extractor-library](https://github.com/ping2A/bugreport-extractor-library)**: load the bundle once, then run parsers in parallel.

## Requirements

- Rust **1.70+**
- Optional: a real `.tar.gz` under `assets/` for `#[ignore]` integration tests
- Optional: **[sysdiagnose-testdata](https://github.com/EC-DIGIT-CSIRC/sysdiagnose-testdata)** (pin `[7e64d5ca133837393c0c7cd3193d0d4dcabc5447](https://github.com/EC-DIGIT-CSIRC/sysdiagnose-testdata/tree/7e64d5ca133837393c0c7cd3193d0d4dcabc5447)`) for the non-ignored `sysdiagnose_testdata` integration test — clone under `testdata/sysdiagnose-testdata` and run `**git lfs pull`** (archives are stored in Git LFS)

## Quick start (CLI)

```bash
# List all SAF parser IDs and descriptions (like `sysdiag list parsers`)
cargo run --release --bin sdx-cli -- list-parsers

# List analyser IDs
cargo run --release --bin sdx-cli -- list-analysers

# Run every parser (native: parser timing table on stdout; no huge JSON unless you opt in)
cargo run --release --bin sdx-cli -- parse -i path/to/sysdiagnose.tar.gz

# Save parse JSON to a file (typical)
cargo run --release --bin sdx-cli -- parse -i path/to/sysdiagnose.tar.gz -o out.json --pretty

# Or print full parse JSON to stdout after the run (like bel-cli --show-parser-results)
cargo run --release --bin sdx-cli -- parse -i path/to/sysdiagnose.tar.gz --show-parser-results --pretty

# Selected parsers only
cargo run --release --bin sdx-cli -- parse -i path/to/sysdiagnose.tar.gz --parser ps --parser sys -o out.json

# Larger members (more RAM), run all analysers into `_analysers`
cargo run --release --bin sdx-cli -- parse -i path/to/sysdiagnose.tar.gz --max-entry-mb 256 --run-analysers -o out.json

# Or only selected analysers (no need for --run-analysers)
cargo run --release --bin sdx-cli -- parse -i path/to/sysdiagnose.tar.gz --analyser coverage --analyser summary -o out.json

# Analyser-only on stdout (prints === Analysers === JSON; add --pretty for layout)
cargo run --release --bin sdx-cli -- parse -i path/to/sysdiagnose.tar.gz --analyser apps --pretty
```

By default the **full parse JSON is not printed to stdout** (same idea as **bugreport-extractor-library** / `bel-cli`). Use `**-o` / `--output`** to write the JSON object (one key per parser module), or `**--show-parser-results**` to print it to stdout after the run. On **native** builds, `parse` prints a **parser performance** table (timings only). Logging uses **stderr**; use `RUST_LOG=error` or `--log error` on `parse`.

## Sigma rules (Sigma Zero)

Optional evaluation with **[Sigma Zero](https://github.com/ping2A/sigmazero)** (Sigma-compatible YAML) runs **after** parsers and optional analysers. With `--rules-dir`, the CLI prints a **Sigma** banner, rule load line, individual **matches**, and a **summary**—after the usual **parser performance** table (native).

**Stdout and JSON:** parse JSON is **never** on stdout unless `**--show-parser-results`**. `**--output**` always writes the JSON file. That keeps Sigma hits (and the stderr hint) easy to read without a multi‑megabyte blob on stdout.

**Native CLI only:** `--rules-dir` is ignored on `wasm32` builds (no filesystem rule loader in that configuration).

### Quick example

```bash
# Recursively loads *.yml under testdata/sigma-rules (see examples/ for demos)
cargo run --release --bin sdx-cli -- parse -i path/to/sysdiagnose.tar.gz \
  --rules-dir testdata/sigma-rules \
  --parser ps --parser crashlogs \
  --sigma-min-level low

# Save parse JSON while running Sigma (recommended)
cargo run --release --bin sdx-cli -- parse -i path/to/sysdiagnose.tar.gz \
  --rules-dir testdata/sigma-rules -o parse.json --pretty
```

Example rules live in `[testdata/sigma-rules/examples/](testdata/sigma-rules/examples/)`; see `[testdata/sigma-rules/README.md](testdata/sigma-rules/README.md)` for a short overview.

### Parser support and log fields

Sigma evaluation runs on whatever parsers succeeded in the same `parse` invocation (e.g. `--parser ps` or the full set). Conversion lives in `[src/detection/sigma/integration.rs](src/detection/sigma/integration.rs)`: each **successful** `ParserType` → JSON value is turned into **up to 15 000** flat `LogEntry` maps per parser. Failed parses are skipped; parsers whose JSON is only an error stub with no extractable rows usually produce **no** entries.

#### How JSON becomes log entries (order of attempts)

1. **Root tabular arrays** — If the parser JSON has a top-level `**rows`**, `**events**`, or `**lines**` key whose value is an array of **objects**, each element is one log entry. Keys on that object are copied **verbatim** into the Sigma field map (e.g. `ps` uses snake_case column names from `ps.txt`: `user`, `pid`, `command`, …).
2. **Map / `files` walk** — If step 1 produced nothing, the converter walks the root object, or `**files`** when that key holds an object. It then applies:
  - **SQLite shape:** nested `{ "…/file.sqlitedb": { "TABLE": [ { row }, … ] } }` → one entry per row with `event_type: sqlite_row`, `sqlite_db_path`, `sqlite_table`, and **each row column** as a top-level field (see `[examples/04_sqlite_table.yml](testdata/sigma-rules/examples/04_sqlite_table.yml)`).
  - **Path-like keys** (contains `/` or ends with `.plist`, `.txt`, `.log`, `.json`, `.jsonl`, `.csv`): string value → `event_type: text_snippet`, `source_path`, `content` (~16 KiB max); array of objects → one entry per object with `source_path` set to that key (e.g. `logdata_statistics` JSONL lines under each file path; `**psthread`** uses root key `**entries**` here, not `rows`/`events`/`lines`).
  - **Nested `rows`** under a path object → same as row entries plus `source_path`.
  - **Other nested objects** under a path → `event_type: structured_file` (when not classified as SQLite), `source_path`, plus flattened keys from that object.
3. **Whole-output fallback** — Very small root objects (≤ 256 keys, no huge strings/arrays) may become a **single** entry mirroring the whole JSON.

Nested blobs (e.g. crash `data` in `crashlogs` `events`) stay under the same key names as in parser output—use `jq` / `-o parse.json` on a real archive to see exact fields.

#### Injected fields (converter-added)

These are merged onto each entry when applicable (your YAML `selection` can match them):


| Field                            | When / meaning                                                                                       |
| -------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `sysdiagnose_parser`             | Always: SAF module id (`ps`, `crashlogs`, `accessibility_tcc`, …).                                   |
| `parser_module`                  | If the parser JSON root has a `parser` string.                                                       |
| `parser_source`                  | If the parser JSON root has a `source` string (e.g. source filename).                                |
| `source_path`                    | Path-keyed extracts, SQLite-in-path layout, or the map key for an array of objects (e.g. `entries`). |
| `event_type`                     | `text_snippet`, `sqlite_row`, or `structured_file` when the converter sets it.                       |
| `content`                        | Body for `text_snippet` entries.                                                                     |
| `sqlite_db_path`, `sqlite_table` | For `sqlite_row` entries.                                                                            |


Parser-native fields (examples): `command`, `user`, `pid`, `datetime`, `message`, `data`, `format`, `source` (e.g. `.ips` path in `[03_crashlogs_ips.yml](testdata/sigma-rules/examples/03_crashlogs_ips.yml)`)—anything present on the row/event object is addressable in Sigma YAML as long as it survives JSON → `LogEntry` deserialization.

#### Parser module ids (all types in this crate)

Every variant of `[ParserType](src/parsers/parser_type.rs)` is **eligible** once its parse succeeds; the **dominant** Sigma shape on a typical sysdiagnose is indicated below (mixed or archive-specific outputs may also emit `text_snippet` / `structured_file` rows). For the **full catalog** of sources, output keys, and extracted fields, see `**[docs/parsed-catalog.md](docs/parsed-catalog.md)`**. The [Parser reference](#parser-reference) below is a shorter subset focused on device fields.


| Parser id                                                       | Typical Sigma shape                              | Example / note                                                                                                                                                                            |
| --------------------------------------------------------------- | ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `accessibility_tcc`                                             | `events`                                         | APOLLO `TCC.db` queries → SAF-style `datetime` / `message` / `data` (includes `source_db`, `apollo_module`).                                                                              |
| `appinstallation`                                               | `sqlite_row`                                     | App install DB rows.                                                                                                                                                                      |
| `avconference_callsettings`                                     | `text_snippet` / path blobs                      | Gzip-backed text extracts.                                                                                                                                                                |
| `battery_bdc`                                                   | `rows`                                           | CSV-style row arrays when present.                                                                                                                                                        |
| `brctl`                                                         | structured `**data**`                            | Parsed `brctl-container-list.txt` + `brctl-dump.txt` (SAF section model).                                                                                                                 |
| `containermanager`                                              | `text_snippet`                                   | Container manager logs.                                                                                                                                                                   |
| `crashlogs`                                                     | `events`                                         | `.ips` JSON header + body; structured `**data.threads**` / `**data.frames**` (iOS 15+ JSON or legacy text); `[03_crashlogs_ips.yml](testdata/sigma-rules/examples/03_crashlogs_ips.yml)`. |
| `disks`                                                         | `rows` / structured                              | Disk listing shape from parser.                                                                                                                                                           |
| `ioacpiplane`, `iodevicetree`, `iofirewire`, `iopower`, `iousb` | structured `**tree**`                            | IOReg `IORegStructParser` port (`src/parsers/ioreg/`).                                                                                                                                    |
| `ioservice`                                                     | `**format: compact**` + depth-limited `**tree**` | Full tree via `ParseOptions { ioservice_full_tree: true }` or `sdx-cli --ioservice-full-tree`.                                                                                            |
| `interactionc`                                                  | `events`                                         | APOLLO `interactionC.db` (contact interaction URLs).                                                                                                                                      |
| `itunesstore`                                                   | `**data**` (table → rows)                        | First `downloads.*.sqlitedb`; upstream `sqlite2struct` shape (`source_path` + table map).                                                                                                 |
| `kbdebug`                                                       | `text_snippet`                                   | Debug text logs.                                                                                                                                                                          |
| `knowledgec`                                                    | `events`                                         | APOLLO `knowledgeC.db` queries (app activity, Safari browsing, Wi‑Fi, …).                                                                                                                 |
| `lockdownd`                                                     | `text_snippet`                                   | Path → log text (`[02_text_snippet_log.yml](testdata/sigma-rules/examples/02_text_snippet_log.yml)`).                                                                                     |
| `logarchive`                                                    | capped `**inventory**` (+ optional `**events**`) | `file_count`, `by_subdir`, largest paths only; decode via default `**logarchive-decode**` — see `[docs/logarchive.md](docs/logarchive.md)`.                                               |
| `logdata_statistics`                                            | path → array of objects                          | Each JSONL line object + `source_path` = statistics file path.                                                                                                                            |
| `logdata_statistics_txt`                                        | `text_snippet`                                   | Plain-text statistics files.                                                                                                                                                              |
| `mcsettingsevents`                                              | `events` / `rows`                                | MC settings events when emitted as arrays.                                                                                                                                                |
| `mcstate_shared_profile`                                        | `text_snippet`                                   | Stub / text profile files.                                                                                                                                                                |
| `mobileactivation`                                              | structured / plist JSON                          | Activation plist extracts.                                                                                                                                                                |
| `mobilebackup`                                                  | path → plist JSON                                | `Installed Applications`, bundle keys, etc.                                                                                                                                               |
| `mobileinstallation`                                            | `text_snippet`                                   | Installation listing text per path.                                                                                                                                                       |
| `networkextension`, `networkextensioncache`                     | `text_snippet` / `sqlite_row`                    | Logs and/or cache SQLite.                                                                                                                                                                 |
| `netusage`                                                      | `events`                                         | APOLLO `netusage.sqlite` (per-process / route usage).                                                                                                                                     |
| `olddsc`                                                        | `text_snippet`                                   | DSC text.                                                                                                                                                                                 |
| `plists`                                                        | `files` + `**meta**`                             | `**/*.plist`; parse failure → `{}`; caps via `SYSDIAGNOSE_PLISTS_MAX_FILES` / `SYSDIAGNOSE_PLISTS_MAX_EACH_BYTES`.                                                                        |
| `powerlogs`                                                     | `events`                                         | APOLLO `CurrentPowerlog.PLSQL` queries → same `events` shape as `accessibility_tcc`.                                                                                                      |
| `ps`                                                            | `rows`                                           | `[01_ps_row_command.yml](testdata/sigma-rules/examples/01_ps_row_command.yml)`.                                                                                                           |
| `psthread`                                                      | root `**entries**` array                         | Same columns as `ps`-style rows + `message`; `source_path` is the string `entries` (see stage 2).                                                                                         |
| `quarantine_events`                                             | `events`                                         | APOLLO quarantine DB (download origin / data URLs).                                                                                                                                       |
| `remotectl_dumpstate`                                           | structured                                       | Tab-hierarchy JSON; **device id** under `data.Device` (see [Device and system identification](#device-and-system-identification)).                                                        |
| `safari_history`                                                | `events`                                         | APOLLO `History.db` (visited URLs, titles, visit times).                                                                                                                                  |
| `screentime`                                                    | `events`                                         | APOLLO Screen Time `RMAdminStore-*.sqlite` (domains / usage).                                                                                                                             |
| `security_sysdiagnose`                                          | `events`                                         | `security-sysdiagnose.txt` → SAF-style keychain / client / meta events.                                                                                                                   |
| `shutdownlogs`                                                  | `events`                                         | Shutdown client events (`datetime`, `message`, `data`, …).                                                                                                                                |
| `spindumpnosymbols`                                             | `events`                                         | `spindump-nosymbols.txt` → SAF-style header + per-process events (same model as upstream Python).                                                                                         |
| `swcutil`                                                       | `events`                                         | `swcutil_show.txt` → SAF-style header / DB / network / settings / memory events (same model as upstream Python).                                                                          |
| `sys`                                                           | structured / plist                               | `plist.ProductName`, `ProductVersion`, `BuildVersion`.                                                                                                                                    |
| `taskinfo`                                                      | `events`                                         | Task / process events.                                                                                                                                                                    |
| `transparency`                                                  | `events` / `lines`                               | Transparency log lines / events.                                                                                                                                                          |
| `transparency_json`                                             | structured / whole                               | Whole `transparency.log` JSON; `**stateMachine.devices`** for linked devices.                                                                                                             |
| `uuid2path`                                                     | path → plist JSON                                | UUID → path mappings.                                                                                                                                                                     |
| `wifi_known_networks`                                           | `events` + `**files**` (path → plist JSON)       | Known-networks plist → timeline events (BSS with coordinates); plist map retained like upstream.                                                                                          |
| `wifinetworks`                                                  | `events` + `**files**` (basename → plist/JSON)   | Wi‑Fi plists + recent-networks JSON; keys match upstream basenames.                                                                                                                       |
| `wifiscan`, `wifisecurity`                                      | structured / `text_snippet`                      | Wi‑Fi scan / security text per parser.                                                                                                                                                    |


### CLI flags


| Flag                       | Meaning                                                                         |
| -------------------------- | ------------------------------------------------------------------------------- |
| `--rules-dir`              | Directory of `.yml` / `.yaml` rules (subdirectories scanned recursively).       |
| `--no-sigma`               | Skip Sigma even when `--rules-dir` is set.                                      |
| `--sigma-min-level`        | Only show matches at or above this level (`low`, `medium`, `high`, `critical`). |
| `--sigma-format`           | `text` (default), `json`, or `silent` (counts in summary only).                 |
| `--sigma-show-log-details` | Print full matched log entry fields for each hit.                               |
| `--sigma-workers`          | Thread pool size for evaluation (default: CPU count).                           |
| `--show-parser-results`    | Print the full parse JSON to stdout after the run (default: off).               |


### Fields for rule authors (quick reference)

Use the **Parser support and log fields** subsection above for extraction order, injected keys, and per-parser notes. Short list of **converter-added** and **common native** fields:


| Field                             | Typical use                                                                                           |
| --------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `sysdiagnose_parser`              | SAF module id (`ps`, `crashlogs`, `lockdownd`, …).                                                    |
| `parser_module` / `parser_source` | Present when the parser output includes `parser` / `source`.                                          |
| `command`, `user`, `pid`, …       | From `rows` / `entries` / line objects (e.g. `ps.txt` → snake_case columns).                          |
| `event_type`                      | e.g. `text_snippet` (UTF-8 file extracts), `sqlite_row`, `structured_file`.                           |
| `source_path`                     | Archive-relative path for file-keyed maps and snippets (or the map key for an array, e.g. `entries`). |
| `content`                         | Up to ~16 KiB of text for `text_snippet` entries.                                                     |
| `sqlite_db_path`, `sqlite_table`  | SQLite exports (per-row entries).                                                                     |


Nested JSON (e.g. crash `.ips` payload under `data`) appears under the same keys as in the parser output. Add or narrow selections in YAML to match the fields your parsers emit.

### Library usage

```rust
use sigma_zero::engine::SigmaEngine;
use sysdiagnose_extractor_library::detection::sigma::extract_all_log_entries;

let mut engine = SigmaEngine::new(None);
engine.load_rules(std::path::Path::new("testdata/sigma-rules"))?;

let batches = extract_all_log_entries(&parse_results);
for (_parser, entries) in batches {
    for log in entries {
        let matches = engine.evaluate_log_entry(&log);
        // inspect RuleMatch values…
    }
}
```

## Library API

```rust
use std::sync::Arc;
use strum::IntoEnumIterator;
use sysdiagnose_extractor_library::{
    all_parser_types, archive::ArchiveOptions, file_loader, parser_for,
    run_parsers_concurrently, ParserType, SysdiagnoseArchive,
};

let arch = Arc::new(SysdiagnoseArchive::open_path("sysdiagnose.tar.gz")?);

// All parser modules (52)
let parsers: Vec<_> = all_parser_types()
    .into_iter()
    .map(|t| (t, parser_for(t)))
    .collect();

let results = run_parsers_concurrently(arch, parsers);
```

- `**ParserType**` — one variant per upstream `[parsers/*.py](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/tree/main/src/sysdiagnose/parsers)` module except `__init__.py` and the tutorial-only `**demo_parser.py**` (**46** modules), plus **six** Rust-only APOLLO extensions (`safari_history`, `knowledgec`, `netusage`, `interactionc`, `quarantine_events`, `screentime`) → **52** parsers total. Each maps to a `*_parser.rs` file under `[src/parsers/](src/parsers/)`; add a variant in `[ParserType](src/parsers/parser_type.rs)`, a new module file, and a `[dispatch](src/parsers/dispatch.rs)` arm when upstream adds a parser.
- `**parser_for`** — `[UniversalParser](src/parsers/dispatch.rs)` dispatches to those parser structs (full Rust ports or structured extracts).
- `**SysdiagnoseArchive::bundle_dir_name()**` / `**acquisition()**` / `**parse_bundle_acquisition()**` — acquisition time from the tarball’s top-level folder name when it matches Apple’s pattern (e.g. `sysdiagnose_2024-01-15_123456_+0000`).

### Device and system identification

Serial number, iOS version, model id, and UDID are **not** in one place — use the parsers below (or analysers that aggregate them).


| What you need                         | Best source                    | JSON path / field                                                                                                                              |
| ------------------------------------- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| **Serial, UDID, OS, build, model id** | `remotectl_dumpstate`          | `data.Device.SerialNumber`, `UniqueDeviceID`, `OSVersion`, `BuildVersion`, `ProductName`, `ProductType`                                        |
| **OS version / build (plist)**        | `sys`                          | `plist.ProductName`, `plist.ProductVersion`, `plist.BuildVersion` (or `ProductBuildVersion`)                                                   |
| **Other Apple devices on account**    | `transparency_json`            | `stateMachine.devices.*` → `serial`, `model`, `osVersion`, `name`                                                                              |
| **Normalized device block**           | `file_stats` analyser          | `device` → `serial_number`, `unique_device_id`, `os_version`, `build`, `product_name`, `product_type` (from `remotectl_dumpstate`)             |
| **Human-readable summary**            | `summary` analyser             | Markdown `## Device` section (same fields as `file_stats.device`)                                                                              |
| **When the bundle was taken**         | Archive metadata               | `SysdiagnoseArchive::acquisition()` / `bundle_dir_name()` — not hardware id                                                                    |
| **Hardware tree (IOReg)**             | `iodevicetree`, `ioservice`, … | Nested keys inside `tree` (varies by dump; may include platform / serial-like props)                                                           |
| **Crash report context**              | `crashlogs`                    | Per-event `data`: metadata, `**threads`** / `**frames**`, `exception`, `faulting_thread`, `used_images`; raw body in `report_raw` when present |


```bash
# Device block only
cargo run --release --bin sdx-cli -- parse -i sysdiagnose.tar.gz \
  --parser remotectl_dumpstate -o out.json --pretty

# Device block via analyser
cargo run --release --bin sdx-cli -- parse -i sysdiagnose.tar.gz \
  --analyser file_stats --pretty
```

The `**plists**` parser may also contain device-related plists (e.g. `SystemVersion.plist`) under `files[<path>]`, but `**remotectl_dumpstate**` is the usual single source for serial + UDID on the captured device.

### Parser reference

> **Full inventory:** `[docs/parsed-catalog.md](docs/parsed-catalog.md)` — all **53 parsers**, **14 analysers**, APOLLO modules, crash thread structure, `network_iocs` sources, and output shapes.

Paths and globs are relative to the **sysdiagnose bundle root** (the folder inside the tarball after the top-level directory is stripped). See `[dispatch.rs](src/parsers/dispatch.rs)` for exact globs and `[docs/parser-upstream-parity.md](docs/parser-upstream-parity.md)` for upstream parity notes.


| Parser ID                   | Data sources                                                                                    | Main output keys                                                                     | Device / system fields                                                                                                                                                                                                            |
| --------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `accessibility_tcc`         | `logs/Accessibility/TCC.db`                                                                     | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `apollo_all`                | All archive SQLite files matching bundled `apollo_modules/` `db_type`                           | `parser`, `format`, `events`, `meta`                                                 | Every bundled APOLLO module (200+); use dedicated parsers for faster targeted runs                                                                                                                                                |
| `appinstallation`           | `logs/appinstallation/AppUpdates.sqlitedb`, `appstored.sqlitedb`                                | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `avconference_callsettings` | `logs/AVConference/*-CallSettings.calldump.gz`                                                  | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `battery_bdc`               | `logs/BatteryBDC/*.csv`                                                                         | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `brctl`                     | `brctl/brctl-container-list.txt`, `brctl/brctl-dump.txt`                                        | `parser`, `data`                                                                     | `data.boot_history[].OS`; other KV in `data.header`                                                                                                                                                                               |
| `containermanager`          | `logs/MobileContainerManager/containermanagerd.log*`                                            | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `crashlogs`                 | `**/crashes_and_spins/**/*.ips`, `**/summaries/crashes_and_spins.log`                           | `parser`, `events`                                                                   | `**data`**: header metadata + `**threads[]**` (`id`, `triggered`, `frames[]` with `symbol`, `image`, `address`) + `**used_images**`; `**report_raw**` retained; `**ips_format**`: `two_part_json` / `single_json` / `legacy_text` |
| `disks`                     | `disks.txt`                                                                                     | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `ioacpiplane`               | `ioreg/IOACPIPlane.txt`                                                                         | `parser`, `tree` (or `{}` if missing)                                                | IOReg properties nested in `tree`                                                                                                                                                                                                 |
| `iodevicetree`              | `ioreg/IODeviceTree.txt`                                                                        | `parser`, `tree`                                                                     | IOReg `tree` (platform / hardware keys when present)                                                                                                                                                                              |
| `iofirewire`                | `ioreg/IOFireWire.txt`                                                                          | `parser`, `tree`                                                                     | IOReg `tree`                                                                                                                                                                                                                      |
| `iopower`                   | `ioreg/IOPower.txt`                                                                             | `parser`, `tree`                                                                     | IOReg `tree`                                                                                                                                                                                                                      |
| `ioservice`                 | `ioreg/IOService.txt`                                                                           | `parser`, `format`, `summary`, `device_properties`, `tree`, `meta`                   | Compact by default; `--ioservice-full-tree` / `ParseOptions` for full `tree`                                                                                                                                                      |
| `iousb`                     | `ioreg/IOUSB.txt`                                                                               | `parser`, `tree`                                                                     | IOReg `tree`                                                                                                                                                                                                                      |
| `interactionc`              | `**/interactionC.db`                                                                            | `parser`, `format`, `events`                                                         | `CONTENT URL`, interaction domains                                                                                                                                                                                                |
| `itunesstore`               | `logs/itunesstored/downloads.*.sqlitedb`                                                        | `parser`, `source_path`, `data`                                                      | —                                                                                                                                                                                                                                 |
| `kbdebug`                   | `kbdebug.txt`                                                                                   | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `knowledgec`                | `**/Knowledge/knowledgeC.db`, `**/CoreDuet/Knowledge/knowledgeC.db`                             | `parser`, `format`, `events`                                                         | URLs / hosts in browsing & app-activity modules when present                                                                                                                                                                      |
| `lockdownd`                 | `logs/MobileLockdown/lockdownd.log*`                                                            | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `logarchive`                | `system_logs.logarchive/**`                                                                     | `parser`, `inventory`, `decode`, `decode_meta` (+ `events` with `logarchive-decode`) | Inventory capped; slim event `data` fields                                                                                                                                                                                        |
| `logdata_statistics`        | `system_logs.logarchive/Extra/logdata.statistics.*.jsonl`                                       | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `logdata_statistics_txt`    | `system_logs.logarchive/Extra/logdata.statistics.*.txt`                                         | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `mcsettingsevents`          | `logs/MCState/Shared/MCSettingsEvents.plist`                                                    | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `mcstate_shared_profile`    | `logs/MCState/Shared/profile-*.stub`                                                            | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `mobileactivation`          | `logs/MobileActivation/mobileactivationd.log*`                                                  | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `mobilebackup`              | `logs/MobileBackup/com.apple.MobileBackup.plist`                                                | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `mobileinstallation`        | `logs/MobileInstallation/mobile_installation.log*`                                              | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `networkextension`          | `logs/Networking/com.apple.networkextension.plist`                                              | path → plist JSON                                                                    | —                                                                                                                                                                                                                                 |
| `networkextensioncache`     | `logs/Networking/com.apple.networkextension.cache.plist`                                        | path → plist JSON                                                                    | —                                                                                                                                                                                                                                 |
| `netusage`                  | `logs/Networking/netusage.sqlite`, `**/netusage.sqlite`                                         | `parser`, `format`, `events`                                                         | Process / route usage rows (IPs rare; see `network_iocs` analyser)                                                                                                                                                                |
| `olddsc`                    | `logs/olddsc/**`                                                                                | `parser`, `format`, `events`                                                         | `events[].data.UUID_String`, `Path` (DSC binary UUIDs)                                                                                                                                                                            |
| `plists`                    | `**/*.plist`                                                                                    | `parser`, `files`, `meta`                                                            | Indirect: any captured plist (e.g. `SystemVersion.plist` keys under `files`)                                                                                                                                                      |
| `powerlogs`                 | `logs/powerlogs/powerlog_*`, `log_*`                                                            | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `ps`                        | `ps.txt`                                                                                        | `parser`, `source`, `rows`                                                           | —                                                                                                                                                                                                                                 |
| `psthread`                  | `ps_thread.txt`                                                                                 | `parser`, `source`, `entries`                                                        | —                                                                                                                                                                                                                                 |
| `quarantine_events`         | `**/com.apple.LaunchServices.QuarantineEventsV2`                                                | `parser`, `format`, `events`                                                         | Download origin / data URLs                                                                                                                                                                                                       |
| `remotectl_dumpstate`       | `remotectl_dumpstate.txt`                                                                       | `parser`, `data`                                                                     | `**data.Device**`: `SerialNumber`, `UniqueDeviceID`, `OSVersion`, `BuildVersion`, `ProductName`, `ProductType`                                                                                                                    |
| `safari_history`            | `**/Safari/History.db`, `**/History.db`                                                         | `parser`, `format`, `events`                                                         | URLs / titles in `events[].data`                                                                                                                                                                                                  |
| `screentime`                | `**/RMAdminStore-Local.sqlite`, `**/RMAdminStore-Cloud.sqlite`                                  | `parser`, `format`, `events`                                                         | Screen Time `DOMAIN` fields                                                                                                                                                                                                       |
| `security_sysdiagnose`      | `security-sysdiagnose.txt`                                                                      | `parser`, `format`, `events`                                                         | Client attrs in `events[].data` (e.g. `product`, `build`, `modelid`)                                                                                                                                                              |
| `shutdownlogs`              | `system_logs.logarchive/Extra/shutdown.log`, `Extra/shutdown.*.log`, `private/var/db/diagnostics/shutdown.log`, `shutdown.*.log` | `parser`, `sources`, `events`                                                                   | Rotated iOS 26 logs ([mvt#830](https://github.com/mvt-project/mvt/issues/830)); trailing binary UUID stripped into `data.uuid` / `data.executable_path`                                                                                                                                                                                                                                 |
| `spindumpnosymbols`         | `**/spindump-nosymbols.txt`                                                                     | `parser`, `format`, `events`                                                         | Header KV in first events (e.g. `os_version`, `hardware_model`)                                                                                                                                                                   |
| `swcutil`                   | `**/swcutil_show.txt`                                                                           | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `sys`                       | `logs/SystemVersion/SystemVersion.plist` (fallbacks: `logs/Splat/OS/…`, `*SystemVersion.plist`) | `parser`, `source`, `message`, `plist`                                               | `**plist**`: `ProductName`, `ProductVersion`, `BuildVersion` / `ProductBuildVersion`                                                                                                                                              |
| `taskinfo`                  | `taskinfo.txt`                                                                                  | `parser`, `source`, `events`, `acquisition_rfc3339`                                  | `acquisition_rfc3339` = bundle capture time                                                                                                                                                                                       |
| `transparency`              | `transparency.log`                                                                              | `parser`, `format`, `events`                                                         | — (timeline only; no `stateMachine.devices`)                                                                                                                                                                                      |
| `transparency_json`         | `transparency.log`                                                                              | pass-through root JSON                                                               | `**stateMachine.devices.***`: `serial`, `model`, `osVersion`, `name`                                                                                                                                                              |
| `uuid2path`                 | `logs/tailspindb/UUIDToBinaryLocations`                                                         | path → plist JSON                                                                    | —                                                                                                                                                                                                                                 |
| `wifi_known_networks`       | `WiFi/com.apple.wifi.known-networks.plist`, `**/WiFi/…`                                         | `parser`, `format`, `events`, `files`                                                | Geo in `events[].data` (`ssid`, `latitude`, `longitude`)                                                                                                                                                                          |
| `wifinetworks`              | `WiFi/*.plist`, `WiFi/com.apple.wifi.recent-networks.json`                                      | `parser`, `format`, `events`, `files`                                                | Same Wi‑Fi geo pattern                                                                                                                                                                                                            |
| `wifiscan`                  | `WiFi/wifi_scan*.txt`                                                                           | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |
| `wifisecurity`              | `WiFi/security.txt`                                                                             | `parser`, `format`, `events`                                                         | —                                                                                                                                                                                                                                 |


`**plists` caps:** `SYSDIAGNOSE_PLISTS_MAX_FILES` (default 600, `0` = unlimited), `SYSDIAGNOSE_PLISTS_MAX_EACH_BYTES` (default 4 MiB, `0` = unlimited). Parse failures → `{}` for that path; paths listed in `meta.parse_failures` / `meta.skipped_oversized`.

`**wrap_jsonl` parsers** (`accessibility_tcc`, `powerlogs`, `safari_history`, `knowledgec`, `netusage`, `wifi_known_networks`, …): each `events[]` item has `datetime`, `message`, `timestamp_desc`, `module`, `data`.

**IOReg parsers** (`ioacpiplane`, `iodevicetree`, …): missing file → `{}`; present file → `parser` + `tree`.

**Plist-map parsers** (`networkextension`, `networkextensioncache`, `uuid2path`): top-level keys are archive paths; values are parsed plist JSON.

### Analysers

Rust module `[analysers](src/analysers/mod.rs)` implements the same core analyser IDs as upstream [SAF `analysers/](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/tree/main/src/sysdiagnose/analysers)` (SAF also ships `**yarascan`**, which is not in this crate). Each analyser receives the in-memory archive plus a map of **parser id → parser JSON** from the current run; if a parser was skipped or failed, the analyser may call `parser_for` internally for the inputs it needs (see `[dispatch.rs](src/analysers/dispatch.rs)` and per-analyser modules under `[analysers/](src/analysers/)`). Several outputs include a `**saf_comparison`** string describing differences from Python (HTML coverage, libmagic, unified log, etc.).


| ID                     | Description                                                    | Data sources                                                                                                                                                                                                                                 | Device / system output                                                                                                                      |
| ---------------------- | -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `accounts`             | Device-user identity (emails, contacts, linked devices)        | `transparency_json`, targeted identity plists (`CloudConfigurationDetails`, `mobilecal`, `EffectiveUserSettings`) + `mobileactivationd` logs + capped `plists` fallback                                                                 | `owner_emails`, `organization_emails`, `activation_lock_usernames`, `contacts`, `apple_accounts`, `linked_devices`, `lockdown_mode`                                      |
| `apps`                 | Aggregate bundle-like identifiers across parsers               | `accessibility_tcc`, `brctl`, `itunesstore`, `appinstallation`, `mobileinstallation`, `powerlogs`, `mobilebackup`, `plists`, `logdata_statistics`, …                                                                                         | — (per-app `**hits**` evidence array; `hits_cap_per_app` = 64)                                                                              |
| `coverage`             | Parser ID presence vs all defined parsers (JSON, not SAF HTML) | Keys in the current `parsed` map; `archive.len()` for file count                                                                                                                                                                             | —                                                                                                                                           |
| `file_stats`           | File counts + directory rollup                                 | All paths from `archive.iter_files()`; extension-based MIME hints; top 100 directories                                                                                                                                                       | `**device**` object from `remotectl_dumpstate` (`serial_number`, `unique_device_id`, `os_version`, `build`, `product_name`, `product_type`) |
| `install_enrichment`   | Correlate installs/deletes with nearby IPA / sideload tools    | `mobileinstallation`, `logarchive`, `crashlogs`, `plists`, `ps`, `psthread`, `shutdownlogs`, `powerlogs`, …                                                                                                                                    | Per-event `enrichments[]` (IPA / TrollStore / TrollDecrypt / …) within a ±30m window                                                       |
| `mcstateshared`        | MCState shared profile stubs                                   | `mcstate_shared_profile` → `logs/MCState/Shared/profile-*.stub`                                                                                                                                                                              | —                                                                                                                                           |
| `network_iocs`         | IPv4 / domain / URL / Wi‑Fi hunting across parser JSON         | `powerlogs`, `swcutil`, `safari_history`, `knowledgec`, `netusage`, `interactionc`, `quarantine_events`, `screentime`, `crashlogs`, `logdata_statistics*`, `taskinfo`, `shutdownlogs`, Wi‑Fi parsers, `logarchive` (decode on by default), … | `**ipv4**`, `**domains**`, `**urls**`, `**ssids**`, `**bssids**` + `**hits**` with `json_path`; `**logarchive_decode**` status              |
| `permissions`          | TCC privacy permissions per bundle id                            | `accessibility_tcc`                                                                                                                                                                                                                          | `app_count`, `apps` (bundle id → `permissions[]`)                                                                                           |
| `plist`                | MDM-related plist highlights                                   | Capped `plists`; `Shared_MDM` / `*.mdm.plist` paths                                                                                                                                                                                          | MDM profile ids / rights (not device serial)                                                                                                |
| `ps_everywhere`        | Deduped process/command lines                                  | `ps`, `psthread`, `taskinfo`, `shutdownlogs`, `logdata_statistics`, `uuid2path`, `remotectl_dumpstate` (**Services**), `spindumpnosymbols`                                                                                                   | —                                                                                                                                           |
| `ps_matrix`            | Per-PID matrix                                                 | `ps`, `psthread`, `taskinfo`, `spindumpnosymbols`                                                                                                                                                                                            | —                                                                                                                                           |
| `summary`              | Markdown summary                                               | `remotectl_dumpstate`, `transparency_json`, capped `plists`, `mcstate_shared_profile`, `security_sysdiagnose`, `shutdownlogs`                                                                                                                | `**## Device`** JSON block; transparency **known devices** table (`serial`, `model`, `osVersion`, `name`)                                   |
| `timesketch`           | Timeline for [Timesketch](https://timesketch.org) import       | All parsers via `get_or_parse`                                                                                                                                                                                                               | Uses parser event timestamps; falls back to `**archive.acquisition()`** when datetime missing                                               |
| `wifi_geolocation`     | GPX XML from known Wi‑Fi BSS coordinates                       | `wifi_known_networks` → `files` / `events`                                                                                                                                                                                                   | Wi‑Fi BSS coordinates (not device serial)                                                                                                   |
| `wifi_geolocation_kml` | KML XML from the same Wi‑Fi data                               | Same as `wifi_geolocation`                                                                                                                                                                                                                   | Same                                                                                                                                        |


These match `cargo run --bin sdx-cli -- list-analysers` (15 analysers).

`**apps` hits** include SQLite row excerpts (`sqlite_db`, `sqlite_table`, `matched_column`), plist paths/keys (`plist_path`, `plist_key`), brctl context, mobileinstallation text previews, and logdata fields (`subsystem`, `category`, `datetime`). Legacy `_{parser}` keys still reflect the last hit from that parser.

#### `timesketch` output (CSV, JSON array, JSONL)

The analyser JSON includes:


| Field               | Description                                                                                                                                                                                                                                               |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `count`             | Number of timeline rows.                                                                                                                                                                                                                                  |
| `events`            | JSON **array** of objects; each row has at least `message`, `datetime`, `timestamp_desc`, `timestamp` (epoch **microseconds**), `time_is_approximate`, `sysdiagnose_parser`, and optional fields such as `parser_module`, `parser_source`, `source_path`. |
| `jsonl`             | **Newline-delimited JSON**: the same objects as `events`, one compact JSON object per line (no surrounding array). Save to a `.jsonl` file or pipe through tools that expect NDJSON/JSONL.                                                                |
| `csv`               | A single string of CSV text (header row plus one row per event) with columns `message`, `datetime`, `timestamp_desc`, `timestamp`, `time_is_approximate`, `sysdiagnose_parser`. For full field sets, use `events` or `jsonl`.                             |
| `events_per_parser` | Map of parser id → how many rows that parser contributed.                                                                                                                                                                                                 |
| `saf_comparison`    | Short note on time fallback and parity vs SAF.                                                                                                                                                                                                            |


Wall-clock times come from parser fields when present; otherwise the archive **bundle acquisition** time is used and `time_is_approximate` is `true` (see module `[timesketch.rs](src/analysers/timesketch.rs)`).

Use `--run-analysers` on `parse` to add an `_analysers` object for **all** analysers, or `--analyser <name>` (repeatable) to run only those names (no need for `--run-analysers` when `--analyser` is set). From code, use `analyser_for(AnalyserType)` and `Analyser::analyse` with a `ParsedByParser` map (see `analysers` module). **summary** and Wi‑Fi geolocation output are aligned with SAF intent but not identical to Python in every detail.

When you use `**--analyser`** or `**--run-analysers**` but do **not** pass `**--show-parser-results`** or `**-o**`, the CLI still prints a `**=== Analysers ===**` section to stdout with the analyser JSON (add `**--pretty**` for readable formatting). Full parser JSON remains opt-in via `**-o**` or `**--show-parser-results**`.

## Coverage vs SAF


| Tier                     | Parsers (examples)                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Behaviour                                                                                                                        |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **Full / close ports**   | `ps`, `psthread`, `sys`, `taskinfo`, `shutdownlogs`, `remotectl_dumpstate` (tab hierarchy), `crashlogs` (`.ips` → structured `threads` / `frames` + `report_raw`; summary log as text)                                                                                                                                                                                                                                                                                                 | Logic aligned with SAF Python                                                                                                    |
| **Structured extract**   | `plists` (`**/*.plist`, env caps + `meta`), SQLite-backed (`appinstallation`, `itunesstore` → `**data`** table map, …); APOLLO parsers (`accessibility_tcc`, `powerlogs`, `safari_history`, `knowledgec`, `netusage`, `interactionc`, `quarantine_events`, `screentime`) → `**events**`; `battery_bdc` → CSV rows; `avconference_callsettings` → gzip text; `logarchive` → capped `**inventory**` (+ optional decode via `**logarchive-decode**` feature — [`docs/logarchive.md`](docs/logarchive.md)) | Same *inputs* as SAF; remaining parsers may still differ in shape from upstream where noted in `docs/parser-upstream-parity.md`. |
| **Text / plist by path** | `brctl`, `lockdownd`, `wifisecurity`, `networkextension`, `uuid2path`, …                                                                                                                                                                                                                                                                                                                                                                                                               | UTF-8 or plist → JSON per matched path                                                                                           |
| **IOReg family**         | `iodevicetree`, `iousb`, …                                                                                                                                                                                                                                                                                                                                                                                                                                                             | `IORegStructParser` → `**tree*`*; `**ioservice**` → compact preview unless `ioservice_full_tree` is set                          |


**UnifiedLogs / `logarchive`**: decode uses Mandiant **[macos-UnifiedLogs](https://github.com/mandiant/macos-UnifiedLogs)** in-process (cross-platform). Enable with Cargo feature **`logarchive-decode`** — see [`docs/logarchive.md`](docs/logarchive.md).

## Archive loading

- **gzip** (`.tar.gz` / `.tgz`), **xz** (`.tar.xz`), or **plain** tar; single top-level directory stripped; `**._*`** skipped. Gzip uses **flate2** with the **`zlib-rs`** backend (faster than the default miniz_oxide decoder).
- Supplemental CSIRC-style crash dumps (members under `private/var/.../CrashReporter/`) are accepted; `crashlogs` matches both `crashes_and_spins/**/*.ips` and `**/CrashReporter/**/*.ips`.
- Nested `sysdiagnose_*.tar.gz` / `.tgz` / `.tar.xz` members are expanded into the same file map by default (outer CrashReporter paths win on conflict). Cap: **`max_nested_sysdiagnose_bytes`** (default **512 MiB**).
- Other members over `**max_entry_bytes**` are skipped (default **64 MiB**).

## Performance tips

### Without changing code

- **Run only the parsers you need.** By default all 53 run. Use `--parser ps --parser crashlogs …`. The ones that cost the most:
  - **`apollo_all`**: re-runs every APOLLO module on every database it finds, repeating the work of `knowledgec`, `powerlogs`, `netusage`, `screentime`, and the other database parsers. Run either `apollo_all` **or** those individual parsers, not both.
  - **`plists`**: reads up to 600 plists. Lower `SYSDIAGNOSE_PLISTS_MAX_FILES` if you don’t need all of them.
  - **`logarchive`**: keep `--logarchive-decode-max-lines` low (default **2 500**). Raising it is the quickest way to make a run slow.
  - **`ioservice`**: leave `--ioservice-full-tree` off.
- **Analyse the same archive more than once?** Decompress once. Turning `.tar.gz` back into raw data is single-threaded. Prefer `pigz -dc sysdiagnose.tar.gz > sysdiagnose.tar` once, then pass the `.tar`. The library memory-maps plain `.tar` files, so loading becomes mostly a copy.
- **Lower `--max-entry-mb`** (default **64**) if you don’t need huge files. Large members are skipped completely (saves time and memory; you lose that data).
- **Build for your CPU:** `RUSTFLAGS="-C target-cpu=native" cargo build --release`. Release already uses LTO with `codegen-units = 1`.
- **Keep output small.** Avoid `--pretty` and `--show-parser-results` on full runs. Writing tens of megabytes of formatted JSON is surprisingly slow.
- **Library use:** load the archive once (`Arc<SysdiagnoseArchive>`) and reuse it for several `run_parsers_concurrently` calls instead of reopening each time. Parser results are `Arc<Value>` so you can share them with analysers / Sigma without deep-cloning.

### Code-side notes

Already in this tree: faster gzip (`zlib-rs`), analysers run in parallel on the CLI, and parser JSON is shared via `Arc<Value>`.

Still worth doing if you lean on SQLite / APOLLO parsers: open databases from memory (`sqlite3_deserialize`) on native instead of writing temp files, and give each parser its own connection so queries can run in parallel. After that, the wall clock is often the slowest single parser (e.g. `logarchive` with a high line limit)—decode `.tracev3` files on separate rayon tasks when you need that.

### Benchmark vs Python SAF

[`scripts/bench_vs_saf.sh`](scripts/bench_vs_saf.sh) times this crate’s release `sdx-cli` against upstream [SAF](https://github.com/EC-DIGIT-CSIRC/sysdiagnose) (`saf` / `sysdiag`) on the same archive and parser set.

```bash
# Install SAF once (venv), then:
./scripts/bench_vs_saf.sh -i path/to/sysdiagnose.tar.gz --saf-dir /path/to/sysdiagnose --runs 3

# Shared subset of parsers (faster)
./scripts/bench_vs_saf.sh -i path/to/sysdiagnose.tar.gz --parsers ps,sys,crashlogs,remotectl_dumpstate

# Include SAF create (extract) in the Python time
./scripts/bench_vs_saf.sh -i path/to/sysdiagnose.tar.gz --e2e
```

By default it uses the **intersection** of parser IDs (so Rust-only modules like `knowledgec` / `apollo_all` are skipped), discards JSON output, and reports mean times plus **SAF / Rust** speedup. Pass `--saf-dir` (or install `saf` on `PATH` / set `SAF_DIR`).

## Tests

```bash
cargo test
cargo test analysers::   # analyser unit tests only
cargo test --test integration_assets -- --ignored --nocapture
cargo test --test sysdiagnose_testdata -- --nocapture   # uses testdata/sysdiagnose-testdata or SYSDIAGNOSE_TESTDATA; skips if missing / LFS only (runs all parsers + wrap_jsonl `required_fields_jsonl` checks)
```

With testdata checked out and LFS objects present, set `**SYSDIAGNOSE_TESTDATA_REQUIRE=1**` to fail the run if no usable `*.tar.gz` is found (for example in a dedicated CI job after `git lfs pull`).

Example:

```bash
git clone https://github.com/EC-DIGIT-CSIRC/sysdiagnose-testdata.git testdata/sysdiagnose-testdata
cd testdata/sysdiagnose-testdata && git checkout 7e64d5ca133837393c0c7cd3193d0d4dcabc5447 && git lfs pull && cd ../..
cargo test --test sysdiagnose_testdata -- --nocapture
```

## Attribution

This software is **explicitly based on** the [Sysdiagnose Analysis Framework (SAF)](https://github.com/EC-DIGIT-CSIRC/sysdiagnose) by **EC-DIGIT-CSIRC** (European Commission). Parser and analyser behaviour is ported or adapted from that project under the same licence. Upstream copyright and contributors remain those of SAF; see also [NOTICE](NOTICE).

## License

Licensed under the **European Union Public Licence v. 1.2 (EUPL-1.2)**—the same licence as [EC-DIGIT-CSIRC/sysdiagnose](https://github.com/EC-DIGIT-CSIRC/sysdiagnose).

See [LICENSE](LICENSE) for the full text, or <https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12>.