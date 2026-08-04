# Parsed artifacts catalog

Canonical inventory of **everything this library extracts** from Apple sysdiagnose archives (`.tar.gz` bundles).

**Counts (verify in CI):** **53 parsers** · **14 analysers** · optional **Sigma** rules over parser JSON.

**Keep this file updated when you add or change a parser/analyser.** Cross-check:

- [`src/parsers/parser_type.rs`](../src/parsers/parser_type.rs) — `ParserType` enum
- [`src/analysers/mod.rs`](../src/analysers/mod.rs) — `AnalyserType` enum
- Tests: `parser_type_enum_iter_matches_expected_count` (53), `analyser_type_enum_iter_matches_expected_count` (14)
- CLI: `cargo run --bin sdx-cli -- list-parsers` / `list-analysers`

Related docs: [parser-upstream-parity.md](parser-upstream-parity.md) · [parser-events-edge-cases.md](parser-events-edge-cases.md) · [logarchive.md](logarchive.md)

---

## How output is shaped

| Shape | Parsers using it | Top-level keys | Per-record fields (typical) |
|-------|------------------|----------------|-----------------------------|
| **`wrap_jsonl`** | Most timeline / APOLLO / log parsers | `parser`, `format` (`"jsonl"`), `events` | `datetime`, `message`, `timestamp_desc`, `module`, `data` |
| **`rows`** | `ps` | `parser`, `source`, `rows` | `user`, `pid`, `command`, … |
| **`entries`** | `psthread` | `parser`, `source`, `entries` | Same columns as `ps`-style rows + `message` |
| **`events` (custom)** | `crashlogs`, `shutdownlogs`, `taskinfo`, … | `parser`, `events` | Varies (see per-parser rows below) |
| **`tree`** | IOReg (`io*`) | `parser`, `tree` | Nested IOService-style objects; `{}` if file missing |
| **Plist map** | `networkextension`, `networkextensioncache`, `uuid2path` | Archive path → plist JSON | — |
| **SQLite table map** | `itunesstore` | `parser`, `source_path`, `data` | Table name → row arrays |
| **Plist bundle** | `plists` | `parser`, `files`, `meta` | `files[path]` = plist JSON; `meta` caps / failures |
| **Structured `data`** | `brctl`, `remotectl_dumpstate` | `parser`, `data` | Hierarchy or section model |
| **Pass-through JSON** | `transparency_json` | Root keys from `transparency.log` | — |
| **Inventory + decode** | `logarchive` | `parser`, `inventory`, `decode`, `note` (+ `events` when decoded) | See [logarchive.md](logarchive.md) |

Environment / features:

| Variable / feature | Effect |
|--------------------|--------|
| `ParseOptions.ioservice_full_tree` | Library API + CLI `--ioservice-full-tree` — full IOService `tree` (default: compact) |
| `SYSDIAGNOSE_PLISTS_MAX_FILES` | Cap plists parsed (default 600; `0` = unlimited) |
| `SYSDIAGNOSE_PLISTS_MAX_EACH_BYTES` | Per-file plist size cap (default 4 MiB) |
| `SYSDIAGNOSE_LOGARCHIVE_INVENTORY_MAX_PATHS` | Cap inventory `paths` listed (default 100; largest files first) |
| `SYSDIAGNOSE_LOGARCHIVE_DECODE_MAX_LINES` | Unified log decode line cap (default 2 500) |
| `SYSDIAGNOSE_IOSERVICE_MAX_DEPTH` | Compact tree depth (default 3) |
| `SYSDIAGNOSE_IOSERVICE_MAX_CHILDREN` | Max children per IOReg node in compact tree (default 48) |
| Cargo feature **`logarchive-decode`** | Default; in-process decode via [`macos-unifiedlogs`](https://github.com/mandiant/macos-UnifiedLogs). Disable with `--no-default-features`. |
| `ParseOptions.logarchive_decode_max_lines` | Library API cap (default 2500) |

---

## Parsers (53)

Paths are relative to the **sysdiagnose bundle root** (inner folder of the tarball). Implementation: [`src/parsers/`](../src/parsers/).

### Access & privacy

| ID | Archive sources | Parsed content | Output |
|----|-----------------|----------------|--------|
| `accessibility_tcc` | `logs/Accessibility/TCC.db` | APOLLO TCC SQLite queries (camera, mic, contacts, …) | `events[]` |
| `security_sysdiagnose` | `security-sysdiagnose.txt` | Keychain rows, client events, meta | `events[]` |
| `transparency` | `transparency.log` | Registration / state-machine timeline lines | `events[]` |
| `transparency_json` | `transparency.log` | Whole JSON document | Root JSON; **`stateMachine.devices`** (serial, model, osVersion, name) |

### Apps & installation

| ID | Archive sources | Parsed content | Output |
|----|-----------------|----------------|--------|
| `appinstallation` | `logs/appinstallation/AppUpdates.sqlitedb`, `appstored.sqlitedb` | Install / update SQLite rows | `events[]` |
| `mobileinstallation` | `logs/MobileInstallation/mobile_installation.log*` | Installation log lines | `events[]` |
| `mobilebackup` | `logs/MobileBackup/com.apple.MobileBackup.plist` | Backup plist, installed apps | `events[]` |
| `mobileactivation` | `logs/MobileActivation/mobileactivationd.log*` | Activation daemon logs | `events[]` |
| `itunesstore` | `logs/itunesstored/downloads.*.sqlitedb` | Downloads DB tables | `source_path`, `data` (table → rows) |
| `containermanager` | `logs/MobileContainerManager/containermanagerd.log*` | Container manager logs | `events[]` |
| `brctl` | `brctl/brctl-container-list.txt`, `brctl/brctl-dump.txt` | CloudDocs containers, boot history | `data` (header, boot_history, …) |
| `olddsc` | `logs/olddsc/**` | Dynamic Shared Cache binaries | `events[]` (`UUID_String`, `Path`) |
| `uuid2path` | `logs/tailspindb/UUIDToBinaryLocations` | UUID → binary path plists | path → plist JSON |

### Device & system

| ID | Archive sources | Parsed content | Output |
|----|-----------------|----------------|--------|
| `remotectl_dumpstate` | `remotectl_dumpstate.txt` | Tab-hierarchy device dump | `data` — **`data.Device`**: SerialNumber, UniqueDeviceID, OSVersion, BuildVersion, ProductName, ProductType |
| `sys` | `logs/SystemVersion/SystemVersion.plist`, fallbacks | SystemVersion plist | `plist` (ProductName, ProductVersion, BuildVersion) |
| `disks` | `disks.txt` | `df`-style disk listing | `events[]` |
| `kbdebug` | `kbdebug.txt` | Keyboard debug log | `events[]` |
| `lockdownd` | `logs/MobileLockdown/lockdownd.log*` | Lockdown daemon logs | `events[]` |
| `mcsettingsevents` | `logs/MCState/Shared/MCSettingsEvents.plist` | MDM / settings events plist | `events[]` |
| `mcstate_shared_profile` | `logs/MCState/Shared/profile-*.stub` | Shared profile stubs | `events[]` |
| `plists` | `**/*.plist` | All captured plists (capped) | `files`, `meta` |

### IOReg hardware trees

| ID | Archive sources | Parsed content | Output |
|----|-----------------|----------------|--------|
| `ioacpiplane` | `ioreg/IOACPIPlane.txt` | IOACPI plane | `tree` |
| `iodevicetree` | `ioreg/IODeviceTree.txt` | Device tree | `tree` |
| `iofirewire` | `ioreg/IOFireWire.txt` | FireWire plane | `tree` |
| `iopower` | `ioreg/IOPower.txt` | Power plane | `tree` |
| `ioservice` | `ioreg/IOService.txt` | IOService plane (compact by default) | `format: compact`, `summary`, `device_properties`, depth-limited `tree`; full tree via `ParseOptions.ioservice_full_tree` or `--ioservice-full-tree` |
| `iousb` | `ioreg/IOUSB.txt` | USB plane | `tree` |

### Logs & diagnostics

| ID | Archive sources | Parsed content | Output |
|----|-----------------|----------------|--------|
| `logarchive` | `system_logs.logarchive/**` | Path inventory (capped); optional unified-log decode | `inventory` (`file_count`, `by_subdir`, capped `paths`), `decode`, `decode_meta`, `events` (slim `data` fields) |
| `logdata_statistics` | `system_logs.logarchive/Extra/logdata.statistics.*.jsonl` | Statistics JSONL | `events[]` |
| `logdata_statistics_txt` | `system_logs.logarchive/Extra/logdata.statistics.*.txt` | Statistics text | `events[]` |
| `shutdownlogs` | `system_logs.logarchive/Extra/shutdown[.N].log`, `private/var/db/diagnostics/shutdown[.N].log` | Shutdown client log (incl. iOS 26 rotations) | `events[]` (pid, command, path, executable_path, uuid, wait time), `sources[]` |
| `spindumpnosymbols` | `**/spindump-nosymbols.txt` | Spindump samples (no symbols) | `events[]` |
| `taskinfo` | `taskinfo.txt` | Task/process snapshot | `events[]`, `acquisition_rfc3339` |
| `ps` | `ps.txt` | Process list | `rows` |
| `psthread` | `ps_thread.txt` | Per-thread process list | `entries` |
| `crashlogs` | `**/crashes_and_spins/**/*.ips`, `**/summaries/crashes_and_spins.log` | Crash/spin reports | See [Crash reports](#crash-reports-crashlogs) below |
| `battery_bdc` | `logs/BatteryBDC/*.csv` | Battery diagnostic CSV | `events[]` |
| `avconference_callsettings` | `logs/AVConference/*-CallSettings.calldump.gz` | AVConference gzip dumps | `events[]` |

### Network & browsing

| ID | Archive sources | Parsed content | Output |
|----|-----------------|----------------|--------|
| `networkextension` | `logs/Networking/com.apple.networkextension.plist` | Network extension plist | path → plist JSON |
| `networkextensioncache` | `logs/Networking/com.apple.networkextension.cache.plist` | NE cache plist | path → plist JSON |
| `netusage` | `logs/Networking/netusage.sqlite`, `**/netusage.sqlite` | APOLLO netusage modules (per-process/route bytes) | `events[]` |
| `swcutil` | `**/swcutil_show.txt` | Shared web credentials DB/network/settings | `events[]` (incl. **domains**) |
| `safari_history` | `**/Safari/History.db`, `**/History.db` | Safari visit history (APOLLO) | `events[]` (URLs, titles) |
| `knowledgec` | `**/Knowledge/knowledgeC.db`, `**/CoreDuet/Knowledge/knowledgeC.db` | All APOLLO modules on `knowledgeC.db` (80+ queries: Safari, Wi‑Fi, app activity, …) | `events[]` |
| `interactionc` | `**/interactionC.db` | Contact interactions (APOLLO) | `events[]` (CONTENT URL, domain id) |
| `quarantine_events` | `**/com.apple.LaunchServices.QuarantineEventsV2` | Download quarantine (APOLLO) | `events[]` (origin/data URLs) |
| `screentime` | `**/RMAdminStore-Local.sqlite`, `**/RMAdminStore-Cloud.sqlite` | Screen Time usage (APOLLO) | `events[]` (DOMAIN, usage) |

### Wi‑Fi

| ID | Archive sources | Parsed content | Output |
|----|-----------------|----------------|--------|
| `wifi_known_networks` | `WiFi/com.apple.wifi.known-networks.plist`, `**/WiFi/…` | Known networks + BSS geo | `events[]`, `files` |
| `wifinetworks` | `WiFi/*.plist`, `WiFi/com.apple.wifi.recent-networks.json` | Recent / saved networks | `events[]`, `files` |
| `wifiscan` | `WiFi/wifi_scan*.txt` | Scan summaries | `events[]` |
| `wifisecurity` | `WiFi/security.txt` | Security / keychain-related Wi‑Fi log | `events[]` |

### Power & telemetry

| ID | Archive sources | Parsed content | Output |
|----|-----------------|----------------|--------|
| `powerlogs` | `logs/powerlogs/powerlog_*`, `log_*` | APOLLO `CurrentPowerlog.PLSQL` (push IP/hostname, network usage, app usage, …) | `events[]` |

---

## APOLLO-backed parsers

Bundled query definitions: [`apollo_modules/`](../apollo_modules/). Runtime: [`src/parsers/apollo.rs`](../src/parsers/apollo.rs). Row cap: **100 000** per query. Failed SQL (schema drift) is skipped.

| Parser ID | SQLite / DB file | Notable extracted fields |
|-----------|------------------|---------------------------|
| `accessibility_tcc` | `TCC.db` | Service, client, last_modified, … |
| `powerlogs` | `CurrentPowerlog.PLSQL` | SERVER IP, SERVERHOSTNAME, interface bytes, app usage, … |
| `safari_history` | `History.db` | URL, visit time, title |
| `knowledgec` | `knowledgeC.db` | URLs, domains, app activity, Wi‑Fi SSID (ACCESS POINT), … |
| `netusage` | `netusage.sqlite` | Process name, Wi‑Fi/cellular bytes |
| `interactionc` | `interactionC.db` | CONTENT URL, DOMAIN IDENTIFIER |
| `quarantine_events` | `QuarantineEventsV2` | ORIGIN URL STRING, DATA URL STRING |
| `screentime` | `RMAdminStore-*.sqlite` | DOMAIN, category/hour usage |
| `apollo_all` | **All** archive SQLite files matching bundled `apollo_modules/` `db_type` | Every bundled APOLLO query on every matching DB (200+ modules; row cap per query) |

**`apollo_all`** discovers DBs via path heuristics (`archive_path_matches_db_type`) and runs the full module registry. Dedicated parsers above remain for targeted / faster runs.

**WASM:** Apollo parsers return empty `events` on `wasm32-unknown-unknown`.

---

## Crash reports (`crashlogs`)

Module: [`src/parsers/crashlogs_ips.rs`](../src/parsers/crashlogs_ips.rs).

Each `.ips` file → one `events[]` item with `source`, `module`, `data`:

| Field | Description |
|-------|-------------|
| `ips_format` | `two_part_json` · `single_json` · `legacy_text` · `unknown` |
| `threads[]` | `id`, `triggered`, `name`, `queue`, `frame_count`, `frames[]` |
| `frames[]` | `index`, `symbol`, `image`, `image_index`, `image_offset`, `address` |
| `faulting_thread` | Index of crashing thread |
| `exception` / `termination` | From JSON payload when present |
| `used_images[]` | `name`, `uuid`, `base`, `arch` (capped at 256) |
| `last_exception_backtrace` | Normalized frames when present |
| `crash_structure` | Truncation flags (64 threads, 128 frames/thread) |
| `report_raw` | Original body text preserved |

`crashes_and_spins.log` summary → `format: summary_text`, `raw` text.

Excludes paths containing `WiFiLQMMetrics`, `OTAUpdate`. **No symbolication.**

---

## Analysers (14)

Analysers consume **parser JSON** (+ archive for missing parsers). Module: [`src/analysers/`](../src/analysers/).

| ID | Produces | Primary inputs | Notable output keys |
|----|----------|----------------|---------------------|
| `apps` | Per-bundle app evidence | `accessibility_tcc`, `brctl`, `itunesstore`, `appinstallation`, `mobileinstallation`, `powerlogs`, `mobilebackup`, `plists`, `logdata_statistics`, … | `apps[]`, `hits` per app |
| `coverage` | Parser coverage report | Current `parsed` map, archive file count | `parser_keys_present`, `parser_types_total` |
| `file_stats` | Archive statistics | All archive paths | `by_top_level_segment`, `by_directory`, **`device`** |
| `install_enrichment` | Install/delete ↔ IPA / sideload tools | `mobileinstallation`, `logarchive`, `crashlogs`, `plists`, `ps`, … | `events[]` with `version`, `enrichments[]` |
| `mcstateshared` | MCState stub listing | `mcstate_shared_profile` | `rows[]` |
| `network_iocs` | Network IOC hunting | 21 parsers (see below) | `ipv4`, `domains`, `urls`, `ssids`, `bssids`, `hits`, `logarchive_decode` |
| `permissions` | TCC privacy rollup per app | `accessibility_tcc` | `app_count`, `apps` (bundle id → `permissions[]`: service, allowed, last_modified, …) |
| `plist` | MDM plist highlights | Capped `plists` | MDM profile paths / keys |
| `ps_everywhere` | Deduped processes | `ps`, `psthread`, `taskinfo`, `shutdownlogs`, `logdata_statistics`, `uuid2path`, `remotectl_dumpstate`, `spindumpnosymbols` | `entries[]` |
| `ps_matrix` | PID presence matrix | `ps`, `psthread`, `taskinfo`, `spindumpnosymbols` | `rows[]` with `in_ps`, `in_psthread`, … |
| `summary` | Markdown report | `remotectl_dumpstate`, `transparency_json`, `plists`, `mcstate_shared_profile`, `security_sysdiagnose`, `shutdownlogs` | `content` (markdown) |
| `timesketch` | Timeline export | All parsers (via `get_or_parse`) | `events`, `jsonl`, `csv`, `events_per_parser` |
| `wifi_geolocation` | GPX XML | `wifi_known_networks` | `xml` |
| `wifi_geolocation_kml` | KML XML | `wifi_known_networks` | `xml` |

### `network_iocs` source parsers

`powerlogs`, `swcutil`, `safari_history`, `knowledgec`, `netusage`, `interactionc`, `quarantine_events`, `screentime`, `networkextension`, `networkextensioncache`, `plists`, `logarchive`, `transparency_json`, `crashlogs`, `logdata_statistics`, `logdata_statistics_txt`, `taskinfo`, `shutdownlogs`, `wifi_known_networks`, `wifinetworks`, `wifiscan`.

Heuristic scan (IPv4 regex, URL hosts, domain-like keys, SSID/BSSID fields). Hits capped at **512**. Not a substitute for PCAP/DNS analysis.

---

## Device identification (quick reference)

| Need | Parser / analyser | Fields |
|------|-------------------|--------|
| Serial, UDID, OS, build, model | `remotectl_dumpstate` | `data.Device.*` |
| Normalized device block | `file_stats` analyser | `device.serial_number`, `unique_device_id`, `os_version`, `build`, `product_name`, `product_type` |
| Human summary | `summary` analyser | Markdown `## Device` |
| OS version plist | `sys` | `plist.ProductName`, `ProductVersion`, `BuildVersion` |
| Linked devices | `transparency_json` | `stateMachine.devices` |
| Crash context | `crashlogs` | `data` metadata, threads, exception |

---

## Sigma detection (optional)

With `--rules-dir`, parser JSON is mapped to Sigma [`LogEntry`](https://github.com/ping2A/sigmazero) rows (`sysdiagnose_parser` = parser id). Example rules: [`testdata/sigma-rules/examples/`](../testdata/sigma-rules/examples/).

---

## Full parser index (A–Z)

| # | Parser ID | Rust module |
|---|-----------|-------------|
| 1 | `accessibility_tcc` | `accessibility_tcc_parser.rs` |
| 2 | `apollo_all` | `apollo_all_parser.rs` |
| 3 | `appinstallation` | `appinstallation_parser.rs` |
| 4 | `avconference_callsettings` | `avconference_callsettings_parser.rs` |
| 5 | `battery_bdc` | `battery_bdc_parser.rs` |
| 6 | `brctl` | `brctl_parser.rs` |
| 7 | `containermanager` | `containermanager_parser.rs` |
| 8 | `crashlogs` | `crashlogs_parser.rs` + `crashlogs_ips.rs` |
| 9 | `disks` | `disks_parser.rs` |
| 10 | `interactionc` | `interactionc_parser.rs` |
| 11 | `ioacpiplane` | `ioacpiplane_parser.rs` |
| 12 | `iodevicetree` | `iodevicetree_parser.rs` |
| 13 | `iofirewire` | `iofirewire_parser.rs` |
| 14 | `iopower` | `iopower_parser.rs` |
| 15 | `ioservice` | `ioservice_parser.rs` |
| 16 | `iousb` | `iousb_parser.rs` |
| 17 | `itunesstore` | `itunesstore_parser.rs` |
| 18 | `kbdebug` | `kbdebug_parser.rs` |
| 19 | `knowledgec` | `knowledgec_parser.rs` |
| 20 | `lockdownd` | `lockdownd_parser.rs` |
| 21 | `logarchive` | `logarchive_parser.rs` (+ `logarchive_decode.rs`) |
| 22 | `logdata_statistics` | `logdata_statistics_parser.rs` |
| 23 | `logdata_statistics_txt` | `logdata_statistics_txt_parser.rs` |
| 24 | `mcsettingsevents` | `mcsettingsevents_parser.rs` |
| 25 | `mcstate_shared_profile` | `mcstate_shared_profile_parser.rs` |
| 26 | `mobileactivation` | `mobileactivation_parser.rs` |
| 27 | `mobilebackup` | `mobilebackup_parser.rs` |
| 28 | `mobileinstallation` | `mobileinstallation_parser.rs` |
| 29 | `networkextension` | `networkextension_parser.rs` |
| 30 | `networkextensioncache` | `networkextensioncache_parser.rs` |
| 31 | `netusage` | `netusage_parser.rs` |
| 32 | `olddsc` | `olddsc_parser.rs` |
| 33 | `plists` | `plists_parser.rs` |
| 34 | `powerlogs` | `powerlogs_parser.rs` |
| 35 | `ps` | `ps_parser.rs` |
| 36 | `psthread` | `psthread_parser.rs` |
| 37 | `quarantine_events` | `quarantine_events_parser.rs` |
| 38 | `remotectl_dumpstate` | `remotectl_dumpstate_parser.rs` |
| 39 | `safari_history` | `safari_history_parser.rs` |
| 40 | `screentime` | `screentime_parser.rs` |
| 41 | `security_sysdiagnose` | `security_sysdiagnose_parser.rs` |
| 42 | `shutdownlogs` | `shutdownlogs_parser.rs` |
| 43 | `spindumpnosymbols` | `spindumpnosymbols_parser.rs` |
| 44 | `swcutil` | `swcutil_parser.rs` |
| 45 | `sys` | `sys_parser.rs` |
| 46 | `taskinfo` | `taskinfo_parser.rs` |
| 47 | `transparency` | `transparency_parser.rs` |
| 48 | `transparency_json` | `transparency_json_parser.rs` |
| 49 | `uuid2path` | `uuid2path_parser.rs` |
| 50 | `wifi_known_networks` | `wifi_known_networks_parser.rs` |
| 51 | `wifinetworks` | `wifinetworks_parser.rs` |
| 52 | `wifiscan` | `wifiscan_parser.rs` |
| 53 | `wifisecurity` | `wifisecurity_parser.rs` |

---
*Upstream baseline: 46 SAF Python parsers + 7 Rust extensions (`apollo_all` catch-all, `safari_history`, `knowledgec`, `netusage`, `interactionc`, `quarantine_events`, `screentime`).*
