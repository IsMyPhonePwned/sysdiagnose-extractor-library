# Parser upstream parity (Rust vs SAF Python)

This document lists **Rust parser modules** in this crate that are **not full parity** with upstream [sysdiagnose](https://github.com/EC-DIGIT-CSIRC/sysdiagnose) `src/sysdiagnose/parsers/` — for example where Python uses **Apollo**, **IORegStructParser**, large bespoke `execute()` logic, or where Rust intentionally exposes only a **structured extract** (raw text, SQLite dumps, plist JSON, inventory).

**Convention:** “Incomplete” here means **not the same algorithm or output shape** as upstream’s `execute()` for that module, not that the Rust code is wrong for its stated goal (often: safe, archive-only extraction for hunting).

**Verification:** Fixture smoke tests live in [`tests/parser_parity.rs`](../tests/parser_parity.rs). Full-archive runs use [`tests/sysdiagnose_testdata.rs`](../tests/sysdiagnose_testdata.rs) when `SYSDIAGNOSE_TESTDATA` points at [sysdiagnose-testdata](https://github.com/EC-DIGIT-CSIRC/sysdiagnose-testdata) (pin **`7e64d5ca133837393c0c7cd3193d0d4dcabc5447`**).

**Full catalog of parsed artifacts:** [`parsed-catalog.md`](parsed-catalog.md) (all 53 parsers, 14 analysers, output shapes).

---

## 1. Apollo (`sysdiagnose.utils.apollo`) — **implemented in Rust**

These parsers now run the same bundled **APOLLO module** `.txt` definitions as upstream (`apollo_modules/`), `os_version='yolo'` semantics (every `SQL Query` section), and emit SAF-shaped **`Event`** objects inside [`wrap_jsonl`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/utils/base.py) (`parser`, `format`, `events`). Implementation: `src/parsers/apollo.rs`, data under crate-root **`apollo_modules/`** (vendored from upstream).

| Parser ID | Upstream | Rust today | Residual gaps (if any) |
|-----------|----------|------------|-------------------------|
| **`accessibility_tcc`** | [`accessibility_tcc.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/accessibility_tcc.py) | `parse_apollo_archives(..., "TCC.db")` | Queries that fail on schema drift are skipped (`try`/`continue` like upstream). Row cap 100k/query. |
| **`powerlogs`** | [`powerlogs.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/powerlogs.py) | `parse_apollo_archives(..., "CurrentPowerlog.PLSQL")` | Same; large PLSQL DBs may hit row cap. |
| **`safari_history`** | *(Rust extension)* | `parse_apollo_archives(..., "History.db")` | Not a separate upstream `parsers/*.py` id; uses bundled `apollo_modules/safari_history.txt` (+ related modules on `History.db`). |
| **`knowledgec`** | *(Rust extension)* | `parse_apollo_archives(..., "knowledgeC.db")` | Runs all APOLLO modules whose `DATABASE=knowledgeC.db` (80+ query defs). |
| **`netusage`** | *(Rust extension)* | `parse_apollo_archives(..., "netusage.sqlite")` | `netusage_zprocess`, `netusage_zliveusage`, `netusage_zliverouteperf` modules. |
| **`interactionc`** | *(Rust extension)* | `parse_apollo_archives(..., "interactionC.db")` | Contact interaction `CONTENT URL` / `DOMAIN IDENTIFIER` fields. |
| **`quarantine_events`** | *(Rust extension)* | `parse_apollo_archives(..., "com.apple.LaunchServices.QuarantineEventsV2")` | Download origin / data URLs. |
| **`screentime`** | *(Rust extension)* | `RMAdminStore-Local.sqlite` + `RMAdminStore-Cloud.sqlite` | Screen Time `DOMAIN` / usage modules. |

**Timestamps:** [`parse_apollo_timestamp_value`](../src/parsers/apollo.rs) handles SQLite `DATETIME()` strings, RFC3339, `YYYY-MM-DDTHH:MM:SS`, Unix epoch **integers/floats**, and fuzzy `KEY_TIMESTAMP` column names (`last modified` ↔ `last_modified`). Unit tests: `apollo_timestamp_*` in `apollo.rs`.

**WASM:** `parse_apollo_archives` returns an empty `events` array on `wasm32-unknown-unknown` (no `rusqlite`).

---

## 2. IOService tree — `IORegStructParser` — **implemented in Rust**

Port of upstream [`IORegStructParser`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/utils/ioreg_parsers/structure_parser.py) + [`string_parser.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/utils/string_parser.py): `src/parsers/ioreg/`. Each plane parser returns `{ parser, tree }` (upstream returns the tree object only). Fixture: `testdata/fixtures/ioreg_basic.txt` (from upstream `test_ioreg_struct.py`).

| Parser ID | Upstream | Rust today | Residual gaps (if any) |
|-----------|----------|------------|-------------------------|
| **`ioacpiplane`** | [`ioacpiplane.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/ioacpiplane.py) | `IORegStructParser::parse_bytes` → **`tree`** | Overflow / non-ASCII covered by `testdata/fixtures/ioreg_overflow.txt`, `ioreg_non_ascii.txt` + unit tests. |
| **`iodevicetree`** | [`iodevicetree.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/iodevicetree.py) | same | same |
| **`iofirewire`** | [`iofirewire.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/iofirewire.py) | same | same |
| **`iopower`** | [`iopower.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/iopower.py) | same | same |
| **`ioservice`** | [`ioservice.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/ioservice.py) | **compact** preview by default (`format`, `summary`, `device_properties`, depth-limited `tree`); full `tree` via [`ParseOptions`](../src/parsers/parse_options.rs) / `--ioservice-full-tree` | Intentional size reduction vs upstream full tree |
| **`iousb`** | [`iousb.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/iousb.py) | same | same |

---

## 3. Large text / sectioned parsers (jsonl `events`)

These SAF modules build **`events`** from long text files (section banners, buffers, and colon-separated fields). Rust mirrors the upstream layout; see the table for paths and residual gaps. Plist-backed modules use the same **`wrap_jsonl`** envelope.

| Parser ID | Upstream | Rust today |
|-----------|----------|------------|
| **`security_sysdiagnose`** | [`security_sysdiagnose.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/222c16b426a8ecfa7a4eab50ee7fec77a964bd36/src/sysdiagnose/parsers/security_sysdiagnose.py) | **Implemented** — same sectioned buffer model as upstream; jsonl `events` via `wrap_jsonl` (`src/parsers/parser_events/security_sysdiagnose.rs`). Client attribute regex / edge cases may still differ slightly from CPython. |
| **`spindumpnosymbols`** | [`spindumpnosymbols.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/222c16b426a8ecfa7a4eab50ee7fec77a964bd36/src/sysdiagnose/parsers/spindumpnosymbols.py) | **Implemented** — same header / `processes_raw` state machine as upstream; jsonl via `wrap_jsonl` (`src/parsers/parser_events/spindumpnosymbols.rs`). |
| **`swcutil`** | [`swcutil.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/swcutil.py) | **Implemented** — DATABASE / NETWORK / SETTINGS / MEMORY banners; jsonl via `wrap_jsonl` (`src/parsers/parser_events/swcutil.rs`). |
| **`wifi_known_networks`** | [`wifi_known_networks.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/wifi_known_networks.py) | **Implemented** — `events` + plist map under **`files`** (`parser_events/wifi_known_networks.rs`). |
| **`wifinetworks`** | [`wifinetworks.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/wifinetworks.py) | **Implemented** — basename-keyed **`files`** (like upstream), plus **`events`** (`parser_events/wifinetworks.rs`). |

---

## 4. Plist load as JSON — no extra SAF semantics / timeline

| Parser ID | Upstream | Rust today | Notes |
|-----------|----------|------------|--------|
| **`networkextension`** | [`networkextension.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/networkextension.py) | `plist_map_patterns` | Plist → JSON only (matches upstream `execute()`). |
| **`networkextensioncache`** | [`networkextensioncache.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/networkextensioncache.py) | `plist_map_patterns` | same |
| **`uuid2path`** | [`uuid2path.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/uuid2path.py) | `plist_map_patterns` | same |

---

## 5. SQLite dump without Apollo — **implemented in Rust**

| Parser ID | Upstream | Rust today | Residual gaps (if any) |
|-----------|----------|------------|-------------------------|
| **`itunesstore`** | [`itunesstore.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/itunesstore.py) | First `downloads.*.sqlitedb` → **`{ parser, source_path, data }`** where **`data`** is table name → row arrays (upstream `sqlite2struct` shape; blobs as `b'…'`). | WASM / very large DB row caps may differ from CPython on edge types. |

Parity smoke: [`tests/parser_parity.rs`](../tests/parser_parity.rs) `parity_itunesstore_data_shape`.

---

## 6. Inventory / bundle / caps

| Parser ID | Upstream | Rust today | Residual gaps (if any) |
|-----------|----------|------------|-------------------------|
| **`brctl`** | [`brctl.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/brctl.py) | **Implemented** — `parse_brctl_folder` → **`data`** (`parser_events/brctl.rs`); upstream `header` is a JSON string in Python, Rust uses an object. | — |
| **`logarchive`** | [`logarchive.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/logarchive.py) | **Capped `inventory`**; **`decode`** + top-level **`events`** via in-process [**macos-unifiedlogs**](https://github.com/mandiant/macos-UnifiedLogs) (default `logarchive-decode`) | Incomplete logarchive when large members skipped by `--max-entry-mb`; line cap via env. |
| **`plists`** | [`plists.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/plists.py) | **`**/*.plist`** sorted; per-file parse failure → `{}` + path in **`meta.parse_failures`**; caps via env **`SYSDIAGNOSE_PLISTS_MAX_FILES`** (default 600, `0` = unlimited) and **`SYSDIAGNOSE_PLISTS_MAX_EACH_BYTES`** (default 4 MiB, `0` = unlimited). Output: `{ parser, files, meta }`. | None for scope / error policy vs upstream `plists.py`. |

---

## 7. Structured extract — **remotectl implemented**

| Parser ID | Upstream | Rust today | Residual gaps (if any) |
|-----------|----------|------------|-------------------------|
| **`remotectl_dumpstate`** | [`remotectl_dumpstate.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/remotectl_dumpstate.py) | `remotectl_tab` → tab hierarchy JSON (arrow regex `^(.+?)=>*(.*)$` aligned with Python). Golden fixture: `testdata/fixtures/remotectl_dumpstate_golden.txt`. | Odd tab lines not in fixture may still differ. |

---

## 8. Whole-document JSON — **parity achieved**

| Parser ID | Upstream | Rust today |
|-----------|----------|------------|
| **`transparency_json`** | [`transparency_json.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/transparency_json.py) | `json_whole_first` on `transparency.log` |

Timeline-style output is **`transparency`** (jsonl), not `transparency_json`.

---

## 9. Closer to upstream — `parser_events` audit

These parsers emit **SAF-shaped events** (or `rows` / `entries`) and are **much closer** than raw extracts. Residual edge cases (time zones, malformed lines, schema drift) are documented in **[`docs/parser-events-edge-cases.md`](parser-events-edge-cases.md)**.

**Parsers covered:** `kbdebug`, `lockdownd`, `disks`, `battery_bdc`, `containermanager`, `mobileactivation`, `mobileinstallation`, `transparency`, `mcsettingsevents`, `mcstate_shared_profile`, `appinstallation`, `olddsc`, `mobilebackup`, `logdata_statistics`, `logdata_statistics_txt`, `avconference_callsettings`, `wifiscan`, `wifisecurity`, `wifi_known_networks`, `wifinetworks`, plus **`ps`**, **`psthread`**, **`sys`**, **`taskinfo`**, **`shutdownlogs`**, **`crashlogs`**.

---

## 10. Platform caveat — WASM

Parsers using **`sqlite_map`** / **rusqlite** (**`itunesstore`**, **`appinstallation`**, …) are **not implemented for `wasm32-unknown-unknown`**. **`accessibility_tcc`**, **`powerlogs`**, **`safari_history`**, **`knowledgec`**, **`netusage`**, **`interactionc`**, **`quarantine_events`**, and **`screentime`** use Apollo on native targets only; on WASM they return empty `events`.

---

## Summary count

Open gap buckets: **§4** (plist-only modules — already match upstream scope), **§6** (`logarchive` decode quality / completeness on partial archives), **§9** (residual edge cases per [`parser-events-edge-cases.md`](parser-events-edge-cases.md)), **§10** (WASM). **§1** (Apollo timestamps/columns), **§2**, **§3**, **§5** (`itunesstore`), **§6** (`brctl`, `plists`, `logarchive` inventory), **§7** (`remotectl_dumpstate`), and **§8** are **implemented** for the core algorithms described above.

---

*Last updated from maintainer audit; update this file when parser implementations change.*
