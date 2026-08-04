# `parser_events` edge-case audit (§9)

Parsers that emit SAF-shaped **`events`** (or tabular `rows` / `entries`) are **close** to upstream Python but can differ on time zones, malformed lines, oversized members, and schema drift. This document records **known residuals** and **test coverage** as of the maintainer audit.

**Verification:** unit tests in [`src/parsers/parser_events/tests.rs`](../src/parsers/parser_events/tests.rs); integration smoke in [`tests/parser_parity.rs`](../tests/parser_parity.rs); full archives via [`tests/sysdiagnose_testdata.rs`](../tests/sysdiagnose_testdata.rs).

---

## Shared behaviour

| Topic | Rust behaviour | Upstream / edge notes |
|-------|----------------|----------------------|
| **Bundle time** | [`sysdiagnose_creation()`](../src/parsers/parser_events/common.rs) reads `sysdiagnose.log` `IN_PROGRESS_sysdiagnose_*` stamp, else `archive.acquisition()`, else UTC now | Matches SAF `BaseInterface.sysdiagnose_creation_datetime` intent |
| **`wrap_jsonl`** | `{ parser, format: "jsonl", events[] }` with `datetime`, `message`, `timestamp_desc`, `module`, `data` | Same envelope as SAF `Event.to_dict` + jsonl wrapper |
| **Oversized UTF-8** | [`MAX_UTF8_FILE`](../src/parsers/mod.rs) — members above limit skipped in `matching_utf8_files` | SAF reads from disk without the same in-memory cap |
| **Missing files** | Parser-specific `error` / empty `events` / `note` fields | Generally aligned; exact strings may differ |

---

## Per-parser audit

| Parser | Module | Known edge cases | Tests |
|--------|--------|------------------|-------|
| **`accessibility_tcc`** | `apollo.rs` | Schema mismatch → query skipped; row cap 100k; timestamp via [`parse_apollo_timestamp_value`](../src/parsers/apollo.rs) (Unix int, SQLite `DATETIME`, ISO strings); fuzzy `KEY_TIMESTAMP` column match | `apollo_tcc_minimal_db_emits_event`, timestamp unit tests |
| **`powerlogs`** | `apollo.rs` | Same as TCC; `ADJUSTED_TIMESTAMP` from nested SQL; large PLSQL DBs | Apollo registry presence |
| **`appinstallation`** | `parser_events/appinstall.rs` | SQLite table shape drift; empty DB → no events | `appinstallation_events_from_tables` in tests.rs |
| **`avconference_callsettings`** | `parser_events/avconf.rs` | Gzip decode failure → skip file; multiline calldump text | `parse_avconference_gzip` |
| **`battery_bdc`** | `parser_events/battery.rs` | CSV header variants; empty CSV | `parse_battery_bdc_csv` |
| **`containermanager`** | `parser_events/multiline.rs` | Rotated logs (`containermanagerd.log.0`); partial lines | `extract_multiline_log` |
| **`disks`** | `parser_events/disks.rs` | `df` column spacing; missing `disks.txt` | `parse_disks_txt` |
| **`kbdebug`** | `parser_events/kbdebug.rs` | Single-file text; no section model | `parse_kbdebug_log` |
| **`lockdownd`** | `parser_events/lockdownd.rs` | Multi-file glob; timestamp regex on log lines | `extract_lockdownd` |
| **`logdata_statistics`** | `parser_events/logdata.rs` | JSONL per line; bad line → `parse_error` object in array | `parse_logdata_statistics_jsonl` |
| **`logdata_statistics_txt`** | `parser_events/logdata.rs` | Plain-text blocks; bundle time fallback | `parse_logdata_statistics_txt` |
| **`mcsettingsevents`** | `parser_events/plistish.rs` | Plist array → events; empty plist | `mc_settings_events` |
| **`mcstate_shared_profile`** | `parser_events/plistish.rs` | Stub text previews | `mcstate_shared_profile_events` |
| **`mobileactivation`** | `parser_events/multiline.rs` | Log rotation glob | multiline helper |
| **`mobilebackup`** | `parser_events/plistish.rs` | Installed-apps array keys | `mobilebackup_events` |
| **`mobileinstallation`** | `parser_events/multiline.rs` | Installation log sections | multiline helper |
| **`olddsc`** | `parser_events/plistish.rs` | Path inventory + UUID strings (not device serial) | `olddsc_events` |
| **`security_sysdiagnose`** | `parser_events/security_sysdiagnose.rs` | Section buffers; tab-continued lines; client attribute regex | dedicated tests in module |
| **`spindumpnosymbols`** | `parser_events/spindumpnosymbols.rs` | Header KV; `processes_raw` state machine | fixture + module tests |
| **`swcutil`** | `parser_events/swcutil.rs` | DATABASE / NETWORK / SETTINGS / MEMORY banners | module tests |
| **`transparency`** | `parser_events/transparency` via tests | JSONL lines → events; does **not** expand `stateMachine.devices` (use `transparency_json`) | `transparency_extract_events` |
| **`wifiscan`** | `parser_events/wifiscan.rs` | Scan text format per iOS version | `parse_wifi_scan` |
| **`wifisecurity`** | `parser_events/wifisecurity.rs` | Missing `security.txt` → error object | `parse_wifi_security` |
| **`wifi_known_networks`** | `parser_events/wifi_known_networks.rs` | BSS without lat/lon skipped; plist retained in `files` | parser_parity + parser tests |
| **`wifinetworks`** | `parser_events/wifinetworks.rs` | Basename keys; recent-networks JSON | parser_parity |

## Dedicated parsers (not under `parser_events/`)

| Parser | Edge cases | Tests |
|--------|------------|-------|
| **`ps`** | `ps.txt` column alignment; empty file | analyser / sigma examples |
| **`psthread`** | Uses root `entries` not `rows` | parser tests |
| **`sys`** | SystemVersion plist fallbacks | sys_parser tests |
| **`taskinfo`** | Process blocks; `acquisition_rfc3339` on output | taskinfo_parser tests |
| **`shutdownlogs`** | Block state machine; SIGTERM line time | shutdownlogs + timesketch test |
| **`crashlogs`** | `.ips` JSON header + raw body; summary log as text | sigma example `03_crashlogs_ips`; structured `data.threads` / `data.frames` via `crashlogs_ips.rs` |

---

## Intentional non-goals (§9)

- **Byte-identical messages** vs CPython on every log line (whitespace, float formatting).
- **Commented-out SAF code paths** in upstream Python that were never enabled in production parsers.
- **libmagic** MIME typing (see `file_stats` analyser `saf_comparison`).

---

*Update this file when adding fixtures or closing a listed gap.*
