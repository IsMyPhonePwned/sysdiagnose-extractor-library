# `logarchive` parser — strategy and decode

Upstream SAF [`logarchive.py`](https://github.com/EC-DIGIT-CSIRC/sysdiagnose/blob/main/src/sysdiagnose/parsers/logarchive.py) decodes Apple **unified logs** inside `system_logs.logarchive/`.

This crate uses Mandiant’s pure-Rust **[macos-UnifiedLogs](https://github.com/mandiant/macos-UnifiedLogs)** in-process via the workspace crate [`logarchive-decode/`](../logarchive-decode/) (`sysdiagnose_logarchive_decode`).

## Default output

The [`logarchive`](../src/parsers/logarchive_parser.rs) parser returns:

- **`inventory`**: rollup under `system_logs.logarchive/` — `file_count`, `total_bytes`, `by_subdir`, capped `paths`
- **`decode`**: status string (`deferred`, `skipped`, `success`, …)
- **`decode_meta`**: tool / counts / errors
- **`events`**: when decode succeeds (requires `logarchive-decode` feature)

## Decode (`logarchive-decode` feature)

On by default. Disable with:

```bash
cargo build --no-default-features --features cli
```

Flow ([`logarchive_decode.rs`](../src/parsers/logarchive_decode.rs)):

1. Materialize `system_logs.logarchive/**` to a temp directory
2. Skip if no `tracev3` files (incomplete bundle / `--max-entry-mb` truncation)
3. Decode with **`macos-unifiedlogs`** (`LogarchiveProvider` → `build_log`)
4. Map rows to top-level **`events`** (slim `data` fields)

### Status values

| Value | Meaning |
|-------|---------|
| `deferred` | Feature disabled |
| `skipped` | No logarchive files, or no tracev3 in materialized tree |
| `failed` | Decoder error (`decode_meta.reason`) |
| `success` | Events decoded (`decode_meta.event_count`) |

### Options

| Source | Meaning |
|--------|---------|
| `ParseOptions.logarchive_decode_max_lines` | Library API cap (default 2500) |
| `SYSDIAGNOSE_LOGARCHIVE_DECODE_MAX_LINES` | Env override for default |
| `sdx-cli --logarchive-decode-max-lines N` | CLI override |
| `SYSDIAGNOSE_LOGARCHIVE_INVENTORY_MAX_PATHS` | Inventory path cap (default 100) |

### Integration test

```bash
SYSDIAGNOSE_LOGARCHIVE_FIXTURE=/path/to/foo.logarchive \
  cargo test -p sysdiagnose_logarchive_decode decode_fixture_logarchive_dir -- --ignored
```

## Workspace

```toml
[workspace]
members = [".", "logarchive-decode"]
```

`macos-unifiedlogs` is pinned to git rev `27ff6651` in `logarchive-decode/Cargo.toml`.
