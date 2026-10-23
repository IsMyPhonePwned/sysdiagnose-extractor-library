<p align="center">
  <img src="docs/logo.png" alt="sysdiagnose Extractor Library" width="420">
</p>

# sysdiagnose-extractor-library

Rust library and CLI (`sdx-cli`) to parse Apple **sysdiagnose** archives (`.tar.gz` / `.tar.xz` / `.tar`) into structured JSON.

Based on the Python [Sysdiagnose Analysis Framework (SAF)](https://github.com/EC-DIGIT-CSIRC/sysdiagnose) by EC-DIGIT-CSIRC: same parser/analyser IDs and similar output shapes, load-once / parse-in-parallel workflow (like [bugreport-extractor-library](https://github.com/ping2A/bugreport-extractor-library)).

**License:** [EUPL-1.2](LICENSE) (same as SAF). See [NOTICE](NOTICE).

## Build

```bash
cargo build --release --bin sdx-cli
# optional: RUSTFLAGS="-C target-cpu=native" cargo build --release --bin sdx-cli
```

Requires Rust 1.70+.

## CLI

```bash
BIN=./target/release/sdx-cli

$BIN list-parsers
$BIN list-analysers

# Parse (timings on stdout; JSON only if you ask)
$BIN parse -i sysdiagnose.tar.gz -o out.json
$BIN parse -i sysdiagnose.tar.gz --parser ps --parser crashlogs -o out.json
$BIN parse -i sysdiagnose.tar.gz --analyser summary --analyser apps --pretty
$BIN parse -i sysdiagnose.tar.gz --run-analysers -o out.json

# Sigma Zero rules (native only)
$BIN parse -i sysdiagnose.tar.gz --rules-dir testdata/sigma-rules \
  --parser ps --parser crashlogs -o out.json
```

**Output:** by default parse JSON is **not** printed to stdout (avoids multi‑MB dumps). Use `-o` / `--output`, or `--show-parser-results`. Analysers alone still print an `=== Analysers ===` section. Logs go to stderr (`--log error`).

**Useful flags**

| Flag | Default / note |
|------|----------------|
| `--parser NAME` | Repeatable; default = all (~67) |
| `--analyser NAME` | Repeatable; or `--run-analysers` for all |
| `--max-entry-mb` | `64` — larger members are skipped |
| `--logarchive-decode-max-lines` | `2500` — raising this slows runs a lot |
| `--ioservice-full-tree` | Off by default (compact preview) |

## Library

```rust
use std::sync::Arc;
use sysdiagnose_extractor_library::{
    all_parser_types, parser_for, run_parsers_concurrently, SysdiagnoseArchive,
};

let arch = Arc::new(SysdiagnoseArchive::open_path("sysdiagnose.tar.gz")?);
let jobs: Vec<_> = all_parser_types()
    .into_iter()
    .map(|t| (t, parser_for(t)))
    .collect();
let results = run_parsers_concurrently(arch, jobs);
// results: Vec<(ParserType, Result<Arc<Value>, _>, Duration)>
```

Reuse one `Arc<SysdiagnoseArchive>` across runs; results are already `Arc<Value>`.

## Device fields

Serial / UDID / OS are not in one place. Prefer:

| Need | Parser | Path |
|------|--------|------|
| Serial, UDID, OS, model | `remotectl_dumpstate` | `data.Device.*` |
| OS / build (plist) | `sys` | `plist.ProductVersion`, `BuildVersion` |
| Linked Apple devices | `transparency_json` | `stateMachine.devices.*` |
| Normalized block | `file_stats` analyser | `device` |

```bash
$BIN parse -i sysdiagnose.tar.gz --parser remotectl_dumpstate -o out.json --pretty
```

## Performance

- Prefer `--parser …` over running all parsers. Avoid running **`apollo_all`** together with `knowledgec` / `powerlogs` / `netusage` / … (duplicate work).
- Cap **`plists`** with `SYSDIAGNOSE_PLISTS_MAX_FILES`; keep **`logarchive`** line limit low; leave **`--ioservice-full-tree`** off.
- For repeated runs: `pigz -dc archive.tar.gz > archive.tar` once, then pass the `.tar` (memory-mapped).
- Skip `--pretty` / `--show-parser-results` on full runs.

Benchmark vs Python SAF: [`scripts/bench_vs_saf.sh`](scripts/bench_vs_saf.sh).

```bash
./scripts/bench_vs_saf.sh -i sysdiagnose.tar.gz --saf-dir /path/to/sysdiagnose --runs 3
```

## Docs & tests

| Doc | Contents |
|-----|----------|
| [`docs/parsed-catalog.md`](docs/parsed-catalog.md) | Full parser / analyser inventory and output shapes |
| [`docs/logarchive.md`](docs/logarchive.md) | Unified-log decode (`logarchive-decode` feature) |
| [`docs/parser-upstream-parity.md`](docs/parser-upstream-parity.md) | Differences vs SAF Python |
| [`testdata/sigma-rules/README.md`](testdata/sigma-rules/README.md) | Example Sigma rules |

```bash
cargo test
cargo test --test sysdiagnose_testdata -- --nocapture   # needs testdata + git lfs
```

Optional testdata:

```bash
git clone https://github.com/EC-DIGIT-CSIRC/sysdiagnose-testdata.git testdata/sysdiagnose-testdata
cd testdata/sysdiagnose-testdata && git checkout 7e64d5ca133837393c0c7cd3193d0d4dcabc5447 && git lfs pull
```
