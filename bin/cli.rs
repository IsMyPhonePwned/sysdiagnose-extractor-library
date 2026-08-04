//! CLI for SAF-aligned parsers (`sysdiag parse` spirit) and analyser listing.

use clap::{Parser, Subcommand};
#[cfg(not(target_arch = "wasm32"))]
use sigma_zero::engine::SigmaEngine;
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::error::Error;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use tracing_subscriber::EnvFilter;

use sysdiagnose_extractor_library::analysers::{all_analyser_types, analyser_for, ParsedByParser};
#[cfg(not(target_arch = "wasm32"))]
use sysdiagnose_extractor_library::detection::sigma::{
    self, output_match, output_match_with_log, should_output_match, SigmaStats,
};
use sysdiagnose_extractor_library::{
    all_parser_types, file_loader, parser_for_with_options, run_parsers_concurrently, AnalyserType,
    ArchiveOptions, ParseOptions, ParserType,
};

#[derive(Parser, Debug)]
#[command(name = "sdx-cli")]
#[command(about = "Parse iOS sysdiagnose .tar.gz / .tar.xz archives (Rust port of SAF parsers)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run one or more SAF parsers on an archive (default: all parsers)
    Parse(ParseArgs),
    /// Print SAF parser module names and descriptions (`sysdiag list parsers`)
    ListParsers,
    /// Print SAF analyser names (`sysdiag list analysers`)
    ListAnalysers,
}

#[derive(Parser, Debug)]
struct ParseArgs {
    /// Path to sysdiagnose `.tar.gz`, `.tar.xz`, or `.tar`
    #[arg(short, long)]
    input: PathBuf,

    /// Parser to run (repeatable). Default: all SAF parsers
    #[arg(short, long = "parser")]
    parsers: Vec<String>,

    /// Pretty-print JSON
    #[arg(long)]
    pretty: bool,

    /// Write JSON to this file instead of stdout
    #[arg(short, long)]
    output: Option<PathBuf>,

    #[arg(long, default_value = "warn")]
    log: String,

    /// Max uncompressed size per tar member in megabytes
    #[arg(long, default_value_t = 64)]
    max_entry_mb: u64,

    /// Run all built-in analysers (uses parser JSON from this run; may re-parse missing inputs)
    #[arg(long)]
    run_analysers: bool,

    /// Analyser to run (repeatable). If set, runs only these (no need for --run-analysers).
    /// With --run-analysers and no --analyser, runs all analysers.
    #[arg(long = "analyser")]
    analysers: Vec<String>,

    /// Directory of Sigma YAML rules ([Sigma Zero](https://github.com/ping2A/sigmazero))
    #[arg(long)]
    rules_dir: Option<PathBuf>,

    /// Skip Sigma evaluation even if --rules-dir is set
    #[arg(long)]
    no_sigma: bool,

    /// Only report Sigma matches at or above this level (low, medium, high, critical)
    #[arg(long)]
    sigma_min_level: Option<String>,

    /// Sigma match output: text, json, or silent (counts only)
    #[arg(long, default_value = "text")]
    sigma_format: String,

    /// Print full matched log fields for each Sigma hit
    #[arg(long)]
    sigma_show_log_details: bool,

    /// Thread count for Sigma / rayon (default: machine CPUs)
    #[arg(long)]
    sigma_workers: Option<usize>,

    /// Print full parse JSON to stdout (like `bel-cli --show-parser-results`).
    /// By default parse JSON is **not** written to stdout; use `-o`/`--output` to save a file, or
    /// this flag to print JSON after the run (keeps Sigma / summary output readable).
    #[arg(long, default_value_t = false)]
    show_parser_results: bool,

    /// Return the full IOService IOReg tree instead of the default compact preview.
    #[arg(long)]
    ioservice_full_tree: bool,

    /// Max unified-log lines to decode from logarchive (default 2500; env SYSDIAGNOSE_LOGARCHIVE_DECODE_MAX_LINES).
    #[arg(long)]
    logarchive_decode_max_lines: Option<usize>,
}

fn resolve_parsers(names: &[String]) -> Result<Vec<ParserType>, String> {
    if names.is_empty() {
        return Ok(all_parser_types());
    }
    names.iter().map(|s| s.parse()).collect()
}

fn resolve_analysers_to_run(args: &ParseArgs) -> Result<Option<Vec<AnalyserType>>, String> {
    if !args.analysers.is_empty() {
        return args
            .analysers
            .iter()
            .map(|s| s.parse())
            .collect::<Result<Vec<_>, _>>()
            .map(Some);
    }
    if args.run_analysers {
        return Ok(Some(all_analyser_types()));
    }
    Ok(None)
}

fn print_parse_json_to_stdout(args: &ParseArgs) -> bool {
    args.output.is_none() && args.show_parser_results
}

#[cfg(not(target_arch = "wasm32"))]
fn print_parser_performance(
    results: &[(
        ParserType,
        Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>>,
        Duration,
    )],
) {
    println!("\n=== Parser performance ===");
    let mut sorted: Vec<_> = results.iter().collect();
    sorted.sort_by_key(|r| std::cmp::Reverse(r.2));
    let mut total = Duration::ZERO;
    for (pt, res, dur) in sorted {
        let status = if res.is_ok() { "ok" } else { "ERR" };
        println!(
            "  [{status}] {:<36} {:>10.2} ms",
            pt.as_str(),
            dur.as_secs_f64() * 1000.0
        );
        total += *dur;
    }
    println!(
        "  {:>38} {:>10.2} ms\n",
        "Total (wall-sum):",
        total.as_secs_f64() * 1000.0
    );
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::ListParsers => {
            let mut rows: Vec<_> = all_parser_types()
                .into_iter()
                .map(|p| (p.as_str(), p.description()))
                .collect();
            rows.sort_by_key(|(a, _)| *a);
            for (name, desc) in rows {
                println!("{name}\t{desc}");
            }
        }
        Commands::ListAnalysers => {
            let mut rows: Vec<_> = all_analyser_types()
                .into_iter()
                .map(|a| (a.as_str(), a.description()))
                .collect();
            rows.sort_by_key(|(a, _)| *a);
            for (name, desc) in rows {
                println!("{name}\t{desc}");
            }
        }
        Commands::Parse(args) => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(
                    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log)),
                )
                .try_init();

            let types = resolve_parsers(&args.parsers)?;
            let opts = ArchiveOptions {
                max_entry_bytes: args.max_entry_mb.saturating_mul(1024 * 1024),
                ..ArchiveOptions::default()
            };
            let archive = file_loader::load_sysdiagnose_file_with_options(&args.input, opts)?;
            let parse_options = ParseOptions {
                ioservice_full_tree: args.ioservice_full_tree,
                logarchive_decode_max_lines: args
                    .logarchive_decode_max_lines
                    .unwrap_or_else(|| ParseOptions::default().logarchive_decode_max_lines),
                ..Default::default()
            };
            let parsers: Vec<_> = types
                .into_iter()
                .map(|t| (t, parser_for_with_options(t, parse_options.clone())))
                .collect();

            let results = run_parsers_concurrently(Arc::clone(&archive), parsers);

            let mut out = serde_json::Map::new();
            let mut parsed_by_parser: ParsedByParser = HashMap::new();
            for (pt, res, dur) in &results {
                let key = pt.as_str().to_string();
                let duration_ms = dur.as_secs_f64() * 1000.0;
                match res {
                    Ok(v) => {
                        parsed_by_parser.insert(key.clone(), v.clone());
                        let mut obj = serde_json::Map::new();
                        obj.insert("ok".to_string(), serde_json::json!(true));
                        obj.insert("duration_ms".to_string(), serde_json::json!(duration_ms));
                        obj.insert("data".to_string(), v.clone());
                        out.insert(key, serde_json::Value::Object(obj));
                    }
                    Err(e) => {
                        let err_msg: String = e.to_string();
                        out.insert(
                            key,
                            serde_json::json!({
                                "ok": false,
                                "duration_ms": duration_ms,
                                "error": err_msg
                            }),
                        );
                    }
                }
            }

            if let Some(analyser_list) = resolve_analysers_to_run(&args)? {
                let mut an = serde_json::Map::new();
                for a in analyser_list {
                    match analyser_for(a).analyse(archive.as_ref(), &parsed_by_parser) {
                        Ok(v) => {
                            an.insert(a.as_str().to_string(), v);
                        }
                        Err(e) => {
                            let err_msg: String = e.to_string();
                            an.insert(
                                a.as_str().to_string(),
                                serde_json::json!({ "error": err_msg }),
                            );
                        }
                    }
                }
                out.insert("_analysers".to_string(), serde_json::Value::Object(an));
            }

            #[cfg(not(target_arch = "wasm32"))]
            print_parser_performance(&results);

            #[cfg(not(target_arch = "wasm32"))]
            if let Some(rules_dir) = &args.rules_dir {
                if !args.no_sigma {
                    println!("=== Sigma rule evaluation ===\n");
                    println!("Loading rules from {} …", rules_dir.display());

                    let mut engine = SigmaEngine::new(args.sigma_workers);
                    let n = engine
                        .load_rules(rules_dir)
                        .map_err(|e| -> Box<dyn Error + Send + Sync> { e.into() })?;
                    tracing::info!(rules = n, path = %rules_dir.display(), "Loaded Sigma rules");
                    println!("Loaded {n} rule(s).\n");

                    let results_for_sigma: Vec<_> = results
                        .iter()
                        .map(|(pt, res, dur)| {
                            let r = match res {
                                Ok(v) => Ok(v.clone()),
                                Err(e) => Err(Box::new(std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    e.to_string(),
                                ))
                                    as Box<dyn Error + Send + Sync>),
                            };
                            (*pt, r, *dur)
                        })
                        .collect();

                    let all_entries = sigma::extract_all_log_entries(&results_for_sigma);
                    let mut stats = SigmaStats::new();
                    stats.total_logs_evaluated =
                        all_entries.iter().map(|(_, entries)| entries.len()).sum();

                    for (pt, log_entries) in all_entries {
                        for log_entry in log_entries {
                            let matches = engine.evaluate_log_entry(&log_entry);
                            for rule_match in matches {
                                if should_output_match(&rule_match, &args.sigma_min_level) {
                                    if args.sigma_show_log_details {
                                        output_match_with_log(
                                            &rule_match,
                                            &log_entry,
                                            &args.sigma_format,
                                        );
                                    } else {
                                        output_match(&rule_match, &args.sigma_format);
                                    }
                                    stats.record_match(&rule_match, pt.as_str());
                                }
                            }
                        }
                    }

                    if args.sigma_format != "silent" {
                        stats.print_summary();
                    } else {
                        println!("Sigma matches: {}\n", stats.total_matches);
                    }
                }
            }
            #[cfg(target_arch = "wasm32")]
            if args.rules_dir.is_some() && !args.no_sigma {
                tracing::warn!(
                    "sdx-cli: --rules-dir is ignored on wasm32 (Sigma rule loading requires a native build)"
                );
            }

            let root = serde_json::Value::Object(out);
            match &args.output {
                Some(path) => {
                    let f = std::fs::File::create(path)?;
                    let mut w = BufWriter::new(f);
                    if args.pretty {
                        serde_json::to_writer_pretty(&mut w, &root)?;
                    } else {
                        serde_json::to_writer(&mut w, &root)?;
                    }
                    writeln!(w)?;
                }
                None => {
                    if print_parse_json_to_stdout(&args) {
                        if args.pretty {
                            serde_json::to_writer_pretty(io::stdout(), &root)?;
                        } else {
                            serde_json::to_writer(io::stdout(), &root)?;
                        }
                        println!();
                    } else if let Some(analysers) = root.get("_analysers") {
                        println!("\n=== Analysers ===\n");
                        if args.pretty {
                            serde_json::to_writer_pretty(io::stdout(), analysers)?;
                        } else {
                            serde_json::to_writer(io::stdout(), analysers)?;
                        }
                        println!();
                    } else {
                        eprintln!(
                            "Parse JSON not written to stdout. \
                             Use -o/--output FILE to save it, or --show-parser-results to print here."
                        );
                    }
                }
            }
        }
    }

    Ok(())
}
