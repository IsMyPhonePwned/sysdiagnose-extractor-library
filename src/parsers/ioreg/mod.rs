//! IORegistry text → structured JSON (upstream `IORegStructParser`).

mod compact;
mod string_parser;
mod structure_parser;

pub use compact::{
    compact_tree, extract_interesting_properties, ioservice_compact_opts, tree_stats,
};
pub use structure_parser::IORegStructParser;
