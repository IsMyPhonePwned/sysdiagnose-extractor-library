//! Shrink large IOReg trees (especially `IOService.txt`) for JSON output.

use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

const DEFAULT_MAX_DEPTH: usize = 3;
const DEFAULT_MAX_CHILDREN: usize = 48;
const DEFAULT_MAX_VALUE_CHARS: usize = 256;
const DEFAULT_MAX_INTERESTING: usize = 64;

#[derive(Clone, Copy, Debug)]
pub struct CompactOpts {
    pub max_depth: usize,
    pub max_children: usize,
    pub max_value_chars: usize,
}

pub fn ioservice_compact_opts() -> CompactOpts {
    CompactOpts {
        max_depth: env_usize("SYSDIAGNOSE_IOSERVICE_MAX_DEPTH", DEFAULT_MAX_DEPTH),
        max_children: env_usize("SYSDIAGNOSE_IOSERVICE_MAX_CHILDREN", DEFAULT_MAX_CHILDREN),
        max_value_chars: env_usize(
            "SYSDIAGNOSE_IOSERVICE_MAX_VALUE_CHARS",
            DEFAULT_MAX_VALUE_CHARS,
        ),
    }
}
fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Count nested object keys (nodes) and leaf/scalar entries (properties).
pub fn tree_stats(tree: &Value) -> (usize, usize) {
    let mut nodes = 0usize;
    let mut props = 0usize;
    walk_stats(tree, &mut nodes, &mut props);
    (nodes, props)
}

fn walk_stats(v: &Value, nodes: &mut usize, props: &mut usize) {
    match v {
        Value::Object(m) => {
            *nodes += 1;
            for (_, child) in m {
                if child.is_object() {
                    walk_stats(child, nodes, props);
                } else {
                    *props += 1;
                }
            }
        }
        Value::Array(a) => {
            for item in a {
                walk_stats(item, nodes, props);
            }
        }
        _ => *props += 1,
    }
}

fn key_is_interesting(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.contains("serial")
        || k.contains("uuid")
        || k.contains("udid")
        || k.contains("ecid")
        || k.contains("imei")
        || k.contains("mlb")
        || k.contains("model")
        || k.contains("version")
        || k.contains("board-id")
        || k.contains("product-name")
        || k.contains("product-id")
        || k.contains("chip-id")
        || k.contains("die-id")
        || k.contains("unique")
        || k.contains("capabilities")
}

/// Pull device-identifying / hardware properties from anywhere in the tree.
pub fn extract_interesting_properties(tree: &Value) -> Map<String, Value> {
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    walk_interesting(tree, "", &mut out);
    if out.len() > DEFAULT_MAX_INTERESTING {
        out = out.into_iter().take(DEFAULT_MAX_INTERESTING).collect();
    }
    out.into_iter().collect()
}

fn walk_interesting(v: &Value, path: &str, out: &mut BTreeMap<String, Value>) {
    if out.len() >= DEFAULT_MAX_INTERESTING {
        return;
    }
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                if child.is_object() {
                    walk_interesting(child, &p, out);
                } else if key_is_interesting(k) {
                    out.insert(p, truncate_value(child, DEFAULT_MAX_VALUE_CHARS));
                }
            }
        }
        Value::Array(a) => {
            for (i, item) in a.iter().enumerate() {
                walk_interesting(item, &format!("{path}[{i}]"), out);
            }
        }
        _ => {}
    }
}

fn truncate_value(v: &Value, max_chars: usize) -> Value {
    match v {
        Value::String(s) if s.len() > max_chars => {
            json!(format!("{}…", &s[..max_chars]))
        }
        _ => v.clone(),
    }
}

/// Depth- and fan-out-limited copy of `tree`. Returns `(compact, truncated)`.
pub fn compact_tree(tree: &Value, opts: &CompactOpts) -> (Value, bool) {
    let mut truncated = false;
    let out = compact_value(tree, 0, opts, &mut truncated);
    (out, truncated)
}

fn compact_value(
    v: &Value,
    depth: usize,
    opts: &CompactOpts,
    truncated: &mut bool,
) -> Value {
    match v {
        Value::Object(m) => {
            if depth >= opts.max_depth {
                *truncated = true;
                return json!({
                    "_truncated": true,
                    "_child_count": m.len(),
                });
            }
            let mut out = Map::new();
            for (i, (k, child)) in m.iter().enumerate() {
                if i >= opts.max_children {
                    *truncated = true;
                    out.insert(
                        "_more_children".into(),
                        json!(m.len() - opts.max_children),
                    );
                    break;
                }
                let cv = if child.is_object() {
                    compact_value(child, depth + 1, opts, truncated)
                } else {
                    truncate_value(child, opts.max_value_chars)
                };
                out.insert(k.clone(), cv);
            }
            Value::Object(out)
        }
        Value::Array(a) => {
            let mut out = Vec::new();
            for (i, item) in a.iter().enumerate() {
                if i >= opts.max_children {
                    *truncated = true;
                    break;
                }
                out.push(compact_value(item, depth + 1, opts, truncated));
            }
            Value::Array(out)
        }
        other => truncate_value(other, opts.max_value_chars),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn compact_tree_limits_depth_and_children() {
        let tree = json!({
            "A": {
                "p1": "v1",
                "B": { "p2": "v2", "C": { "deep": "hidden" } }
            },
            "sibling": "x"
        });
        let opts = CompactOpts {
            max_depth: 2,
            max_children: 10,
            max_value_chars: 64,
        };
        let (c, trunc) = compact_tree(&tree, &opts);
        assert!(trunc);
        assert!(c["A"]["B"].get("_truncated").is_some());
    }

    #[test]
    fn extracts_serial_like_properties() {
        let tree = json!({
            "IODeviceTree": {
                "arm-io": {
                    "IOPlatformSerialNumber": "SN123",
                    "other": "noise"
                }
            }
        });
        let props = extract_interesting_properties(&tree);
        assert!(props.keys().any(|k| k.contains("IOPlatformSerialNumber")));
    }
}
