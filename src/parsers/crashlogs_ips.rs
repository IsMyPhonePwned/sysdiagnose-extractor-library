//! Normalize Apple `.ips` crash reports into structured `threads` / `frames` on parser `data`.

use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

const MAX_THREADS: usize = 64;
const MAX_FRAMES_PER_THREAD: usize = 128;
const MAX_USED_IMAGES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpsFormat {
    TwoPartJson,
    SingleJson,
    LegacyText,
    Unknown,
}

impl IpsFormat {
    fn as_str(self) -> &'static str {
        match self {
            IpsFormat::TwoPartJson => "two_part_json",
            IpsFormat::SingleJson => "single_json",
            IpsFormat::LegacyText => "legacy_text",
            IpsFormat::Unknown => "unknown",
        }
    }
}

/// Merge first-line JSON header with body text; add `threads`, `frames`, and related fields.
pub fn enrich_ips_report(header: Value, body: &str) -> Value {
    let body = body.trim();
    let mut data = header.as_object().cloned().unwrap_or_default();

    if !body.is_empty() {
        data.insert("report_raw".into(), json!(body));
    }

    let mut format = IpsFormat::Unknown;
    let mut payload: Option<Value> = None;

    if !body.is_empty() {
        if let Ok(v) = serde_json::from_str::<Value>(body) {
            format = IpsFormat::TwoPartJson;
            payload = Some(v);
        }
    }

    if payload.is_none() {
        if data.contains_key("threads") || data.contains_key("usedImages") {
            format = IpsFormat::SingleJson;
            payload = Some(Value::Object(data.clone()));
        }
    }

    if let Some(p) = payload {
        apply_structured_payload(&mut data, &p, format);
    } else if !body.is_empty() {
        if let Some(legacy) = parse_legacy_text_threads(body) {
            format = IpsFormat::LegacyText;
            data.insert("threads".into(), legacy.threads);
            if let Some(ft) = legacy.faulting_thread {
                data.insert("faulting_thread".into(), json!(ft));
            }
            data.insert(
                "crash_structure".into(),
                json!({
                    "threads_total": legacy.threads_total,
                    "threads_truncated": legacy.threads_truncated,
                }),
            );
        }
    }

    data.insert("ips_format".into(), json!(format.as_str()));
    Value::Object(data)
}

struct LegacyParse {
    threads: Value,
    faulting_thread: Option<u64>,
    threads_total: usize,
    threads_truncated: bool,
}

struct StructuredApply {
    threads: Value,
    faulting_thread: Option<u64>,
    exception: Option<Value>,
    termination: Option<Value>,
    used_images: Value,
    last_exception_backtrace: Option<Value>,
    threads_total: usize,
    threads_truncated: bool,
    frames_truncated: bool,
    images_total: usize,
    images_truncated: bool,
}

fn apply_structured_payload(data: &mut Map<String, Value>, payload: &Value, format: IpsFormat) {
    let structured = extract_structured(payload);
    data.insert("ips_format".into(), json!(format.as_str()));
    data.insert("threads".into(), structured.threads);
    if let Some(ft) = structured.faulting_thread {
        data.insert("faulting_thread".into(), json!(ft));
    }
    if let Some(ex) = structured.exception {
        data.insert("exception".into(), ex);
    }
    if let Some(term) = structured.termination {
        data.insert("termination".into(), term);
    }
    data.insert("used_images".into(), structured.used_images);
    if let Some(le) = structured.last_exception_backtrace {
        data.insert("last_exception_backtrace".into(), le);
    }
    data.insert(
        "crash_structure".into(),
        json!({
            "threads_total": structured.threads_total,
            "threads_truncated": structured.threads_truncated,
            "frames_truncated": structured.frames_truncated,
            "images_total": structured.images_total,
            "images_truncated": structured.images_truncated,
        }),
    );
}

fn extract_structured(payload: &Value) -> StructuredApply {
    let images = payload
        .get("usedImages")
        .or_else(|| payload.get("used_images"))
        .and_then(threads_as_array)
        .unwrap_or_default();
    let images_total = images.len();
    let images_truncated = images_total > MAX_USED_IMAGES;
    let used_images = json!(
        images
            .iter()
            .take(MAX_USED_IMAGES)
            .enumerate()
            .map(|(idx, img)| normalize_used_image(idx, img))
            .collect::<Vec<_>>()
    );

    let raw_threads = payload
        .get("threads")
        .and_then(threads_value_to_vec);
    let threads_total = raw_threads.as_ref().map(|t| t.len()).unwrap_or(0);
    let threads_truncated = threads_total > MAX_THREADS;

    let faulting_thread = payload
        .get("faultingThread")
        .or_else(|| payload.get("faulting_thread"))
        .and_then(parse_u64);

    let mut frames_truncated = false;
    let mut out_threads = Vec::new();
    if let Some(raw) = raw_threads {
        for (i, th) in raw.iter().take(MAX_THREADS).enumerate() {
            let (thread, ft) = normalize_thread(th, i, &images, faulting_thread);
            frames_truncated |= ft;
            out_threads.push(thread);
        }
    }

    let last_exception_backtrace = payload
        .get("lastExceptionBacktrace")
        .or_else(|| payload.get("last_exception_backtrace"))
        .map(|v| normalize_backtrace_frames(v, &images));

    StructuredApply {
        threads: json!(out_threads),
        faulting_thread,
        exception: payload.get("exception").cloned(),
        termination: payload.get("termination").cloned(),
        used_images,
        last_exception_backtrace,
        threads_total,
        threads_truncated,
        frames_truncated,
        images_total,
        images_truncated,
    }
}

fn threads_value_to_vec(v: &Value) -> Option<Vec<&Value>> {
    if let Some(a) = v.as_array() {
        return Some(a.iter().collect());
    }
    let obj = v.as_object()?;
    let mut pairs: Vec<(u64, &Value)> = obj
        .iter()
        .filter_map(|(k, val)| k.parse::<u64>().ok().map(|n| (n, val)))
        .collect();
    pairs.sort_by_key(|(n, _)| *n);
    Some(pairs.into_iter().map(|(_, v)| v).collect())
}

fn threads_as_array(v: &Value) -> Option<Vec<&Value>> {
    v.as_array().map(|a| a.iter().collect())
}

fn normalize_used_image(index: usize, img: &Value) -> Value {
    let name = img
        .get("name")
        .or_else(|| img.get("path"))
        .or_else(|| img.get("source"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    json!({
        "index": index,
        "name": name,
        "uuid": img.get("uuid").and_then(|x| x.as_str()).unwrap_or(""),
        "arch": img.get("arch").and_then(|x| x.as_str()).unwrap_or(""),
        "base": format_address(parse_u64_from_value(img.get("base"))),
    })
}

fn normalize_thread(
    th: &Value,
    fallback_id: usize,
    images: &[&Value],
    faulting_thread: Option<u64>,
) -> (Value, bool) {
    let id = th
        .get("id")
        .and_then(parse_u64)
        .unwrap_or(fallback_id as u64);
    let triggered = th
        .get("triggered")
        .and_then(|x| x.as_bool())
        .unwrap_or_else(|| faulting_thread == Some(id));
    let name = th.get("name").and_then(|x| x.as_str()).unwrap_or("");
    let queue = th
        .get("queue")
        .or_else(|| th.get("dispatch_queue"))
        .and_then(|x| x.as_str())
        .unwrap_or("");

    let raw_frames = th
        .get("frames")
        .and_then(threads_as_array)
        .unwrap_or_default();
    let frames_truncated = raw_frames.len() > MAX_FRAMES_PER_THREAD;
    let frames: Vec<Value> = raw_frames
        .iter()
        .take(MAX_FRAMES_PER_THREAD)
        .enumerate()
        .map(|(fi, fr)| normalize_frame(fi, fr, images))
        .collect();

    (
        json!({
            "id": id,
            "triggered": triggered,
            "name": name,
            "queue": queue,
            "frame_count": raw_frames.len(),
            "frames": frames,
        }),
        frames_truncated,
    )
}

fn normalize_backtrace_frames(v: &Value, images: &[&Value]) -> Value {
    let frames = v
        .as_array()
        .map(|a| {
            a.iter()
                .enumerate()
                .map(|(i, fr)| normalize_frame(i, fr, images))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!(frames)
}

fn normalize_frame(index: usize, fr: &Value, images: &[&Value]) -> Value {
    let image_index = fr.get("imageIndex").and_then(parse_u64);
    let image_offset = fr
        .get("imageOffset")
        .or_else(|| fr.get("image_offset"))
        .and_then(parse_u64);
    let symbol = fr
        .get("symbol")
        .or_else(|| fr.get("symbolName"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let symbol_location = fr
        .get("symbolLocation")
        .or_else(|| fr.get("symbol_location"))
        .and_then(parse_u64);

    let image_name = image_index
        .and_then(|idx| images.get(idx as usize))
        .and_then(|img| {
            img.get("name")
                .or_else(|| img.get("source"))
                .and_then(|x| x.as_str())
        })
        .unwrap_or("");

    let address = match (image_index, image_offset) {
        (Some(ii), Some(off)) => images
            .get(ii as usize)
            .and_then(|img| parse_u64_from_value(img.get("base")))
            .map(|base| format_address(Some(base.wrapping_add(off)))),
        _ => fr
            .get("address")
            .or_else(|| fr.get("pc"))
            .and_then(|x| x.as_str().map(str::to_string))
            .or_else(|| parse_u64_from_value(fr.get("address")).map(|a| format_address(Some(a)))),
    };

    json!({
        "index": index,
        "symbol": symbol,
        "symbol_location": symbol_location,
        "image": image_name,
        "image_index": image_index,
        "image_offset": image_offset,
        "address": address.unwrap_or_default(),
    })
}

fn parse_u64(v: &Value) -> Option<u64> {
    parse_u64_from_value(Some(v))
}

fn parse_u64_from_value(v: Option<&Value>) -> Option<u64> {
    let v = v?;
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    if let Some(n) = v.as_i64() {
        return u64::try_from(n).ok();
    }
    let s = v.as_str()?.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    s.parse().ok()
}

fn format_address(addr: Option<u64>) -> String {
    match addr {
        Some(a) => format!("0x{a:x}"),
        None => String::new(),
    }
}

fn legacy_thread_header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^Thread\s+(\d+)(?:\s+(?:name|Name):\s*(.*?))?(?:\s+(?:Crashed|Triggered))?:?\s*$",
        )
        .expect("legacy thread header regex")
    })
}

fn legacy_frame_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^\s*(\d+)\s+([^\s]+)\s+(0x[0-9a-fA-F]+)(?:\s+(0x[0-9a-fA-F]+)\s+\+\s+(\d+))?",
        )
        .expect("legacy frame regex")
    })
}

fn parse_legacy_text_threads(body: &str) -> Option<LegacyParse> {
    let mut threads: Vec<Value> = Vec::new();
    let mut current: Option<Map<String, Value>> = None;
    let mut faulting_thread: Option<u64> = None;

    for line in body.lines() {
        let t = line.trim_end();
        if let Some(cap) = legacy_thread_header_re().captures(t) {
            if let Some(m) = current.take() {
                threads.push(Value::Object(m));
            }
            let id: u64 = cap.get(1)?.as_str().parse().ok()?;
            let name = cap
                .get(2)
                .map(|m| m.as_str().trim())
                .filter(|s| !s.is_empty())
                .unwrap_or("");
            let crashed = t.to_ascii_lowercase().contains("crashed")
                || t.to_ascii_lowercase().contains("triggered");
            if crashed {
                faulting_thread = Some(id);
            }
            let mut m = Map::new();
            m.insert("id".into(), json!(id));
            m.insert("triggered".into(), json!(crashed));
            m.insert("name".into(), json!(name));
            m.insert("queue".into(), json!(""));
            m.insert("frames".into(), json!([]));
            current = Some(m);
            continue;
        }

        if let Some(ref mut m) = current {
            if let Some(cap) = legacy_frame_re().captures(t) {
                let frame_index: u64 = cap.get(1)?.as_str().parse().ok()?;
                let image = cap.get(2)?.as_str();
                let addr = cap.get(3)?.as_str();
                let image_base = cap.get(4).map(|c| c.as_str()).unwrap_or("");
                let offset = cap
                    .get(5)
                    .and_then(|c| c.as_str().parse::<u64>().ok());
                let frame = json!({
                    "index": frame_index,
                    "symbol": "",
                    "image": image,
                    "address": addr,
                    "image_base": image_base,
                    "image_offset": offset,
                });
                if let Some(Value::Array(frames)) = m.get_mut("frames") {
                    if frames.len() < MAX_FRAMES_PER_THREAD {
                        frames.push(frame);
                    }
                }
            }
        }
    }

    if let Some(m) = current.take() {
        threads.push(Value::Object(m));
    }

    if threads.is_empty() {
        return None;
    }

    let threads_total = threads.len();
    let threads_truncated = threads_total > MAX_THREADS;
    for th in &mut threads {
        if let Some(obj) = th.as_object_mut() {
            if let Some(Value::Array(frames)) = obj.get("frames") {
                obj.insert("frame_count".into(), json!(frames.len()));
            }
        }
    }
    threads.truncate(MAX_THREADS);

    Some(LegacyParse {
        threads: json!(threads),
        faulting_thread,
        threads_total,
        threads_truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn two_part_json_extracts_threads_and_images() {
        let header = json!({
            "app_name": "TestApp",
            "captureTime": "2024-01-01T00:00:00Z"
        });
        let body = json!({
            "faultingThread": 0,
            "exception": { "type": "EXC_CRASH", "signal": "SIGABRT" },
            "usedImages": [{
                "name": "TestApp",
                "uuid": "UU1",
                "base": 4294967296_u64
            }],
            "threads": [{
                "id": 0,
                "triggered": true,
                "frames": [{
                    "imageIndex": 0,
                    "imageOffset": 4096,
                    "symbol": "main"
                }]
            }]
        })
        .to_string();

        let data = enrich_ips_report(header, &body);
        assert_eq!(data["ips_format"], "two_part_json");
        assert_eq!(data["faulting_thread"], 0);
        assert_eq!(data["exception"]["type"], "EXC_CRASH");
        let threads = data["threads"].as_array().unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0]["triggered"], true);
        let frames = threads[0]["frames"].as_array().unwrap();
        assert_eq!(frames[0]["symbol"], "main");
        assert_eq!(frames[0]["image"], "TestApp");
        assert!(frames[0]["address"]
            .as_str()
            .unwrap()
            .starts_with("0x"));
    }

    #[test]
    fn single_json_header_with_embedded_threads() {
        let header = json!({
            "captureTime": "2024-06-01",
            "faultingThread": 1,
            "usedImages": [{ "name": "libx", "base": "0x1000" }],
            "threads": [
                { "id": 0, "frames": [{ "imageIndex": 0, "imageOffset": 8, "symbol": "foo" }] },
                { "id": 1, "triggered": true, "frames": [{ "imageIndex": 0, "imageOffset": 16, "symbol": "bar" }] }
            ]
        });
        let data = enrich_ips_report(header, "");
        assert_eq!(data["ips_format"], "single_json");
        assert_eq!(data["threads"].as_array().unwrap().len(), 2);
        assert_eq!(data["faulting_thread"], 1);
    }

    #[test]
    fn legacy_text_parses_thread_stacks() {
        let header = json!({ "procName": "Foo", "captureTime": "2020-01-01" });
        let body = r#"Incident Identifier: ABC
Thread 0 Crashed:
0   FooApp   0x0000000100ab1000 0x100ab0000 + 4096
1   libdyld  0x00000001802a8000 0x1802a0000 + 32768
Thread 1 name: com.apple.NSURLConnectionLoader
0   libnetwork  0x00000001b2c3d000 0x1b2c00000 + 250000
"#;
        let data = enrich_ips_report(header, body);
        assert_eq!(data["ips_format"], "legacy_text");
        assert_eq!(data["faulting_thread"], 0);
        let threads = data["threads"].as_array().unwrap();
        assert_eq!(threads.len(), 2);
        assert_eq!(threads[0]["frames"].as_array().unwrap().len(), 2);
        assert_eq!(threads[0]["frames"][0]["image"], "FooApp");
        assert_eq!(threads[1]["name"], "com.apple.NSURLConnectionLoader");
    }
}
