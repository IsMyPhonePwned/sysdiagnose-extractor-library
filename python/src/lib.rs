//! Python module `sysdiagnose_extractor`.

use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::{json, Map, Value};
use sysdiagnose_extractor_library::{
    all_parser_types, parser_for, run_parsers_concurrently, SysdiagnoseArchive,
};

fn to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    let text = serde_json::to_string(value).map_err(|err| PyValueError::new_err(err.to_string()))?;
    Ok(py.import("json")?.call_method1("loads", (text,))?.unbind())
}

/// Parser ids and descriptions.
#[pyfunction]
fn list_parsers(py: Python<'_>) -> PyResult<Py<PyAny>> {
    let items: Vec<Value> = all_parser_types()
        .into_iter()
        .map(|kind| json!({"name": kind.as_str(), "description": kind.description()}))
        .collect();
    to_py(py, &Value::Array(items))
}

/// Parse a sysdiagnose archive. Omit `parsers` to run all of them.
#[pyfunction]
#[pyo3(signature = (path, parsers=None))]
fn parse(py: Python<'_>, path: &str, parsers: Option<Vec<String>>) -> PyResult<Py<PyAny>> {
    let selected = match parsers {
        Some(names) if !names.is_empty() => names
            .iter()
            .map(|name| {
                name.parse().map_err(|err: String| {
                    PyValueError::new_err(format!("unknown sysdiagnose parser: {err}"))
                })
            })
            .collect::<PyResult<Vec<_>>>()?,
        _ => all_parser_types(),
    };
    let archive = Arc::new(
        SysdiagnoseArchive::open_path(path).map_err(|err| PyValueError::new_err(err.to_string()))?,
    );
    let jobs = selected.into_iter().map(|kind| (kind, parser_for(kind))).collect();
    let mut out = Map::new();
    for (kind, result, duration) in run_parsers_concurrently(archive, jobs) {
        let entry = match result {
            Ok(data) => {
                json!({"ok": true, "ms": duration.as_secs_f64() * 1000.0, "data": data.as_ref()})
            }
            Err(err) => {
                json!({"ok": false, "ms": duration.as_secs_f64() * 1000.0, "error": err.to_string()})
            }
        };
        out.insert(kind.as_str().to_string(), entry);
    }
    to_py(py, &Value::Object(out))
}

#[pymodule]
fn sysdiagnose_extractor(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(list_parsers, m)?)?;
    m.add_function(wrap_pyfunction!(parse, m)?)?;
    Ok(())
}
