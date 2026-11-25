//! Append-only JSONL audit log. Raw prompt text is never written, only a SHA-256 digest.

use crate::detect::Kind;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub ts_ms: u128,
    pub request_id: String,
    pub route: &'static str,
    pub decision: &'static str,
    pub reason: Option<String>,
    pub findings: BTreeMap<Kind, usize>,
    pub response_redactions: usize,
    pub injection_score: f32,
    pub injection_rules: Vec<&'static str>,
    pub prompt_sha256: String,
    pub upstream_status: Option<u16>,
    pub latency_us: u128,
}

pub struct AuditLog {
    out: Mutex<BufWriter<File>>,
}

impl AuditLog {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            out: Mutex::new(BufWriter::new(file)),
        })
    }

    pub fn record(&self, event: &AuditEvent) {
        let mut out = self.out.lock().unwrap_or_else(|e| e.into_inner());
        let result = serde_json::to_writer(&mut *out, event)
            .map_err(std::io::Error::from)
            .and_then(|_| out.write_all(b"\n"))
            .and_then(|_| out.flush());
        if let Err(e) = result {
            tracing::error!(error = %e, "failed to write audit event");
        }
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_one_json_line_per_event() {
        let path = std::env::temp_dir().join(format!("audit-{}.jsonl", std::process::id()));
        let log = AuditLog::open(&path).unwrap();
        let event = AuditEvent {
            ts_ms: 1,
            request_id: "r1".into(),
            route: "/v1/chat/completions",
            decision: "redact",
            reason: None,
            findings: BTreeMap::from([(Kind::Email, 2)]),
            response_redactions: 0,
            injection_score: 0.0,
            injection_rules: vec![],
            prompt_sha256: sha256_hex(b"hello"),
            upstream_status: Some(200),
            latency_us: 10,
        };
        log.record(&event);
        log.record(&event);
        let body = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(body.lines().count(), 2);
        assert!(body.contains(r#""email":2"#));
        assert!(!body.contains("hello"));
    }
}
