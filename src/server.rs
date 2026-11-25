//! OpenAI-compatible HTTP gateway.

use crate::audit::{AuditEvent, AuditLog, sha256_hex};
use crate::detect::Kind;
use crate::engine::{Decision, Direction, Guard, Inspection};
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const FORWARDED_HEADERS: [&str; 3] = ["authorization", "openai-organization", "openai-project"];

pub struct AppState {
    pub guard: Guard,
    pub client: reqwest::Client,
    pub upstream: String,
    pub audit: Option<AuditLog>,
}

pub fn router(state: Arc<AppState>) -> Router {
    let limit = state.guard.policy().max_body_bytes;
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/scan", post(scan))
        .route("/v1/chat/completions", post(chat_completions))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

#[derive(Deserialize)]
struct ScanRequest {
    text: String,
}

async fn scan(State(st): State<Arc<AppState>>, Json(req): Json<ScanRequest>) -> Json<Inspection> {
    Json(st.guard.inspect(&req.text, Direction::Request))
}

/// Calls `f` on every text fragment of an OpenAI message `content` (string or content-part array).
fn for_each_text(content: Option<&mut Value>, f: &mut impl FnMut(&mut String)) {
    match content {
        Some(Value::String(s)) => f(s),
        Some(Value::Array(parts)) => {
            for part in parts {
                if part.get("type").and_then(Value::as_str) == Some("text")
                    && let Some(Value::String(s)) = part.get_mut("text")
                {
                    f(s);
                }
            }
        }
        _ => {}
    }
}

#[derive(Default)]
struct Summary {
    findings: BTreeMap<Kind, usize>,
    injection_score: f32,
    injection_rules: Vec<&'static str>,
    block_reason: Option<String>,
    redacted: bool,
    response_redactions: usize,
}

impl Summary {
    fn absorb(&mut self, ins: &Inspection) {
        for f in &ins.findings {
            *self.findings.entry(f.kind).or_default() += 1;
        }
        if ins.injection.score > self.injection_score {
            self.injection_score = ins.injection.score;
            self.injection_rules = ins.injection.rules.clone();
        }
        match &ins.decision {
            Decision::Block { reason } if self.block_reason.is_none() => {
                self.block_reason = Some(reason.clone())
            }
            Decision::Redact => self.redacted = true,
            _ => {}
        }
    }

    fn decision(&self) -> &'static str {
        match (&self.block_reason, self.redacted) {
            (Some(_), _) => "block",
            (None, true) => "redact",
            _ => "allow",
        }
    }
}

fn error(status: StatusCode, kind: &str, message: &str) -> Response {
    let body = json!({ "error": { "message": message, "type": kind, "code": kind } });
    (status, Json(body)).into_response()
}

fn next_request_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!("{:x}-{}", now_ms(), COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

fn redact_response(guard: &Guard, body: &Bytes, summary: &mut Summary) -> Option<Bytes> {
    let mut value: Value = serde_json::from_slice(body).ok()?;
    let choices = value.get_mut("choices")?.as_array_mut()?;
    for choice in choices {
        let content = choice.get_mut("message").and_then(|m| m.get_mut("content"));
        for_each_text(content, &mut |text| {
            if let Some(r) = guard.inspect(text, Direction::Response).redacted {
                summary.response_redactions += 1;
                *text = r;
            }
        });
    }
    (summary.response_redactions > 0).then(|| Bytes::from(value.to_string()))
}

async fn chat_completions(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let request_id = next_request_id();
    let mut summary = Summary::default();
    let mut upstream_status = None;

    let response = 'handle: {
        let mut payload: Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                break 'handle error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    &format!("invalid JSON body: {e}"),
                );
            }
        };
        if let Some(messages) = payload.get_mut("messages").and_then(Value::as_array_mut) {
            for message in messages {
                for_each_text(message.get_mut("content"), &mut |text| {
                    let ins = st.guard.inspect(text, Direction::Request);
                    summary.absorb(&ins);
                    if let Some(r) = ins.redacted {
                        *text = r;
                    }
                });
            }
        }
        if let Some(reason) = &summary.block_reason {
            break 'handle error(StatusCode::FORBIDDEN, "policy_violation", reason);
        }

        let streaming = payload.get("stream").and_then(Value::as_bool) == Some(true);
        let url = format!("{}/v1/chat/completions", st.upstream.trim_end_matches('/'));
        let mut req = st.client.post(url).json(&payload);
        for name in FORWARDED_HEADERS {
            if let Some(v) = headers.get(name) {
                req = req.header(name, v);
            }
        }
        let upstream = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                break 'handle error(StatusCode::BAD_GATEWAY, "upstream_error", &e.to_string());
            }
        };
        let status = upstream.status();
        upstream_status = Some(status.as_u16());
        let content_type = upstream
            .headers()
            .get(header::CONTENT_TYPE)
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_static("application/json"));

        let mut resp = if streaming {
            Response::new(Body::from_stream(upstream.bytes_stream()))
        } else {
            let bytes = match upstream.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    break 'handle error(StatusCode::BAD_GATEWAY, "upstream_error", &e.to_string());
                }
            };
            let bytes = if st.guard.policy().scan_responses && status.is_success() {
                redact_response(&st.guard, &bytes, &mut summary).unwrap_or(bytes)
            } else {
                bytes
            };
            Response::new(Body::from(bytes))
        };
        *resp.status_mut() = status;
        resp.headers_mut()
            .insert(header::CONTENT_TYPE, content_type);
        resp
    };

    if let Some(audit) = &st.audit {
        audit.record(&AuditEvent {
            ts_ms: now_ms(),
            request_id: request_id.clone(),
            route: "/v1/chat/completions",
            decision: summary.decision(),
            reason: summary.block_reason.clone(),
            findings: summary.findings.clone(),
            response_redactions: summary.response_redactions,
            injection_score: summary.injection_score,
            injection_rules: summary.injection_rules.clone(),
            prompt_sha256: sha256_hex(&body),
            upstream_status,
            latency_us: started.elapsed().as_micros(),
        });
    }

    let mut response = response;
    let h = response.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        h.insert("x-request-id", v);
    }
    h.insert(
        "x-llmfence-decision",
        HeaderValue::from_static(summary.decision()),
    );
    response
}
