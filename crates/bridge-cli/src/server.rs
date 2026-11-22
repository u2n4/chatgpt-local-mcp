//! Loopback-only authenticated HTTP API + Streamable HTTP MCP (`/mcp`) + BridgePulse Static UI server.
//! Enforces:
//! - Loopback binding (`127.0.0.1` only)
//! - Exact `Host` header match and strict same-origin `Origin` validation
//! - Two authentication schemes:
//!   1) Bearer / `X-Bridge-Token` (BridgePulse UI & local CLI)
//!   2) Mutual HMAC-SHA256 (`X-Bridge-Principal`, `X-Bridge-Nonce`, `X-Bridge-Timestamp`, `X-Bridge-Signature`)
//!      with nonce replay guard and signed response header matching Python v0.2.0 `broker.py` for apples-to-apples parity!
//! - Modern MCP `2026-07-28` Streamable HTTP endpoint (`POST /mcp`) validating `MCP-Protocol-Version` and rejecting
//!   unsupported `Last-Event-ID` resumption per official spec [S02].

use crate::admission::{Admission, Lane};
use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use bridge_adapters::devices::{DeviceChannel, SignedHostEnvelope};
use bridge_adapters::mcp::{McpAdapterConfig, McpDispatcher};
use bridge_adapters::providers::probe_all_providers;
use bridge_core::state::StateStore;
use bridge_platform::host_resources;
#[cfg(windows)]
use bridge_platform::windows::probe_mxc_backend;
use bridge_types::*;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower_http::services::ServeDir;

type HmacSha256 = Hmac<Sha256>;

pub struct AppState {
    pub store: StateStore,
    pub state_dir: PathBuf,
    pub host_id: HostId,
    environment_kind: Option<String>,
    pub local_token: String,
    pub edge_token: String,
    pub executor_token: String,
    pub bound_host: String,
    pub ui_dist_dir: Option<PathBuf>,
    seen_nonces: [Mutex<ReplayWindow>; 3],
    admission: Admission,
}

#[derive(Default)]
struct ReplayWindow {
    keys: HashSet<String>,
    order: VecDeque<(Instant, String)>,
}

impl ReplayWindow {
    fn accept(&mut self, key: &str, now: Instant) -> Result<(), Option<u64>> {
        // A signature can first arrive up to 30 seconds before its timestamp.
        // Retain its nonce throughout the entire possible validity window.
        while self.order.front().is_some_and(|(expires, _)| *expires <= now) {
            let (_, expired) = self.order.pop_front().expect("front exists");
            self.keys.remove(&expired);
        }
        if self.keys.contains(key) {
            return Err(None);
        }
        if self.keys.len() >= 32_768 {
            return Err(self.order.front().map(|(expires, _)| {
                expires.saturating_duration_since(now).as_millis().max(1) as u64
            }));
        }
        self.keys.insert(key.to_string());
        self.order.push_back((now + Duration::from_secs(61), key.to_string()));
        Ok(())
    }
}

struct HmacProof {
    principal_name: String,
    token_hex: String,
    nonce: String,
    stamp: String,
}

fn ensure_token(state_dir: &PathBuf, filename: &str) -> anyhow::Result<String> {
    let p = state_dir.join(filename);
    if p.is_file() {
        let t = std::fs::read_to_string(&p)?.trim().to_string();
        if t.len() == 64 {
            return Ok(t);
        }
    }
    let tok = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    std::fs::write(&p, &tok)?;
    Ok(tok)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn compute_hmac_hex(
    token_hex: &str,
    purpose: &str,
    principal: &str,
    nonce: &str,
    stamp: &str,
    body: &[u8],
) -> Option<String> {
    let key = hex::decode(token_hex).ok()?;
    let mut mac = HmacSha256::new_from_slice(&key).ok()?;
    let prefix = format!("edge-project-bridge/v1|{purpose}|{principal}|{nonce}|{stamp}|");
    mac.update(prefix.as_bytes());
    mac.update(body);
    Some(hex::encode(mac.finalize().into_bytes()))
}

fn check_host_and_origin(headers: &HeaderMap, st: &AppState) -> Result<(), Response> {
    let host_hdr = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if host_hdr != st.bound_host {
        return Err(json_resp(
            StatusCode::FORBIDDEN,
            json!({"ok": false, "code": "INVALID_HOST", "message": "Loopback Host header mismatch."}),
            None,
        ));
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let allowed = format!("http://{}", st.bound_host);
        if origin != allowed {
            return Err(json_resp(
                StatusCode::FORBIDDEN,
                json!({"ok": false, "code": "FORBIDDEN_ORIGIN", "message": "Cross-origin browser request denied."}),
                None,
            ));
        }
    }
    Ok(())
}

fn validate_headers_and_auth(
    headers: &HeaderMap,
    st: &AppState,
    raw_body: Option<&[u8]>,
) -> Result<(Principal, Option<HmacProof>), Response> {
    check_host_and_origin(headers, st)?;

    // Support Python-compatible HMAC-SHA256 mutual auth when X-Bridge-Signature is present
    if let Some(sig) = headers.get("x-bridge-signature").and_then(|v| v.to_str().ok()) {
        let p_name = headers.get("x-bridge-principal").and_then(|v| v.to_str().ok()).unwrap_or("");
        let nonce = headers.get("x-bridge-nonce").and_then(|v| v.to_str().ok()).unwrap_or("");
        let stamp = headers.get("x-bridge-timestamp").and_then(|v| v.to_str().ok()).unwrap_or("");
        let (principal, tok, replay_window) = match p_name {
            "local" => (Principal::Local, st.local_token.clone(), &st.seen_nonces[0]),
            "edge" => (Principal::Edge, st.edge_token.clone(), &st.seen_nonces[1]),
            "executor" => (Principal::DelegatedExecutor("default".into()), st.executor_token.clone(), &st.seen_nonces[2]),
            _ => {
                return Err(json_resp(
                    StatusCode::UNAUTHORIZED,
                    json!({"ok": false, "code": "AUTH_REQUIRED", "message": "Unknown HMAC principal."}),
                    None,
                ));
            }
        };
        let now = Utc::now().timestamp();
        if nonce.len() != 32 || !nonce.bytes().all(|b| b.is_ascii_hexdigit())
            || sig.len() != 64 || !stamp.parse::<i64>().is_ok_and(|ts| now.abs_diff(ts) <= 30)
        {
            return Err(json_resp(
                StatusCode::UNAUTHORIZED,
                json!({"ok": false, "code": "AUTH_REQUIRED", "message": "Invalid or expired HMAC request headers."}),
                None,
            ));
        }
        let expected = compute_hmac_hex(&tok, "request", p_name, nonce, stamp, raw_body.unwrap_or(&[]))
            .unwrap_or_default();
        if !constant_time_eq(sig, &expected) {
            return Err(json_resp(
                StatusCode::UNAUTHORIZED,
                json!({"ok": false, "code": "AUTH_REQUIRED", "message": "HMAC request signature mismatch."}),
                None,
            ));
        }
        let proof = HmacProof {
            principal_name: p_name.to_string(),
            token_hex: tok,
            nonce: nonce.to_string(),
            stamp: stamp.to_string(),
        };
        let acceptance = replay_window.lock().map_err(|_| {
            request_worker_error(BridgeError::new(
                ErrorCode::InternalError, "HMAC nonce window unavailable.", OriginLayer::Auth,
            ), Some(&proof))
        })?.accept(nonce, Instant::now());
        match acceptance {
            Ok(()) => return Ok((principal, Some(proof))),
            Err(None) => return Err(json_resp(
                StatusCode::UNAUTHORIZED,
                json!({"ok": false, "code": "AUTH_REQUIRED", "message": "Replayed HMAC nonce rejected."}),
                Some(&proof),
            )),
            Err(Some(wait)) => return Err(request_worker_error(
                BridgeError::new(ErrorCode::ResourceBusy, "HMAC nonce window saturated.", OriginLayer::Auth)
                    .with_details(json!({"retry_after_ms": wait, "reason": "nonce_window"})),
                Some(&proof),
            )),
        }
    }

    let supplied = headers
        .get("x-bridge-token")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
        })
        .unwrap_or("");

    if supplied.is_empty() {
        return Err(json_resp(
            StatusCode::UNAUTHORIZED,
            json!({"ok": false, "code": "AUTH_REQUIRED", "message": "Authenticated token or HMAC signature required; loopback alone is not auth."}),
            None,
        ));
    }
    if constant_time_eq(supplied, &st.local_token) {
        Ok((Principal::Local, None))
    } else if constant_time_eq(supplied, &st.edge_token) {
        Ok((Principal::Edge, None))
    } else if constant_time_eq(supplied, &st.executor_token) {
        Ok((Principal::DelegatedExecutor("default".to_string()), None))
    } else {
        Err(json_resp(
            StatusCode::UNAUTHORIZED,
            json!({"ok": false, "code": "AUTH_REQUIRED", "message": "Invalid authentication token."}),
            None,
        ))
    }
}

fn json_resp(status: StatusCode, body: Value, hmac_proof: Option<&HmacProof>) -> Response {
    let raw = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = (
        status,
        [(header::CONTENT_TYPE, HeaderValue::from_static("application/json"))],
        raw.clone(),
    )
        .into_response();
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    if let Some(p) = hmac_proof {
        if let Some(sig) = compute_hmac_hex(
            &p.token_hex,
            &format!("response:{}", status.as_u16()),
            &p.principal_name,
            &p.nonce,
            &p.stamp,
            &raw,
        ) {
            if let Ok(hv) = HeaderValue::from_str(&sig) {
                h.insert("x-bridge-signature", hv);
            }
        }
    }
    resp
}

fn timed(mut response: Response, queue_wait: Duration) -> Response {
    let value = format!("{:.3}", queue_wait.as_secs_f64() * 1000.0);
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().insert("x-bridge-queue-wait-ms", value);
    }
    response
}

fn request_worker_error(error: BridgeError, proof: Option<&HmacProof>) -> Response {
    let status = if error.code == ErrorCode::ResourceBusy {
        StatusCode::TOO_MANY_REQUESTS
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    json_resp(status, json!(error.to_structured()), proof)
}

async fn api_overview(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (principal, proof) = match validate_headers_and_auth(&headers, &st, None) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if !principal.is_local() {
        return json_resp(
            StatusCode::FORBIDDEN,
            json!({"ok": false, "code": "BRIDGE_POLICY_DENIED", "message": "BridgePulse overview requires the owner credential."}),
            proof.as_ref(),
        );
    }
    let state = Arc::clone(&st);
    match st.admission.run(Lane::Heavy, &principal, move || overview(&state)).await {
        Ok((body, wait)) => timed(json_resp(StatusCode::OK, body, proof.as_ref()), wait),
        Err(err) => request_worker_error(err, proof.as_ref()),
    }
}

fn overview(st: &AppState) -> Value {
    let health = st.store.health_snapshot().ok();
    let projects = st.store.list_projects(&Principal::Local).unwrap_or_default();
    let grants = st.store.list_task_grants(None).unwrap_or_default();
    let runs = st.store.list_durable_runs(None, 25).unwrap_or_default();
    let evidences = st.store.list_evidence_manifests(None, 25).unwrap_or_default();
    let devices = st.store.list_paired_devices().unwrap_or_default();
    let resources = host_resources();
    let providers = probe_all_providers();
    #[cfg(windows)]
    let containment = probe_mxc_backend();
    #[cfg(not(windows))]
    let containment = json!({"backend": "posix", "verified": false});

    json!({
            "ok": true,
            "bridge_version": BRIDGE_VERSION,
            "environment_kind": st.environment_kind,
            "versions": st.store.version_contract(),
            "principal": Principal::Local.as_db_key(),
            "host_id": st.host_id.0,
            "health": health,
            "resources": resources,
            "containment": containment,
            "providers": providers,
            "projects": projects,
            "grants": grants,
            "runs": runs,
            "evidence_manifests": evidences,
            "paired_devices": devices,
            "request_admission": st.admission.snapshot(),
    })
}

async fn api_tool_call(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    raw: Bytes,
) -> Response {
    let (principal, proof) = match validate_headers_and_auth(&headers, &st, Some(&raw)) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let body: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(_) => {
            return json_resp(
                StatusCode::BAD_REQUEST,
                json!({"ok": false, "code": "INVALID_ARGUMENT", "message": "Invalid JSON body."}),
                proof.as_ref(),
            );
        }
    };
    let method = body.get("method").and_then(|v| v.as_str()).unwrap_or("").to_owned();
    let params = body.get("params").cloned().unwrap_or_else(|| json!({}));
    let dispatcher = McpDispatcher::new(
        st.store.clone(),
        McpAdapterConfig::new(principal.clone(), st.host_id.clone()).with_environment(st.environment_kind.clone()),
    );
    let result = st.admission.run(Lane::for_tool(&method), &principal, move || {
        dispatcher.dispatch_tool(&method, &params)
    }).await;
    match result {
        Ok((Ok(res), wait)) => timed(json_resp(StatusCode::OK, json!({"ok": true, "result": res}), proof.as_ref()), wait),
        Ok((Err(err), wait)) => timed(json_resp(
            StatusCode::BAD_REQUEST,
            serde_json::to_value(err.to_structured()).unwrap(),
            proof.as_ref(),
        ), wait),
        Err(err) => request_worker_error(err, proof.as_ref()),
    }
}

/// Modern MCP `2026-07-28` + Legacy Streamable HTTP POST endpoint (`/mcp`) (§5, §6 [S01-S02]).
async fn api_mcp_streamable_http(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    raw: Bytes,
) -> Response {
    let (principal, proof) = match validate_headers_and_auth(&headers, &st, Some(&raw)) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let proto_hdr = headers
        .get("mcp-protocol-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !proto_hdr.is_empty()
        && proto_hdr != MCP_MODERN_PROTOCOL_VERSION
        && !MCP_LEGACY_PROTOCOL_VERSIONS.contains(&proto_hdr)
    {
        return json_resp(
            StatusCode::BAD_REQUEST,
            json!({
                "ok": false,
                "code": "PROTOCOL_MISMATCH",
                "message": format!("Unsupported MCP-Protocol-Version header '{proto_hdr}'."),
                "supported": [MCP_MODERN_PROTOCOL_VERSION, "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]
            }),
            proof.as_ref(),
        );
    }
    // Modern 2026-07-28 Streamable HTTP does NOT support Last-Event-ID resumption [S02].
    if proto_hdr == MCP_MODERN_PROTOCOL_VERSION && headers.get("last-event-id").is_some() {
        return json_resp(
            StatusCode::BAD_REQUEST,
            json!({
                "ok": false,
                "code": "PROTOCOL_MISMATCH",
                "message": "MCP 2026-07-28 Streamable HTTP does not support Last-Event-ID stream resumption; poll durable run_id instead."
            }),
            proof.as_ref(),
        );
    }
    let frame: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(_) => {
            return json_resp(
                StatusCode::BAD_REQUEST,
                json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "Parse error"}}),
                proof.as_ref(),
            );
        }
    };
    let dispatcher = McpDispatcher::new(
        st.store.clone(),
        McpAdapterConfig::new(principal.clone(), st.host_id.clone()).with_environment(st.environment_kind.clone()),
    );
    let modern = proto_hdr == MCP_MODERN_PROTOCOL_VERSION
        || modern_body_version(&frame) == Some(MCP_MODERN_PROTOCOL_VERSION);
    let request_id = frame.get("id").cloned();
    let is_tool_call = frame.get("method").and_then(Value::as_str) == Some("tools/call");
    let result = st.admission.run(Lane::for_frame(&frame), &principal, move || {
        if modern {
            modern_mcp_response(&headers, &frame, &dispatcher)
        } else {
            dispatcher.handle_jsonrpc(&frame).map(|body| (StatusCode::OK, body))
        }
    }).await;
    match result {
        Ok((Some((status, body)), wait)) => timed(json_resp(status, body, proof.as_ref()), wait),
        Ok((None, _)) => (StatusCode::ACCEPTED, "").into_response(),
        Err(err) if is_tool_call && request_id.is_some() => {
            let mut response = bridge_adapters::mcp::tool_error_response(
                request_id.unwrap_or(Value::Null),
                &err.to_structured(),
            );
            if modern {
                annotate_modern_result(&mut response);
            }
            json_resp(StatusCode::OK, response, proof.as_ref())
        }
        Err(err) => request_worker_error(err, proof.as_ref()),
    }
}

const MCP_PROTOCOL_META: &str = "/params/_meta/io.modelcontextprotocol~1protocolVersion";

fn annotate_modern_result(response: &mut Value) {
    if let Some(result) = response.get_mut("result").and_then(Value::as_object_mut) {
        result.insert("resultType".into(), json!("complete"));
        result.entry("_meta").or_insert_with(|| json!({}))["io.modelcontextprotocol/serverInfo"] =
            json!({"name":"edge_project_bridge", "version":BRIDGE_VERSION});
    }
}

fn modern_body_version(frame: &Value) -> Option<&str> {
    frame.pointer(MCP_PROTOCOL_META).and_then(Value::as_str)
}

fn modern_mcp_response(
    headers: &HeaderMap,
    frame: &Value,
    dispatcher: &McpDispatcher,
) -> Option<(StatusCode, Value)> {
    let header = |name| headers.get(name).and_then(|h| h.to_str().ok());
    let method = frame.get("method").and_then(Value::as_str);
    let request_id = frame.get("id").cloned().unwrap_or(Value::Null);
    let name_key = if method == Some("resources/read") { "/params/uri" } else { "/params/name" };
    let name = frame.pointer(name_key).and_then(Value::as_str);
    let needs_name = matches!(method, Some("tools/call" | "resources/read" | "prompts/get"));

    // Reject inconsistency before dispatch. Authentication and principal derivation have
    // already run, and neither headers nor per-request metadata can choose a principal.
    let mismatch = if header("mcp-protocol-version") != Some(MCP_MODERN_PROTOCOL_VERSION)
        || modern_body_version(frame) != Some(MCP_MODERN_PROTOCOL_VERSION)
    {
        Some("MCP-Protocol-Version must match the modern version in params._meta.")
    } else if method.is_none() || header("mcp-method") != method {
        Some("Mcp-Method must match the JSON-RPC method.")
    } else if needs_name && (name.is_none() || header("mcp-name") != name) {
        Some("Mcp-Name must match the tool name, prompt name, or resource URI.")
    } else {
        None
    };
    if let Some(message) = mismatch {
        return Some((
            StatusCode::BAD_REQUEST,
            json!({"jsonrpc":"2.0", "id":request_id,
                   "error":{"code":-32020, "message":message}}),
        ));
    }

    let server_info = json!({"name":"edge_project_bridge", "version":BRIDGE_VERSION});
    if method == Some("server/discover") && !request_id.is_null() {
        let versions: Vec<_> = std::iter::once(MCP_MODERN_PROTOCOL_VERSION)
            .chain(MCP_LEGACY_PROTOCOL_VERSIONS.iter().copied())
            .collect();
        return Some((StatusCode::OK, json!({"jsonrpc":"2.0", "id":request_id, "result":{
            "resultType":"complete", "supportedVersions":versions, "capabilities":{"tools":{}},
            "_meta":{"io.modelcontextprotocol/serverInfo":server_info}
        }})));
    }
    if method == Some("initialize") {
        return Some((StatusCode::NOT_FOUND, json!({"jsonrpc":"2.0", "id":request_id,
            "error":{"code":-32601, "message":"Use server/discover or per-request protocol metadata."}
        })));
    }
    let mut response = dispatcher.handle_jsonrpc(frame)?;
    annotate_modern_result(&mut response);
    let status = if response.pointer("/error/code").and_then(Value::as_i64) == Some(-32601) {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::OK
    };
    Some((status, response))
}

/// Authenticated peer host-agent channel endpoint (§10).
async fn api_host_envelope(
    State(st): State<Arc<AppState>>,
    Json(envelope): Json<SignedHostEnvelope>,
) -> Response {
    let Ok(chan) = DeviceChannel::init(st.store.clone(), &st.state_dir, "local-host") else {
        return json_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"ok": false, "code": "INTERNAL_ERROR", "message": "Host identity initialization failed."}),
            None,
        );
    };
    match chan.verify_incoming_envelope(&envelope) {
        Ok(peer) => json_resp(
            StatusCode::OK,
            json!({
                "ok": true,
                "authenticated_peer": peer.host_id,
                "approved_scopes": peer.approved_scopes,
                "target_host_id": st.host_id.0,
                "received_payload_bytes": envelope.payload_json.len(),
            }),
            None,
        ),
        Err(e) => json_resp(
            StatusCode::UNAUTHORIZED,
            serde_json::to_value(e.to_structured()).unwrap(),
            None,
        ),
    }
}

async fn fallback_ui(State(st): State<Arc<AppState>>) -> Response {
    if let Some(ref dist) = st.ui_dist_dir {
        let index = dist.join("index.html");
        if let Ok(html) = std::fs::read_to_string(&index) {
            let mut resp = Html(html).into_response();
            let h = resp.headers_mut();
            h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
            h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
            h.insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"),
            );
            return resp;
        }
    }
    Html(
        "<!DOCTYPE html><html lang=\"ar\" dir=\"rtl\"><head><meta charset=\"utf-8\"><title>BridgePulse V0.4.0</title></head><body><h1>BridgePulse V0.4.0</h1><p>Build static assets in <code>apps/bridgepulse</code> with <code>npm run build</code> to serve the full Svelte workbench.</p></body></html>",
    )
    .into_response()
}

pub async fn run_http_broker(
    store: StateStore,
    state_dir: PathBuf,
    host_id: HostId,
    port: u16,
    ui_dist_dir: Option<PathBuf>,
    environment_kind: Option<String>,
) -> anyhow::Result<()> {
    let local_token = ensure_token(&state_dir, "owner.token")?;
    let edge_token = ensure_token(&state_dir, "edge.token")?;
    let executor_token = ensure_token(&state_dir, "executor.token")?;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let actual_addr = listener.local_addr()?;
    let bound_host = format!("127.0.0.1:{}", actual_addr.port());

    let shared = Arc::new(AppState {
        store,
        state_dir: state_dir.clone(),
        host_id: host_id.clone(),
        environment_kind,
        local_token,
        edge_token,
        executor_token,
        bound_host: bound_host.clone(),
        ui_dist_dir: ui_dist_dir.clone(),
        seen_nonces: std::array::from_fn(|_| Mutex::new(ReplayWindow::default())),
        admission: Admission::default(),
    });

    let discovery = state_dir.join("rust-broker.json");
    std::fs::write(
        &discovery,
        serde_json::to_string_pretty(&json!({
            "port": actual_addr.port(),
            "host_id": host_id.0,
            "bridge_version": BRIDGE_VERSION,
        }))?,
    )?;

    let mut app = Router::new()
        .route("/api/overview", get(api_overview))
        .route("/api/v1/call", post(api_tool_call))
        .route("/v1/call", post(api_tool_call))
        .route("/mcp", post(api_mcp_streamable_http))
        .route("/api/v1/host-envelope", post(api_host_envelope))
        .route("/", get(fallback_ui));

    if let Some(ref dist) = ui_dist_dir {
        if dist.is_dir() {
            app = app.nest_service("/assets", ServeDir::new(dist.join("assets")));
        }
    }

    let app = app.with_state(shared);
    eprintln!("Edge Project Bridge V0.4.0 Rust broker + BridgePulse ready on http://{bound_host}");
    axum::serve(listener, app).await?;
    let _ = std::fs::remove_file(&discovery);
    Ok(())
}
