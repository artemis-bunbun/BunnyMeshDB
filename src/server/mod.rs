//! HTTP API server (axum) — L1 admin, L2/L3 data routes, capability auth.

pub mod config;
pub mod tls;

use crate::caps::{Capability, PermSet, RevocationSet, Scope, Tier, TokenCache};
use crate::core::hlc::Hlc;
use crate::core::ident::{Keypair, PublicKey};
use crate::ns::{account_write, authorize_cached, ensure_l3_namespace, CapCache};
use crate::query::{QueryCtx, eval};
use crate::schema::{check_supported, validate_schema};
use crate::storage::{ConflictPolicy, Entry, StorageError, Store, Version};
use crate::util::{b64_encode, b64url_decode};
use axum::extract::{Extension, Path, Query as AxumQuery, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value as JValue};
use std::collections::HashMap;
use parking_lot::RwLock as PLRwLock;
use std::sync::Arc;

// ---------- state ----------

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<PLRwLock<Store>>,
    pub root: PublicKey,
    pub kp: Arc<Keypair>,
    pub revocations: Arc<PLRwLock<RevocationSet>>,
    pub host_name: String,
    pub default_quota: u64,
    /// Mesh sync trigger: fired immediately after writes commit.
    pub sync_tx: Option<tokio::sync::mpsc::Sender<()>>,
    /// Namespace change fan-out for SSE push: every committed write (local
    /// HTTP or mesh-applied) broadcasts the namespace name. Subscribers
    /// re-read the log head on delivery.
    pub change_tx: Arc<tokio::sync::broadcast::Sender<String>>,
    /// Revocation epoch — bumped on every revoke. Cap verify results cached
    /// against this epoch are valid until it changes.
    pub rev_epoch: Arc<std::sync::atomic::AtomicU64>,
    /// cap nonce → epoch it was fully verified in (bounded; see ns.rs).
    pub cap_cache: Arc<CapCache>,
    /// token digest → parsed capability (content-addressed parse cache).
    pub token_cache: Arc<TokenCache>,
}

impl AppState {
    fn notify_sync(&self) {
        if let Some(tx) = &self.sync_tx {
            let _ = tx.try_send(());
        }
    }

    /// Fan out a namespace-change event to SSE subscribers. Nothing to do —
    /// the broadcast send is fire-and-forget (no receivers → dropped).
    fn notify_change(&self, ns: &str) {
        let _ = self.change_tx.send(ns.to_string());
    }
}

/// Capabilities attached by the auth middleware (Some for L1/L2 bearer caps,
/// None for headerless L3 requests). Holds `Arc<Capability>` so the middleware
/// passes the token-cache's shared capability straight through — no
/// per-request deep clone of the whole capability (its strings/arrays).
#[derive(Clone)]
pub struct AuthCaps(pub Vec<Arc<Capability>>);

// ---------- responses ----------

fn err_json(code: StatusCode, error: &str) -> Response {
    (code, Json(json!({ "error": error }))).into_response()
}

/// Authorize failures on a presented capability → 403 (forbidden). 401 is
/// reserved for a missing/malformed header (middleware). Quota → 409.
fn auth_to_response(e: crate::ns::AuthError) -> Response {
    match e {
        crate::ns::AuthError::QuotaExceeded { .. } => err_json(StatusCode::CONFLICT, "quota_exceeded"),
        _ => err_json(StatusCode::FORBIDDEN, "forbidden"),
    }
}

// ---------- auth middleware ----------

/// `Authorization: Bearer bmdb-cap:<base64url(cap_json)>`.
/// - No header → `Extension<Option<AuthCaps>>` = None (L3 allowed).
/// - Header present but unparseable → 401.
/// - Valid → Some(caps).
pub async fn auth_mw(
    state: State<AppState>,
    headers: HeaderMap,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let header = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok());
    match header {
        None => {
            let mut req = req;
            req.extensions_mut().insert(None::<AuthCaps>);
            next.run(req).await
        }
        Some(h) => {
            // Parse cache: sha256 digest → parsed capability. Content-addressed,
            // so a hit is byte-identical to re-parsing; per-request verification
            // (sig, expiry, revocation) still runs in the authorize path.
            let digest = crate::caps::token_digest(h);
            let cap = match state.token_cache.get(&digest) {
                Some(arc) => Ok(arc),
                None => match parse_cap_header(h) {
                    Ok(cap) => {
                        let arc = std::sync::Arc::new(cap);
                        state.token_cache.put(digest, arc.clone());
                        Ok(arc)
                    }
                    Err(e) => Err(e),
                },
            };
            match cap {
                Ok(arc) => {
                    let mut req = req;
                    // Hand the shared Arc straight to the handler — no clone.
                    req.extensions_mut().insert(Some(AuthCaps(vec![arc])));
                    next.run(req).await
                }
                Err(_) => err_json(StatusCode::UNAUTHORIZED, "invalid_capability"),
            }
        }
    }
}

fn parse_cap_header(h: &str) -> Result<Capability, String> {
    let rest = h.strip_prefix("Bearer ").ok_or("expected Bearer scheme")?;
    let b64 = rest.strip_prefix("bmdb-cap:").ok_or("expected bmdb-cap: token")?;
    let cap_json = String::from_utf8(b64url_decode(b64)?).map_err(|e| e.to_string())?;
    Capability::from_json(&cap_json)
}

/// L1/L2: principal = cap subject; authorize `scope` with `perms`.
fn auth_l1_l2(
    state: &AppState,
    caps: Option<&AuthCaps>,
    scope: &Scope,
    perms: PermSet,
    now_ms: u64,
) -> Result<PublicKey, Response> {
    let caps = caps.ok_or_else(|| err_json(StatusCode::UNAUTHORIZED, "invalid_capability"))?;
    let principal = caps
        .0
        .first()
        .map(|c| (*c).subject)
        .ok_or_else(|| err_json(StatusCode::UNAUTHORIZED, "invalid_capability"))?;
    let revs = state.revocations.read();
    // Read the epoch AFTER taking the read lock: a concurrent revoke either
    // happened-before (visible to this reader) or is blocked on the write
    // lock, so a cached hit can never mask a revocation.
    let epoch = state.rev_epoch.load(std::sync::atomic::Ordering::SeqCst);
    authorize_cached(scope, &principal, perms, &caps.0, &state.root, &revs, &state.host_name, now_ms, Some(&*state.cap_cache), epoch)
        .map_err(auth_to_response)?;
    Ok(principal)
}

/// L3: principal = pk in the `u/<pk>` namespace; no header needed.
fn auth_l3(state: &AppState, scope: &Scope, now_ms: u64) -> Result<PublicKey, Response> {
    let pk_hex = scope
        .ns
        .strip_prefix("u/")
        .ok_or_else(|| err_json(StatusCode::FORBIDDEN, "forbidden"))?;
    let pk = pk_hex
        .parse::<PublicKey>()
        .map_err(|_| err_json(StatusCode::FORBIDDEN, "forbidden"))?;
    let revs = state.revocations.read();
    authorize_cached(scope, &pk, PermSet::READ.union(PermSet::WRITE), &[], &state.root, &revs, &state.host_name, now_ms, None, 0)
        .map_err(auth_to_response)?;
    Ok(pk)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn policy_str(p: ConflictPolicy) -> &'static str {
    match p {
        ConflictPolicy::Lww => "lww",
        ConflictPolicy::CrdtRegister => "register",
    }
}

/// Wall-clock expiry of the winning version (0 = never). Purely advisory —
/// GET/scan treat an expired value as absent.
fn entry_expires_at(e: &Entry) -> u64 {
    match e {
        Entry::Lww(v) => v.expires_at,
        Entry::Register(vs) => vs
            .iter()
            .max_by(|a, b| (a.hlc, a.replica).cmp(&(b.hlc, b.replica)))
            .map(|v| v.expires_at)
            .unwrap_or(0),
    }
}

/// Latest value, unless the winning version is past its TTL (`now` wall-clock
/// ms), in which case the key reads as absent.
fn latest_value(e: &Entry, now: u64) -> Option<Vec<u8>> {
    match e {
        Entry::Lww(v) if v.expires_at == 0 || v.expires_at > now => Some(v.value.clone()),
        Entry::Lww(_) => None,
        Entry::Register(vs) => vs
            .iter()
            .filter(|v| v.expires_at == 0 || v.expires_at > now)
            .max_by(|a, b| (a.hlc, a.replica).cmp(&(b.hlc, b.replica)))
            .map(|v| v.value.clone()),
    }
}

/// Raw version descriptor for `/conflicts` and `?versions=true` — exposes
/// every replica's divergent value, not just the winning one.
fn version_json(v: &Version) -> JValue {
    json!({
        "hlc": v.hlc,
        "replica": hex::encode(&v.replica),
        "seq": v.seq,
        "expires_at": v.expires_at,
        "value_b64": b64_encode(&v.value),
    })
}

/// Build the requested scope for a data route: host/<tier>/<ns>[/dir-prefix].
fn data_scope(tier: Tier, ns: &str, key: &str, host: &str) -> Scope {
    let key = key.trim_start_matches('/');
    let prefix = match key.rfind('/') {
        Some(i) if i > 0 => Some(key[..i].to_string()),
        _ => None,
    };
    Scope { host: host.to_string(), tier, ns: ns.to_string(), prefix }
}

fn l1_scope(state: &AppState) -> Scope {
    Scope { host: state.host_name.clone(), tier: Tier::L1, ns: "*".into(), prefix: None }
}

// ---------- handlers ----------

async fn healthz() -> Json<JValue> {
    Json(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct CreateNsBody {
    name: String,
    #[serde(default = "default_policy")]
    policy: String,
}
fn default_policy() -> String {
    "lww".to_string()
}

async fn l1_list_namespaces(
    State(state): State<AppState>,
    Extension(caps): Extension<Option<AuthCaps>>,
) -> Response {
    match auth_l1_l2(&state, caps.as_ref(), &l1_scope(&state), PermSet::ADMIN, now_ms()) {
        Ok(_) => {}
        Err(r) => return r,
    }
    let store = state.store.read();
    let namespaces: Vec<JValue> = store
        .namespaces()
        .into_iter()
        .map(|(name, policy)| json!({ "name": name, "policy": policy_str(policy) }))
        .collect();
    Json(namespaces).into_response()
}

async fn l1_create_namespace(
    State(state): State<AppState>,
    Extension(caps): Extension<Option<AuthCaps>>,
    Json(body): Json<CreateNsBody>,
) -> Response {
    match auth_l1_l2(&state, caps.as_ref(), &l1_scope(&state), PermSet::ADMIN, now_ms()) {
        Ok(_) => {}
        Err(r) => return r,
    }
    if body.name.starts_with("u/") {
        return err_json(StatusCode::FORBIDDEN, "forbidden");
    }
    let policy = match body.policy.as_str() {
        "lww" => ConflictPolicy::Lww,
        "register" => ConflictPolicy::CrdtRegister,
        _ => return err_json(StatusCode::BAD_REQUEST, "bad_request"),
    };
    let mut store = state.store.write();
    match store.create_namespace(&body.name, policy) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(StorageError::NamespaceExists(_)) => err_json(StatusCode::CONFLICT, "namespace_exists"),
        Err(StorageError::BadName(_)) => err_json(StatusCode::BAD_REQUEST, "bad_request"),
        Err(e) => {
            tracing::error!(%e, "create namespace");
            err_json(StatusCode::INTERNAL_SERVER_ERROR, "internal")
        }
    }
}

#[derive(Deserialize)]
struct IssueCapBody {
    scope: String,
    #[serde(default)]
    perms: Vec<String>,
    expiry_ms: Option<u64>,
    /// Principal the cap is issued to (defaults to the admin/issuer).
    to: Option<String>,
}

// ---------- JSON-Schema per namespace (admin) ----------

/// GET /l1/namespaces/{ns}/schema — the active schema JSON, or 404 if unset.
async fn l1_schema_get(
    State(state): State<AppState>,
    Extension(caps): Extension<Option<AuthCaps>>,
    Path(ns): Path<String>,
) -> Response {
    match auth_l1_l2(&state, caps.as_ref(), &l1_scope(&state), PermSet::ADMIN, now_ms()) {
        Ok(_) => {}
        Err(r) => return r,
    }
    let store = state.store.read();
    match store.schema(&ns) {
        Some(bytes) => {
            let s = String::from_utf8_lossy(bytes).into_owned();
            let v = serde_json::from_str::<JValue>(&s).unwrap_or(JValue::Null);
            Json(v).into_response()
        }
        None => err_json(StatusCode::NOT_FOUND, "no_schema"),
    }
}

/// POST /l1/namespaces/{ns}/schema — set the schema (body is the raw JSON
/// Schema). Rejects unsupported keywords up front so enforcement is honest.
async fn l1_schema_set(
    State(state): State<AppState>,
    Extension(caps): Extension<Option<AuthCaps>>,
    Path(ns): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    match auth_l1_l2(&state, caps.as_ref(), &l1_scope(&state), PermSet::ADMIN, now_ms()) {
        Ok(_) => {}
        Err(r) => return r,
    }
    let s = String::from_utf8_lossy(&body).into_owned();
    let schema = match serde_json::from_str::<JValue>(&s) {
        Ok(v) => v,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "bad_json"),
    };
    match check_supported(&schema) {
        Ok(()) => {}
        Err(msg) => return err_json(StatusCode::BAD_REQUEST, format!("unsupported_schema: {msg}").as_str()),
    }
    let mut store = state.store.write();
    if store.policy(&ns).is_none() {
        return err_json(StatusCode::NOT_FOUND, "namespace_not_found");
    }
    let hlc = Hlc::now().to_u64();
    let rid = state.root.to_bytes();
    match store.set_schema(&ns, Some(&body), hlc, rid, rid) {
        Ok(seq) => {
            drop(store);
            state.notify_sync();
            state.notify_change(&ns);
            Json(json!({ "ok": true, "seq": seq })).into_response()
        }
        Err(e) => {
            tracing::error!(%e, "set schema");
            err_json(StatusCode::INTERNAL_SERVER_ERROR, "internal")
        }
    }
}

/// DELETE /l1/namespaces/{ns}/schema — clear the schema (validation off).
async fn l1_schema_clear(
    State(state): State<AppState>,
    Extension(caps): Extension<Option<AuthCaps>>,
    Path(ns): Path<String>,
) -> Response {
    match auth_l1_l2(&state, caps.as_ref(), &l1_scope(&state), PermSet::ADMIN, now_ms()) {
        Ok(_) => {}
        Err(r) => return r,
    }
    let mut store = state.store.write();
    if store.policy(&ns).is_none() {
        return err_json(StatusCode::NOT_FOUND, "namespace_not_found");
    }
    let hlc = Hlc::now().to_u64();
    let rid = state.root.to_bytes();
    match store.set_schema(&ns, None, hlc, rid, rid) {
        Ok(seq) => {
            drop(store);
            state.notify_sync();
            state.notify_change(&ns);
            Json(json!({ "ok": true, "seq": seq })).into_response()
        }
        Err(e) => {
            tracing::error!(%e, "clear schema");
            err_json(StatusCode::INTERNAL_SERVER_ERROR, "internal")
        }
    }
}

async fn l1_issue_cap(
    State(state): State<AppState>,
    Extension(caps): Extension<Option<AuthCaps>>,
    Json(body): Json<IssueCapBody>,
) -> Response {
    let principal = match auth_l1_l2(&state, caps.as_ref(), &l1_scope(&state), PermSet::ADMIN, now_ms()) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let target = match Scope::parse(&body.scope) {
        Ok(s) if s.tier == Tier::L2 && s.host == state.host_name => s,
        _ => return err_json(StatusCode::BAD_REQUEST, "bad_request"),
    };
    let perms = match PermSet::parse_list(&body.perms) {
        Ok(p) => p,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "bad_request"),
    };
    let subject = match &body.to {
        Some(hex) => match hex.parse::<PublicKey>() {
            Ok(pk) => pk,
            Err(_) => return err_json(StatusCode::BAD_REQUEST, "bad_request"),
        },
        None => principal,
    };
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).expect("os rng");
    let cap = Capability::sign_for(target, perms, body.expiry_ms, u64::from_le_bytes(nonce), subject, &state.kp);
    let mut store = state.store.write();
    let mut ledger = store
        .meta_get("sys/caps")
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default();
    ledger.push_str(&cap.to_json());
    ledger.push('\n');
    store.meta_set("sys/caps", ledger.into_bytes());
    Json(serde_json::from_str::<JValue>(&cap.to_json()).unwrap()).into_response()
}

async fn l1_list_caps(
    State(state): State<AppState>,
    Extension(caps): Extension<Option<AuthCaps>>,
) -> Response {
    match auth_l1_l2(&state, caps.as_ref(), &l1_scope(&state), PermSet::ADMIN, now_ms()) {
        Ok(_) => {}
        Err(r) => return r,
    }
    let store = state.store.read();
    let ledger = store.meta_get("sys/caps").map(|v| v.to_vec()).unwrap_or_default();
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(&ledger).lines() {
        if !line.trim().is_empty() {
            if let Ok(v) = serde_json::from_str::<JValue>(line) {
                out.push(v);
            }
        }
    }
    Json(out).into_response()
}

#[derive(Deserialize)]
struct RevokeBody {
    scope: String,
    to: String,
}

async fn l1_revoke(
    State(state): State<AppState>,
    Extension(caps): Extension<Option<AuthCaps>>,
    Json(body): Json<RevokeBody>,
) -> Response {
    match auth_l1_l2(&state, caps.as_ref(), &l1_scope(&state), PermSet::ADMIN, now_ms()) {
        Ok(_) => {}
        Err(r) => return r,
    }
    let target_scope = match Scope::parse(&body.scope) {
        Ok(s) => s,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "bad_request"),
    };
    let to = match body.to.parse::<PublicKey>() {
        Ok(pk) => pk,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "bad_request"),
    };
    {
        let mut revs = state.revocations.write();
        revs.revoke_principal(&target_scope, &to.to_string());
        // Bump under the same write lock, before release: any request that
        // reads the new epoch is guaranteed to observe this revocation.
        state.rev_epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    let mut store = state.store.write();
    let mut ledger = store
        .meta_get("sys/revocations")
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default();
    ledger.push_str(&format!("{}\t{}\n", target_scope.to_url(), to));
    store.meta_set("sys/revocations", ledger.into_bytes());
    Json(json!({ "ok": true })).into_response()
}

/// Authorize a data route (L2 cap or L3 owner), return the principal.
/// `perms` is the minimum this request needs — GET readers pass
/// `PermSet::READ` so a read-only cap can actually read (the old code
/// demanded READ+WRITE on every data route, so read-only caps got 403).
fn data_auth(
    state: &AppState,
    caps: Option<&AuthCaps>,
    ns: &str,
    key: &str,
    perms: PermSet,
) -> Result<(PublicKey, Tier), Response> {
    let tier = if ns.starts_with("u/") { Tier::L3 } else { Tier::L2 };
    let scope = data_scope(tier, ns, key, &state.host_name);
    let now = now_ms();
    if tier == Tier::L3 {
        auth_l3(state, &scope, now).map(|p| (p, tier))
    } else {
        auth_l1_l2(state, caps, &scope, perms, now).map(|p| (p, tier))
    }
}

async fn l2_data(
    State(state): State<AppState>,
    Extension(caps): Extension<Option<AuthCaps>>,
    method: Method,
    Path((ns, key)): Path<(String, String)>,
    _query: AxumQuery<HashMap<String, String>>,
    body: axum::body::Bytes,
) -> Response {
    handle_data(&state, caps.as_ref(), &ns, &key, method, _query.0, &body)
}

async fn l3_data(
    State(state): State<AppState>,
    Extension(_caps): Extension<Option<AuthCaps>>,
    method: Method,
    Path((pk, key)): Path<(String, String)>,
    _query: AxumQuery<HashMap<String, String>>,
    body: axum::body::Bytes,
) -> Response {
    let ns = format!("u/{pk}");
    handle_data(&state, None, &ns, &key, method, _query.0, &body)
}

/// GET /l2/{ns}?prefix= — scan form (no key segment).
async fn l2_scan(
    State(state): State<AppState>,
    Extension(caps): Extension<Option<AuthCaps>>,
    Path(ns): Path<String>,
    query: AxumQuery<HashMap<String, String>>,
) -> Response {
    handle_scan(&state, caps.as_ref(), &ns, query.0)
}

/// GET /l3/u/{pk}?prefix= — scan form.
async fn l3_scan(
    State(state): State<AppState>,
    Extension(_caps): Extension<Option<AuthCaps>>,
    Path(pk): Path<String>,
    query: AxumQuery<HashMap<String, String>>,
) -> Response {
    handle_scan(&state, None, &format!("u/{pk}"), query.0)
}

fn handle_scan(state: &AppState, caps: Option<&AuthCaps>, ns: &str, query: HashMap<String, String>) -> Response {
    let p = match query.get("prefix") {
        Some(p) => p.clone(),
        None => return err_json(StatusCode::BAD_REQUEST, "bad_request"),
    };
    match data_auth(state, caps, ns, "", PermSet::READ) {
        Ok(_) => {}
        Err(r) => return r,
    }
    let store = state.store.read();
    let rows = store.scan(ns, p.as_bytes());
    let now = now_ms();
    let entries: Vec<JValue> = rows
        .into_iter()
        .filter(|(_, e)| latest_value(e, now).is_some())
        .map(|(k, e)| {
            json!({
                "key": String::from_utf8_lossy(&k),
                "value_b64": b64_encode(&latest_value(&e, now).unwrap_or_default()),
                "expires_at": entry_expires_at(&e),
            })
        })
        .collect();
    Json(json!({ "entries": entries })).into_response()
}

fn handle_data(
    state: &AppState,
    caps: Option<&AuthCaps>,
    ns: &str,
    key: &str,
    method: Method,
    query: HashMap<String, String>,
    body: &[u8],
) -> Response {
    let perms = if method == Method::GET { PermSet::READ } else { PermSet::WRITE };
    let (principal, tier) = match data_auth(state, caps, ns, key, perms) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let k = url_decoded(key);
    match method {
        Method::GET => {
            if let Some(p) = query.get("prefix") {
                let store = state.store.read();
                let rows = store.scan(ns, p.as_bytes());
                let now = now_ms();
                let entries: Vec<JValue> = rows
                    .into_iter()
                    .filter(|(_, e)| latest_value(e, now).is_some())
                    .map(|(k, e)| {
                        json!({
                            "key": String::from_utf8_lossy(&k),
                            "value_b64": b64_encode(&latest_value(&e, now).unwrap_or_default()),
                            "expires_at": entry_expires_at(&e),
                        })
                    })
                    .collect();
                Json(json!({ "entries": entries })).into_response()
            } else if query.get("versions").map(|v| v == "true").unwrap_or(false) {
                // Raw-version read: expose every divergent version on the key
                // (Register policy) instead of the winning value.
                let store = state.store.read();
                match store.get(ns, &k) {
                    Some(Entry::Lww(v)) => Json(json!({
                        "key": String::from_utf8_lossy(&k),
                        "versions": [version_json(v)],
                    }))
                    .into_response(),
                    Some(Entry::Register(vs)) => Json(json!({
                        "key": String::from_utf8_lossy(&k),
                        "versions": vs.iter().map(version_json).collect::<Vec<_>>(),
                    }))
                    .into_response(),
                    None => err_json(StatusCode::NOT_FOUND, "not_found"),
                }
            } else {
                let store = state.store.read();
                let now = now_ms();
                match store.get(ns, &k) {
                    Some(e) => latest_value(e, now)
                        .map(|v| v.into_response())
                        .unwrap_or_else(|| err_json(StatusCode::NOT_FOUND, "not_found")),
                    None => err_json(StatusCode::NOT_FOUND, "not_found"),
                }
            }
        }
        Method::PUT => {
            let mut store = state.store.write();
            if tier == Tier::L3 {
                if let Err(e) = ensure_l3_namespace(&mut store, &principal) {
                    return auth_to_response(e);
                }
            } else if store.policy(ns).is_none() {
                return err_json(StatusCode::NOT_FOUND, "namespace_not_found");
            }
            if let Err(e) = account_write(&mut store, ns, body.len() as u64, state.default_quota) {
                return auth_to_response(e);
            }
            let hlc = Hlc::now().to_u64();
            let rid = state.root.to_bytes();
            // Enforce the namespace JSON-Schema (if set) before commit.
            if let Some(schema_bytes) = store.schema(ns) {
                let src = String::from_utf8_lossy(schema_bytes).into_owned();
                let schema = serde_json::from_str::<JValue>(&src).unwrap_or(JValue::Null);
                let payload = String::from_utf8_lossy(body).into_owned();
                match serde_json::from_str::<JValue>(&payload) {
                    Ok(value) => match validate_schema(&schema, &value) {
                        Ok(()) => {}
                        Err(msg) => return err_json(StatusCode::BAD_REQUEST, format!("schema_violation: {msg}").as_str()),
                    },
                    Err(_) => return err_json(StatusCode::BAD_REQUEST, "schema_violation: value is not valid JSON"),
                }
            }
            // `?ttl=<secs>` sets a wall-clock expiry (0/absent = never).
            // Overflow on absurd values merely wraps → value reads already-expired.
            let expires_at = match query.get("ttl").and_then(|s| s.parse::<u64>().ok()) {
                Some(secs) if secs > 0 => now_ms() + secs * 1000,
                _ => 0,
            };
            match store.put(ns, &k, body, hlc, rid, principal.to_bytes(), expires_at) {
                Ok(seq) => {
                    drop(store);
                    state.notify_sync();
                    state.notify_change(&ns);
                    Json(json!({ "ok": true, "seq": seq, "expires_at": expires_at })).into_response()
                }
                Err(e) => {
                    tracing::error!(%e, "put");
                    err_json(StatusCode::INTERNAL_SERVER_ERROR, "internal")
                }
            }
        }
        Method::DELETE => {
            let mut store = state.store.write();
            if store.policy(ns).is_none() {
                return err_json(StatusCode::NOT_FOUND, "namespace_not_found");
            }
            let hlc = Hlc::now().to_u64();
            let rid = state.root.to_bytes();
            match store.delete(ns, &k, hlc, rid, principal.to_bytes()) {
                Ok(_) => {
                    drop(store);
                    state.notify_sync();
                    state.notify_change(&ns);
                    Json(json!({ "ok": true })).into_response()
                }
                Err(e) => {
                    tracing::error!(%e, "delete");
                    err_json(StatusCode::INTERNAL_SERVER_ERROR, "internal")
                }
            }
        }
        _ => err_json(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed"),
    }
}

fn url_decoded(s: &str) -> Vec<u8> {
    // axum already percent-decodes path segments; keep the raw UTF-8 bytes.
    s.as_bytes().to_vec()
}

#[derive(Deserialize)]
struct QlBody {
    expr: String,
}

fn run_ql(state: &AppState, caps: Option<&AuthCaps>, ns: &str, expr: &str) -> Response {
    match data_auth(state, caps, ns, "", PermSet::WRITE) {
        Ok(_) => {}
        Err(r) => return r,
    }
    let mut store = state.store.write();
    let mut ctx = QueryCtx { store: &mut store, scope: Some(ns.to_string()), host_id: state.root };
    match eval(&mut ctx, expr) {
        Ok(v) => {
            let j: JValue = serde_json::from_str(&v.json()).unwrap_or(JValue::Null);
            Json(j).into_response()
        }
        Err(e) => {
            tracing::warn!(%e, "ql eval");
            err_json(StatusCode::BAD_REQUEST, "query_error")
        }
    }
}

async fn ql_l2(
    State(state): State<AppState>,
    Extension(caps): Extension<Option<AuthCaps>>,
    Path(ns): Path<String>,
    Json(body): Json<QlBody>,
) -> Response {
    run_ql(&state, caps.as_ref(), &ns, &body.expr)
}

async fn ql_l3(
    State(state): State<AppState>,
    Extension(_caps): Extension<Option<AuthCaps>>,
    Path(pk): Path<String>,
    Json(body): Json<QlBody>,
) -> Response {
    run_ql(&state, None, &format!("u/{pk}"), &body.expr)
}

// ---------- change feed ----------

/// GET /l2/{ns}/head — namespace log head (seq + chain hash). Poll or change
/// events against this to detect new writes without pulling the whole feed.
async fn l2_head(
    State(state): State<AppState>,
    Extension(caps): Extension<Option<AuthCaps>>,
    Path(ns): Path<String>,
) -> Response {
    match data_auth(&state, caps.as_ref(), &ns, "", PermSet::READ) {
        Ok(_) => {}
        Err(r) => return r,
    }
    let store = state.store.read();
    match store.head(&ns) {
        Some((seq, h)) => Json(json!({ "seq": seq, "hash": hex::encode(&h) })).into_response(),
        None => err_json(StatusCode::NOT_FOUND, "namespace_not_found"),
    }
}

/// GET /l2/{ns}/changes?since=<seq> — log records after `since`, oldest
/// first. Each change is one durable record (PUT / DEL / TTL). Polling with
/// `since` = the previous response's `head.seq` yields a gapless stream.
async fn l2_changes(
    State(state): State<AppState>,
    Extension(caps): Extension<Option<AuthCaps>>,
    Path(ns): Path<String>,
    query: AxumQuery<HashMap<String, String>>,
) -> Response {
    match data_auth(&state, caps.as_ref(), &ns, "", PermSet::READ) {
        Ok(_) => {}
        Err(r) => return r,
    }
    let since = query.0.get("since").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let store = state.store.read();
    if store.policy(&ns).is_none() {
        return err_json(StatusCode::NOT_FOUND, "namespace_not_found");
    }
    let head = store.head(&ns).map(|(seq, h)| json!({ "seq": seq, "hash": hex::encode(&h) })).unwrap_or(JValue::Null);
    let changes: Vec<JValue> = match store.log_records(&ns, since + 1) {
        Ok(recs) => recs
            .into_iter()
            .map(|(seq, bytes)| {
                match crate::storage::log::Record::parse_chain(&bytes, None) {
                    Ok((rec, _)) => json!({
                        "seq": seq,
                        "key_b64": b64_encode(&rec.key),
                        "value_b64": b64_encode(&rec.value),
                        "del": rec.tag == crate::storage::log::TAG_DEL,
                        "ttl": rec.expires_at != 0,
                        "expires_at": rec.expires_at,
                        "hlc": rec.hlc,
                    }),
                    Err(_) => json!({ "seq": seq, "parse_error": true }),
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    Json(json!({ "since": since, "head": head, "changes": changes })).into_response()
}

/// L3 owner-namespace variants (no capability — identity is the namespace).
async fn l3_head(
    State(state): State<AppState>,
    Extension(_caps): Extension<Option<AuthCaps>>,
    Path(pk): Path<String>,
) -> Response {
    let ns = format!("u/{pk}");
    match data_auth(&state, None, &ns, "", PermSet::READ) {
        Ok(_) => {}
        Err(r) => return r,
    }
    let store = state.store.read();
    match store.head(&ns) {
        Some((seq, h)) => Json(json!({ "seq": seq, "hash": hex::encode(&h) })).into_response(),
        None => err_json(StatusCode::NOT_FOUND, "namespace_not_found"),
    }
}

async fn l3_changes(
    State(state): State<AppState>,
    Extension(_caps): Extension<Option<AuthCaps>>,
    Path(pk): Path<String>,
    query: AxumQuery<HashMap<String, String>>,
) -> Response {
    let ns = format!("u/{pk}");
    match data_auth(&state, None, &ns, "", PermSet::READ) {
        Ok(_) => {}
        Err(r) => return r,
    }
    let since = query.0.get("since").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let store = state.store.read();
    if store.policy(&ns).is_none() {
        return err_json(StatusCode::NOT_FOUND, "namespace_not_found");
    }
    let head = store.head(&ns).map(|(seq, h)| json!({ "seq": seq, "hash": hex::encode(&h) })).unwrap_or(JValue::Null);
    let changes: Vec<JValue> = match store.log_records(&ns, since + 1) {
        Ok(recs) => recs
            .into_iter()
            .map(|(seq, bytes)| {
                match crate::storage::log::Record::parse_chain(&bytes, None) {
                    Ok((rec, _)) => json!({
                        "seq": seq,
                        "key_b64": b64_encode(&rec.key),
                        "value_b64": b64_encode(&rec.value),
                        "del": rec.tag == crate::storage::log::TAG_DEL,
                        "ttl": rec.expires_at != 0,
                        "expires_at": rec.expires_at,
                        "hlc": rec.hlc,
                    }),
                    Err(_) => json!({ "seq": seq, "parse_error": true }),
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    Json(json!({ "since": since, "head": head, "changes": changes })).into_response()
}

// ---------- conflict observation ----------

/// GET /l2/{ns}/conflicts — every Register-policy key holding >1
/// concurrent version (divergent replicas that LWW-style reads silently
/// collapse). Exposes each divergent value so clients can reconcile.
async fn l2_conflicts(
    State(state): State<AppState>,
    Extension(caps): Extension<Option<AuthCaps>>,
    Path(ns): Path<String>,
) -> Response {
    match data_auth(&state, caps.as_ref(), &ns, "", PermSet::READ) {
        Ok(_) => {}
        Err(r) => return r,
    }
    let store = state.store.read();
    let mut out: Vec<JValue> = Vec::new();
    for (k, e) in store.scan(&ns, b"") {
        match e {
            Entry::Register(vs) if vs.len() > 1 => out.push(json!({
                "key": String::from_utf8_lossy(&k),
                "count": vs.len(),
                "versions": vs.iter().map(version_json).collect::<Vec<_>>(),
            })),
            _ => {}
        }
    }
    Json(json!({ "conflicts": out })).into_response()
}

async fn l3_conflicts(
    State(state): State<AppState>,
    Extension(_caps): Extension<Option<AuthCaps>>,
    Path(pk): Path<String>,
) -> Response {
    let ns = format!("u/{pk}");
    match data_auth(&state, None, &ns, "", PermSet::READ) {
        Ok(_) => {}
        Err(r) => return r,
    }
    let store = state.store.read();
    let mut out: Vec<JValue> = Vec::new();
    for (k, e) in store.scan(&ns, b"") {
        match e {
            Entry::Register(vs) if vs.len() > 1 => out.push(json!({
                "key": String::from_utf8_lossy(&k),
                "count": vs.len(),
                "versions": vs.iter().map(version_json).collect::<Vec<_>>(),
            })),
            _ => {}
        }
    }
    Json(json!({ "conflicts": out })).into_response()
}

// ---------- SSE change push ----------

/// GET /l2/{ns}/events — Server-Sent Events: emits one `change` event per
/// committed write to the namespace (local HTTP or mesh-applied). Each
/// payload is the log head at delivery time; the subscriber replays the
/// delta via `changes?since=<head.seq>`. First connect emits nothing until
/// the next write — seed read state with `head`/`changes` first.
async fn l2_events(
    State(state): State<AppState>,
    Extension(caps): Extension<Option<AuthCaps>>,
    Path(ns): Path<String>,
) -> Response {
    match data_auth(&state, caps.as_ref(), &ns, "", PermSet::READ) {
        Ok(_) => {}
        Err(r) => return r,
    }
    sse_events(state, ns)
}

async fn l3_events(
    State(state): State<AppState>,
    Extension(_caps): Extension<Option<AuthCaps>>,
    Path(pk): Path<String>,
) -> Response {
    let ns = format!("u/{pk}");
    match data_auth(&state, None, &ns, "", PermSet::READ) {
        Ok(_) => {}
        Err(r) => return r,
    }
    sse_events(state, ns)
}

/// The event stream: subscribe to the namespace broadcast, emit the current
/// log head on every event for this namespace, stay connected until the
/// broadcast channel closes (daemon shutdown).
fn sse_events(state: AppState, ns: String) -> Response {
    let rx = state.change_tx.subscribe();
    let store = state.store.clone();
    let stream = futures::stream::unfold((rx, store, ns.clone()), |(mut rx, store, ns)| async move {
        loop {
            match rx.recv().await {
                Ok(ev_ns) if ev_ns == ns => {
                    let payload = match store.read().head(&ns) {
                        Some((seq, h)) => json!({ "ns": ns, "seq": seq, "hash": hex::encode(&h) }),
                        None => json!({ "ns": ns, "seq": 0 }),
                    };
                    let ev = Event::default().event("change").json_data(payload).unwrap_or_default();
                    return Some((Ok::<_, std::convert::Infallible>(ev), (rx, store, ns)));
                }
                Ok(_) => continue,
                Err(_) => return None, // channel closed → end the stream
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::new()).into_response()
}

// ---------- router ----------

pub fn app(state: AppState) -> Router {
    let protected = Router::new()
        .route("/l1/namespaces", get(l1_list_namespaces).post(l1_create_namespace))
        .route("/l1/namespaces/{ns}/schema", get(l1_schema_get).post(l1_schema_set).delete(l1_schema_clear))
        .route("/l1/caps", get(l1_list_caps).post(l1_issue_cap))
        .route("/l1/revoke", post(l1_revoke))
        .route("/l2/{ns}", get(l2_scan))
        .route("/l3/u/{pk}", get(l3_scan))
        .route("/l2/{ns}/{*key}", get(l2_data).put(l2_data).delete(l2_data))
        .route("/l3/u/{pk}/{*key}", get(l3_data).put(l3_data).delete(l3_data))
        .route("/l2/{ns}/ql", post(ql_l2))
        .route("/l3/u/{pk}/ql", post(ql_l3))
        .route("/l2/{ns}/head", get(l2_head))
        .route("/l2/{ns}/changes", get(l2_changes))
        .route("/l3/u/{pk}/head", get(l3_head))
        .route("/l3/u/{pk}/changes", get(l3_changes))
        .route("/l2/{ns}/conflicts", get(l2_conflicts))
        .route("/l3/u/{pk}/conflicts", get(l3_conflicts))
        .route("/l2/{ns}/events", get(l2_events))
        .route("/l3/u/{pk}/events", get(l3_events))
        .layer(middleware::from_fn_with_state(state.clone(), auth_mw))
        .with_state(state.clone());
    Router::new()
        .route("/healthz", get(healthz))
        .merge(protected)
        .with_state(state)
}