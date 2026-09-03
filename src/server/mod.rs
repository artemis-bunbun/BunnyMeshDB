//! HTTP API server (axum) — L1 admin, L2/L3 data routes, capability auth.

pub mod config;

use crate::caps::{Capability, PermSet, RevocationSet, Scope, Tier};
use crate::core::hlc::Hlc;
use crate::core::ident::{Keypair, PublicKey};
use crate::ns::{account_write, authorize_cached, ensure_l3_namespace, CapCache};
use crate::query::{QueryCtx, eval};
use crate::storage::{ConflictPolicy, Entry, StorageError, Store};
use crate::util::{b64_encode, b64url_decode};
use axum::extract::{Extension, Path, Query as AxumQuery, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
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
    /// Revocation epoch — bumped on every revoke. Cap verify results cached
    /// against this epoch are valid until it changes.
    pub rev_epoch: Arc<std::sync::atomic::AtomicU64>,
    /// cap nonce → epoch it was fully verified in (bounded; see ns.rs).
    pub cap_cache: Arc<CapCache>,
}

impl AppState {
    fn notify_sync(&self) {
        if let Some(tx) = &self.sync_tx {
            let _ = tx.try_send(());
        }
    }
}

/// Capabilities attached by the auth middleware (Some for L1/L2 bearer caps,
/// None for headerless L3 requests).
#[derive(Clone)]
pub struct AuthCaps(pub Vec<Capability>);

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
    _state: State<AppState>,
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
        Some(h) => match parse_cap_header(h) {
            Ok(cap) => {
                let mut req = req;
                req.extensions_mut().insert(Some(AuthCaps(vec![cap])));
                next.run(req).await
            }
            Err(_) => err_json(StatusCode::UNAUTHORIZED, "invalid_capability"),
        },
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
        .map(|c| c.subject)
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

fn latest_value(e: &Entry) -> Option<Vec<u8>> {
    match e {
        Entry::Lww(v) => Some(v.value.clone()),
        Entry::Register(vs) => vs
            .iter()
            .max_by(|a, b| (a.hlc, a.replica).cmp(&(b.hlc, b.replica)))
            .map(|v| v.value.clone()),
    }
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
fn data_auth(
    state: &AppState,
    caps: Option<&AuthCaps>,
    ns: &str,
    key: &str,
) -> Result<(PublicKey, Tier), Response> {
    let tier = if ns.starts_with("u/") { Tier::L3 } else { Tier::L2 };
    let scope = data_scope(tier, ns, key, &state.host_name);
    let now = now_ms();
    if tier == Tier::L3 {
        auth_l3(state, &scope, now).map(|p| (p, tier))
    } else {
        auth_l1_l2(state, caps, &scope, PermSet::READ.union(PermSet::WRITE), now).map(|p| (p, tier))
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
    match data_auth(state, caps, ns, "") {
        Ok(_) => {}
        Err(r) => return r,
    }
    let store = state.store.read();
    let rows = store.scan(ns, p.as_bytes());
    let entries: Vec<JValue> = rows
        .into_iter()
        .map(|(k, e)| {
            json!({
                "key": String::from_utf8_lossy(&k),
                "value_b64": b64_encode(&latest_value(&e).unwrap_or_default()),
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
    let (principal, tier) = match data_auth(state, caps, ns, key) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let k = url_decoded(key);
    match method {
        Method::GET => {
            if let Some(p) = query.get("prefix") {
                let store = state.store.read();
                let rows = store.scan(ns, p.as_bytes());
                let entries: Vec<JValue> = rows
                    .into_iter()
                    .map(|(k, e)| {
                        json!({
                            "key": String::from_utf8_lossy(&k),
                            "value_b64": b64_encode(&latest_value(&e).unwrap_or_default()),
                        })
                    })
                    .collect();
                Json(json!({ "entries": entries })).into_response()
            } else {
                let store = state.store.read();
                match store.get(ns, &k) {
                    Some(e) => latest_value(e)
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
            match store.put(ns, &k, body, hlc, rid, principal.to_bytes()) {
                Ok(seq) => {
                    drop(store);
                    state.notify_sync();
                    Json(json!({ "ok": true, "seq": seq })).into_response()
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
    match data_auth(state, caps, ns, "") {
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

// ---------- router ----------

pub fn app(state: AppState) -> Router {
    let protected = Router::new()
        .route("/l1/namespaces", get(l1_list_namespaces).post(l1_create_namespace))
        .route("/l1/caps", get(l1_list_caps).post(l1_issue_cap))
        .route("/l1/revoke", post(l1_revoke))
        .route("/l2/{ns}", get(l2_scan))
        .route("/l3/u/{pk}", get(l3_scan))
        .route("/l2/{ns}/{*key}", get(l2_data).put(l2_data).delete(l2_data))
        .route("/l3/u/{pk}/{*key}", get(l3_data).put(l3_data).delete(l3_data))
        .route("/l2/{ns}/ql", post(ql_l2))
        .route("/l3/u/{pk}/ql", post(ql_l3))
        .layer(middleware::from_fn_with_state(state.clone(), auth_mw))
        .with_state(state.clone());
    Router::new()
        .route("/healthz", get(healthz))
        .merge(protected)
        .with_state(state)
}