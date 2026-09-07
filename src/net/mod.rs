//! Mesh sync (M3): libp2p pull-only replication with TOFU pinning.
//!
//! Wire (JSON, request-response `/bmdb-sync/1.0.0`):
//! - `Hello` → `HelloResponse { host_id, hlc, namespaces: [{ns, seq, hash}] }`
//! - `Pull { ns, from_seq }` → `Records { ns, records: [{seq, payload_b64}] }`
//!   (chunk ≤ 1000 records / ~1 MiB)
//!
//! Pull-only: each tick, for namespaces present on both peers, pull from
//! `local_seq+1`, verify (CRC + intra-batch chain + HLC monotonic), append
//! via `Store::apply_synced`, checkpoint when >1000 records applied. Any
//! verification failure skips the namespace for this peer and retries next
//! tick — corruption is never introduced.
//!
//! Trust (MESH-001): requests are only served when the requester's
//! noise-authenticated peer id matches a stored pin (Pull), or the requester
//! is a configured-but-unpinned peer completing the TOFU Hello handshake
//! (Hello only — see `inbound_access`). Everything else is answered with an
//! explicit `SyncResponse::Denied` and nothing is read or stored.

pub mod merge;

use crate::core::hlc::Hlc;
use crate::core::ident::PublicKey;
use crate::net::merge::verify_batch;
use crate::server::config::Config;
use crate::storage::Store;
use crate::util::b64_encode;
use futures::StreamExt;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, StreamProtocol};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

// ---------- wire ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncRequest {
    Hello,
    Pull { ns: String, from_seq: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    Hello(HelloResponse),
    Records(Records),
    /// MESH-001: explicit refusal — the requester is not a configured peer
    /// whose stored pin's peer_id_of matches the connection-authenticated
    /// peer id. Nothing was read or stored for them; the puller sees this
    /// as a denial and backs off to the next tick.
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloResponse {
    pub host_id: String,
    pub hlc: u64,
    pub namespaces: Vec<NsHead>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsHead {
    pub ns: String,
    pub seq: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Records {
    pub ns: String,
    pub records: Vec<Rec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rec {
    pub seq: u64,
    pub payload_b64: String,
}

const PROTO: StreamProtocol = StreamProtocol::new("/bmdb-sync/1.0.0");
const MAX_RECORDS: usize = 1000;
const MAX_FRAME_BYTES: usize = 960 * 1024;
/// Records applied in one round before a checkpoint is forced.
const CHECKPOINT_EVERY: u64 = 1000;
/// MESH-005: at most this many pull chunks (one request-response round) per
/// peer per tick. A peer with a deep backlog — or a hostile one — cannot
/// monopolize a tick's event loop; the remainder defers to the next tick.
const MAX_CHUNKS_PER_TICK: u64 = 32;
/// MESH-006: a single record whose base64 payload alone exceeds ~8 MiB cannot
/// fit the codec's response cap (~10 MiB) even as a solo frame. Serving it
/// would wedge the stream; such records are refused and the namespace is
/// skipped for this round (the puller retries next tick — never a wedge).
const MAX_SINGLE_RECORD_B64: usize = 8 * 1024 * 1024;

#[derive(libp2p::swarm::NetworkBehaviour)]
struct Behaviour {
    sync: request_response::json::Behaviour<SyncRequest, SyncResponse>,
}

impl Behaviour {
    fn new() -> Behaviour {
        let cfg = request_response::Config::default()
            .with_request_timeout(std::time::Duration::from_secs(15));
        Behaviour {
            sync: request_response::json::Behaviour::new([(PROTO, ProtocolSupport::Full)], cfg),
        }
    }
}

// ---------- engine ----------

pub struct SyncEngine {
    pub store: Arc<RwLock<Store>>,
    /// Our node keypair; doubles as the libp2p identity (same ed25519 seed).
    pub kp: crate::core::ident::Keypair,
    pub cfg: Arc<Mutex<Config>>,
    pub cfg_path: PathBuf,
    /// Namespace-change fan-out (SSE push): Some when the daemon serves the
    /// HTTP events API — mesh-applied writes notify subscribers too.
    pub change_tx: Option<tokio::sync::broadcast::Sender<String>>,
    /// Median-of-8 skew samples per peer name.
    skew: HashMap<String, VecDeque<i64>>,
}

impl SyncEngine {
    pub fn new(
        store: Arc<RwLock<Store>>,
        kp: crate::core::ident::Keypair,
        cfg: Arc<Mutex<Config>>,
        cfg_path: PathBuf,
        change_tx: Option<tokio::sync::broadcast::Sender<String>>,
    ) -> SyncEngine {
        SyncEngine { store, kp, cfg, cfg_path, change_tx, skew: HashMap::new() }
    }

    /// Run the swarm event loop until shutdown. `trigger` fires a sync round
    /// immediately (HTTP writes); `tick_secs` is the periodic cadence.
    pub async fn run(self, mut trigger: mpsc::Receiver<()>, tick_secs: u64) {
        let identity = match make_libp2p_identity(&self.kp) {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(%e, "build libp2p identity");
                return;
            }
        };
        let mut swarm = match build_swarm(identity) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(%e, "swarm build failed ({tick_secs}s tick)");
                return;
            }
        };

        let p2p_listen = {
            let cfg = self.cfg.lock();
            cfg.node.p2p_listen.clone()
        };
        // `p2p_listen` is normally a bare TCP port, wrapped below as
        // /ip4/0.0.0.0/tcp/<port> (all interfaces). A "/"-containing value is
        // taken as a full multiaddr and used as-is (bind knob), e.g.
        // "/ip4/127.0.0.1/tcp/9002" to bind a specific interface.
        let listen_addr = if p2p_listen.contains('/') {
            p2p_listen.clone()
        } else {
            format!("/ip4/0.0.0.0/tcp/{p2p_listen}")
        };
        match listen_addr.parse::<Multiaddr>() {
            Ok(a) => {
                if let Err(e) = swarm.listen_on(a.clone()) {
                    tracing::warn!(%e, %a, "listen failed");
                }
            }
            Err(e) => tracing::warn!(%e, "bad p2p_listen {p2p_listen:?}"),
        }

        let mut runner = Runner {
            swarm,
            engine: self,
            peer: HashMap::new(),
            round_applied: 0,
            pending_dials: HashMap::new(),
            pending_pulls: HashMap::new(),
        };
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(tick_secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => runner.kick_all(),
                maybe = trigger.recv() => {
                    if maybe.is_none() { break; }
                    runner.kick_all();
                }
                event = runner.swarm.select_next_some() => runner.handle(event),
            }
        }
        runner.engine.store.write().checkpoint().ok();
        tracing::info!("sync loop exiting");
    }
}


/// Build the swarm: tokio + tcp + noise + yamux, one request-response behaviour.
/// The builder chain returns Results at two stages; flatten them here.
fn build_swarm(identity: libp2p::identity::Keypair) -> Result<libp2p::Swarm<Behaviour>, String> {
    let phase = libp2p::SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|e| format!("transport: {e}"))?;
    let phase = phase
        .with_behaviour(|_| Behaviour::new())
        .map_err(|e| format!("behaviour: {e}"))?;
    Ok(phase.build())
}
fn make_libp2p_identity(kp: &crate::core::ident::Keypair) -> Result<libp2p::identity::Keypair, String> {
    let mut seed = kp.to_seed();
    libp2p::identity::Keypair::ed25519_from_bytes(&mut seed)
        .map_err(|e| format!("ed25519_from_bytes: {e}"))
}

/// libp2p PeerId for a host pubkey (same ed25519 key). We derive the PeerId
/// from the raw pubkey bytes via the protobuf-encoding path used by libp2p:
/// PeerId is the sha256 multihash of the key, so this purely-derivable
/// function makes TOFU pinning and connection binding agree.
fn peer_id_of(pk: &PublicKey) -> PeerId {
    let ed = libp2p::identity::ed25519::PublicKey::try_from_bytes(&pk.to_bytes())
        .expect("valid ed25519 pk");
    PeerId::from_public_key(&libp2p::identity::PublicKey::from(ed))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn addr_key(a: &Multiaddr) -> String {
    a.to_string()
}

// ---------- peer runtime ----------

#[derive(Debug, Clone, PartialEq)]
enum Phase {
    /// Nothing in flight; next round starts fresh.
    Idle,
    /// Bare address dialed; awaiting ConnectionEstablished to bind the peer id.
    WaitingDial,
    /// Hello request sent; awaiting HelloResponse.
    AwaitingHello,
    /// A Pull for `ns` is in flight, expecting `target` total seq.
    Pulling { ns: String, target: u64 },
    /// Round finished for this peer.
    Done,
    /// Peer unusable this round (e.g. pin mismatch).
    Bad(String),
}

/// Per-connected-peer runtime state.
struct PeerCtx {
    addr: Multiaddr,
    pid: Option<PeerId>,
    pin: Option<PublicKey>,
    phase: Phase,
    /// Pull chunks processed this round (MESH-005): reset on every kick_all,
    /// capped at MAX_CHUNKS_PER_TICK per peer.
    round_chunks: u64,
}

/// MESH-001 access classification for an inbound request.
#[derive(Debug, Clone, PartialEq)]
enum InboundAccess {
    /// Requester is not a configured peer (or is a configured peer whose
    /// stored pin mismatches the connection): deny everything.
    Deny,
    /// Configured but unpinned: the TOFU Hello handshake may complete
    /// (that is how the pin is established) but no data is served.
    HelloOnly { name: String },
    /// Configured peer whose stored pin's peer_id_of matches the
    /// connection-authenticated peer id: full access (Hello + Pull).
    Full { name: String },
}

struct Runner {
    swarm: libp2p::Swarm<Behaviour>,
    engine: SyncEngine,
    peer: HashMap<String, PeerCtx>,
    round_applied: u64,
    /// Bare-address dials awaiting ConnectionEstablished: addr string → name.
    pending_dials: HashMap<String, String>,
    /// Per-name queue of namespaces still to pull this round.
    pending_pulls: HashMap<String, VecDeque<(String, u64)>>,
}

impl Runner {
    /// (Re)start a sync round for every configured peer not mid-flight.
    fn kick_all(&mut self) {
        tracing::info!("kick_all: {} peers", self.peer.keys().count());
        self.round_applied = 0;
        let peers: Vec<(String, String)> = {
            let cfg = self.engine.cfg.lock();
            cfg.peers.iter().map(|p| (p.name.clone(), p.addr.clone())).collect()
        };
        for (name, addr_s) in peers {
            let addr = match addr_s.parse::<Multiaddr>() {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!(peer = %name, %e, "bad peer addr {addr_s:?}");
                    continue;
                }
            };
            let pin = self.load_pin(&name);
            match self.peer.get_mut(&name) {
                Some(ctx) => {
                    ctx.addr = addr;
                    // MESH-005: a new round resets the per-peer chunk budget.
                    ctx.round_chunks = 0;
                    if matches!(ctx.phase, Phase::AwaitingHello | Phase::Pulling { .. } | Phase::WaitingDial) {
                        continue;
                    }
                    ctx.phase = Phase::Idle;
                    self.kick(name.clone());
                }
                None => {
                    self.peer.insert(
                        name.clone(),
                        PeerCtx { addr, pid: None, pin, phase: Phase::Idle, round_chunks: 0 },
                    );
                    self.kick(name);
                }
            }
        }
    }

    fn load_pin(&self, name: &str) -> Option<PublicKey> {
        let cfg = self.engine.cfg.lock();
        cfg.peer(name).and_then(|p| p.pin.parse::<PublicKey>().ok())
    }

    /// Advance one peer's round: ensure a connection, then send Hello.
    fn kick(&mut self, name: String) {
        tracing::info!("kick {name} phase={:?}", self.peer.get(&name).map(|c| c.phase.clone()));
        let phase = { self.peer.get(&name).map(|c| c.phase.clone()).unwrap_or(Phase::Idle) };
        if matches!(phase, Phase::AwaitingHello | Phase::Pulling { .. } | Phase::WaitingDial) {
            return;
        }
        let (pid_known, addr) = {
            let c = self.peer.get(&name).unwrap();
            (c.pid, c.addr.clone())
        };
        match pid_known {
            Some(pid) => {
                if !self.swarm.behaviour_mut().sync.is_connected(&pid) {
                    self.swarm.add_peer_address(pid, addr.clone());
                    if let Err(e) = self.swarm.dial(pid) {
                        tracing::warn!(peer = %name, %e, "dial");
                    }
                    self.phase_set(&name, Phase::WaitingDial);
                    return;
                }
                self.send_hello(name, pid);
            }
            None => {
                let key = addr_key(&addr);
                // A stale pending entry (previous dial failed before any
                // ConnectionEstablished) must never block a retry.
                self.pending_dials.remove(&key);
                match self.swarm.dial(addr.clone()) {
                    Ok(()) => {
                        self.pending_dials.insert(key, name.clone());
                        self.phase_set(&name, Phase::WaitingDial);
                    }
                    Err(e) => {
                        tracing::warn!(peer = %name, %e, "dial");
                        self.phase_set(&name, Phase::Idle);
                    }
                }
            }
        }
    }

    fn send_hello(&mut self, name: String, pid: PeerId) {
        self.swarm
            .behaviour_mut()
            .sync
            .send_request(&pid, SyncRequest::Hello);
        self.phase_set(&name, Phase::AwaitingHello);
    }

    // -- outbound response handling --

    fn on_hello(&mut self, pid: PeerId, resp: HelloResponse) {
        let name = match self.name_for_pid(pid) {
            Some(n) => n,
            None => {
                tracing::warn!(%pid, "hello from unknown peer");
                return;
            }
        };
        let peer_pk = match resp.host_id.parse::<PublicKey>() {
            Ok(pk) => pk,
            Err(e) => {
                tracing::warn!(peer = %name, %e, "bad host_id");
                self.phase_set(&name, Phase::Bad("bad host_id".into()));
                return;
            }
        };
        {
            let ctx = self.peer.get_mut(&name).unwrap();
            match ctx.pin {
                None => {
                    // MESH-003: TOFU only binds when the advertised host_id IS
                    // the key of the connection-authenticated peer id. We must
                    // never pin a key a Hello merely CLAIMS — an attacker who
                    // won the dial must not be able to permanently displace the
                    // peer's identity via a forged plaintext host_id.
                    let advertised_pid = peer_id_of(&peer_pk);
                    if pid != advertised_pid {
                        tracing::warn!(
                            peer = %name,
                            claimed = %resp.host_id,
                            auth_pid = %pid,
                            "hello host_id does not match the connection-authenticated peer id; refusing to pin",
                        );
                        self.phase_set(&name, Phase::Bad("host_id/connection mismatch".into()));
                        return;
                    }
                    ctx.pin = Some(peer_pk);
                    ctx.pid = Some(advertised_pid);
                    self.persist_pin(&name, &peer_pk);
                }
                Some(existing) if existing != peer_pk => {
                    tracing::warn!(peer = %name, expected = %existing, got = %resp.host_id, "[sync] peer pin mismatch");
                    self.phase_set(&name, Phase::Bad("pin mismatch".into()));
                    return;
                }
                Some(_) => {}
            }
        }

        // Clock estimate: median of the last 8 samples of (peer_hcl_ms - local_ms).
        let sample = (resp.hlc >> 16) as i64 - now_ms();
        let median = {
            let buf = self.engine.skew.entry(name.clone()).or_default();
            if buf.len() == 8 {
                buf.pop_front();
            }
            buf.push_back(sample);
            let mut v: Vec<i64> = buf.iter().copied().collect();
            v.sort_unstable();
            v[v.len() / 2]
        };
        self.engine.store.write().set_peer_clock(&name, median);

        // Namespaces to pull: we host them and the peer is ahead.
        let mut pulls: Vec<(String, u64)> = Vec::new();
        {
            let store = self.engine.store.read();
            for nh in &resp.namespaces {
                if store.policy(&nh.ns).is_none() {
                    continue;
                }
                if let Some((local_seq, _)) = store.head(&nh.ns) {
                    if local_seq < nh.seq {
                        // MESH-005: nh.seq is peer-supplied — never chase it
                        // further than (MAX_RECORDS × MAX_CHUNKS_PER_TICK × 2)
                        // ahead of our local head: a legitimately far-ahead
                        // peer still converges, over a few ticks, while a wild
                        // seq cannot force one unbounded pull binge.
                        let max_target = local_seq + (MAX_RECORDS as u64) * MAX_CHUNKS_PER_TICK * 2;
                        let target = nh.seq.min(max_target);
                        if local_seq < target {
                            pulls.push((nh.ns.clone(), target));
                        }
                    }
                }
            }
        }
        tracing::info!(peer = %name, pulls = ?pulls.iter().map(|(n,s)| format!("{n}@{s}")).collect::<Vec<_>>(), "hello processed");
        if pulls.is_empty() {
            self.phase_set(&name, Phase::Done);
            return;
        }
        let (ns, target) = pulls.remove(0);
        self.pending_pulls.insert(name.clone(), pulls.into_iter().collect());
        self.send_pull(name, ns, target);
    }

    fn send_pull(&mut self, name: String, ns: String, target: u64) {
        let pid = self.peer.get(&name).unwrap().pid.unwrap();
        let from_seq = {
            let store = self.engine.store.read();
            store.head(&ns).map(|(s, _)| s + 1).unwrap_or(1)
        };
        tracing::info!(peer = %name, ns = %ns, from_seq, target, pid = %pid, "sending pull");
        self.swarm
            .behaviour_mut()
            .sync
            .send_request(&pid, SyncRequest::Pull { ns: ns.clone(), from_seq });
        self.phase_set(&name, Phase::Pulling { ns, target });
    }

    fn on_records(&mut self, pid: PeerId, recs: Records) {
        tracing::info!(%pid, n = recs.records.len(), ns = %recs.ns, "records received");
        let name = match self.name_for_pid(pid) {
            Some(n) => n,
            None => return,
        };
        let (ns, target) = match self.peer.get(&name).map(|c| c.phase.clone()) {
            Some(Phase::Pulling { ns, target }) => (ns, target),
            _ => {
                tracing::warn!(peer = %name, "records without pending pull");
                return;
            }
        };
        if recs.ns != ns {
            tracing::warn!(peer = %name, got = %recs.ns, want = %ns, "records for wrong ns");
            self.phase_set(&name, Phase::Idle);
            return;
        }
        // MESH-002 residual: per-peer namespace allow-list, enforced at apply
        // time. A peer scoped to Some(list) may only contribute records to
        // the listed namespaces; None (the default) = all shared namespaces.
        // Read fresh from the shared config each batch so live edits apply to
        // the very next round (same semantics as inbound_access). A skipped
        // namespace progresses exactly like an empty chunk — warn, mark the
        // phase Done, and let the next Hello re-evaluate — never a wedge.
        let allowed = {
            let cfg = self.engine.cfg.lock();
            match cfg.peer(&name) {
                Some(p) => p.namespaces.as_ref().map(|list| list.contains(&ns)),
                None => None,
            }
        };
        match allowed {
            Some(false) => {
                tracing::warn!(peer = %name, ns = %ns, "peer not allowed to contribute to namespace; skipping namespace this round");
                self.phase_set(&name, Phase::Done);
                return;
            }
            _ => {}
        }
        let mut batch: Vec<(u64, Vec<u8>)> = Vec::with_capacity(recs.records.len());
        for r in &recs.records {
            match crate::util::b64_decode(&r.payload_b64) {
                Ok(bytes) => batch.push((r.seq, bytes)),
                Err(e) => {
                    tracing::warn!(peer = %name, ns = %ns, %e, "bad payload_b64");
                    self.phase_set(&name, Phase::Idle);
                    return;
                }
            }
        }
        let parsed = match verify_batch([0u8; 32], &batch) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(peer = %name, ns = %ns, %e, "[sync] skipping namespace this round");
                self.phase_set(&name, Phase::Done);
                return;
            }
        };
        let mut apply_failed = false;
        let mut applied = 0u64;
        let local_seq;
        {
            let mut store = self.engine.store.write();
            match store.apply_synced_batch(&ns, &parsed) {
                Ok(n) => {
                    self.round_applied += n;
                    applied = n;
                }
                Err(e) => {
                    tracing::warn!(peer = %name, ns = %ns, %e, "apply_synced");
                    apply_failed = true;
                }
            }
            if !apply_failed {
                if self.round_applied > 0 && self.round_applied % CHECKPOINT_EVERY <= parsed.len() as u64 {
                    if let Err(e) = store.checkpoint() {
                        tracing::warn!(%e, "checkpoint after sync");
                    }
                }
                local_seq = store.head(&ns).map(|(s, _)| s).unwrap_or(0);
                // Fan out to SSE subscribers: mesh-applied writes are change
                // events too (the local HTTP clients watching this ns).
                if let Some(tx) = &self.engine.change_tx {
                    let _ = tx.send(ns.clone());
                }
            } else {
                local_seq = 0;
            }
        }
        if apply_failed {
            self.phase_set(&name, Phase::Idle);
            return;
        }
        // MESH-005: require progress. An empty chunk — the peer is at/below
        // our from_seq, or the window held only records we already apply —
        // means re-pulling would loop forever over the same records. Treat it
        // like a verify failure: skip the namespace this round; the next
        // Hello re-evaluates from the current head.
        if applied == 0 {
            tracing::warn!(peer = %name, ns = %ns, local_seq, "pull applied 0 records; skipping namespace this round");
            self.phase_set(&name, Phase::Done);
            return;
        }
        // MESH-005: cap pull chunks per peer per tick — a backloggy (or
        // belligerent) peer must not monopolize a tick; the rest defers to
        // the next kick.
        let chunks = {
            let c = self.peer.get_mut(&name).unwrap();
            c.round_chunks += 1;
            c.round_chunks
        };
        if chunks >= MAX_CHUNKS_PER_TICK {
            tracing::info!(peer = %name, ns = %ns, chunks, "hit per-tick pull cap; deferring to next tick");
            self.phase_set(&name, Phase::Done);
            return;
        }
        if local_seq < target {
            self.send_pull(name.clone(), ns, target);
            return;
        }
        match self.pending_pulls.get_mut(&name).and_then(|q| q.pop_front()) {
            Some((next_ns, next_target)) => self.send_pull(name, next_ns, next_target),
            None => {
                self.pending_pulls.remove(&name);
                self.phase_set(&name, Phase::Done);
            }
        }
    }

    // -- inbound requests --

    /// Classify an inbound request by trust level. Computed fresh from the
    /// shared config on every call — no stale allow-list to refresh: live
    /// add/remove/pin edits apply to the very next request.
    ///
    /// The check is done purely on the connection-authenticated peer id:
    /// `peer` is the noise-verified identity of whoever sent the request.
    /// - A stored pin deriving to that pid ⇒ `Full`.
    /// - A pid we bound to an unpinned configured peer via our OWN outbound
    ///   dial (the TOFU trust anchor: the key that answered at the address we
    ///   configured) ⇒ `HelloOnly` — it may complete the handshake so the
    ///   pin can be established, but must not pull data yet.
    /// - A configured peer whose stored pin does NOT match the connection
    ///   (rotated key / MITM), or no config membership at all ⇒ `Deny`.
    fn inbound_access(&self, peer: PeerId) -> InboundAccess {
        let cfg = self.engine.cfg.lock();
        for p in &cfg.peers {
            if p.pin.is_empty() {
                continue;
            }
            let matches = match p.pin.parse::<PublicKey>() {
                Ok(pk) => peer_id_of(&pk) == peer,
                Err(_) => false, // a malformed pin never matches (fail closed)
            };
            if matches {
                return InboundAccess::Full { name: p.name.clone() };
            }
        }
        match self.name_for_pid(peer) {
            Some(name) if cfg.peer(&name).map(|p| p.pin.is_empty()).unwrap_or(false) => {
                InboundAccess::HelloOnly { name }
            }
            _ => InboundAccess::Deny,
        }
    }

    /// MESH-001 access classification for an inbound request.
    fn on_request(&mut self, peer: PeerId, request: SyncRequest, channel: request_response::ResponseChannel<SyncResponse>) {
        match self.inbound_access(peer) {
            InboundAccess::Deny => {
                tracing::warn!(%peer, "denied inbound sync request: not a configured+pinned peer");
                let _ = self.swarm.behaviour_mut().sync.send_response(channel, SyncResponse::Denied);
            }
            InboundAccess::HelloOnly { name } => match request {
                // TOFU bootstrap: an unpinned-but-configured peer may exchange
                // Hellos — that handshake is exactly how the pin gets bound
                // (MESH-003 verifies host_id against the connection pid) — but
                // it receives NO data until it is pinned (MESH-001).
                SyncRequest::Hello => self.serve_hello(name, peer, channel),
                SyncRequest::Pull { ns, .. } => {
                    tracing::warn!(%peer, name = %name, ns = %ns, "denied pull from unpinned peer");
                    let _ = self.swarm.behaviour_mut().sync.send_response(channel, SyncResponse::Denied);
                }
            },
            InboundAccess::Full { name } => match request {
                SyncRequest::Hello => self.serve_hello(name, peer, channel),
                SyncRequest::Pull { ns, from_seq } => self.serve_pull(name, peer, channel, ns, from_seq),
            },
        }
    }

    fn serve_hello(&mut self, name: String, peer: PeerId, channel: request_response::ResponseChannel<SyncResponse>) {
        tracing::info!(%peer, name = %name, "inbound hello");
        let (host_id, hlc, namespaces) = {
            let store = self.engine.store.read();
            let namespaces = store
                .namespaces_with_head()
                .into_iter()
                .map(|(ns, seq, hash)| NsHead { ns, seq, hash: hex::encode(hash) })
                .collect();
            (self.engine.kp.public().to_string(), Hlc::now().to_u64(), namespaces)
        };
        let resp = SyncResponse::Hello(HelloResponse { host_id, hlc, namespaces });
        let _ = self.swarm.behaviour_mut().sync.send_response(channel, resp);
    }

    fn serve_pull(&mut self, name: String, peer: PeerId, channel: request_response::ResponseChannel<SyncResponse>, ns: String, from_seq: u64) {
        tracing::info!(%peer, name = %name, ns = %ns, from_seq, "inbound pull");
        let records = {
            let store = self.engine.store.read();
            match store.log_records(&ns, from_seq, MAX_RECORDS as u64) {
                Ok(recs) => {
                    let mut out = Vec::new();
                    let mut bytes = 0usize;
                    let mut skip = false;
                    for (seq, payload) in recs {
                        let b64_len = (payload.len() + 2) / 3 * 4;
                        if b64_len > MAX_SINGLE_RECORD_B64 {
                            // MESH-006: a single record whose base64 alone
                            // exceeds ~8 MiB cannot fit the codec response cap
                            // (~10 MiB) even as a solo frame — serving it would
                            // wedge the stream permanently. Refuse the whole
                            // chunk: the puller applies nothing and skips the
                            // namespace this round, retrying next tick (a
                            // warning every round, never an infinite wedge).
                            tracing::warn!(peer = %name, ns = %ns, seq, b64_len, "record too large to serve; skipping namespace");
                            skip = true;
                            break;
                        }
                        if payload.len() > MAX_FRAME_BYTES {
                            // A record bigger than the chunk budget but within
                            // the codec cap: send it ALONE rather than skip it
                            // — an empty chunk makes the puller re-pull forever
                            // from the same seq.
                            if out.is_empty() {
                                out.push(Rec { seq, payload_b64: b64_encode(&payload) });
                            }
                            break;
                        }
                        if out.len() >= MAX_RECORDS || bytes + payload.len() > MAX_FRAME_BYTES {
                            break;
                        }
                        bytes += payload.len();
                        out.push(Rec { seq, payload_b64: b64_encode(&payload) });
                    }
                    if skip { Vec::new() } else { out }
                }
                Err(_) => Vec::new(),
            }
        };
        let resp = SyncResponse::Records(Records { ns, records });
        let _ = self.swarm.behaviour_mut().sync.send_response(channel, resp);
    }

    // -- event loop --

    fn handle(&mut self, event: SwarmEvent<<Behaviour as libp2p::swarm::NetworkBehaviour>::ToSwarm>) {
        // The derive names one variant per field; ours has a single `sync` field.
        match event {
            SwarmEvent::Behaviour(ev) => match ev {
                BehaviourEvent::Sync(inner) => self.handle_sync_event(inner),
            },
            other => self.handle_swarm_event(other),
        }
    }

    /// Non-behaviour swarm events (dial/conn lifecycle, listen).
    fn handle_swarm_event(&mut self, event: SwarmEvent<<Behaviour as libp2p::swarm::NetworkBehaviour>::ToSwarm>) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, connection_id: _, .. } => {
                if let libp2p::core::ConnectedPoint::Dialer { address, .. } = endpoint {
                    let key = addr_key(&address);
                    let name = self.pending_dials.remove(&key).or_else(|| {
                        // Dial-by-PeerId path (address already known): the
                        // peer is WaitingDial with no bound pid — bind it.
                        self.peer
                            .iter()
                            .find(|(_, c)| c.phase == Phase::WaitingDial && c.pid.is_none())
                            .map(|(n, _)| n.clone())
                    });
                    if let Some(name) = name {
                        let bind = {
                            let c = self.peer.get_mut(&name).unwrap();
                            c.pid = Some(peer_id);
                            c.phase == Phase::WaitingDial
                        };
                        if bind {
                            self.send_hello(name, peer_id);
                        }
                    }
                }
            }
            SwarmEvent::ConnectionClosed { peer_id, connection_id: _, .. } => {
                if let Some(name) = self.name_for_pid(peer_id) {
                    if self.peer.get(&name).map(|c| c.phase.clone()) == Some(Phase::WaitingDial) {
                        self.phase_set(&name, Phase::Idle);
                    }
                }
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, connection_id: _, .. } => {
                // A refused/failed dial must NOT strand the round: clear any
                // pending dial marker and fall back to Idle so the next tick
                // (or write trigger) retries.
                tracing::warn!(%error, peer = ?peer_id, "outgoing connection error");
                match peer_id {
                    Some(pid) => {
                        if let Some(name) = self.name_for_pid(pid) {
                            self.phase_set(&name, Phase::Idle);
                        }
                    }
                    None => {
                        self.pending_dials.clear();
                        for (name, ctx) in self.peer.iter_mut() {
                            if ctx.phase == Phase::WaitingDial {
                                ctx.phase = Phase::Idle;
                                tracing::info!(peer = %name, "dial failed, back to Idle");
                            }
                        }
                    }
                }
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!(%address, "[sync] listening");
            }
            _ => {}
        }
    }

    /// request-response events from the sync behaviour.
    fn handle_sync_event(&mut self, ev: request_response::Event<SyncRequest, SyncResponse>) {
        match ev {
            request_response::Event::Message { peer, message, connection_id: _ } => match message {
                request_response::Message::Request { request, channel, .. } => {
                    self.on_request(peer, request, channel);
                }
                request_response::Message::Response { response, .. } => match response {
                    SyncResponse::Hello(h) => self.on_hello(peer, h),
                    SyncResponse::Records(r) => self.on_records(peer, r),
                    // MESH-001: the serving peer refused us (we are not a
                    // pinned+configured peer on their side). Back off to Idle
                    // and retry next tick.
                    SyncResponse::Denied => {
                        if let Some(name) = self.name_for_pid(peer) {
                            tracing::warn!(peer = %name, "sync request denied by peer");
                            self.phase_set(&name, Phase::Idle);
                        }
                    }
                },
            },
            request_response::Event::OutboundFailure { peer, error, .. } => {
                if let Some(name) = self.name_for_pid(peer) {
                    tracing::warn!(peer = %name, %error, "outbound sync failure");
                    self.phase_set(&name, Phase::Idle);
                }
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                tracing::warn!(%peer, %error, "inbound sync failure");
            }
            _ => {}
        }
    }

    fn name_for_pid(&self, pid: PeerId) -> Option<String> {
        self.peer
            .iter()
            .find(|(_, c)| c.pid == Some(pid))
            .map(|(n, _)| n.clone())
    }

    fn phase_set(&mut self, name: &str, phase: Phase) {
        if let Some(c) = self.peer.get_mut(name) {
            c.phase = phase;
        }
    }

    fn persist_pin(&mut self, name: &str, pk: &PublicKey) {
        let mut failed = false;
        {
            let mut cfg = self.engine.cfg.lock();
            if let Some(p) = cfg.peer_mut(name) {
                p.pin = pk.to_string();
            }
            if let Err(e) = cfg.save(&self.engine.cfg_path) {
                // MESH-003: a swallowed persist failure silently leaves the
                // peer unpinned on disk — the next restart re-TOFUs, and a
                // MITM who wins that reconnect displaces the identity.
                // Escalate: error log + fail this kick so the operator sees
                // it. The in-memory pin still guards this running session.
                tracing::error!(%e, peer = %name, "FAILED to persist TOFU pin — in-memory pin only; sync may re-TOFU after restart");
                failed = true;
            }
        }
        if failed {
            self.phase_set(name, Phase::Bad("pin persist failed".into()));
        }
    }
}
#[cfg(test)]
mod tests {
}
