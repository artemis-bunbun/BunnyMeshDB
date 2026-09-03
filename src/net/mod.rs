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
use parking_lot::Mutex;
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
    pub store: Arc<Mutex<Store>>,
    /// Our node keypair; doubles as the libp2p identity (same ed25519 seed).
    pub kp: crate::core::ident::Keypair,
    pub cfg: Arc<Mutex<Config>>,
    pub cfg_path: PathBuf,
    /// Median-of-8 skew samples per peer name.
    skew: HashMap<String, VecDeque<i64>>,
}

impl SyncEngine {
    pub fn new(
        store: Arc<Mutex<Store>>,
        kp: crate::core::ident::Keypair,
        cfg: Arc<Mutex<Config>>,
        cfg_path: PathBuf,
    ) -> SyncEngine {
        SyncEngine { store, kp, cfg, cfg_path, skew: HashMap::new() }
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
        match format!("/ip4/0.0.0.0/tcp/{p2p_listen}").parse::<Multiaddr>() {
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
        runner.engine.store.lock().checkpoint().ok();
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

struct PeerCtx {
    addr: Multiaddr,
    pid: Option<PeerId>,
    pin: Option<PublicKey>,
    phase: Phase,
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
                    if matches!(ctx.phase, Phase::AwaitingHello | Phase::Pulling { .. } | Phase::WaitingDial) {
                        continue;
                    }
                    ctx.phase = Phase::Idle;
                    self.kick(name.clone());
                }
                None => {
                    self.peer.insert(
                        name.clone(),
                        PeerCtx { addr, pid: None, pin, phase: Phase::Idle },
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
                if self.pending_dials.contains_key(&key) {
                    return; // dial already in flight
                }
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
                    // TOFU: first successful Hello binds the pin.
                    let pk = peer_pk;
                    ctx.pin = Some(pk);
                    ctx.pid = Some(peer_id_of(&pk));
                    self.persist_pin(&name, &pk);
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
        self.engine.store.lock().set_peer_clock(&name, median);

        // Namespaces to pull: we host them and the peer is ahead.
        let mut pulls: Vec<(String, u64)> = Vec::new();
        {
            let store = self.engine.store.lock();
            for nh in &resp.namespaces {
                if store.policy(&nh.ns).is_none() {
                    continue;
                }
                if let Some((local_seq, _)) = store.head(&nh.ns) {
                    if local_seq < nh.seq {
                        pulls.push((nh.ns.clone(), nh.seq));
                    }
                }
            }
        }
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
            let store = self.engine.store.lock();
            store.head(&ns).map(|(s, _)| s + 1).unwrap_or(1)
        };
        self.swarm
            .behaviour_mut()
            .sync
            .send_request(&pid, SyncRequest::Pull { ns: ns.clone(), from_seq });
        self.phase_set(&name, Phase::Pulling { ns, target });
    }

    fn on_records(&mut self, pid: PeerId, recs: Records) {
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
        let local_seq;
        {
            let mut store = self.engine.store.lock();
            match store.apply_synced_batch(&ns, &parsed) {
                Ok(n) => self.round_applied += n,
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
            } else {
                local_seq = 0;
            }
        }
        if apply_failed {
            self.phase_set(&name, Phase::Idle);
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

    fn on_request(&mut self, peer: PeerId, request: SyncRequest, channel: request_response::ResponseChannel<SyncResponse>) {
        match request {
            SyncRequest::Hello => {
                let (host_id, hlc, namespaces) = {
                    let store = self.engine.store.lock();
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
            SyncRequest::Pull { ns, from_seq } => {
                let records = {
                    let store = self.engine.store.lock();
                    match store.log_records(&ns, from_seq) {
                        Ok(recs) => {
                            let mut out = Vec::new();
                            let mut bytes = 0usize;
                            for (seq, payload) in recs {
                                if out.len() >= MAX_RECORDS || bytes + payload.len() > MAX_FRAME_BYTES {
                                    break;
                                }
                                bytes += payload.len();
                                out.push(Rec { seq, payload_b64: b64_encode(&payload) });
                            }
                            out
                        }
                        Err(_) => Vec::new(),
                    }
                };
                let _ = peer;
                let resp = SyncResponse::Records(Records { ns, records });
                let _ = self.swarm.behaviour_mut().sync.send_response(channel, resp);
            }
        }
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
                    if let Some(name) = self.pending_dials.remove(&key) {
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
        let mut cfg = self.engine.cfg.lock();
        if let Some(p) = cfg.peer_mut(name) {
            p.pin = pk.to_string();
        }
        if let Err(e) = cfg.save(&self.engine.cfg_path) {
            tracing::warn!(%e, "persist pin");
        }
    }
}