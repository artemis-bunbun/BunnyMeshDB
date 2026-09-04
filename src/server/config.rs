//! Server config (`config.toml`).

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub node: Node,
    #[serde(default)]
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Node {
    /// Authority used in scope URLs and host validation.
    #[serde(default = "default_name")]
    pub name: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_listen")]
    pub listen: String,
    /// libp2p listen port (mesh sync).
    #[serde(default = "default_p2p_listen")]
    pub p2p_listen: String,
    /// Tokio worker threads for the daemon runtime (default 4 — the mesh
    /// workload rarely needs more; raise for single-node write throughput).
    #[serde(default = "default_workers")]
    pub worker_threads: usize,
    /// Build the libp2p mesh-sync engine (default true). Set false for a
    /// lightweight API-only daemon (no swarm/noise allocations — RSS drops
    /// ~60-80 MB); replication is then served by other nodes pulling from
    /// this node's log.
    #[serde(default = "default_mesh_sync")]
    pub mesh_sync: bool,
    /// Seconds between mesh pull rounds (default 30). Lower (e.g. 5) for more
    /// responsive convergence at the cost of a little extra background I/O;
    /// zero disables periodic pulls (writes still trigger a kick).
    #[serde(default = "default_sync_interval")]
    pub sync_interval_secs: u64,
    /// Fsync every write before acknowledging (default false). When false the
    /// store takes the fast no-per-record-fsync path — a crash can lose the
    /// single in-flight write. Set true for durability-sensitive workloads
    /// (write throughput drops accordingly).
    #[serde(default)]
    pub durable_writes: bool,
    /// Automatically compact logs + GC expired TTL rows every this many
    /// seconds (default 0 = off). Only applies to standalone (non-mesh-synced)
    /// nodes; the same safety guard as `bunnymeshdb compact`. Mesh-connected
    /// nodes are never auto-compacted (the log is the replication dedupe key).
    #[serde(default = "default_gc_interval")]
    pub gc_interval_secs: u64,
    /// Request rate limiting (on by default).
    #[serde(default)]
    pub ratelimit: Ratelimit,
    /// Optional TLS termination. When both `cert_path` (PEM cert chain) and
    /// `key_path` (PEM private key) are set, the HTTP API is served over
    /// TLS — capability tokens in flight are then encrypted at the transport
    /// layer (defense-in-depth; capability auth is still the app boundary).
    #[serde(default)]
    pub tls: Option<Tls>,
    #[serde(default)]
    pub l3: L3,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Tls {
    /// Path to a PEM certificate chain (leaf first).
    pub cert_path: String,
    /// Path to the matching PEM private key (PKCS#8 / SEC1 / PKCS#1).
    pub key_path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct L3 {
    #[serde(default = "default_quota")]
    pub default_quota: u64,
}

/// Request rate limiting. On by default to keep a default-deployed node cheap
/// to DoS; a developer can dial it back (or disable via `enabled = false`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ratelimit {
    #[serde(default = "default_ratelimit_enabled")]
    pub enabled: bool,
    /// Max requests per token per window; 0 = effectively unlimited.
    #[serde(default = "default_ratelimit_max")]
    pub max_requests: u64,
    /// Sliding-window size in seconds.
    #[serde(default = "default_ratelimit_window")]
    pub window_secs: u64,
}

impl Default for Ratelimit {
    fn default() -> Ratelimit {
        default_ratelimit()
    }
}

fn default_ratelimit_enabled() -> bool {
    true
}
fn default_ratelimit_max() -> u64 {
    600
}
fn default_ratelimit_window() -> u64 {
    60
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Peer {
    pub name: String,
    pub addr: String,
    /// TOFU pin — peer host_id hex, filled on first successful Hello.
    #[serde(default)]
    pub pin: String,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            node: Node {
                name: default_name(),
                data_dir: default_data_dir(),
                listen: default_listen(),
                p2p_listen: default_p2p_listen(),
                worker_threads: default_workers(),
                mesh_sync: default_mesh_sync(),
                sync_interval_secs: default_sync_interval(),
                durable_writes: false,
                gc_interval_secs: default_gc_interval(),
                ratelimit: default_ratelimit(),
                tls: None,
                l3: L3 { default_quota: default_quota() },
            },
            peers: Vec::new(),
        }
    }
}

impl Default for Node {
    fn default() -> Node {
        Node {
            name: default_name(),
            data_dir: default_data_dir(),
            listen: default_listen(),
            p2p_listen: default_p2p_listen(),
            worker_threads: default_workers(),
            mesh_sync: default_mesh_sync(),
            sync_interval_secs: default_sync_interval(),
            durable_writes: false,
            gc_interval_secs: default_gc_interval(),
            ratelimit: default_ratelimit(),
            tls: None,
            l3: L3 { default_quota: default_quota() },
        }
    }
}

impl Default for L3 {
    fn default() -> L3 {
        L3 { default_quota: default_quota() }
    }
}

fn default_name() -> String {
    "api.bunnymeshdb.test.com".to_string()
}
fn default_data_dir() -> String {
    "./data".to_string()
}
fn default_workers() -> usize {
    4
}
fn default_mesh_sync() -> bool {
    true
}
fn default_sync_interval() -> u64 {
    30
}
fn default_gc_interval() -> u64 {
    0
}
fn default_ratelimit() -> Ratelimit {
    Ratelimit {
        enabled: default_ratelimit_enabled(),
        max_requests: default_ratelimit_max(),
        window_secs: default_ratelimit_window(),
    }
}
fn default_listen() -> String {
    "127.0.0.1:8848".to_string()
}
fn default_p2p_listen() -> String {
    "9002".to_string()
}
fn default_quota() -> u64 {
    1073741824 // 1 GiB
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("read config {path:?}: {e}"))?;
        let mut cfg: Config = toml::from_str(&text)
            .map_err(|e| format!("parse config {path:?}: {e}"))?;
        // Normalize: data_dir relative to the config file's directory.
        if let Some(parent) = path.parent() {
            if !cfg.node.data_dir.starts_with('/') {
                cfg.node.data_dir = parent.join(&cfg.node.data_dir).to_string_lossy().into_owned();
            }
        }
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = toml::to_string(self).map_err(|e| format!("serialize config: {e}"))?;
        std::fs::write(path, text).map_err(|e| format!("write config {path:?}: {e}"))
    }

    pub fn peer_mut(&mut self, name: &str) -> Option<&mut Peer> {
        self.peers.iter_mut().find(|p| p.name == name)
    }

    pub fn peer(&self, name: &str) -> Option<&Peer> {
        self.peers.iter().find(|p| p.name == name)
    }

    /// Add a peer (name + libp2p multiaddr). Errors if the name already exists.
    pub fn add_peer(&mut self, name: &str, addr: &str) -> Result<(), String> {
        if self.peer(name).is_some() {
            return Err(format!("peer {name:?} already exists"));
        }
        match addr.to_string().parse::<libp2p::Multiaddr>() {
            Ok(_) => {}
            Err(_) => return Err(format!("invalid peer addr {addr:?}")),
        }
        self.peers.push(Peer { name: name.to_string(), addr: addr.to_string(), pin: "".to_string() });
        Ok(())
    }

    /// Remove a peer by name. Returns true if it was present.
    pub fn remove_peer(&mut self, name: &str) -> bool {
        let before = self.peers.len();
        let mut keep: Vec<Peer> = Vec::new();
        for p in self.peers.iter() {
            if p.name != name {
                keep.push(p.clone());
            }
        }
        self.peers = keep;
        self.peers.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_with_defaults_and_relpath() {
        let dir = std::env::temp_dir().join(format!("bmd-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.toml");
        std::fs::write(
            &p,
            r#"
[node]
name = "api.bunnymeshdb.test.com"
listen = "127.0.0.1:8848"

[node.l3]
default_quota = 1024

[[peers]]
name = "node2"
addr = "/ip4/127.0.0.1/tcp/9002"
"#,
        )
        .unwrap();
        let cfg = Config::load(&p).unwrap();
        assert_eq!(cfg.node.name, "api.bunnymeshdb.test.com");
        assert_eq!(cfg.node.listen, "127.0.0.1:8848");
        assert_eq!(cfg.node.l3.default_quota, 1024);
        // data_dir defaulted and made absolute relative to config location
        assert!(cfg.node.data_dir.starts_with(&dir.to_string_lossy().into_owned()));
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].pin, "");
    }

    #[test]
    fn missing_file_errors() {
        assert!(Config::load(Path::new("/nonexistent/bmdb/config.toml")).is_err());
    }
}