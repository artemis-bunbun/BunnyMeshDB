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
    #[serde(default)]
    pub l3: L3,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct L3 {
    #[serde(default = "default_quota")]
    pub default_quota: u64,
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
fn default_listen() -> String {
    "127.0.0.1:8848".to_string()
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