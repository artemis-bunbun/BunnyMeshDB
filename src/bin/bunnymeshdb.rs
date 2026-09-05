//! `bunnymeshdb` — the user-facing CLI: init a node directory, or run a REPL
//! against a data dir.
#![deny(warnings)]

use bunnymeshdb::core::meta;
use bunnymeshdb::query::{QueryCtx, eval};
use bunnymeshdb::storage::Store;
use clap::{Parser, Subcommand};
use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Recursively copy `src` → `dst`. Backups hold the root private key
/// (`meta.bin`), so every copied file is written 0600 (same-owner).
fn copy_tree(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dst).map_err(|e| format!("mkdir {}: {e}", dst.display()))?;
    let iter = std::fs::read_dir(src).map_err(|e| format!("read dir {}: {e}", src.display()))?;
    for entry in iter {
        let entry = entry.map_err(|e| format!("read entry in {}: {e}", src.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "." || name == ".." {
            continue;
        }
        let from = src.join(&name);
        let to = dst.join(&name);
        let is_dir = entry.file_type().map_err(|e| format!("stat {}: {e}", from.display()))?.is_dir();
        if is_dir {
            copy_tree(&from, &to)?;
        } else {
            copy_file(&from, &to)?;
        }
    }
    Ok(())
}

fn copy_file(src: &Path, dst: &Path) -> Result<(), String> {
    let bytes = std::fs::read(src).map_err(|e| format!("read {}: {e}", src.display()))?;
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(dst)
        .map_err(|e| format!("create {}: {e}", dst.display()))?;
    f.write_all(&bytes).map_err(|e| format!("write {}: {e}", dst.display()))?;
    f.sync_all().map_err(|e| format!("sync {}: {e}", dst.display()))?;
    Ok(())
}

#[derive(Parser)]
#[command(name = "bunnymeshdb", about = "BunnyMeshDB CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a node data directory (generates the root keypair).
    Init { dir: PathBuf },
    /// Interactive REPL over a data dir.
    Repl {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// List mesh peers (name, addr, TOFU pin) from the server config.
    Peers {
        #[arg(long)]
        config: PathBuf,
    },
    /// Clear a peer's TOFU pin (re-pins on next successful Hello).
    Untrust {
        #[arg(long)]
        config: PathBuf,
        name: String,
    },
    /// Rotate the node's root keypair. Persists a fresh key as active; the
    /// previous active key is kept valid (so existing caps keep working)
    /// unless --drop-predecessor, which severs it (existing caps must be
    /// re-issued). The daemon must be stopped. Pass --reissue-admin to sign
    /// a fresh L1 admin cap with the new key.
    RotateKey {
        /// Node data dir to rotate.
        data: PathBuf,
        /// Sever the previous root key (compromise recovery): it can no
        /// longer mint caps; all its caps are invalid and must be re-issued.
        #[arg(long)]
        drop_predecessor: bool,
        /// Also sign a fresh L1 admin cap with the new key (recommended after
        /// a drop, to avoid losing admin access).
        #[arg(long)]
        reissue_admin: bool,
    },
    /// Snapshot a node's data dir (checkpointed, crash-consistent) to `out`.
    Backup {
        /// Node data dir to back up.
        data: PathBuf,
        /// Destination directory for the backup.
        #[arg(long)]
        out: PathBuf,
    },
    /// Restore a previously-taken backup back into a node data dir.
    Restore {
        /// Backup directory produced by `bunnymeshdb backup`.
        backup: PathBuf,
        /// Target data dir (must not already contain a node).
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Compact logs + GC expired TTL entries (standalone nodes only; the
    /// daemon must be stopped). Refuses a node that has mesh-synced.
    Compact {
        /// Node data dir to compact.
        data: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Init { dir } => {
            let data = dir.join("data");
            match meta::init(&data) {
                Ok(kp) => println!("node key: {}", kp.public()),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Peers { config } => {
            match bunnymeshdb::server::config::Config::load(&config) {
                Ok(cfg) => {
                    if cfg.peers.is_empty() {
                        println!("(no peers configured)");
                    }
                    for p in &cfg.peers {
                        let pin = if p.pin.is_empty() { "(none)" } else { &p.pin };
                        println!("{}  {}  pin={}", p.name, p.addr, pin);
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Untrust { config, name } => {
            match bunnymeshdb::server::config::Config::load(&config) {
                Ok(mut cfg) => {
                    match cfg.peer_mut(&name) {
                        Some(p) => {
                            p.pin.clear();
                            match cfg.save(&config) {
                                Ok(()) => println!("cleared pin for {name}"),
                                Err(e) => {
                                    eprintln!("error: {e}");
                                    std::process::exit(1);
                                }
                            }
                        }
                        None => {
                            eprintln!("error: no peer named {name:?}");
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Backup { data, out } => {
            // Open validates integrity, then checkpoint flushes logs + snapshot
            // so the copy below is crash-consistent (no torn tail).
            let mut store = match Store::open(&data) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: open store: {e}");
                    std::process::exit(1);
                }
            };
            match store.checkpoint() {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("error: checkpoint: {e}");
                    std::process::exit(1);
                }
            }
            drop(store);
            match copy_tree(&data, &out) {
                Ok(()) => println!("backup written to {}", out.display()),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Restore { backup, data_dir } => {
            if data_dir.join("meta.bin").exists() {
                eprintln!("error: {} already contains a node (meta.bin present)", data_dir.display());
                std::process::exit(1);
            }
            match copy_tree(&backup, &data_dir) {
                Ok(()) => println!("restored {} → {}", backup.display(), data_dir.display()),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Compact { data } => {
            match bunnymeshdb::storage::compact_dir(&data) {
                Ok(reclaimed) => {
                    println!("compacted {} ({} bytes reclaimed); logs restarted at seq 1", data.display(), reclaimed);
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::RotateKey { data, drop_predecessor, reissue_admin } => {
            match bunnymeshdb::core::rotate::rotate_root(&data, drop_predecessor, reissue_admin) {
                Ok(out) => {
                    if let Some(h) = out.admin_cap {
                        println!("new admin cap: {h}");
                    }
                    if let Some(w) = out.admin_warning {
                        eprintln!("warning: {w}");
                    }
                    if out.dropped {
                        println!("rotated root key: {} → {}", out.old_root, out.new_root);
                        println!("predecessor DROPPED — every cap signed by {} is now invalid; re-issue them.", out.old_root);
                    } else {
                        println!("rotated root key: {} → {}", out.old_root, out.new_root);
                        println!("predecessor {} kept valid — existing caps/records still verify (graceful).", out.old_root);
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Commands::Repl { data_dir } => {
            let kp = match meta::load(&data_dir) {
                Ok(kp) => kp,
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            };
            let mut store = match Store::open(&data_dir) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            };
            let host_id = kp.public();
            let mut ctx = QueryCtx { store: &mut store, scope: None, host_id, remote: false };
            repl(&mut ctx);
        }
    }
}

fn repl(ctx: &mut QueryCtx) {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    let mut line = String::new();
    loop {
        line.clear();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(e) => {
                eprintln!("ERR read: {e}");
                break;
            }
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "exit" {
            break;
        }
        match eval(ctx, trimmed) {
            Ok(v) => {
                let _ = writeln!(out, "{}", v.json());
            }
            Err(e) => {
                let _ = writeln!(out, "ERR {e:?}");
            }
        }
        let _ = out.flush();
    }
}