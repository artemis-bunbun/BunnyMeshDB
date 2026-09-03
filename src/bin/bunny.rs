//! `bunny` — the user-facing CLI: init a node directory, or run a REPL
//! against a data dir.

use bunnymeshdb::core::meta;
use bunnymeshdb::query::{QueryCtx, eval};
use bunnymeshdb::storage::Store;
use clap::{Parser, Subcommand};
use std::io::{BufRead, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "bunny", about = "BunnyMeshDB CLI")]
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
            let mut ctx = QueryCtx { store: &mut store, scope: None, host_id };
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