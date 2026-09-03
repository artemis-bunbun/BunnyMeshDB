//! `bunnymeshdbd` — the server daemon: config → store → HTTP API.
//! Checkpoints on SIGINT/SIGTERM and every 60 s.

use bunnymeshdb::caps::{Capability, PermSet, RevocationSet, Scope, Tier};
use bunnymeshdb::core::ident::PublicKey;
use bunnymeshdb::core::meta;
use bunnymeshdb::server::config::Config;
use bunnymeshdb::server::{AppState, app};
use bunnymeshdb::storage::Store;
use clap::{Parser, Subcommand};
use parking_lot::{Mutex, RwLock};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "bunnymeshdbd", about = "BunnyMeshDB daemon")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the HTTP API.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))
        .init();
    let cli = Cli::parse();
    let config_path = match cli.cmd {
        Cmd::Serve { config } => config,
    };
    let cfg = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fatal: {e}");
            std::process::exit(1);
        }
    };

    let kp = match meta::load(std::path::Path::new(&cfg.node.data_dir)) {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("fatal: {e} (run `bunny init <dir>` first, pass its data dir in config)");
            std::process::exit(1);
        }
    };
    let root = kp.public();
    let mut store = match Store::open(std::path::Path::new(&cfg.node.data_dir)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fatal: open store: {e}");
            std::process::exit(1);
        }
    };

    // Admin capability bootstrap: generated at first boot (subject = root),
    // persisted in the sys/admin_cap meta key, printed at startup.
    let admin_cap: String = if let Some(v) = store.meta_get("sys/admin_cap") {
        String::from_utf8_lossy(v).into_owned()
    } else {
        let scope = Scope { host: cfg.node.name.clone(), tier: Tier::L1, ns: "*".into(), prefix: None };
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).expect("os rng");
        let cap = Capability::sign(scope, PermSet::ADMIN, None, u64::from_le_bytes(nonce), &kp);
        let header = cap.to_header();
        store.meta_set("sys/admin_cap", header.clone().into_bytes());
        header
    };

    // Revocation tombstones persisted in meta sys/revocations ("scope\tto\n").
    let mut revocations = RevocationSet::new();
    if let Some(v) = store.meta_get("sys/revocations") {
        for line in String::from_utf8_lossy(v).lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((scope_s, to_s)) = line.split_once('\t') {
                match (Scope::parse(scope_s), to_s.parse::<PublicKey>()) {
                    (Ok(scope), Ok(to)) => revocations.revoke_principal(&scope, &to.to_string()),
                    _ => {}
                }
            }
        }
    }

    tracing::info!(host = %cfg.node.name, listen = %cfg.node.listen, "serving");
    tracing::info!("admin cap: {admin_cap}");

    // --- mesh sync (M3) ---
    let (sync_tx, sync_rx) = tokio::sync::mpsc::channel::<()>(64);
    let store_arc: Arc<Mutex<bunnymeshdb::storage::Store>> = Arc::new(Mutex::new(store));
    let sync_cfg = Arc::new(Mutex::new(cfg.clone()));
    let engine = bunnymeshdb::net::SyncEngine::new(
        store_arc.clone(),
        kp.clone(),
        sync_cfg,
        config_path,
    );
    let sync_task = tokio::spawn(engine.run(sync_rx, 30));

    let state = AppState {
        store: store_arc,
        root,
        kp: Arc::new(kp),
        revocations: Arc::new(RwLock::new(revocations)),
        host_name: cfg.node.name.clone(),
        default_quota: cfg.node.l3.default_quota,
        sync_tx: Some(sync_tx),
    };

    // Periodic checkpoint every 60 s.
    let ckpt_store = state.store.clone();
    let ckpt_task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            ckpt_store.lock().checkpoint().ok();
        }
    });

    let listener = match tokio::net::TcpListener::bind(&cfg.node.listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("fatal: bind {}: {e}", cfg.node.listen);
            std::process::exit(1);
        }
    };

    let shutdown_store = state.store.clone();
    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal(shutdown_store))
        .await
        .expect("serve failed");
    ckpt_task.abort();
    sync_task.abort();
    tracing::info!("bye");
}

/// Wait for SIGINT/SIGTERM; checkpoint the store on the way out.
async fn shutdown_signal(store: Arc<Mutex<Store>>) {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let term = {
        let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        async move { sig.recv().await }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
    tracing::info!("signal received, checkpointing");
    store.lock().checkpoint().ok();
}