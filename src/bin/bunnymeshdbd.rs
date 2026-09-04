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

// mimalloc (optional, `cargo build --features mimalloc`): Microsoft's
// allocator. We measured 32-conn GET / 4 workers: glibc + native malloc
// ~278k/s, musl + native malloc ~75k/s (musl's single shared heap collapses
// under worker contention), musl + mimalloc ~210-250k/s (parity with glibc),
// glibc + mimalloc ~244k/s (native glibc malloc is slightly better). So this
// exists to rescue Alpine/musl builds; leave it OFF for glibc/Ubuntu. The
// Docker-alpine build enables it via `--features mimalloc`.
#[cfg(feature = "mimalloc")]
use mimalloc::MiMalloc;
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Parser)]
#[command(name = "bunnymeshdbd", about = "BunnyMeshDB daemon")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the HTTP API (+ optional L3 FUSE mount).
    Serve {
        #[arg(long)]
        config: PathBuf,
        /// Mount the L3 filesystem at this path (Linux + /dev/fuse).
        #[arg(long)]
        mount: Option<PathBuf>,
    },
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))
        .init();
    let cli = Cli::parse();
    let (config_path, mount_at) = match cli.cmd {
        Cmd::Serve { config, mount } => (config, mount),
    };
    let cfg = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fatal: {e}");
            std::process::exit(1);
        }
    };

    // Build the runtime by hand so the worker count comes from config (and
    // defaults to a light 4 instead of one per core).
    let n_workers = cfg.node.worker_threads.max(1);
    tracing::info!(worker_threads = n_workers, "starting daemon runtime");
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(n_workers)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fatal: build runtime: {e}");
            std::process::exit(1);
        }
    };
    rt.block_on(run(config_path, mount_at, cfg));
}

async fn run(config_path: PathBuf, mount_at: Option<PathBuf>, cfg: Config) {
    let data_path = std::path::Path::new(&cfg.node.data_dir);
    // Guarded serve: if the data dir is uninitialized (no meta.bin), initialize
    // it inline so `serve` works on a fresh config without a separate `init`.
    // Never clobbers: if meta.bin exists but fails to load, that is corrupt and
    // we refuse to touch it.
    let kp = match meta::load(data_path) {
        Ok(kp) => kp,
        Err(_) if !data_path.join("meta.bin").exists() => {
            tracing::info!("data dir uninitialized — initializing {}", cfg.node.data_dir);
            match meta::init(data_path) {
                Ok(kp) => kp,
                Err(e) => {
                    eprintln!("fatal: init data dir: {e}");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("fatal: {e} (meta.bin exists but is unreadable — refusing to overwrite)");
            std::process::exit(1);
        }
    };
    let root = kp.public();
    let mut store = match Store::open_durable(std::path::Path::new(&cfg.node.data_dir), cfg.node.durable_writes) {
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
    // Optional: a daemon with mesh_sync=false skips the whole libp2p swarm
    // (noise/yamux/request-response allocations) — a lightweight API-only
    // node. Other mesh nodes can still pull from its log via their own
    // engines; this node just never dials or listens on p2p.
    let store_arc: Arc<RwLock<bunnymeshdb::storage::Store>> = Arc::new(RwLock::new(store));
    let (change_tx, _) = tokio::sync::broadcast::channel::<String>(256);
    let (sync_tx, sync_task);
    // Shared runtime config: the mesh engine dials from this Arc, and the
    // admin peer API mutates + saves it (so live peer edits reach the engine).
    let runtime_cfg: Arc<Mutex<bunnymeshdb::server::config::Config>> = Arc::new(Mutex::new(cfg.clone()));
    if cfg.node.mesh_sync {
        let (tx, rx) = tokio::sync::mpsc::channel::<()>(64);
        let engine = bunnymeshdb::net::SyncEngine::new(
            store_arc.clone(),
            kp.clone(),
            runtime_cfg.clone(),
            config_path.clone(),
            Some(change_tx.clone()),
        );
        let task = tokio::spawn(engine.run(rx, cfg.node.sync_interval_secs.max(1)));
        sync_tx = Some(tx);
        sync_task = Some(task);
    } else {
        tracing::info!("mesh sync disabled (mesh_sync=false) — API-only daemon");
        sync_tx = None;
        sync_task = None;
    }

    let state = AppState {
        store: store_arc,
        root,
        kp: Arc::new(kp),
        revocations: Arc::new(RwLock::new(revocations)),
        host_name: cfg.node.name.clone(),
        default_quota: cfg.node.l3.default_quota,
        sync_tx,
        change_tx: Arc::new(change_tx),
        rev_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        cap_cache: Arc::new(bunnymeshdb::ns::CapCache::new()),
        token_cache: Arc::new(bunnymeshdb::caps::TokenCache::new()),
        metrics: Arc::new(bunnymeshdb::server::Metrics::new()),
        ratelimiter: Arc::new(bunnymeshdb::server::ratelimit::RateLimiter::new(
            cfg.node.ratelimit.enabled,
            cfg.node.ratelimit.max_requests,
            cfg.node.ratelimit.window_secs,
        )),
        config: runtime_cfg,
        config_path,
    };

    // L3-as-filesystem (M4): mount in a background thread when requested.
    if let Some(mnt) = mount_at {
        if !std::path::Path::new("/dev/fuse").exists() {
            eprintln!("fatal: --mount requires /dev/fuse");
            std::process::exit(1);
        }
        // Provision the L3 namespace the mount backs (`u/<root>`, LWW),
        // mirroring ensure_l3_namespace — without it every write fails BadName.
        {
            let mut store = state.store.write();
            let ns = format!("u/{}", root);
            if store.policy(&ns).is_none() {
                if let Err(e) = store.create_namespace(&ns, bunnymeshdb::storage::ConflictPolicy::Lww) {
                    eprintln!("fatal: provision L3 namespace: {e}");
                    std::process::exit(1);
                }
            }
        }
        let fs = bunnymeshdb::fs::MeshFs::new(state.store.clone(), root.to_bytes());
        match fs.mount_and_run(mnt.clone()) {
            Ok(()) => tracing::info!(mount = %mnt.display(), "L3 filesystem mounted"),
            Err(e) => {
                eprintln!("fatal: mount {}: {e}", mnt.display());
                std::process::exit(1);
            }
        }
        // `_session` lives until process exit: its BackgroundSession drops on
        // process teardown, unmounting the FUSE connection so no stale mount
        // (Transport endpoint is not connected) survives a restart.
    }

    // Periodic checkpoint every 60 s.
    let ckpt_store = state.store.clone();
    let ckpt_task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            ckpt_store.write().checkpoint().ok();
        }
    });

    // Optional automatic log compaction + TTL GC for standalone nodes.
    // Refuses mesh-synced nodes (same safety guard as `bunnymeshdb compact`).
    if cfg.node.gc_interval_secs > 0 {
        let gc_store = state.store.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(cfg.node.gc_interval_secs));
            loop {
                tick.tick().await;
                match gc_store.write().gc_live() {
                    Ok(n) if n > 0 => tracing::info!("auto-compact: reclaimed {n} bytes"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(%e, "auto-compact skipped"),
                }
            }
        });
    }

    let shutdown_store = state.store.clone();
    let serve_app = app(state);
    match cfg.node.tls {
        Some(tls) => {
            tracing::info!("serving over TLS ({})", tls.cert_path);
            let listener = match bunnymeshdb::server::tls::build(&cfg.node.listen, &tls).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("fatal: {e}");
                    std::process::exit(1);
                }
            };
            axum::serve(listener, serve_app)
                .with_graceful_shutdown(shutdown_signal(shutdown_store))
                .await
                .expect("serve failed");
        }
        None => {
            let listener = match tokio::net::TcpListener::bind(&cfg.node.listen).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("fatal: bind {}: {e}", cfg.node.listen);
                    std::process::exit(1);
                }
            };
            axum::serve(listener, serve_app)
                .with_graceful_shutdown(shutdown_signal(shutdown_store))
                .await
                .expect("serve failed");
        }
    }
    ckpt_task.abort();
    if let Some(t) = sync_task {
        t.abort();
    }
    tracing::info!("bye");
}

/// Wait for SIGINT/SIGTERM; checkpoint the store on the way out.
async fn shutdown_signal(store: Arc<RwLock<Store>>) {
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
    store.write().checkpoint().ok();
}