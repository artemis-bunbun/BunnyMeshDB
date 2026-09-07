//! BunnyMeshDB library crate: core, storage, query (bins are thin shells).
//! Warnings are denied (treated as errors) for this crate only — the
//! compiler enforces the zero-warning rule rather than a log-scan in CI, and
//! dependency warnings never break the build.
#![deny(warnings)]

pub mod caps;
pub mod core;
pub mod fs;
pub mod net;
pub mod ns;
pub mod util;
pub mod query;
pub mod schema;
pub mod server;
pub mod storage;

/// Release version, kept in lockstep with `Cargo.toml [package] version`.
/// Exposed for `--version` on the CLI and daemon binaries.
pub const VERSION: &str = "0.4.1";