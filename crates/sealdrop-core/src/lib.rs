//! sealdrop core: packaging, age encryption, signed manifests, hardened extraction,
//! timed release. No interactive I/O lives here.

pub mod argon2id;
pub mod crypt;
pub mod error;
pub mod extract;
pub mod hashing;
pub mod keys;
pub mod manifest;
pub mod open;
pub mod pack;
pub mod passphrase;
pub mod policy;
pub mod probe;
pub mod progress;
pub mod release;
pub mod seal;

pub use error::{Error, Result};

/// Crate version, embedded in `meta.json` and manifests.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Tool string, e.g. `sealdrop 0.2.0`.
pub const TOOL: &str = concat!("sealdrop ", env!("CARGO_PKG_VERSION"));
