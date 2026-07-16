// Unified nkct C-ABI shim. P2P transport is always built; the shared-keyring.db
// wrapper is compiled only under the `keyring` feature. See Cargo.toml.

pub mod p2p;
pub mod pty;

#[cfg(feature = "keyring")]
pub mod keyring;
