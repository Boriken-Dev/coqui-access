//! Building blocks shared by access providers, independent of any plugin host.
//!
//! | Module | Purpose |
//! | --- | --- |
//! | [`mod@secret`] | Generate a prefixed 256-bit secret, hash it with optional domain separation, compare in constant time. |
//! | [`mod@file`] | Atomic private (`0600`) writes, bounded reads, change stamps. |
//! | [`mod@store`] | A TOML document in one file that reloads when another process writes it. |
//!
//! Errors are plain `String`s that never contain file contents or secrets.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

pub mod file;
pub mod secret;
pub mod store;

pub use store::Store;
