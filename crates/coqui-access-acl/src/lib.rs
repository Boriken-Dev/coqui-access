#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::alloc_instead_of_core
)]

extern crate alloc;

mod check;
mod condition;
mod entry;
mod error;
mod inherit;
mod options;
mod path;
mod principal;
mod rights;

pub use check::{Context, Decision};
pub use condition::{Conditions, Truth};
pub use entry::{Acl, Effect, Entry, Inherit, ItemAcl, Mode};
pub use error::AclError;
pub use inherit::Child;
pub use options::{Limits, OnMissing, Options, Weakening};
pub use path::AclStore;
pub use principal::{Principal, PrincipalError};
pub use rights::{Rights, RightsSchema, RightsSchemaBuilder};
