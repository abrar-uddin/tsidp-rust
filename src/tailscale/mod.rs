//! Client for the tailscaled LocalAPI and the JSON shapes it returns.

pub mod localapi;
pub mod types;

pub use localapi::{LocalApi, LocalApiError};
pub use types::{Status, WhoIsResponse};
