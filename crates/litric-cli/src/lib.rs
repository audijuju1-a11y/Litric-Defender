//! Client library for the `litricd` local API.
//!
//! The CLI in this crate is a *thin consumer* of the daemon: it owns no detection
//! logic. Everything here is transport, error mapping and rendering.

pub mod client;
