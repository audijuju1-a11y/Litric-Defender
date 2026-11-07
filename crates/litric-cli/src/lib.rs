//! Client library for the `litricd` local API.
//!
//! The HTTP client in this crate is a *thin consumer* of the daemon: it owns no
//! detection logic. Everything here is transport, error mapping and rendering.
//! The separate `litric guard` command deliberately uses the core policy
//! in-process because it must launch a child after the scan.

pub mod client;
