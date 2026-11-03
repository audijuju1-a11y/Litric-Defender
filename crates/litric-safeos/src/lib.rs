//! Litric SafeOS — portable safety core for application isolation.
//!
//! What this crate is: the policy and data-integrity half of SafeOS. Risk
//! classification, fail-closed execution policy, the secure file broker, the
//! session journal/recovery planner, Windows Sandbox configuration generation
//! and backend availability reporting. Everything here is deterministic and
//! unit-tested; none of it requires Windows to verify.
//!
//! What this crate is **not**: a hypervisor client, a WFP engine or a sandbox
//! launcher. Those need a Windows host with Hyper-V, the Windows Sandbox feature
//! and (for WFP) administrator rights, none of which exist in this build
//! environment. They are reported as unavailable rather than simulated. See
//! `docs/SAFEOS_LIMITATIONS.md`.
//!
//! Design rules:
//!
//! * **Fail closed.** When isolation is required but unavailable, the decision is
//!   `Deny` — never "run on the host anyway".
//! * **Unsigned is not malicious.** Absence of a signature lowers trust; it never
//!   by itself raises the risk level.
//! * **Unknown is not clean.** An unverified application lands at Level 1 and
//!   needs isolation, not a green check.
//! * **No silent data loss.** The broker stages, verifies and never overwrites
//!   without explicit approval.

pub mod broker;
pub mod journal;
pub mod model;
pub mod policy;
pub mod risk;
pub mod sandbox;

pub use model::{BackendStatus, Blocker, ExecutionLevel, HostFacts, Readiness};
pub use policy::{Action, BackendSet, Decision};
pub use risk::{ApplicationFacts, HashTrust, RiskAssessment};
