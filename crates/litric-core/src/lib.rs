//! Litric Defender core engine.
//!
//! This crate is the detection brain of Litric Defender. It is deliberately
//! platform-neutral so the same code runs in the Windows service, in the CLI
//! scanner on any platform, and in the automated test suite.
//!
//! Layers, bottom-up:
//! * `bytes`/`hash`/`entropy` — total, bounds-checked primitives
//! * `pe`/`authenticode`/`format`/`archive` — static structure analysis
//! * `rules` — Litric Rule Syntax engine with its own Aho-Corasick matcher
//! * `heuristics` — weighted, explainable behavioural/structural signals
//! * `engine` — aggregation into a single verdict with evidence
//! * `threatdb` — signed, versioned, revocable detection database
//! * `scan` — orchestration, budgets, caching, accounting
//! * `scan_quarantine` — post-scan quarantine of malicious detections
//! * `quarantine` — encrypted vault
//! * `ranshield`/`honeyvault` — anti-ransomware behavioural engine
//! * `mitre` — ATT&CK mapping for every signal we emit

pub mod archive;
pub mod biff;
pub mod deobfuscate;
pub mod authenticode;
pub mod bytes;
pub mod engine;
pub mod entropy;
pub mod error;
pub mod format;
pub mod guard;
pub mod hash;
pub mod heuristics;
pub mod pe;
pub mod quarantine;
pub mod ranshield;
pub mod rules;
pub mod safety;
pub mod scan;
pub mod scan_quarantine;
pub mod taxonomy;
pub mod threatdb;
pub mod vba;
#[cfg(windows)]
pub mod winplatform;
pub mod xlm;

/// Semantic version of the detection engine. Threat databases declare a
/// `min_engine`; a database that requires a newer engine is refused rather
/// than silently half-applied.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Engine identity used in verdicts, logs and update manifests.
pub const ENGINE_NAME: &str = "litric-engine";
