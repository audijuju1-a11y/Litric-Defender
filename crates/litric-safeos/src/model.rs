//! Host capability model and readiness evaluation.
//!
//! The facts here are *evidence supplied by the Windows platform agent*, not
//! values guessed from the build. This crate never probes the host itself. If no
//! agent has supplied facts, `known` is false and every backend is unavailable.

use serde_json::Value;

/// A UTC calendar date used for lifecycle decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LifecycleDate {
    pub year: i32,
    pub month: u8,
    pub day: u8,
}

impl LifecycleDate {
    pub const fn new(year: i32, month: u8, day: u8) -> Self {
        LifecycleDate { year, month, day }
    }

    /// Today's UTC date, derived from the system clock without a date crate.
    pub fn today() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        civil_from_days(secs.div_euclid(86_400))
    }
}

impl std::fmt::Display for LifecycleDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// One Windows 11 release and the end-of-servicing dates that apply to it.
///
/// This is the single source of truth for build acceptance. The dates come from
/// Microsoft's Windows 11 release information: Home/Pro/Pro Education/Pro for
/// Workstations receive 24 months, Enterprise/Education receive 36 months.
#[derive(Debug, Clone, Copy)]
pub struct WindowsRelease {
    pub name: &'static str,
    pub build: u32,
    pub home_pro_end: LifecycleDate,
    pub enterprise_education_end: LifecycleDate,
}

/// Windows 11 releases Litric accepts. Builds absent from this table are not
/// claimed as supported, even when their number is above a historical floor.
pub const WINDOWS_11_RELEASES: &[WindowsRelease] = &[
    WindowsRelease {
        name: "24H2",
        build: 26_100,
        home_pro_end: LifecycleDate::new(2026, 10, 14),
        enterprise_education_end: LifecycleDate::new(2027, 10, 12),
    },
    WindowsRelease {
        name: "25H2",
        build: 26_200,
        home_pro_end: LifecycleDate::new(2027, 10, 12),
        enterprise_education_end: LifecycleDate::new(2028, 10, 10),
    },
    WindowsRelease {
        name: "26H1",
        build: 28_000,
        home_pro_end: LifecycleDate::new(2028, 3, 14),
        enterprise_education_end: LifecycleDate::new(2029, 3, 13),
    },
    WindowsRelease {
        name: "26H2",
        build: 26_300,
        home_pro_end: LifecycleDate::new(2028, 10, 10),
        enterprise_education_end: LifecycleDate::new(2029, 10, 9),
    },
];

/// Lifecycle outcome for a reported build and edition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildSupport {
    Supported {
        release: &'static str,
        end: LifecycleDate,
        edition: &'static str,
    },
    Expired {
        release: &'static str,
        end: LifecycleDate,
        edition: &'static str,
    },
    UnknownBuild,
    UnknownEdition,
}

impl BuildSupport {
    pub fn is_supported(self) -> bool {
        matches!(self, BuildSupport::Supported { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EditionChannel {
    HomePro,
    Enterprise,
}

fn edition_channel(edition: &str) -> Option<(EditionChannel, &'static str)> {
    let e = edition.to_ascii_lowercase();
    if e.contains("pro education")
        || e.contains("home")
        || e.contains("pro for workstations")
        || e.contains(" se")
    {
        return Some((EditionChannel::HomePro, "Home/Pro"));
    }
    if e.contains("enterprise") || e.contains("education") {
        return Some((EditionChannel::Enterprise, "Enterprise/Education"));
    }
    if e.contains("pro") {
        return Some((EditionChannel::HomePro, "Home/Pro"));
    }
    None
}

/// Resolves a reported build and edition against the one lifecycle table above.
pub fn lifecycle_status(facts: &HostFacts, today: LifecycleDate) -> BuildSupport {
    let Some(release) = WINDOWS_11_RELEASES
        .iter()
        .find(|r| r.build == facts.windows_build)
    else {
        return BuildSupport::UnknownBuild;
    };
    let Some((channel, edition)) = edition_channel(&facts.windows_edition) else {
        return BuildSupport::UnknownEdition;
    };
    let end = match channel {
        EditionChannel::HomePro => release.home_pro_end,
        EditionChannel::Enterprise => release.enterprise_education_end,
    };
    if today > end {
        BuildSupport::Expired {
            release: release.name,
            end,
            edition,
        }
    } else {
        BuildSupport::Supported {
            release: release.name,
            end,
            edition,
        }
    }
}

/// Converts days since the Unix epoch to a proleptic Gregorian date.
/// Howard Hinnant's civil-from-days algorithm; no external date dependency.
fn civil_from_days(days: i64) -> LifecycleDate {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(month <= 2);
    LifecycleDate {
        year: year as i32,
        month: month as u8,
        day: day as u8,
    }
}

/// Below this the resource governor refuses to start a VM.
pub const MIN_RAM_MB: u64 = 4096;
/// Free disk needed for a disposable sandbox session.
pub const MIN_DISK_SANDBOX_MB: u64 = 10 * 1024;
/// Free disk needed for a managed Hyper-V session (base + overlay).
pub const MIN_DISK_VM_MB: u64 = 20 * 1024;

/// Execution isolation level, 0 (trusted) to 3 (confirmed malicious).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExecutionLevel {
    Trusted = 0,
    Unknown = 1,
    Suspicious = 2,
    Malicious = 3,
}

impl ExecutionLevel {
    pub fn number(self) -> u8 {
        self as u8
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ExecutionLevel::Trusted => "trusted",
            ExecutionLevel::Unknown => "unknown",
            ExecutionLevel::Suspicious => "suspicious",
            ExecutionLevel::Malicious => "malicious",
        }
    }
}

/// Facts collected from the Windows host by a platform agent.
///
/// Every field is optional evidence: a missing value is `None`/zero and makes the
/// corresponding backend unavailable, never "probably fine".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    /// False when no agent has reported anything; everything is then unavailable.
    pub known: bool,
    pub windows_edition: String,
    pub windows_build: u32,
    /// VT-x/AMD-V exposed to the OS and not disabled by policy.
    pub virtualization_enabled: bool,
    pub hyperv_feature_present: bool,
    pub sandbox_feature_present: bool,
    pub total_ram_mb: u64,
    pub free_disk_mb: u64,
    /// Logical processors reported by the host; 0 when unknown. The resource
    /// governor refuses to plan vCPUs without it.
    pub logical_cpus: u32,
    /// Existing WinNAT networks. WinNAT supports one; Litric will not remove one.
    pub existing_nat_networks: u32,
    /// False when the agent could not query WinNAT (usually: not elevated).
    /// A failed query is not evidence of zero NAT networks.
    pub nat_query_ok: bool,
    pub wsl_switches: u32,
    pub docker_switches: u32,
}

impl HostFacts {
    /// No platform agent has reported; treat the host as unknown.
    pub fn unknown() -> Self {
        HostFacts {
            known: false,
            windows_edition: String::new(),
            windows_build: 0,
            virtualization_enabled: false,
            hyperv_feature_present: false,
            sandbox_feature_present: false,
            total_ram_mb: 0,
            free_disk_mb: 0,
            logical_cpus: 0,
            existing_nat_networks: 0,
            nat_query_ok: false,
            wsl_switches: 0,
            docker_switches: 0,
        }
    }

    /// Parses facts reported by a platform agent. Absent fields stay absent.
    pub fn from_json(value: &Value) -> Self {
        let num = |k: &str| value.get(k).and_then(|v| v.as_u64());
        HostFacts {
            known: value.get("known").and_then(|v| v.as_bool()).unwrap_or(false),
            windows_edition: value
                .get("windows_edition")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            windows_build: num("windows_build").unwrap_or(0) as u32,
            virtualization_enabled: value
                .get("virtualization_enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            hyperv_feature_present: value
                .get("hyperv_feature_present")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            sandbox_feature_present: value
                .get("sandbox_feature_present")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            total_ram_mb: num("total_ram_mb").unwrap_or(0),
            free_disk_mb: num("free_disk_mb").unwrap_or(0),
            logical_cpus: num("logical_cpus").unwrap_or(0) as u32,
            existing_nat_networks: num("existing_nat_networks").unwrap_or(0) as u32,
            nat_query_ok: value
                .get("nat_query_ok")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            wsl_switches: num("wsl_switches").unwrap_or(0) as u32,
            docker_switches: num("docker_switches").unwrap_or(0) as u32,
        }
    }
}

/// A reason a component cannot be used, with the action the user must take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocker {
    pub component: &'static str,
    pub reason: String,
    pub remediation: String,
}

/// What the host can actually do, derived only from reported facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    pub windows: bool,
    pub hyperv_usable: bool,
    pub sandbox_usable: bool,
    /// The local gateway can be created without disturbing existing networking.
    pub gateway_usable: bool,
    pub blockers: Vec<Blocker>,
}

impl Readiness {
    /// Evaluates readiness against today's UTC date.
    pub fn evaluate(facts: &HostFacts) -> Self {
        Self::evaluate_at(facts, LifecycleDate::today())
    }

    /// Deterministic variant used by tests and by callers that supply a clock.
    pub fn evaluate_at(facts: &HostFacts, today: LifecycleDate) -> Self {
        let mut blockers = Vec::new();

        if !facts.known {
            blockers.push(Blocker {
                component: "platform_agent",
                reason: "no host facts have been reported by litric-agent".into(),
                remediation: "install and run the Litric Windows platform agent; \
                              SafeOS cannot evaluate capabilities without it"
                    .into(),
            });
            return Readiness {
                windows: false,
                hyperv_usable: false,
                sandbox_usable: false,
                gateway_usable: false,
                blockers,
            };
        }

        let windows = !facts.windows_edition.is_empty();
        if !windows {
            blockers.push(Blocker {
                component: "windows",
                reason: "host is not Windows; SafeOS isolation backends are Windows-only".into(),
                remediation: "run SafeOS on Windows 11 Pro or Enterprise".into(),
            });
            return Readiness {
                windows: false,
                hyperv_usable: false,
                sandbox_usable: false,
                gateway_usable: false,
                blockers,
            };
        }

        let lifecycle = lifecycle_status(facts, today);
        if !lifecycle.is_supported() {
            let (reason, remediation) = match lifecycle {
                BuildSupport::Expired {
                    release,
                    end,
                    edition,
                } => (
                    format!(
                        "Windows 11 {release} (build {}, {edition}) reached end of support on {end}; \
                         the build is outside the documented lifecycle table",
                        facts.windows_build
                    ),
                    "install a supported Windows 11 release (25H2 or 26H2)".into(),
                ),
                BuildSupport::UnknownBuild => (
                    format!(
                        "Windows build {} is not in the documented Windows 11 lifecycle table \
                         (24H2, 25H2, 26H1, 26H2); support cannot be claimed",
                        facts.windows_build
                    ),
                    "report a build from a supported Windows 11 release".into(),
                ),
                BuildSupport::UnknownEdition => (
                    format!(
                        "Windows edition `{}` is not a recognised Home, Pro, Enterprise, or \
                         Education edition; support cannot be claimed",
                        facts.windows_edition
                    ),
                    "report the edition exactly as Windows reports it".into(),
                ),
                BuildSupport::Supported { .. } => unreachable!(),
            };
            blockers.push(Blocker {
                component: "windows_build",
                reason,
                remediation,
            });
        }

        let virt_ok = facts.virtualization_enabled;
        if !virt_ok {
            blockers.push(Blocker {
                component: "virtualization",
                reason: "hardware virtualization (VT-x/AMD-V) is not enabled".into(),
                remediation: "enable virtualization in firmware; Litric will not change firmware settings".into(),
            });
        }

        if !facts.sandbox_feature_present {
            blockers.push(Blocker {
                component: "windows_sandbox",
                reason: "Windows Sandbox feature is not installed or not enabled".into(),
                remediation: "enable Windows Sandbox in Windows Features (requires a restart); \
                              Litric will not change Windows features for you"
                    .into(),
            });
        }

        let build_ok = lifecycle.is_supported();
        let ram_ok = facts.total_ram_mb >= MIN_RAM_MB;
        if !ram_ok {
            blockers.push(Blocker {
                component: "memory",
                reason: format!(
                    "{} MB installed is below the {} MB minimum for isolation",
                    facts.total_ram_mb, MIN_RAM_MB
                ),
                remediation: "add RAM or accept that risky applications cannot be isolated".into(),
            });
        }

        let sandbox_disk_ok = facts.free_disk_mb >= MIN_DISK_SANDBOX_MB;
        let vm_disk_ok = facts.free_disk_mb >= MIN_DISK_VM_MB;
        if !sandbox_disk_ok {
            blockers.push(Blocker {
                component: "disk",
                reason: format!(
                    "{} MB free is below the {} MB needed for a Windows Sandbox session",
                    facts.free_disk_mb, MIN_DISK_SANDBOX_MB
                ),
                remediation: "free disk space; Litric will not delete user data to make room".into(),
            });
        } else if !vm_disk_ok {
            blockers.push(Blocker {
                component: "disk",
                reason: format!(
                    "{} MB free is below the {} MB needed for a managed VM",
                    facts.free_disk_mb, MIN_DISK_VM_MB
                ),
                remediation: "free disk space; Litric will not delete user data to make room".into(),
            });
        }

        // WinNAT supports a single NAT network per host. If one already exists,
        // Litric must not remove or reconfigure it, so the gateway stays off.
        // An unreadable NAT state is treated as a conflict, never as "none".
        if !facts.nat_query_ok {
            blockers.push(Blocker {
                component: "network_gateway",
                reason: "WinNAT state could not be queried (the agent usually needs elevation)".into(),
                remediation: "run the agent elevated if you want gateway eligibility evaluated; \
                              otherwise isolation stays offline"
                    .into(),
            });
        }
        let nat_conflict = facts.existing_nat_networks > 0;
        if nat_conflict {
            blockers.push(Blocker {
                component: "network_gateway",
                reason: format!(
                    "{} existing WinNAT network(s); WinNAT supports one and Litric will not remove one",
                    facts.existing_nat_networks
                ),
                remediation: "use offline sandbox analysis, or choose a gateway design that does not reuse WinNAT".into(),
            });
        }

        Readiness {
            windows,
            hyperv_usable: build_ok && virt_ok && facts.hyperv_feature_present && ram_ok && vm_disk_ok,
            sandbox_usable: build_ok && virt_ok && facts.sandbox_feature_present && ram_ok && sandbox_disk_ok,
            gateway_usable: build_ok
                && virt_ok
                && facts.hyperv_feature_present
                && facts.nat_query_ok
                && !nat_conflict,
            blockers,
        }
    }
}

/// Availability of one execution backend, for status reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendStatus {
    pub kind: &'static str,
    pub available: bool,
    pub reason: String,
    /// True when this backend cannot be exercised in the current build at all.
    pub requires_windows: bool,
}

/// Backends and their honest availability on this host.
pub fn backend_status(facts: &HostFacts) -> Vec<BackendStatus> {
    let r = Readiness::evaluate(facts);
    vec![
        BackendStatus {
            kind: "windows_sandbox",
            available: r.sandbox_usable,
            reason: if r.sandbox_usable {
                "Windows Sandbox feature detected; sessions are offline-only (networking disabled)".into()
            } else {
                first_reason(&r, "windows_sandbox")
            },
            requires_windows: true,
        },
        BackendStatus {
            kind: "hyperv_managed",
            available: r.hyperv_usable,
            reason: if r.hyperv_usable {
                "Hyper-V can host an isolated VM; gateway availability checked separately".into()
            } else {
                first_reason(&r, "hyperv_managed")
            },
            requires_windows: true,
        },
        BackendStatus {
            kind: "network_gateway",
            available: r.gateway_usable,
            reason: if r.gateway_usable {
                "dedicated internal switch + WFP policy can be created".into()
            } else {
                first_reason(&r, "network_gateway")
            },
            requires_windows: true,
        },
    ]
}

fn first_reason(r: &Readiness, component: &str) -> String {
    r.blockers
        .iter()
        .find(|b| b.component == component || b.component == "virtualization" || b.component == "windows")
        .map(|b| b.reason.clone())
        .or_else(|| r.blockers.first().map(|b| b.reason.clone()))
        .unwrap_or_else(|| "backend not implemented in this build".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn good() -> HostFacts {
        HostFacts {
            known: true,
            windows_edition: "Windows 11 Pro".into(),
            windows_build: 26_200,
            virtualization_enabled: true,
            hyperv_feature_present: true,
            sandbox_feature_present: true,
            total_ram_mb: 16 * 1024,
            free_disk_mb: 100 * 1024,
            logical_cpus: 8,
            existing_nat_networks: 0,
            nat_query_ok: true,
            wsl_switches: 1,
            docker_switches: 1,
        }
    }

    #[test]
    fn unknown_facts_make_everything_unavailable() {
        let r = Readiness::evaluate(&HostFacts::unknown());
        assert!(!r.hyperv_usable && !r.sandbox_usable && !r.gateway_usable);
        assert!(r.blockers.iter().any(|b| b.component == "platform_agent"));
    }

    #[test]
    fn unsupported_host_facts_cannot_claim_isolation_backends() {
        let mut f = good();
        f.windows_edition.clear();
        let r = Readiness::evaluate(&f);
        assert!(!r.hyperv_usable && !r.sandbox_usable);
        assert!(r.blockers.iter().any(|b| b.component == "windows"));
    }

    #[test]
    fn good_host_is_usable() {
        let r = Readiness::evaluate(&good());
        assert!(r.hyperv_usable && r.sandbox_usable && r.gateway_usable);
        assert!(r.blockers.is_empty());
    }

    #[test]
    fn missing_sandbox_feature_is_a_named_blocker() {
        let mut f = good();
        f.sandbox_feature_present = false;
        let r = Readiness::evaluate(&f);
        assert!(!r.sandbox_usable);
        let b = r
            .blockers
            .iter()
            .find(|b| b.component == "windows_sandbox")
            .expect("sandbox blocker");
        assert!(b.reason.contains("not installed or not enabled"));
    }

    #[test]
    fn low_ram_disables_isolation_instead_of_risking_the_host() {
        let mut f = good();
        f.total_ram_mb = 2048;
        let r = Readiness::evaluate(&f);
        assert!(!r.hyperv_usable && !r.sandbox_usable);
        assert!(r.blockers.iter().any(|b| b.component == "memory"));
    }

    #[test]
    fn existing_nat_blocks_gateway_but_not_offline_sandbox() {
        let mut f = good();
        f.existing_nat_networks = 1;
        let r = Readiness::evaluate(&f);
        assert!(!r.gateway_usable);
        assert!(r.sandbox_usable);
        assert!(r.blockers.iter().any(|b| b.component == "network_gateway"));
    }

    #[test]
    fn failed_nat_query_blocks_gateway_instead_of_assuming_zero() {
        let mut f = good();
        f.nat_query_ok = false;
        let r = Readiness::evaluate(&f);
        assert!(!r.gateway_usable);
        assert!(r.blockers.iter().any(|b| b.component == "network_gateway"));
    }

    #[test]
    fn low_disk_blocks_vm_but_allows_sandbox() {
        let mut f = good();
        f.free_disk_mb = 12 * 1024;
        let r = Readiness::evaluate(&f);
        assert!(!r.hyperv_usable);
        assert!(r.sandbox_usable);
    }

    #[test]
    fn supported_25h2_and_26h2_builds_are_accepted() {
        let today = LifecycleDate::new(2026, 11, 3);
        for build in [26_200, 26_300] {
            let mut f = good();
            f.windows_build = build;
            let r = Readiness::evaluate_at(&f, today);
            assert!(r.sandbox_usable, "build {build} should be supported");
            assert!(!r.blockers.iter().any(|b| b.component == "windows_build"));
        }
    }

    #[test]
    fn expired_24h2_is_rejected_with_lifecycle_reason() {
        let mut f = good();
        f.windows_build = 26_100;
        let r = Readiness::evaluate_at(&f, LifecycleDate::new(2026, 11, 3));
        assert!(!r.sandbox_usable && !r.hyperv_usable);
        let b = r
            .blockers
            .iter()
            .find(|b| b.component == "windows_build")
            .expect("lifecycle blocker");
        assert!(b.reason.contains("24H2"), "reason: {}", b.reason);
        assert!(b.reason.contains("end of support"), "reason: {}", b.reason);
        assert!(b.reason.contains("2026-10-14"), "reason: {}", b.reason);
    }

    #[test]
    fn enterprise_24h2_uses_its_own_end_date() {
        let mut f = good();
        f.windows_edition = "Windows 11 Enterprise".into();
        f.windows_build = 26_100;
        let supported = Readiness::evaluate_at(&f, LifecycleDate::new(2026, 11, 3));
        assert!(supported.sandbox_usable);
        assert!(!supported.blockers.iter().any(|b| b.component == "windows_build"));

        let expired = Readiness::evaluate_at(&f, LifecycleDate::new(2027, 10, 13));
        assert!(!expired.sandbox_usable);
        let b = expired
            .blockers
            .iter()
            .find(|b| b.component == "windows_build")
            .expect("enterprise lifecycle blocker");
        assert!(b.reason.contains("Enterprise/Education"), "reason: {}", b.reason);
        assert!(b.reason.contains("2027-10-12"), "reason: {}", b.reason);
    }

    #[test]
    fn unknown_build_is_not_accepted_by_a_numeric_floor() {
        let mut f = good();
        f.windows_build = 22_631;
        let r = Readiness::evaluate_at(&f, LifecycleDate::new(2026, 11, 3));
        assert!(!r.sandbox_usable);
        let b = r
            .blockers
            .iter()
            .find(|b| b.component == "windows_build")
            .expect("unknown build blocker");
        assert!(b.reason.contains("not in the documented Windows 11 lifecycle table"));
    }

    #[test]
    fn json_facts_parse_and_default_to_unavailable() {
        let f = HostFacts::from_json(&json!({
            "known": true,
            "windows_edition": "Windows 11 Pro",
            "windows_build": 26_200,
            "virtualization_enabled": true,
            "hyperv_feature_present": true,
            "sandbox_feature_present": false,
            "total_ram_mb": 16384,
            "free_disk_mb": 51200
        }));
        assert!(f.known);
        let r = Readiness::evaluate(&f);
        assert!(r.hyperv_usable);
        assert!(!r.sandbox_usable);
        assert_eq!(f.existing_nat_networks, 0);
    }
}
