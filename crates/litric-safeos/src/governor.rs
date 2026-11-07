//! Resource governor: the one place that decides whether the host can afford
//! another isolated session.
//!
//! This is enforcement, not advice. `sandbox::prepare` refuses to write a `.wsb`
//! unless the governor returns a plan, and the plan's memory value is what the
//! sandbox actually receives. The rules exist to protect the host: the machine
//! must stay usable while an untrusted application runs inside isolation.
//!
//! Every number is derived from facts reported by the platform agent, and a
//! missing fact refuses the session instead of being guessed:
//!
//! * at least [`MIN_GUEST_RAM_MB`] for the guest and at most 40% of installed
//!   RAM (the rest is reserved for Windows),
//! * at most [`MAX_VCPUS`] and at most half of the reported logical processors,
//! * at most [`MAX_HEAVY_SESSIONS`] heavy session at a time,
//! * a disk reservation that is added on top of a host reserve. The governor
//!   never frees space by deleting user data.

use serde_json::{json, Value};

use crate::model::{ExecutionLevel, HostFacts, Readiness, MIN_DISK_SANDBOX_MB, MIN_DISK_VM_MB};

/// RAM kept for Windows itself even on a small host.
pub const HOST_RESERVE_RAM_MB: u64 = 2048;
/// Free disk that must remain after a session's reservation.
pub const HOST_RESERVE_DISK_MB: u64 = 5 * 1024;
/// Smallest guest memory the governor will hand out.
pub const MIN_GUEST_RAM_MB: u64 = 2048;
/// Windows Sandbox is the lightweight backend; it never gets a large VM budget.
pub const MAX_SANDBOX_RAM_MB: u64 = 4096;
/// Upper bound for a managed Hyper-V guest.
pub const MAX_VM_RAM_MB: u64 = 8192;
/// vCPU ceiling for ordinary 4C/8T class machines.
pub const MAX_VCPUS: u32 = 4;
/// One heavy isolation session at a time (master prompt §11 default).
pub const MAX_HEAVY_SESSIONS: usize = 1;

/// Backends the governor can plan for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    WindowsSandbox,
    HyperV,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::WindowsSandbox => "windows_sandbox",
            Backend::HyperV => "hyperv_managed",
        }
    }
}

/// What the caller wants to run and what it already runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRequest {
    pub backend: Backend,
    pub level: ExecutionLevel,
    /// Heavy sessions already active. The caller counts them; the governor caps.
    pub running_heavy: usize,
    /// Optional caller preference; the governor may reduce it.
    pub requested_ram_mb: Option<u64>,
    pub requested_vcpus: Option<u32>,
}

impl ResourceRequest {
    pub fn new(backend: Backend, level: ExecutionLevel) -> Self {
        ResourceRequest {
            backend,
            level,
            running_heavy: 0,
            requested_ram_mb: None,
            requested_vcpus: None,
        }
    }
}

/// Allocated resources for one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePlan {
    pub backend: Backend,
    pub ram_mb: u64,
    pub vcpus: u32,
    pub disk_reserve_mb: u64,
}

/// The governor's verdict. `Reduce` still runs; it never silently runs on the
/// host and never silently overcommits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernorDecision {
    Allow(ResourcePlan),
    Reduce {
        plan: ResourcePlan,
        reasons: Vec<String>,
    },
    Refuse {
        reasons: Vec<String>,
        remediation: String,
    },
}

impl GovernorDecision {
    /// The plan when the session may start (allowed or reduced).
    pub fn plan(&self) -> Option<&ResourcePlan> {
        match self {
            GovernorDecision::Allow(p) => Some(p),
            GovernorDecision::Reduce { plan, .. } => Some(plan),
            GovernorDecision::Refuse { .. } => None,
        }
    }

    /// Stable JSON for the status API. Never claims more than the decision made.
    pub fn to_json(&self) -> Value {
        match self {
            GovernorDecision::Allow(p) => json!({
                "decision": "allow",
                "backend": p.backend.as_str(),
                "ram_mb": p.ram_mb,
                "vcpus": p.vcpus,
                "disk_reserve_mb": p.disk_reserve_mb,
                "reasons": [],
            }),
            GovernorDecision::Reduce { plan, reasons } => json!({
                "decision": "reduce",
                "backend": plan.backend.as_str(),
                "ram_mb": plan.ram_mb,
                "vcpus": plan.vcpus,
                "disk_reserve_mb": plan.disk_reserve_mb,
                "reasons": reasons,
            }),
            GovernorDecision::Refuse {
                reasons,
                remediation,
            } => json!({
                "decision": "refuse",
                "backend": Value::Null,
                "ram_mb": Value::Null,
                "vcpus": Value::Null,
                "disk_reserve_mb": Value::Null,
                "reasons": reasons,
                "remediation": remediation,
            }),
        }
    }
}

/// Plans resources for one session, refusing when the host cannot afford it.
pub fn decide(facts: &HostFacts, request: &ResourceRequest) -> GovernorDecision {
    if request.level == ExecutionLevel::Malicious {
        return GovernorDecision::Refuse {
            reasons: vec![
                "the application is classified malicious; no backend may execute it".into(),
            ],
            remediation: "quarantine the sample and preserve the report as evidence".into(),
        };
    }
    if !facts.known {
        return GovernorDecision::Refuse {
            reasons: vec!["no host facts have been reported; capacity is unknown".into()],
            remediation: "run litric-agent on the Windows host so the governor can plan".into(),
        };
    }
    if request.running_heavy >= MAX_HEAVY_SESSIONS {
        return GovernorDecision::Refuse {
            reasons: vec![format!(
                "{} heavy session(s) already running; the governor allows {}",
                request.running_heavy, MAX_HEAVY_SESSIONS
            )],
            remediation: "wait for the running session to finish; litric will not overcommit \
                          the host"
                .into(),
        };
    }
    if facts.logical_cpus == 0 {
        return GovernorDecision::Refuse {
            reasons: vec!["the host report did not include a logical processor count".into()],
            remediation: "run the current litric-agent; vCPU limits cannot be planned without \
                          a CPU count"
                .into(),
        };
    }

    let readiness = Readiness::evaluate(facts);
    let usable = match request.backend {
        Backend::WindowsSandbox => readiness.sandbox_usable,
        Backend::HyperV => readiness.hyperv_usable,
    };
    if !usable {
        let mut reasons: Vec<String> = readiness
            .blockers
            .iter()
            .map(|b| format!("{}: {}", b.component, b.reason))
            .collect();
        if reasons.is_empty() {
            reasons.push(format!(
                "{} is not usable on this host",
                request.backend.as_str()
            ));
        }
        return GovernorDecision::Refuse {
            reasons,
            remediation: "resolve the listed host blockers; the governor will not start an \
                          isolated workload without them"
                .into(),
        };
    }

    // --- memory ---------------------------------------------------------
    let ram_reserve = HOST_RESERVE_RAM_MB.max(facts.total_ram_mb / 4);
    let ram_budget = facts.total_ram_mb.saturating_sub(ram_reserve);
    if ram_budget < MIN_GUEST_RAM_MB {
        return GovernorDecision::Refuse {
            reasons: vec![format!(
                "reserving {ram_reserve} MB for Windows leaves {ram_budget} MB; a guest needs \
                 at least {MIN_GUEST_RAM_MB} MB"
            )],
            remediation: "add RAM or close memory-heavy applications; litric will not starve \
                          the host"
                .into(),
        };
    }
    let ceiling = match request.backend {
        Backend::WindowsSandbox => MAX_SANDBOX_RAM_MB,
        Backend::HyperV => MAX_VM_RAM_MB,
    };
    let wanted_ram = request
        .requested_ram_mb
        .unwrap_or(ceiling)
        .clamp(MIN_GUEST_RAM_MB, ceiling);
    let ram_mb = wanted_ram.min(ram_budget);

    // --- disk -----------------------------------------------------------
    let disk_reserve_mb = match request.backend {
        Backend::WindowsSandbox => MIN_DISK_SANDBOX_MB,
        Backend::HyperV => MIN_DISK_VM_MB,
    };
    if facts.free_disk_mb < disk_reserve_mb + HOST_RESERVE_DISK_MB {
        return GovernorDecision::Refuse {
            reasons: vec![format!(
                "{} MB free is below the {disk_reserve_mb} MB session reservation plus the \
                 {HOST_RESERVE_DISK_MB} MB host reserve",
                facts.free_disk_mb
            )],
            remediation: "free disk space; litric will not delete user data to make room".into(),
        };
    }

    // --- CPU ------------------------------------------------------------
    let vcpu_ceiling = (facts.logical_cpus / 2).clamp(1, MAX_VCPUS);
    let vcpus = match request.requested_vcpus {
        Some(n) => n.clamp(1, vcpu_ceiling),
        None => vcpu_ceiling,
    };

    let mut reasons = Vec::new();
    if ram_mb < wanted_ram {
        reasons.push(format!(
            "requested {wanted_ram} MB reduced to {ram_mb} MB to keep {ram_reserve} MB for Windows"
        ));
    }
    if let Some(n) = request.requested_vcpus {
        if vcpus < n {
            reasons.push(format!(
                "requested {n} vCPU(s) reduced to {vcpus} to keep the host responsive"
            ));
        }
    }

    let plan = ResourcePlan {
        backend: request.backend,
        ram_mb,
        vcpus,
        disk_reserve_mb,
    };
    if reasons.is_empty() {
        GovernorDecision::Allow(plan)
    } else {
        GovernorDecision::Reduce { plan, reasons }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            wsl_switches: 0,
            docker_switches: 0,
        }
    }

    fn sandbox_request() -> ResourceRequest {
        ResourceRequest::new(Backend::WindowsSandbox, ExecutionLevel::Unknown)
    }

    fn reasons_of(d: &GovernorDecision) -> String {
        match d {
            GovernorDecision::Allow(_) => String::new(),
            GovernorDecision::Reduce { reasons, .. } => reasons.join("; "),
            GovernorDecision::Refuse { reasons, .. } => reasons.join("; "),
        }
    }

    #[test]
    fn unknown_facts_are_refused_instead_of_guessed() {
        let d = decide(&HostFacts::unknown(), &sandbox_request());
        assert!(matches!(d, GovernorDecision::Refuse { .. }));
        assert!(reasons_of(&d).contains("capacity is unknown"));
    }

    #[test]
    fn malicious_is_refused_for_every_backend() {
        for backend in [Backend::WindowsSandbox, Backend::HyperV] {
            let d = decide(
                &good(),
                &ResourceRequest::new(backend, ExecutionLevel::Malicious),
            );
            assert!(matches!(d, GovernorDecision::Refuse { .. }));
            assert!(reasons_of(&d).contains("must not execute") || reasons_of(&d).contains("no backend"));
        }
    }

    #[test]
    fn a_second_heavy_session_is_refused() {
        let mut request = sandbox_request();
        request.running_heavy = 1;
        let d = decide(&good(), &request);
        assert!(matches!(d, GovernorDecision::Refuse { .. }));
        assert!(reasons_of(&d).contains("already running"));
    }

    #[test]
    fn a_good_host_allows_a_bounded_sandbox() {
        let d = decide(&good(), &sandbox_request());
        let plan = d.plan().expect("plan");
        assert_eq!(d, GovernorDecision::Allow(plan.clone()));
        assert_eq!(plan.ram_mb, 4096);
        assert_eq!(plan.vcpus, 4);
        assert_eq!(plan.disk_reserve_mb, MIN_DISK_SANDBOX_MB);
    }

    #[test]
    fn a_constrained_host_is_reduced_with_a_reason() {
        let mut facts = good();
        facts.total_ram_mb = 4096;
        let d = decide(&facts, &sandbox_request());
        let plan = d.plan().expect("reduced plan still runs");
        assert_eq!(plan.ram_mb, 2048);
        assert!(matches!(d, GovernorDecision::Reduce { .. }));
        assert!(reasons_of(&d).contains("reduced to 2048 MB"));
    }

    #[test]
    fn a_missing_cpu_count_is_refused() {
        let mut facts = good();
        facts.logical_cpus = 0;
        let d = decide(&facts, &sandbox_request());
        assert!(matches!(d, GovernorDecision::Refuse { .. }));
        assert!(reasons_of(&d).contains("logical processor"));
    }

    #[test]
    fn low_disk_refuses_without_deleting_anything() {
        let mut facts = good();
        facts.free_disk_mb = 14 * 1024;
        let d = decide(&facts, &sandbox_request());
        match &d {
            GovernorDecision::Refuse {
                reasons,
                remediation,
            } => {
                assert!(reasons.join(" ").contains("host reserve"));
                assert!(remediation.contains("will not delete user data"));
            }
            other => panic!("expected refuse, got {other:?}"),
        }
    }

    #[test]
    fn an_oversized_vcpu_request_is_reduced() {
        let mut request = sandbox_request();
        request.requested_vcpus = Some(8);
        let d = decide(&good(), &request);
        let plan = d.plan().expect("plan");
        assert_eq!(plan.vcpus, 4);
        assert!(matches!(d, GovernorDecision::Reduce { .. }));
        assert!(reasons_of(&d).contains("vCPU"));
    }

    #[test]
    fn the_hyperv_plan_respects_the_vm_ram_ceiling() {
        let d = decide(
            &good(),
            &ResourceRequest::new(Backend::HyperV, ExecutionLevel::Suspicious),
        );
        let plan = d.plan().expect("plan");
        assert_eq!(plan.ram_mb, MAX_VM_RAM_MB);
        assert_eq!(plan.vcpus, MAX_VCPUS);
        assert_eq!(plan.disk_reserve_mb, MIN_DISK_VM_MB);
    }

    #[test]
    fn json_reports_the_decision_it_made() {
        let allow = decide(&good(), &sandbox_request()).to_json();
        assert_eq!(allow["decision"], "allow");
        assert_eq!(allow["ram_mb"], 4096);

        let refuse = decide(&HostFacts::unknown(), &sandbox_request()).to_json();
        assert_eq!(refuse["decision"], "refuse");
        assert!(refuse["remediation"].as_str().unwrap().contains("litric-agent"));
    }
}
