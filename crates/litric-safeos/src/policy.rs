//! Fail-closed execution policy.
//!
//! The only rule that really matters: if an application needs isolation and the
//! isolation backend is not available, the answer is **Deny**. There is no path in
//! this module that turns "no sandbox" into "run on the host".

use crate::model::ExecutionLevel;

/// Which backends the caller has confirmed usable (from `Readiness`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendSet {
    pub sandbox: bool,
    pub hyperv: bool,
    pub gateway: bool,
}

impl BackendSet {
    pub fn none() -> Self {
        BackendSet {
            sandbox: false,
            hyperv: false,
            gateway: false,
        }
    }
}

/// What should happen to the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Level 0 only: normal execution with existing protection.
    RunOnHost,
    /// Disposable Windows Sandbox. Networking is always disabled in this backend.
    RunInSandbox,
    /// Managed Hyper-V VM. `network` is false when the gateway is unavailable.
    RunInVm { network: bool },
    /// Confirmed malicious: do not execute; quarantine through the vault.
    BlockAndQuarantine,
    /// Required isolation is unavailable. Refuse to launch; tell the user why.
    Deny,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::RunOnHost => "run_on_host",
            Action::RunInSandbox => "run_in_windows_sandbox",
            Action::RunInVm { network: true } => "run_in_vm_with_gateway",
            Action::RunInVm { network: false } => "run_in_vm_offline",
            Action::BlockAndQuarantine => "block_and_quarantine",
            Action::Deny => "deny",
        }
    }
}

/// Policy decision with the reasons that must be shown to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    pub reasons: Vec<String>,
    pub remediation: Option<String>,
}

/// Maps a risk level to an action, refusing to degrade to host execution.
pub fn decide(level: ExecutionLevel, backends: &BackendSet) -> Decision {
    match level {
        ExecutionLevel::Trusted => Decision {
            action: Action::RunOnHost,
            reasons: vec!["verified identity with a validated signing chain".into()],
            remediation: None,
        },
        ExecutionLevel::Unknown => {
            if backends.sandbox {
                Decision {
                    action: Action::RunInSandbox,
                    reasons: vec![
                        "unverified application".into(),
                        "Windows Sandbox is the disposable offline backend".into(),
                    ],
                    remediation: None,
                }
            } else if backends.hyperv {
                Decision {
                    action: Action::RunInVm { network: false },
                    reasons: vec![
                        "unverified application".into(),
                        "Windows Sandbox is unavailable; using an offline Hyper-V VM".into(),
                    ],
                    remediation: None,
                }
            } else {
                Decision {
                    action: Action::Deny,
                    reasons: vec![
                        "unverified application".into(),
                        "no isolation backend is available on this host".into(),
                        "refusing to run an unverified application on the host".into(),
                    ],
                    remediation: Some(
                        "enable Windows Sandbox or Hyper-V (requires virtualization and a restart), \
                         or do not run this application"
                            .into(),
                    ),
                }
            }
        }
        ExecutionLevel::Suspicious => {
            if backends.hyperv {
                Decision {
                    action: Action::RunInVm {
                        network: backends.gateway,
                    },
                    reasons: if backends.gateway {
                        vec![
                            "suspicious indicators".into(),
                            "full VM isolation with gateway-mediated networking".into(),
                        ]
                    } else {
                        vec![
                            "suspicious indicators".into(),
                            "full VM isolation; the network gateway is unavailable so the VM is offline"
                                .into(),
                        ]
                    },
                    remediation: None,
                }
            } else {
                Decision {
                    action: Action::Deny,
                    reasons: vec![
                        "suspicious indicators require full VM isolation".into(),
                        "Hyper-V is not available".into(),
                        "Windows Sandbox is not an acceptable substitute for network-capable \
                         suspicious workloads, and the host is not an option"
                            .into(),
                    ],
                    remediation: Some("enable Hyper-V, or do not run this application".into()),
                }
            }
        }
        ExecutionLevel::Malicious => Decision {
            action: Action::BlockAndQuarantine,
            reasons: vec![
                "confirmed malicious evidence".into(),
                "host execution is blocked".into(),
            ],
            remediation: Some("quarantine the sample and preserve the report as evidence".into()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_without_backends_is_denied_not_run_on_host() {
        let d = decide(ExecutionLevel::Unknown, &BackendSet::none());
        assert_eq!(d.action, Action::Deny);
        assert!(d.reasons.iter().any(|r| r.contains("refusing")));
        assert!(d.remediation.is_some());
    }

    #[test]
    fn suspicious_never_falls_back_to_sandbox_or_host() {
        let b = BackendSet {
            sandbox: true,
            hyperv: false,
            gateway: false,
        };
        let d = decide(ExecutionLevel::Suspicious, &b);
        assert_eq!(d.action, Action::Deny);
        assert_ne!(d.action, Action::RunOnHost);
    }

    #[test]
    fn unknown_uses_sandbox_when_available() {
        let b = BackendSet {
            sandbox: true,
            hyperv: true,
            gateway: true,
        };
        assert_eq!(
            decide(ExecutionLevel::Unknown, &b).action,
            Action::RunInSandbox
        );
    }

    #[test]
    fn suspicious_with_hyperv_but_no_gateway_is_offline_vm() {
        let b = BackendSet {
            sandbox: true,
            hyperv: true,
            gateway: false,
        };
        assert_eq!(
            decide(ExecutionLevel::Suspicious, &b).action,
            Action::RunInVm { network: false }
        );
    }

    #[test]
    fn malicious_is_blocked_regardless_of_backends() {
        let b = BackendSet {
            sandbox: true,
            hyperv: true,
            gateway: true,
        };
        assert_eq!(
            decide(ExecutionLevel::Malicious, &b).action,
            Action::BlockAndQuarantine
        );
    }

    #[test]
    fn only_trusted_runs_on_host() {
        for level in [
            ExecutionLevel::Unknown,
            ExecutionLevel::Suspicious,
            ExecutionLevel::Malicious,
        ] {
            let d = decide(
                level,
                &BackendSet {
                    sandbox: true,
                    hyperv: true,
                    gateway: true,
                },
            );
            assert_ne!(d.action, Action::RunOnHost, "level {level:?}");
        }
    }
}
