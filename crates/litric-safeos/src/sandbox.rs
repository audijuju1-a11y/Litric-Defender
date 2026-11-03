//! Windows Sandbox configuration generation and launch.
//!
//! `prepare` runs the runtime readiness check, writes a locked-down `.wsb` and
//! returns what would be executed. `launch` spawns Windows Sandbox and is gated on
//! `#[cfg(windows)]`: a Linux or macOS build cannot launch it and says so.
//!
//! Launching is only the boundary in front of execution; it does not claim the
//! guest is trustworthy. See `docs/SAFEOS_WINDOWS_VERIFICATION.md` for the manual
//! checks that must pass on a real Windows 11 host before calling it verified.
//!
//! The generated configuration is deliberately locked down: networking disabled,
//! every redirection disabled, vGPU off by default, and at most read-only mapped
//! folders that must be explicit staging paths.

use std::path::{Path, PathBuf};

use crate::model::{HostFacts, Readiness};

/// Sandbox resource and mapping plan for one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPlan {
    pub ram_mb: u32,
    pub vgpu: bool,
    /// Host folders exposed read-only. Must be staging directories, never roots.
    pub read_only_inputs: Vec<PathBuf>,
    pub logon_command: Option<String>,
}

impl Default for SandboxPlan {
    fn default() -> Self {
        SandboxPlan {
            ram_mb: 4096,
            vgpu: false,
            read_only_inputs: Vec::new(),
            logon_command: None,
        }
    }
}

/// Rejects plans that would expose the host or misconfigure the sandbox.
pub fn validate(plan: &SandboxPlan) -> Result<(), String> {
    if !(2048..=16384).contains(&plan.ram_mb) {
        return Err(format!(
            "sandbox memory {} MB is outside the supported 2048-16384 MB range",
            plan.ram_mb
        ));
    }
    for input in &plan.read_only_inputs {
        let s = input.to_string_lossy();
        let is_drive_root = (s.len() == 2 && s.ends_with(':'))
            || (s.len() == 3 && (s.ends_with(":\\") || s.ends_with(":/")));
        if is_drive_root || s == "/" || s == "\\" {
            return Err(format!(
                "refusing to map an entire volume into the sandbox: {}",
                input.display()
            ));
        }
        if s.to_ascii_lowercase().contains("\\users\\") || s.contains("/home/") {
            return Err(format!(
                "refusing to map a user profile into the sandbox: {}",
                input.display()
            ));
        }
    }
    Ok(())
}

/// Renders the `.wsb` XML. Fails closed on an invalid plan.
pub fn to_wsb(plan: &SandboxPlan) -> Result<String, String> {
    validate(plan)?;
    let mut x = String::new();
    x.push_str("<Configuration>\n");
    x.push_str("  <Networking>Disable</Networking>\n");
    x.push_str("  <ClipboardRedirection>Disable</ClipboardRedirection>\n");
    x.push_str("  <AudioInput>Disable</AudioInput>\n");
    x.push_str("  <VideoInput>Disable</VideoInput>\n");
    x.push_str("  <PrinterRedirection>Disable</PrinterRedirection>\n");
    x.push_str(&format!(
        "  <vGPU>{}</vGPU>\n",
        if plan.vgpu { "Enable" } else { "Disable" }
    ));
    x.push_str(&format!("  <MemoryInMB>{}</MemoryInMB>\n", plan.ram_mb));
    if !plan.read_only_inputs.is_empty() {
        x.push_str("  <MappedFolders>\n");
        for (i, input) in plan.read_only_inputs.iter().enumerate() {
            x.push_str("    <MappedFolder>\n");
            x.push_str(&format!(
                "      <HostFolder>{}</HostFolder>\n",
                escape(&input.display().to_string())
            ));
            x.push_str(&format!(
                "      <SandboxFolder>C:\\Litric\\input\\{i}</SandboxFolder>\n"
            ));
            x.push_str("      <ReadOnly>true</ReadOnly>\n");
            x.push_str("    </MappedFolder>\n");
        }
        x.push_str("  </MappedFolders>\n");
    }
    if let Some(cmd) = &plan.logon_command {
        x.push_str("  <LogonCommand>\n");
        x.push_str(&format!("    <Command>{}</Command>\n", escape(cmd)));
        x.push_str("  </LogonCommand>\n");
    }
    x.push_str("</Configuration>\n");
    Ok(x)
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// True when this build contains a launcher. The gate is compile-time.
pub const LAUNCH_IMPLEMENTED: bool = cfg!(windows);

/// Flips to true only after the checklist in
/// `docs/SAFEOS_WINDOWS_VERIFICATION.md` has been executed on a real host.
pub const LAUNCH_VERIFIED_ON_WINDOWS: bool = false;

/// Explain why launching is unavailable, if it is.
pub fn launch_unavailable_reason() -> &'static str {
    if LAUNCH_IMPLEMENTED {
        "Windows Sandbox launcher is compiled in but has not been verified on a real \
         Windows host yet"
    } else {
        "Windows Sandbox launch requires a Windows build; this binary cannot launch it"
    }
}

/// Why a launch was refused. Every variant is a refusal, never a fallback to host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchError {
    /// Runtime readiness failed; the strings are user-facing blockers.
    NotReady(Vec<String>),
    /// This build is not Windows; sandbox execution cannot even be attempted.
    NotWindows,
    /// The requested application or plan is unsafe/invalid.
    Invalid(String),
    /// The .wsb configuration could not be written.
    Config(String),
    /// Windows Sandbox could not be started.
    Spawn(String),
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LaunchError::NotReady(r) => {
                write!(f, "sandbox is not ready: {}", r.join("; "))
            }
            LaunchError::NotWindows => write!(f, "{}", launch_unavailable_reason()),
            LaunchError::Invalid(m) => write!(f, "invalid launch request: {m}"),
            LaunchError::Config(m) => write!(f, "cannot prepare the sandbox: {m}"),
            LaunchError::Spawn(m) => write!(f, "cannot start Windows Sandbox: {m}"),
        }
    }
}

impl std::error::Error for LaunchError {}

/// A validated session that is ready to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedLaunch {
    pub config_path: PathBuf,
    /// Command that runs inside the sandbox (read-only mapped app path).
    pub command: String,
}

/// Result of an actual spawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchOutcome {
    pub config_path: PathBuf,
    pub command: String,
    pub pid: u32,
    /// `Some` only when the caller asked to wait.
    pub exit_code: Option<i32>,
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Runtime readiness check + locked-down `.wsb` generation. Never executes.
pub fn prepare(
    facts: &HostFacts,
    app: &Path,
    workdir: &Path,
) -> Result<PreparedLaunch, LaunchError> {
    let readiness = Readiness::evaluate(facts);
    if !readiness.sandbox_usable {
        let reasons = if !facts.known {
            vec!["no host facts have been reported; run litric-agent on Windows".to_string()]
        } else {
            readiness
                .blockers
                .iter()
                .map(|b| format!("{}: {}", b.component, b.reason))
                .collect()
        };
        return Err(LaunchError::NotReady(reasons));
    }

    let app = app.canonicalize().map_err(|e| {
        LaunchError::Invalid(format!("cannot access `{}`: {e}", app.display()))
    })?;
    if !app.is_file() {
        return Err(LaunchError::Invalid(
            "path must be a regular file; directories are not supported".into(),
        ));
    }
    let parent = app
        .parent()
        .ok_or_else(|| LaunchError::Invalid("file has no parent directory".into()))?;
    let name = app
        .file_name()
        .ok_or_else(|| LaunchError::Invalid("file has no name".into()))?
        .to_string_lossy()
        .to_string();

    // The app is mapped read-only at C:\Litric\input\0 inside the guest.
    let command = format!("\"C:\\Litric\\input\\0\\{name}\"");
    let plan = SandboxPlan {
        ram_mb: 4096,
        vgpu: false,
        read_only_inputs: vec![parent.to_path_buf()],
        logon_command: Some(command.clone()),
    };
    let xml = to_wsb(&plan).map_err(LaunchError::Invalid)?;

    std::fs::create_dir_all(workdir).map_err(|e| {
        LaunchError::Config(format!("cannot create `{}`: {e}", workdir.display()))
    })?;
    let config_path = workdir.join(format!("litric-sandbox-{}.wsb", nanos()));
    std::fs::write(&config_path, xml).map_err(|e| {
        LaunchError::Config(format!("cannot write `{}`: {e}", config_path.display()))
    })?;
    Ok(PreparedLaunch {
        config_path,
        command,
    })
}

/// Starts a prepared session. Windows only; every other build refuses.
pub fn launch(prepared: &PreparedLaunch, wait: bool) -> Result<LaunchOutcome, LaunchError> {
    #[cfg(not(windows))]
    {
        let _ = (prepared, wait);
        Err(LaunchError::NotWindows)
    }
    #[cfg(windows)]
    {
        use std::process::Command;

        let root = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("C:\\Windows"));
        let exe = root.join("System32").join("WindowsSandbox.exe");
        if !exe.is_file() {
            return Err(LaunchError::Spawn(format!(
                "Windows Sandbox is not installed (`{}` is missing); enable it in \
                 Windows Features and reboot",
                exe.display()
            )));
        }
        let mut child = Command::new(&exe)
            .arg(&prepared.config_path)
            .spawn()
            .map_err(|e| LaunchError::Spawn(format!("cannot start `{}`: {e}", exe.display())))?;
        let pid = child.id();
        let exit_code = if wait {
            let status = child
                .wait()
                .map_err(|e| LaunchError::Spawn(format!("waiting for the sandbox failed: {e}")))?;
            status.code()
        } else {
            None
        };
        Ok(LaunchOutcome {
            config_path: prepared.config_path.clone(),
            command: prepared.command.clone(),
            pid,
            exit_code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_disables_networking_and_all_redirection() {
        let xml = to_wsb(&SandboxPlan::default()).unwrap();
        assert!(xml.contains("<Networking>Disable</Networking>"));
        assert!(xml.contains("<ClipboardRedirection>Disable</ClipboardRedirection>"));
        assert!(xml.contains("<AudioInput>Disable</AudioInput>"));
        assert!(xml.contains("<VideoInput>Disable</VideoInput>"));
        assert!(xml.contains("<PrinterRedirection>Disable</PrinterRedirection>"));
        assert!(xml.contains("<vGPU>Disable</vGPU>"));
    }

    #[test]
    fn mapped_folders_are_read_only() {
        let plan = SandboxPlan {
            read_only_inputs: vec![PathBuf::from("C:\\ProgramData\\Litric\\stage\\s1")],
            ..Default::default()
        };
        let xml = to_wsb(&plan).unwrap();
        assert!(xml.contains("<ReadOnly>true</ReadOnly>"));
        assert!(xml.contains("Litric\\\\stage") || xml.contains("Litric\\stage"));
    }

    #[test]
    fn refuses_to_map_a_whole_drive() {
        let plan = SandboxPlan {
            read_only_inputs: vec![PathBuf::from("C:\\")],
            ..Default::default()
        };
        assert!(validate(&plan).is_err());
        assert!(to_wsb(&plan).is_err());
    }

    #[test]
    fn refuses_to_map_a_user_profile() {
        let plan = SandboxPlan {
            read_only_inputs: vec![PathBuf::from("C:\\Users\\alice")],
            ..Default::default()
        };
        assert!(validate(&plan).is_err());
    }

    #[test]
    fn xml_special_characters_are_escaped() {
        let plan = SandboxPlan {
            logon_command: Some("cmd /c echo <a&b>".into()),
            ..Default::default()
        };
        let xml = to_wsb(&plan).unwrap();
        assert!(xml.contains("&lt;a&amp;b&gt;"));
        assert!(!xml.contains("<a&b>"));
    }

    #[test]
    fn launch_capability_matches_the_compile_time_gate() {
        assert_eq!(LAUNCH_IMPLEMENTED, cfg!(windows));
        assert!(!LAUNCH_VERIFIED_ON_WINDOWS);
    }

    fn good_facts() -> HostFacts {
        HostFacts {
            known: true,
            windows_edition: "Windows 11 Pro".into(),
            windows_build: 22631,
            virtualization_enabled: true,
            hyperv_feature_present: true,
            sandbox_feature_present: true,
            total_ram_mb: 16 * 1024,
            free_disk_mb: 100 * 1024,
            existing_nat_networks: 0,
            nat_query_ok: true,
            wsl_switches: 0,
            docker_switches: 0,
        }
    }

    fn fixture(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "litric-sbx-{tag}-{}-{}",
            std::process::id(),
            nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let app = dir.join("sample.exe");
        std::fs::write(&app, b"MZ-placeholder").unwrap();
        (dir, app)
    }

    #[test]
    fn unknown_facts_refuse_launch_before_any_process() {
        let (dir, app) = fixture("unknown");
        match prepare(&HostFacts::unknown(), &app, &dir.join("cfg")) {
            Err(LaunchError::NotReady(r)) => assert!(r.join(" ").contains("litric-agent")),
            other => panic!("expected NotReady, got {other:?}"),
        }
    }

    #[test]
    fn underpowered_host_refuses_launch() {
        let (dir, app) = fixture("ram");
        let mut facts = good_facts();
        facts.total_ram_mb = 2048;
        assert!(matches!(
            prepare(&facts, &app, &dir.join("cfg")),
            Err(LaunchError::NotReady(_))
        ));
    }

    #[test]
    fn missing_feature_refuses_launch() {
        let (dir, app) = fixture("feature");
        let mut facts = good_facts();
        facts.sandbox_feature_present = false;
        assert!(matches!(
            prepare(&facts, &app, &dir.join("cfg")),
            Err(LaunchError::NotReady(_))
        ));
    }

    #[test]
    fn prepare_writes_a_locked_down_config_and_never_executes() {
        let (dir, app) = fixture("prepare");
        let prepared = prepare(&good_facts(), &app, &dir.join("cfg")).expect("prepare");
        let xml = std::fs::read_to_string(&prepared.config_path).expect("config");
        assert!(xml.contains("<Networking>Disable</Networking>"));
        assert!(xml.contains("<ReadOnly>true</ReadOnly>"));
        assert!(prepared.command.contains("sample.exe"));
        assert!(xml.contains("sample.exe"));
        assert!(!xml.contains("<Networking>Enable</Networking>"));
    }

    #[test]
    fn non_windows_launch_refuses_after_preparing() {
        let (dir, app) = fixture("platform");
        let prepared = prepare(&good_facts(), &app, &dir.join("cfg")).expect("prepare");
        #[cfg(not(windows))]
        assert!(matches!(launch(&prepared, false), Err(LaunchError::NotWindows)));
        #[cfg(windows)]
        let _ = (prepared, dir);
    }
}
