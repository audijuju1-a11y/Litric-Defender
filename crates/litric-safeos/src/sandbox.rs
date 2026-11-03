//! Windows Sandbox configuration generation.
//!
//! This produces the `.wsb` document only. Launching Windows Sandbox requires the
//! feature to be installed and a Windows 11 host; nothing here launches it, and the
//! backend reports itself unavailable elsewhere.
//!
//! The generated configuration is deliberately locked down: networking disabled,
//! every redirection disabled, vGPU off by default, and at most read-only mapped
//! folders that must be explicit staging paths.

use std::path::PathBuf;

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

/// True when this build can launch a sandbox session. Always false here.
pub const LAUNCH_IMPLEMENTED: bool = false;

/// Explain why launching is unavailable.
pub fn launch_unavailable_reason() -> &'static str {
    "Windows Sandbox launch is not implemented in this build; configuration \
     generation is implemented and tested, execution requires Windows 11"
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
    fn launch_is_honestly_unavailable() {
        assert!(!LAUNCH_IMPLEMENTED);
        assert!(launch_unavailable_reason().contains("not implemented"));
    }
}
