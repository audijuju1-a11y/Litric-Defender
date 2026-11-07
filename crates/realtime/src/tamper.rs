//! Classifies process command lines that destroy recovery options.
//! Pure function: the OS source (ETW process-creation) is PLANNED.
//! Legitimate admin use exists; the engine treats a hit as ONE signal
//! (35 points) and only contains when other signals correlate.

pub fn classify_command(image: &str, cmdline: &str) -> Option<&'static str> {
    let img = image.rsplit(|c| c == '\\' || c == '/').next()?.to_lowercase();
    let c = cmdline.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ");
    match img.trim_end_matches(".exe") {
        "vssadmin" if c.contains("delete shadows") || c.contains("resize shadowstorage") => {
            Some("vssadmin deletes or shrinks shadow copies")
        }
        "diskshadow" if c.contains("delete shadows") => Some("diskshadow deletes shadow copies"),
        "wmic" if c.contains("shadowcopy") && c.contains("delete") => Some("wmic deletes shadow copies"),
        "wbadmin" if c.contains("delete catalog") || c.contains("delete systemstatebackup") || c.contains("delete backup") => {
            Some("wbadmin deletes backups or catalog")
        }
        "bcdedit" if (c.contains("recoveryenabled") && c.split(' ').any(|t| t == "no" || t == "off"))
            || (c.contains("bootstatuspolicy") && c.contains("ignoreallfailures")) => {
            Some("bcdedit disables Windows recovery")
        }
        "powershell" | "pwsh" if c.contains("win32_shadowcopy") && (c.contains("delete") || c.contains("remove")) => {
            Some("PowerShell removes shadow copies")
        }
        _ => None,
    }
}
