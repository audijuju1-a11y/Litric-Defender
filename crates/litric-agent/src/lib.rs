//! Litric SafeOS platform agent (library).
//!
//! The agent is **read-only**: it queries Windows for host facts and reports them
//! to the local daemon. It never enables a feature, creates a network, changes a
//! service or starts a VM. The PowerShell script below is inspected by a test to
//! keep it that way.
//!
//! Facts are evidence, not permission. If a query fails, the corresponding
//! capability is false (and, for WinNAT, explicitly `nat_query_ok = false` so the
//! gateway is refused rather than assumed safe).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use litric_safeos::model::{backend_status, HostFacts, Readiness};
use serde_json::{json, Value};

/// Read-only PowerShell collector. It prints exactly one JSON object.
///
/// Queries that need elevation are wrapped in try/catch and degrade to
/// "unknown", never to an optimistic default.
pub const COLLECT_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$natQueryOk = $true
$natCount = 0
try { $natCount = @(Get-NetNat -ErrorAction Stop).Count } catch { $natQueryOk = $false }

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$cpu = @(Get-CimInstance -ClassName Win32_Processor)[0]
$disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"

$sandbox = Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\WindowsSandbox.exe')
if (-not $sandbox) {
  try {
    $f = Get-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -ErrorAction Stop
    $sandbox = ($f.State -eq 'Enabled')
  } catch { }
}

$hv = $false
try {
  $hf = Get-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Hyper-V-All' -ErrorAction Stop
  $hv = ($hf.State -eq 'Enabled')
} catch {
  $vmms = Get-Service -Name vmms -ErrorAction SilentlyContinue
  $hv = ([bool]$cs.HypervisorPresent) -and ($null -ne $vmms)
}

$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
$wsl = @($adapters | Where-Object { $_.Name -like '*WSL*' -or $_.InterfaceDescription -like '*WSL*' }).Count
$docker = @($adapters | Where-Object { $_.InterfaceDescription -like '*Docker*' -or $_.Name -like 'vEthernet*' }).Count

[ordered]@{
  known = $true
  windows_edition = [string]$os.Caption
  windows_build = [int]$os.BuildNumber
  virtualization_enabled = [bool]($cpu.VirtualizationFirmwareEnabled -and $cpu.SecondLevelAddressTranslationExtensions)
  hyperv_feature_present = [bool]$hv
  sandbox_feature_present = [bool]$sandbox
  total_ram_mb = [int64][math]::Floor($cs.TotalPhysicalMemory / 1MB)
  free_disk_mb = if ($null -ne $disk) { [int64][math]::Floor($disk.FreeSpace / 1MB) } else { 0 }
  existing_nat_networks = [int]$natCount
  nat_query_ok = $natQueryOk
  wsl_switches = [int]$wsl
  docker_switches = [int]$docker
} | ConvertTo-Json -Compress
"#;

/// Rejects reports that cannot be evidence of a Windows host.
pub fn validate(f: &HostFacts) -> Result<(), String> {
    if !f.known {
        return Err("agent report did not set known=true".into());
    }
    if f.windows_edition.trim().is_empty() {
        return Err("windows_edition is required".into());
    }
    if f.windows_build == 0 {
        return Err("windows_build is required".into());
    }
    if f.total_ram_mb == 0 {
        return Err("total_ram_mb is required".into());
    }
    if f.existing_nat_networks > 64 {
        return Err("existing_nat_networks looks implausible".into());
    }
    Ok(())
}

/// Parses a collector/fixture report and validates it.
pub fn facts_from_json_text(text: &str) -> Result<HostFacts, String> {
    let v: Value =
        serde_json::from_str(text).map_err(|e| format!("invalid facts JSON: {e}"))?;
    let facts = HostFacts::from_json(&v);
    validate(&facts)?;
    Ok(facts)
}

/// Serialises facts in the same shape the collector emits.
pub fn facts_json(f: &HostFacts) -> Value {
    json!({
        "known": f.known,
        "windows_edition": f.windows_edition,
        "windows_build": f.windows_build,
        "virtualization_enabled": f.virtualization_enabled,
        "hyperv_feature_present": f.hyperv_feature_present,
        "sandbox_feature_present": f.sandbox_feature_present,
        "total_ram_mb": f.total_ram_mb,
        "free_disk_mb": f.free_disk_mb,
        "existing_nat_networks": f.existing_nat_networks,
        "nat_query_ok": f.nat_query_ok,
        "wsl_switches": f.wsl_switches,
        "docker_switches": f.docker_switches,
    })
}

/// Human-readable summary. Always shows host support and build support apart.
pub fn summary(f: &HostFacts) -> String {
    let r = Readiness::evaluate(f);
    let mut s = String::new();
    s.push_str(&format!(
        "host          : {} (build {})\n",
        f.windows_edition, f.windows_build
    ));
    s.push_str(&format!(
        "virtualization: {}\n",
        if f.virtualization_enabled { "enabled" } else { "NOT enabled" }
    ));
    s.push_str(&format!(
        "memory / disk : {} MB / {} MB free\n",
        f.total_ram_mb, f.free_disk_mb
    ));
    s.push_str(&format!(
        "NAT networks  : {} (query {})\n",
        f.existing_nat_networks,
        if f.nat_query_ok { "ok" } else { "FAILED — gateway refused" }
    ));
    for b in backend_status(f) {
        s.push_str(&format!(
            "  {:<18} host supports: {:<3}  litric can launch: no (not implemented)\n",
            b.kind,
            if b.available { "yes" } else { "no" }
        ));
    }
    if !r.blockers.is_empty() {
        s.push_str("blockers:\n");
        for b in &r.blockers {
            s.push_str(&format!("  - {}: {}\n", b.component, b.reason));
        }
    }
    s
}

/// Runs the read-only collector. Only available on Windows builds.
pub fn collect() -> Result<HostFacts, String> {
    #[cfg(windows)]
    {
        use std::process::Command;
        let out = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                COLLECT_SCRIPT,
            ])
            .output()
            .map_err(|e| format!("cannot run powershell.exe: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "collector failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        facts_from_json_text(text.trim())
            .map_err(|e| format!("{e}; raw output: {}", text.trim()))
    }
    #[cfg(not(windows))]
    {
        Err("host probing is Windows-only and this binary was built for another OS; \
             use --fixture <facts.json> for offline testing"
            .into())
    }
}

/// Sends facts to the daemon. Returns (status code, body).
pub fn submit(addr: &str, token: &str, facts: &HostFacts) -> Result<(u16, String), String> {
    let body = facts_json(facts).to_string();
    let req = format!(
        "POST /api/v1/safeos/host-facts HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Authorization: Bearer {token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream =
        TcpStream::connect(addr).map_err(|e| format!("cannot reach litricd at {addr}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("send failed: {e}"))?;
    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(|e| format!("read failed: {e}"))?;
    let status = resp
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| "malformed HTTP response from litricd".to_string())?;
    let body = resp
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    // tiny_http may use chunked encoding; strip the chunk framing when present.
    let body = if resp.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        decode_chunked(&body)
    } else {
        body
    };
    Ok((status, body))
}

fn decode_chunked(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some((size_line, tail)) = rest.split_once("\r\n") {
        let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        if tail.len() < size {
            break;
        }
        out.push_str(&tail[..size]);
        rest = tail[size..].strip_prefix("\r\n").unwrap_or(&tail[size..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{
        "known": true,
        "windows_edition": "Windows 11 Pro",
        "windows_build": 22631,
        "virtualization_enabled": true,
        "hyperv_feature_present": true,
        "sandbox_feature_present": true,
        "total_ram_mb": 16384,
        "free_disk_mb": 102400,
        "existing_nat_networks": 0,
        "nat_query_ok": true,
        "wsl_switches": 1,
        "docker_switches": 1
    }"#;

    #[test]
    fn a_real_shaped_report_parses_and_is_usable() {
        let f = facts_from_json_text(GOOD).expect("fixture");
        assert!(f.known);
        let r = Readiness::evaluate(&f);
        assert!(r.sandbox_usable && r.hyperv_usable && r.gateway_usable);
    }

    #[test]
    fn reports_without_known_are_rejected() {
        let e = facts_from_json_text(r#"{"windows_edition":"Windows 11 Pro"}"#).unwrap_err();
        assert!(e.contains("known=true"), "{e}");
    }

    #[test]
    fn reports_without_windows_identity_are_rejected() {
        let e = facts_from_json_text(r#"{"known":true,"windows_build":22631,"total_ram_mb":8192}"#)
            .unwrap_err();
        assert!(e.contains("windows_edition"), "{e}");
    }

    #[test]
    fn a_failed_nat_query_is_not_treated_as_zero() {
        let text = GOOD.replace("\"nat_query_ok\": true", "\"nat_query_ok\": false");
        let f = facts_from_json_text(&text).expect("fixture");
        let r = Readiness::evaluate(&f);
        assert!(!r.gateway_usable);
        assert!(summary(&f).contains("FAILED"));
    }

    #[test]
    fn summary_never_claims_litric_can_launch() {
        let f = facts_from_json_text(GOOD).expect("fixture");
        let s = summary(&f);
        assert!(s.contains("litric can launch: no"));
        assert!(!s.contains("litric can launch: yes"));
    }

    #[test]
    fn collector_is_read_only() {
        for forbidden in [
            "Remove-",
            "Set-NetNat",
            "New-NetNat",
            "Disable-",
            "Enable-",
            "Start-Process",
            "Stop-Service",
            "Restart-",
            "Set-Service",
            "New-VM",
            "Remove-VM",
        ] {
            assert!(
                !COLLECT_SCRIPT.contains(forbidden),
                "collector must stay read-only but contains `{forbidden}`"
            );
        }
    }

    #[test]
    fn chunked_responses_are_decoded() {
        let body = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(body), "hello world");
    }
}
