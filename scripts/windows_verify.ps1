<#
 Litric Defender - Windows 11 acceptance run.
 Run in a DISPOSABLE VM or a machine you are willing to test on, from the repository root,
 in a normal (non-elevated) PowerShell, with Rust >= 1.85 installed (>= 1.95 to include litric-yara).
 It runs only the repository's own tests and writes evidence to windows-evidence.txt.
 It does NOT execute malware, change Windows Security settings, or install any driver.
#>
$ErrorActionPreference = 'Continue'
$out = 'windows-evidence.txt'
"Litric Windows evidence - $(Get-Date -Format o)" | Out-File $out
"OS: $((Get-CimInstance Win32_OperatingSystem).Caption) $((Get-CimInstance Win32_OperatingSystem).BuildNumber)" | Out-File $out -Append
"rustc: $(rustc --version)" | Out-File $out -Append
"RAM MB: $([int]((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1MB))" | Out-File $out -Append

$steps = @(
  @{ n='workspace tests (excluding yara)'; c='cargo test --workspace --exclude litric-yara' },
  @{ n='wintrust tests (Windows-only tests included)'; c='cargo test -p litric-wintrust' },
  @{ n='realtime + recovery + honeyvault + guard tests'; c='cargo test -p realtime -p recovery -p honeyvault -p litric-guard' },
  @{ n='real-time monitor e2e (ReadDirectoryChangesW path)'; c='cargo test -p litric-monitor' },
  @{ n='yara module tests (needs Rust 1.95+)'; c='cargo test -p litric-yara' },
  @{ n='release build of the CLI'; c='cargo build --release -p litric-cli' }
)
foreach ($s in $steps) {
  "`n=== $($s.n) ===" | Out-File $out -Append
  $log = & cmd /c "$($s.c) 2>&1"
  ($log | Select-String -Pattern 'test result|FAILED|panicked|error(\[|:)|Finished' | ForEach-Object { $_.Line }) | Out-File $out -Append
  "exit code: $LASTEXITCODE" | Out-File $out -Append
}

# Authenticode spot checks through the library path used by the product (expectations are printed, not assumed)
"`n=== Authenticode (embedded signatures only; catalog-signed system files are NOT supported) ===" | Out-File $out -Append
"Expected: a Microsoft-signed installer with an embedded signature -> Trusted; a text renamed to .exe -> NoEmbeddedSignature/Rejected" | Out-File $out -Append
"Run: cargo test -p litric-wintrust -- --nocapture   (see above)" | Out-File $out -Append
Write-Host "Done. Send windows-evidence.txt back so the Windows status can move from UNPROVEN to TESTED."
