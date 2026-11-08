<#
 Litric Defender - real-time protection acceptance run (Windows 11).

 Proves, with the REAL daemon and the industry-standard EICAR test string, that:
   1. a file dropped into a watched folder while the daemon runs is detected, moved into the
      encrypted vault, and removed from its original place (event path);
   2. a file that already existed before the daemon started is handled by the startup sweep;
   3. a benign file is left alone;
   4. /status reports user-mode real-time honestly (monitor alive, but NO blocking, NO kernel sensor);
   5. the vault entry verifies (decrypts and re-hashes);
   7. a harmless ransomware simulation (random-data overwrite + marker-extension renames of the
      script's own temp files, no decoy) is detected from behaviour alone;
   6. the ransomware behaviour layer sees the same file events: tampering with a decoy file raises a
      critical incident that is reported as NOT contained (alert-only, no process attribution).

 Run from the repository root in PowerShell. Rust >= 1.85 required. An elevated prompt is the safest
 choice because the daemon hardens its data directory to SYSTEM/Administrators; if the token cannot be
 read the script says so.

 It uses only a temporary folder, writes the harmless EICAR string (never real malware), listens on
 127.0.0.1 only, and does NOT change Microsoft Defender or any Windows Security setting.

 IMPORTANT - Microsoft Defender: if Defender real-time protection is on, it will also act on the EICAR
 file and may remove it before Litric does. In that case the result is reported INCONCLUSIVE (exit 2),
 never PASS: the script only passes when Litric's OWN vault holds the file. Run it on a machine or VM
 where you accept that, or where Defender is already configured the way you want. This script will
 not touch that configuration for you.

 Exit codes: 0 = all checks passed, 1 = a check failed, 2 = inconclusive (another product interfered).
 Evidence is written to realtime-evidence.txt.
#>
param(
  [int]$Port = 18787,
  [int]$TimeoutSeconds = 40
)
$ErrorActionPreference = 'Stop'
$evidence = Join-Path (Get-Location) 'realtime-evidence.txt'
$script:failures = 0
$script:inconclusive = 0

function Log([string]$m) { Write-Host $m; $m | Out-File $evidence -Append -Encoding utf8 }
function Pass([string]$m) { Log "PASS         $m" }
function Fail([string]$m) { $script:failures++; Log "FAIL         $m" }
function Maybe([string]$m) { $script:inconclusive++; Log "INCONCLUSIVE $m" }

# The EICAR string is assembled at run time so this script file is not itself a detection.
function New-EicarBytes {
  $a = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EI'
  $b = 'CAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
  return [System.Text.Encoding]::ASCII.GetBytes($a + $b)
}

"Litric real-time acceptance - $(Get-Date -Format o)" | Out-File $evidence -Encoding utf8
$os = Get-CimInstance Win32_OperatingSystem
Log "OS: $($os.Caption) build $($os.BuildNumber); rustc: $(rustc --version)"
try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  Log "Microsoft Defender real-time protection enabled: $($mp.RealTimeProtectionEnabled) (this script does not change it)"
  $defenderOn = [bool]$mp.RealTimeProtectionEnabled
} catch {
  Log "Microsoft Defender state could not be read ($($_.Exception.Message)); assuming it may interfere"
  $defenderOn = $true
}

# --- build -------------------------------------------------------------------------------------
Log "`n=== build litricd (release) ==="
& cargo build --release -p litric-service 2>&1 | Select-String -Pattern 'error|warning: unused|Finished' | ForEach-Object { Log $_.Line }
$exe = Join-Path (Get-Location) 'target\release\litricd.exe'
if (-not (Test-Path $exe)) { Fail "litricd.exe was not built"; exit 1 }

# --- fixtures ----------------------------------------------------------------------------------
$root = Join-Path ([System.IO.Path]::GetTempPath()) ("litric_rt_" + [guid]::NewGuid().ToString('N').Substring(0, 8))
$watch = Join-Path $root 'watch'
$data = Join-Path $root 'data'
New-Item -ItemType Directory -Force -Path $watch | Out-Null
$decoyDir = Join-Path $watch 'Litric Decoys'
$pre = Join-Path $watch 'preexisting_before_start.com'
$benign = Join-Path $watch 'notes.txt'
[System.IO.File]::WriteAllBytes($pre, (New-EicarBytes))          # exists BEFORE the daemon starts
[System.IO.File]::WriteAllText($benign, 'meeting notes - nothing to see')
Start-Sleep -Milliseconds 800
$preSurvivedStart = Test-Path $pre
Log "fixtures in $root (pre-existing EICAR still present before start: $preSurvivedStart)"

$daemon = $null
try {
  # --- start the daemon with the monitor on, watching ONLY the temporary folder ----------------
  $args = @('serve', '--addr', "127.0.0.1:$Port", '--data-dir', $data, '--rules', 'rules',
            '--realtime', 'on', '--realtime-no-default-dirs', '--realtime-watch', $watch,
            '--realtime-decoy-dir', "`"$decoyDir`"")
  Log "`n=== start: litricd $($args -join ' ') ==="
  $stdout = Join-Path $root 'litricd.out.txt'
  $stderr = Join-Path $root 'litricd.err.txt'
  $daemon = Start-Process -FilePath $exe -ArgumentList $args -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr

  $base = "http://127.0.0.1:$Port/api/v1"
  $up = $false
  for ($i = 0; $i -lt 60 -and -not $up; $i++) {
    Start-Sleep -Milliseconds 500
    if ($daemon.HasExited) { break }
    try { Invoke-RestMethod -Uri "$base/health" -TimeoutSec 2 | Out-Null; $up = $true } catch { }
  }
  if (-not $up) {
    Fail "the daemon did not come up"
    if (Test-Path $stderr) { Get-Content $stderr -Tail 20 | ForEach-Object { Log "  stderr: $_" } }
    exit 1
  }
  $tokenFile = Join-Path $data 'api.token'
  try { $token = (Get-Content $tokenFile -ErrorAction Stop).Trim() }
  catch { Fail "cannot read $tokenFile ($($_.Exception.Message)) - rerun from an ELEVATED PowerShell"; exit 1 }
  $h = @{ Authorization = "Bearer $token" }
  function Api([string]$p) { Invoke-RestMethod -Headers $h -Uri "$base/$p" -TimeoutSec 10 }

  # --- 4. honest status -------------------------------------------------------------------------
  Log "`n=== status honesty ==="
  $st = Api 'status'
  Log "state=$($st.state) real_time_protection=$($st.real_time_protection)"
  if ($st.real_time_protection -eq $true) { Pass "status reports the user-mode monitor as running" } else { Fail "status does not report the monitor as running (realtime: $($st.realtime | ConvertTo-Json -Compress))" }
  if ($st.capabilities.real_time_file_blocking -eq $false -and $st.capabilities.kernel_sensor -eq $false) { Pass "status does NOT claim blocking or a kernel sensor" } else { Fail "status over-claims blocking or a kernel sensor" }
  if ($st.state -in @('realtime_user_mode', 'realtime_degraded')) { Pass "state is '$($st.state)' (never 'protected')" } else { Fail "unexpected state '$($st.state)'" }

  # --- 2. startup sweep (file existed before start) ---------------------------------------------
  Log "`n=== startup sweep: file that existed before the daemon started ==="
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do { Start-Sleep -Milliseconds 500; $q = @((Api 'quarantine').entries) } while ((Get-Date) -lt $deadline -and $q.Count -lt 1)
  if ($q.Count -ge 1 -and -not (Test-Path $pre)) { Pass "pre-existing EICAR was quarantined by the sweep and removed from disk" }
  elseif (-not (Test-Path $pre)) { Maybe "the pre-existing file vanished but Litric's vault is empty - another product (likely Defender) removed it first" }
  else { Fail "pre-existing EICAR is still on disk after $TimeoutSeconds s (sweep did not act)" }
  $sw = (Api 'realtime').sweep
  Log "sweep: finished=$($sw.finished) visited=$($sw.visited) errors=$($sw.errors) truncated=$($sw.truncated)"

  # --- 1. event path (file dropped while running) -----------------------------------------------
  Log "`n=== real-time event path: file dropped while the daemon is running ==="
  $before = @((Api 'quarantine').entries).Count
  $drop = Join-Path $watch 'invoice_dropped_live.com'
  [System.IO.File]::WriteAllBytes($drop, (New-EicarBytes))
  $t0 = Get-Date
  $deadline = $t0.AddSeconds($TimeoutSeconds)
  do { Start-Sleep -Milliseconds 250; $now = @((Api 'quarantine').entries).Count } while ((Get-Date) -lt $deadline -and $now -le $before)
  $latency = [int]((Get-Date) - $t0).TotalMilliseconds
  if ($now -gt $before -and -not (Test-Path $drop)) { Pass "EICAR dropped at runtime was quarantined and removed in about $latency ms" }
  elseif (-not (Test-Path $drop)) { Maybe "the dropped file vanished but Litric's vault did not grow - another product (likely Defender) removed it first" }
  else { Fail "dropped EICAR is still on disk after $TimeoutSeconds s" }

  # --- 3. benign untouched ------------------------------------------------------------------------
  Log "`n=== benign file ==="
  [System.IO.File]::WriteAllText((Join-Path $watch 'benign_live.txt'), 'hello world')
  Start-Sleep -Seconds 2
  if ((Test-Path $benign) -and (Test-Path (Join-Path $watch 'benign_live.txt'))) { Pass "benign files were left alone" } else { Fail "a benign file was removed" }

  # --- 5. vault integrity + evidence -------------------------------------------------------------
  Log "`n=== vault ==="
  $entries = @((Api 'quarantine').entries)
  foreach ($e in $entries) { Log "vault entry: $($e.id) <- $($e.original_path)" }
  $v = @((Api 'quarantine/verify').results)
  $bad = @($v | Where-Object { -not $_.ok })
  if ($entries.Count -gt 0 -and $bad.Count -eq 0) { Pass "every vault entry decrypts and re-hashes ($($v.Count) checked)" }
  elseif ($entries.Count -eq 0) { Log "no vault entries to verify" }
  else { Fail "$($bad.Count) vault entr(ies) failed verification" }

  # --- 6. ransomware layer: decoy tamper -> critical incident -----------------------------------
  Log "`n=== ransomware layer: decoy tampering ==="
  $rw = (Api 'status').realtime.ransomware
  if ($rw.running -eq $true) { Pass "the RansomShield feed is attached to the monitor and running" } else { Fail "the RansomShield feed is not running ($($rw | ConvertTo-Json -Compress))" }
  $decoy = Get-ChildItem -LiteralPath $decoyDir -File -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $decoy) { Fail "no decoy files were created in $decoyDir" }
  else {
    $rnd = New-Object byte[] 8192
    (New-Object System.Random 7).NextBytes($rnd)
    [System.IO.File]::WriteAllBytes($decoy.FullName, $rnd)                 # what ransomware does ...
    Rename-Item -LiteralPath $decoy.FullName -NewName ($decoy.Name + '.locked')   # ... then renames
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do { Start-Sleep -Milliseconds 300; $rw = (Api 'status').realtime.ransomware } while ((Get-Date) -lt $deadline -and @($rw.incidents).Count -lt 1)
    $inc = @($rw.incidents)
    if ($inc.Count -ge 1 -and $inc[0].level -eq 'critical') { Pass "decoy tampering raised a critical incident: $($inc[0].reasons[0])" } else { Fail "no critical incident after decoy tampering ($($rw | ConvertTo-Json -Compress -Depth 4))" }
    if ($inc.Count -ge 1 -and $inc[0].contained -eq $false) { Pass "the incident honestly reports contained=false (alert only)" } elseif ($inc.Count -ge 1) { Fail "the incident claims containment it cannot provide" }
  }
  # --- 7. harmless ransomware simulation: behaviour only, no decoy involved -----------------------
  Log "`n=== ransomware simulation (own temp files only, no decoys) ==="
  $before = @((Api 'status').realtime.ransomware.incidents).Count
  $sim = Join-Path $watch 'sim_docs'
  New-Item -ItemType Directory -Force -Path $sim | Out-Null
  1..60 | ForEach-Object { [System.IO.File]::WriteAllText((Join-Path $sim "file$_.docx"), ('original text ' * 60)) }
  Start-Sleep -Seconds 35   # outlast the 30 s incident cooldown so this run is reported on its own
  $rng = New-Object System.Random 11
  1..60 | ForEach-Object {
    $f = Join-Path $sim "file$_.docx"
    $b = New-Object byte[] 16384; $rng.NextBytes($b)
    [System.IO.File]::WriteAllBytes($f, $b)                    # "encrypt": random data, high entropy
    Rename-Item -LiteralPath $f -NewName "file$_.docx.locked"    # marker extension
  }
  [System.IO.File]::WriteAllText((Join-Path $sim 'README_RESTORE_FILES.txt'), 'test note - this is a harmless simulation')
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do { Start-Sleep -Milliseconds 300; $after = @((Api 'status').realtime.ransomware.incidents).Count } while ((Get-Date) -lt $deadline -and $after -le $before)
  if ($after -gt $before) { Pass "the simulated ransomware run raised a new critical incident from behaviour alone" } else { Fail "the simulated ransomware run was not detected" }

  $st = Api 'status'
  if (@($st.realtime.degraded).Count -eq 0) { Pass "no layer reports degraded protection" } else { Fail "degraded: $($st.realtime.degraded -join '; ')" }

  Log "`n=== monitor detail ==="
  $rt = Api 'realtime'
  Log ($rt | ConvertTo-Json -Depth 6)
  Log "recent events:"
  (Api 'realtime/events?limit=20').events | ForEach-Object { Log ("  " + ($_ | ConvertTo-Json -Compress -Depth 5)) }
}
finally {
  if ($daemon -and -not $daemon.HasExited) { Stop-Process -Id $daemon.Id -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Milliseconds 500
  Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
}

Log "`n=== result ==="
if ($script:failures -gt 0) { Log "FAILED: $($script:failures) check(s) failed. Send realtime-evidence.txt back."; exit 1 }
if ($script:inconclusive -gt 0) {
  Log "INCONCLUSIVE: $($script:inconclusive) check(s) could not be attributed to Litric because another product removed the file first. This is not a pass."
  exit 2
}
Log "ALL CHECKS PASSED on this machine. This proves user-mode, post-write real-time detection + quarantine only; it does not prove pre-execution blocking or process-level ransomware containment (not implemented)."
exit 0
