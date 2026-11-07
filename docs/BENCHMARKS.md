# Benchmarks — measured on native Windows 11

All numbers below were produced on the host described in
`docs/WINDOWS_EVIDENCE.md` (Windows 11 Home build 26300, Intel i3-10105F
4C/8T, 16 GB RAM, `x86_64-pc-windows-gnu`, release build, 73 rules,
single-threaded engine, real files read in place). They are not vendor
comparisons, not whole-disk estimates and not detection-rate measurements.

Reproduce:

```powershell
cargo build --release
.\target\release\litric.exe bench 'C:\Windows\System32\WindowsPowerShell\v1.0' --local --rules rules --runs 3
.\target\release\litric.exe bench 'C:\Windows\System32\drivers' --local --rules rules --runs 3
```

## Engine throughput (in-process bench)

| Corpus | Files | Best of 3 | Throughput |
|---|---:|---:|---:|
| `WindowsPowerShell\v1.0` (scripts, XML, DLLs) | 767 | 1.520 s | 505 files/s, 10.4 MB/s |
| `System32\drivers` (`.sys` PE images) | 603 | 10.832 s | 56 files/s, 12.8 MB/s |

Three runs on the PowerShell corpus: 1.520 / 1.564 / 1.567 s. The driver corpus
is dominated by PE parsing, not file count; small-file throughput is the number
relevant to a quick scan.

## User-visible scan path

`litric scan <dir> --local --json` includes process start-up, JSON rendering and
report writing. On the same corpora it took 2.503 s (306 files/s) for
PowerShell and 15.961 s (37.8 files/s) for drivers. Use the JSON number for
latency expectations and the bench number for engine comparisons.

## False positives

1,370 benign Microsoft Windows files scanned: 0 malicious, 0 suspicious, 1
unreadable. All were `unknown` because no hash feed is installed. This is a
corpus result, not a general FP rate.

## Not measured

Large (>1 GB) files, whole-disk scans, multi-threaded scanning, network shares,
NTFS alternate data streams, real-time event latency, idle CPU/RAM of the
service, Windows Sandbox or Hyper-V overhead (unavailable on this Home-edition
host), and any comparison against another antivirus product. Peak memory of the
scan process was not captured reliably and is not claimed.
