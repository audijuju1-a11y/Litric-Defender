//! Test fixture for the process gate: a harmless process that lives long enough
//! to be suspended, scanned and (in an enforcement test) terminated.
//!
//! This binary is not part of the protection stack and is not installed by any
//! packaging step. It exists so the gate's real Win32 suspend/terminate path can
//! be exercised with a benign process instead of live malware.

use std::time::Duration;

fn main() {
    let mut hold = 20u64;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--hold" {
            if let Some(value) = args.next() {
                hold = value.parse().unwrap_or(20);
            }
        }
    }
    println!("litric-pgate-selftest pid={} hold={hold}s", std::process::id());
    std::thread::sleep(Duration::from_secs(hold));
}
