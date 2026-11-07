//! Windows sources and response. STATUS: written but NOT yet compiled or
//! run (no Windows toolchain/VM available when this was authored).
//! Run `cargo check -p realtime` on Windows first and fix any API drift.
//!
//! Known limits (by design, documented in STATUS.md):
//!  * ReadDirectoryChangesW does not identify the acting process: events
//!    carry pid 0, so they can alert but never trigger containment.
//!  * A kernel buffer overflow (0 bytes returned) means lost events; it is
//!    counted as dropped so protection shows as degraded.

use crate::{Containment, Pipeline, RawEvent, RawKind};
use std::sync::{atomic::Ordering, Arc};
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadDirectoryChangesW, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY,
    FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE,
    FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, OpenThread, SuspendThread, THREAD_SUSPEND_RESUME,
};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Recursively watch `root` on a background thread. Runs until the
/// handle read fails (e.g. directory removed).
pub fn watch(root: &str, pipe: Arc<Pipeline>) -> std::thread::JoinHandle<()> {
    let root = root.to_string();
    std::thread::spawn(move || unsafe {
        let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
        let h = CreateFileW(
            wide.as_ptr(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            0,
        );
        if h == INVALID_HANDLE_VALUE {
            pipe.stats.dropped.fetch_add(1, Ordering::Relaxed); // visible as degraded
            return;
        }
        // DWORD-aligned 64 KiB buffer.
        let mut buf = vec![0u32; 16 * 1024];
        let filter = FILE_NOTIFY_CHANGE_FILE_NAME
            | FILE_NOTIFY_CHANGE_CREATION
            | FILE_NOTIFY_CHANGE_LAST_WRITE
            | FILE_NOTIFY_CHANGE_SIZE;
        loop {
            let mut bytes: u32 = 0;
            let ok = ReadDirectoryChangesW(
                h,
                buf.as_mut_ptr() as *mut _,
                (buf.len() * 4) as u32,
                1, // watch subtree
                filter,
                &mut bytes,
                std::ptr::null_mut(),
                None,
            );
            if ok == 0 {
                let _ = GetLastError();
                break;
            }
            if bytes == 0 {
                // Kernel buffer overflowed: events were lost.
                pipe.stats.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let base = buf.as_ptr() as *const u8;
            let mut off = 0usize;
            loop {
                let p = base.add(off);
                let next = *(p as *const u32) as usize;
                let action = *(p.add(4) as *const u32);
                let name_len = *(p.add(8) as *const u32) as usize / 2;
                let name = std::slice::from_raw_parts(p.add(12) as *const u16, name_len);
                let rel = String::from_utf16_lossy(name);
                let path = format!("{}\\{}", root.trim_end_matches('\\'), rel);
                let kind = match action {
                    1 => Some(RawKind::Created),
                    2 => Some(RawKind::Deleted),
                    3 => Some(RawKind::Modified),
                    5 => Some(RawKind::Renamed {
                        new_ext: std::path::Path::new(&rel)
                            .extension()
                            .map(|e| e.to_string_lossy().to_string())
                            .unwrap_or_default(),
                    }),
                    _ => None, // 4 = rename-old-name: ignored
                };
                if let Some(kind) = kind {
                    pipe.submit(RawEvent { pid: 0, image: String::new(), path, kind, t_ms: now_ms() });
                }
                if next == 0 {
                    break;
                }
                off += next;
            }
        }
        CloseHandle(h);
    })
}

/// Suspends every thread of a process using documented Win32 APIs.
pub struct Suspender;

impl Containment for Suspender {
    fn suspend(&mut self, pid: u32) -> Result<(), String> {
        unsafe {
            // Never suspend ourselves or the System/idle pseudo-processes.
            if pid <= 4 || pid == GetCurrentProcessId() {
                return Err(format!("refusing to suspend protected pid {pid}"));
            }
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snap == INVALID_HANDLE_VALUE {
                return Err("thread snapshot failed".into());
            }
            let mut te: THREADENTRY32 = std::mem::zeroed();
            te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            let (mut suspended, mut failed) = (0u32, 0u32);
            let mut more = Thread32First(snap, &mut te);
            while more != 0 {
                if te.th32OwnerProcessID == pid {
                    let t = OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32ThreadID);
                    if t != 0 {
                        if SuspendThread(t) != u32::MAX { suspended += 1 } else { failed += 1 }
                        CloseHandle(t);
                    } else {
                        failed += 1;
                    }
                }
                more = Thread32Next(snap, &mut te);
            }
            CloseHandle(snap);
            if suspended == 0 {
                Err(format!("no threads suspended for pid {pid} ({failed} failures)"))
            } else if failed > 0 {
                Err(format!("partially suspended pid {pid}: {suspended} ok, {failed} failed"))
            } else {
                Ok(())
            }
        }
    }
}
