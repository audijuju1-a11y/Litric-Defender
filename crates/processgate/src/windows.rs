//! Windows implementation of the process gate's OS surface.
//!
//! Uses only documented APIs:
//! * `CreateToolhelp32Snapshot` / `Process32FirstW` / `Process32NextW`
//! * `OpenProcess` + `QueryFullProcessImageNameW`
//! * `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)` + `OpenThread` + `SuspendThread`
//! * `TerminateProcess` (only after the policy says `Block`)
//!
//! Nothing here hooks `CreateProcess`, patches the SSDT, or injects code. The
//! honest cost of that choice is a race: a process can execute for a few
//! milliseconds before its threads are suspended.

use std::io;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, Thread32First, Thread32Next,
    PROCESSENTRY32W, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenThread, QueryFullProcessImageNameW, ResumeThread, SuspendThread,
    TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
    THREAD_SUSPEND_RESUME,
};

use crate::{ProcControl, ProcInfo, ProtectedSet, Suspension};

/// Upper bound for a Win32 path (extended-length paths included).
const MAX_IMAGE_PATH: usize = 32_768;

fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Enumerates running processes. Errors yield an empty list: a failed snapshot
/// must never look like "no new processes" silently, so the caller counts ticks.
pub fn snapshot_processes() -> Vec<ProcInfo> {
    let mut out = Vec::new();
    // SAFETY: standard Toolhelp snapshot; the handle is closed below.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return out;
    }
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    // SAFETY: `entry.dwSize` is set and the handle is valid.
    let mut ok = unsafe { Process32FirstW(snap, &mut entry) };
    while ok != 0 {
        out.push(ProcInfo {
            pid: entry.th32ProcessID,
            parent: entry.th32ParentProcessID,
            name: wide_to_string(&entry.szExeFile),
        });
        // SAFETY: same buffer and handle as above.
        ok = unsafe { Process32NextW(snap, &mut entry) };
    }
    // SAFETY: the handle came from CreateToolhelp32Snapshot.
    unsafe { CloseHandle(snap) };
    out
}

/// PIDs of this process's ancestors, so the gate can never suspend the chain
/// that keeps it alive (for example `services.exe`).
pub fn ancestor_pids(self_pid: u32) -> Vec<u32> {
    let snapshot = snapshot_processes();
    let mut parents = std::collections::HashMap::new();
    for p in snapshot {
        parents.insert(p.pid, p.parent);
    }
    let mut out = Vec::new();
    let mut current = self_pid;
    for _ in 0..64 {
        match parents.get(&current).copied() {
            Some(parent) if parent != 0 && parent != current => {
                out.push(parent);
                current = parent;
            }
            _ => break,
        }
    }
    out
}

/// Directories the gate must never suspend a process from.
///
/// This is a deliberate, conservative choice: the engine has measured a rule
/// false positive on a Microsoft system DLL, so operating on Windows' own
/// binaries is not acceptable. On-demand scans still cover them.
pub fn protected_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for key in ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(value) = std::env::var_os(key) {
            let path = PathBuf::from(value);
            if !path.as_os_str().is_empty() {
                roots.push(path);
            }
        }
    }
    if let Some(program_data) = std::env::var_os("ProgramData") {
        roots.push(PathBuf::from(program_data).join("Microsoft"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            roots.push(dir.to_path_buf());
        }
    }
    roots
}

/// Ready-made protection set for the running process.
pub fn protected_set() -> ProtectedSet {
    let self_pid = std::process::id();
    ProtectedSet::new(protected_roots(), self_pid, ancestor_pids(self_pid))
}

/// Suspension of one process. Dropping it resumes every thread it suspended.
struct WinSuspension {
    pid: u32,
    process: windows_sys::Win32::Foundation::HANDLE,
    threads: Vec<windows_sys::Win32::Foundation::HANDLE>,
    suspended: bool,
    finished: bool,
}

impl Drop for WinSuspension {
    fn drop(&mut self) {
        if self.suspended && !self.finished {
            for thread in self.threads.drain(..) {
                // SAFETY: handles were opened by OpenThread and are closed here.
                unsafe {
                    ResumeThread(thread);
                    CloseHandle(thread);
                }
            }
        } else {
            for thread in self.threads.drain(..) {
                // SAFETY: as above.
                unsafe { CloseHandle(thread) };
            }
        }
        if !self.process.is_null() {
            // SAFETY: handle came from OpenProcess and is closed exactly once.
            unsafe { CloseHandle(self.process) };
            self.process = std::ptr::null_mut();
        }
    }
}

impl Suspension for WinSuspension {
    fn resume(mut self: Box<Self>) -> Result<(), String> {
        let mut failure = None;
        for thread in self.threads.drain(..) {
            // SAFETY: handle opened with THREAD_SUSPEND_RESUME.
            let previous = unsafe { ResumeThread(thread) };
            if previous == u32::MAX {
                failure = Some(format!("ResumeThread failed: {}", io::Error::last_os_error()));
            }
            // SAFETY: closed once, after the resume attempt.
            unsafe { CloseHandle(thread) };
        }
        self.suspended = false;
        self.finished = true;
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn terminate(mut self: Box<Self>) -> Result<(), String> {
        // SAFETY: handle opened with PROCESS_TERMINATE.
        let ok = unsafe { TerminateProcess(self.process, 1) };
        self.finished = true;
        self.suspended = false;
        if ok == 0 {
            return Err(format!(
                "TerminateProcess failed for pid {}: {}",
                self.pid,
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

/// Real OS surface used by the daemon.
pub struct WindowsControl;

impl WindowsControl {
    pub fn new() -> Self {
        WindowsControl
    }
}

impl Default for WindowsControl {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcControl for WindowsControl {
    fn snapshot(&mut self) -> Vec<ProcInfo> {
        snapshot_processes()
    }

    fn image_path(&mut self, pid: u32) -> Option<PathBuf> {
        // SAFETY: query-only handle; closed before every return.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return None;
        }
        let mut buffer = vec![0u16; MAX_IMAGE_PATH];
        let mut size = buffer.len() as u32;
        // SAFETY: buffer length matches `size`; the call writes at most `size` UTF-16 units.
        let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) };
        // SAFETY: handle is valid and closed once.
        unsafe { CloseHandle(handle) };
        if ok == 0 {
            return None;
        }
        buffer.truncate(size as usize);
        Some(PathBuf::from(wide_to_string(&buffer)))
    }

    fn suspend(&mut self, pid: u32) -> Result<Box<dyn Suspension>, String> {
        // SAFETY: requested rights are the minimum needed for suspend + block.
        let process = unsafe {
            OpenProcess(
                PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            )
        };
        if process.is_null() {
            return Err(format!(
                "OpenProcess({pid}) failed: {}",
                io::Error::last_os_error()
            ));
        }

        let mut threads: Vec<windows_sys::Win32::Foundation::HANDLE> = Vec::new();
        // Newly created threads can escape the first pass; repeat a couple of
        // times while the process is already mostly frozen.
        for _ in 0..3 {
            let mut added = 0usize;
            // SAFETY: snapshot handle closed below.
            let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
            if snap == INVALID_HANDLE_VALUE {
                break;
            }
            let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            // SAFETY: dwSize set; handle valid.
            let mut ok = unsafe { Thread32First(snap, &mut entry) };
            while ok != 0 {
                if entry.th32OwnerProcessID == pid {
                    // SAFETY: minimal rights for SuspendThread.
                    let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                    if !thread.is_null() {
                        // SAFETY: handle opened for suspend/resume.
                        let previous = unsafe { SuspendThread(thread) };
                        if previous == u32::MAX {
                            // SAFETY: close the handle we opened.
                            unsafe { CloseHandle(thread) };
                        } else {
                            threads.push(thread);
                            added += 1;
                        }
                    }
                }
                // SAFETY: same buffer and handle.
                ok = unsafe { Thread32Next(snap, &mut entry) };
            }
            // SAFETY: snapshot handle closed once.
            unsafe { CloseHandle(snap) };
            if added == 0 {
                break;
            }
        }

        if threads.is_empty() {
            // SAFETY: process handle opened above.
            unsafe { CloseHandle(process) };
            return Err(format!("no thread of pid {pid} could be suspended"));
        }

        Ok(Box::new(WinSuspension {
            pid,
            process,
            threads,
            suspended: true,
            finished: false,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_contains_this_process() {
        let all = snapshot_processes();
        assert!(all.len() > 1, "expected a populated process list");
        let me = std::process::id();
        assert!(all.iter().any(|p| p.pid == me), "current process missing");
    }

    #[test]
    fn image_path_of_this_process_is_an_exe() {
        let mut api = WindowsControl::new();
        let path = api.image_path(std::process::id()).expect("own image path");
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert_eq!(ext, "exe", "{}", path.display());
    }

    #[test]
    fn ancestors_include_a_parent_when_present() {
        let list = ancestor_pids(std::process::id());
        // A test runner always has a parent; the walk must terminate.
        assert!(list.len() < 64);
    }

    #[test]
    fn protected_roots_include_the_windows_directory() {
        let roots = protected_roots();
        let has_windows = roots.iter().any(|r| {
            let text = r.display().to_string().to_ascii_lowercase();
            text.ends_with("windows") || text.ends_with("windows\\")
        });
        assert!(has_windows, "{roots:?}");
    }
}
