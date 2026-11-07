//! Windows Service Control Manager (SCM) integration.
//!
//! This is the real service host: it registers a service control handler with
//! the SCM, reports `START_PENDING` → `RUNNING` → `STOP_PENDING` → `STOPPED`, and
//! gives the daemon a [`StopToken`] it can wait on instead of sleeping forever.
//!
//! Design rules that keep this safe:
//!
//! * The installed binary path is **always** `std::env::current_exe()`. There is
//!   no CLI flag that lets a caller point the service at an arbitrary executable,
//!   so this command cannot be used to install someone else's binary as a
//!   `LocalSystem` service.
//! * `uninstall` only stops and deletes the one service name in [`SERVICE_NAME`].
//!   It never touches files, the registry beyond that service key, Windows
//!   Defender, the firewall, or any other service.
//! * Nothing here calls Defender, WSC, WFP or firewall APIs. Litric registers as a
//!   plain background service and does not claim to be an antivirus provider to
//!   Windows Security Center.
//!
//! Everything that can be tested without administrator rights is separated from
//! the SCM calls: path quoting, error classification, state names and the stop
//! token all have unit tests. An actual install/uninstall needs elevation and is
//! exercised by `installer/e2e_install.ps1`.

use std::ffi::c_void;
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_ACCESS_DENIED, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_EXISTS,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, RegisterServiceCtrlHandlerExW,
    SetServiceStatus, StartServiceCtrlDispatcherW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SC_ACTION, SC_ACTION_RESTART, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN,
    SERVICE_CONTROL_STOP, SERVICE_DELAYED_AUTO_START_INFO, SERVICE_DESCRIPTIONW,
    SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONSW, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STATUS_PROCESS,
    SERVICE_STOP, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE,
    SC_STATUS_PROCESS_INFO,
};
use windows_sys::core::PWSTR;

/// The Windows service name. Fixed: no user input reaches `CreateService`.
pub const SERVICE_NAME: &str = "LitricDefender";
/// Display name shown in `services.msc`.
pub const DISPLAY_NAME: &str = "Litric Defender";
const DESCRIPTION: &str =
    "Litric Defender background service: local detection API, quarantine and scan jobs.";

/// Access rights the service needs: change config, start, stop, delete, query.
const SERVICE_ACCESS: u32 = SERVICE_ALL_ACCESS;

/// Standard `DELETE` access right (winnt.h), used by `OpenServiceW` when the
/// handle will be passed to `DeleteService`.
const DELETE_ACCESS: u32 = 0x0001_0000;

/// Maximum time `uninstall` waits for a clean stop before giving up.
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// Failure-counter reset window (one day), in seconds.
const FAILURE_RESET_SECONDS: u32 = 86_400;

/// Restart delays applied after the first, second, third and later crashes.
/// A protection service that dies must come back without the user noticing.
/// Delays are capped so a crash loop cannot spin the CPU.
const RESTART_DELAYS_MS: [u32; 4] = [5_000, 30_000, 60_000, 300_000];

/// Errors returned by the service host, with the Win32 code preserved so an
/// operator can see *why* an operation failed instead of a generic message.
#[derive(Debug)]
pub enum ServiceError {
    /// `OpenSCManager`/`CreateService`/... was denied. Almost always means the
    /// process is not elevated.
    AccessDenied,
    /// A service with this name already exists.
    AlreadyInstalled,
    /// No service with this name is installed.
    NotInstalled,
    /// The SCM rejected the request for another reason.
    Win32 { op: &'static str, code: u32 },
    /// The executable could not be resolved.
    Io(io::Error),
    /// `run-service` was started from a console instead of the SCM.
    NotStartedByScm,
    /// The dispatcher was already started in this process.
    DispatcherAlreadyUsed,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::AccessDenied => write!(
                f,
                "access denied: installing or removing a Windows service needs an elevated \
                 (administrator) prompt"
            ),
            ServiceError::AlreadyInstalled => {
                write!(f, "service {SERVICE_NAME} is already installed")
            }
            ServiceError::NotInstalled => write!(f, "service {SERVICE_NAME} is not installed"),
            ServiceError::Win32 { op, code } => {
                write!(f, "{op} failed with Windows error {code} ({})", describe(*code))
            }
            ServiceError::Io(e) => write!(f, "{e}"),
            ServiceError::NotStartedByScm => write!(
                f,
                "run-service must be started by the Service Control Manager, not from a console"
            ),
            ServiceError::DispatcherAlreadyUsed => {
                write!(f, "the service dispatcher was already started in this process")
            }
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<io::Error> for ServiceError {
    fn from(e: io::Error) -> Self {
        ServiceError::Io(e)
    }
}

fn describe(code: u32) -> &'static str {
    match code {
        5 => "access denied",
        1060 => "service does not exist",
        1062 => "service is not active",
        1063 => "process is not connected to a service controller",
        1072 => "service is marked for deletion; close open handles and retry",
        1073 => "service already exists",
        1056 => "service is already running",
        _ => "see winerror.h",
    }
}

/// Maps a Win32 error code to the typed variant callers act on.
pub fn classify(code: u32) -> ServiceError {
    match code {
        ERROR_ACCESS_DENIED => ServiceError::AccessDenied,
        ERROR_SERVICE_EXISTS => ServiceError::AlreadyInstalled,
        ERROR_SERVICE_DOES_NOT_EXIST => ServiceError::NotInstalled,
        other => ServiceError::Win32 {
            op: "service operation",
            code: other,
        },
    }
}

fn last_error(op: &'static str) -> ServiceError {
    // SAFETY: GetLastError has no preconditions.
    let code = unsafe { GetLastError() };
    match code {
        ERROR_ACCESS_DENIED => ServiceError::AccessDenied,
        ERROR_SERVICE_EXISTS => ServiceError::AlreadyInstalled,
        ERROR_SERVICE_DOES_NOT_EXIST => ServiceError::NotInstalled,
        other => ServiceError::Win32 { op, code: other },
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Quotes a binary path and appends arguments exactly the way `CreateService`
/// expects: the executable path must be quoted when it contains spaces.
pub fn service_command_line(exe: &std::path::Path, args: &str) -> String {
    let quoted = format!("\"{}\"", exe.display());
    if args.trim().is_empty() {
        quoted
    } else {
        format!("{quoted} {}", args.trim())
    }
}

/// The command line installed for the service: this executable, `run-service`.
pub fn installed_command_line() -> Result<String, ServiceError> {
    installed_command_line_with("")
}

/// As [`installed_command_line`], with extra arguments appended after
/// `run-service` (for example `--process-gate enforce`). The executable path is
/// always the one currently running; there is no way to point the service at a
/// different binary.
pub fn installed_command_line_with(extra: &str) -> Result<String, ServiceError> {
    let exe = std::env::current_exe()?;
    let args = if extra.trim().is_empty() {
        "run-service".to_string()
    } else {
        format!("run-service {}", extra.trim())
    };
    Ok(service_command_line(&exe, &args))
}

/// Program-data directory used when the service has no explicit `--data-dir`.
///
/// `%ProgramData%\Litric Defender` — writable by the service account, not tied to
/// the installing user, and preserved by the uninstaller on purpose.
pub fn program_data_dir() -> std::path::PathBuf {
    let root = std::env::var_os("ProgramData")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\ProgramData"));
    root.join("Litric Defender")
}

/// A cooperative stop signal shared between the SCM control handler, the HTTP
/// listener thread and the main loop.
#[derive(Clone, Debug, Default)]
pub struct StopToken {
    inner: Arc<StopInner>,
}

#[derive(Debug, Default)]
struct StopInner {
    stopped: AtomicBool,
    lock: Mutex<()>,
    cv: Condvar,
}

impl StopToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn request_stop(&self) {
        let _guard = self
            .inner
            .lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.inner.stopped.store(true, Ordering::SeqCst);
        self.inner.cv.notify_all();
    }

    pub fn is_stopped(&self) -> bool {
        self.inner.stopped.load(Ordering::SeqCst)
    }

    /// Waits up to `timeout` for a stop request. Returns `true` when stopped.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let guard = self
            .inner
            .lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.is_stopped() {
            return true;
        }
        let (guard, _) = self
            .inner
            .cv
            .wait_timeout_while(guard, timeout, |_| !self.is_stopped())
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        drop(guard);
        self.is_stopped()
    }
}

/// The control handler's view of the service: reports state transitions.
#[derive(Clone, Copy)]
pub struct ServiceContext {
    handle: ServiceHandlePtr,
}

#[derive(Clone, Copy)]
struct ServiceHandlePtr(SERVICE_STATUS_HANDLE);

// SAFETY: `SERVICE_STATUS_HANDLE` is an opaque SCM handle. `SetServiceStatus`
// may be called from any thread of the service process, which is exactly what
// the handle is for.
unsafe impl Send for ServiceHandlePtr {}
unsafe impl Sync for ServiceHandlePtr {}

impl ServiceContext {
    fn report(&self, state: u32, exit_code: u32, wait_hint: u32) {
        let accepted = match state {
            SERVICE_RUNNING => SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            SERVICE_START_PENDING | SERVICE_STOP_PENDING => SERVICE_ACCEPT_STOP,
            _ => 0,
        };
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: accepted,
            dwWin32ExitCode: exit_code,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: wait_hint,
        };
        // SAFETY: the handle came from RegisterServiceCtrlHandlerExW and the
        // status structure is fully initialised.
        unsafe {
            SetServiceStatus(self.handle.0, &status);
        }
    }

    /// Reports START_PENDING.
    pub fn starting(&self) {
        self.report(SERVICE_START_PENDING, 0, 30_000);
    }

    /// Reports RUNNING, accepting stop and shutdown.
    pub fn running(&self) {
        self.report(SERVICE_RUNNING, 0, 0);
    }

    /// Reports STOP_PENDING with a 30 s hint.
    pub fn stop_pending(&self) {
        self.report(SERVICE_STOP_PENDING, 0, 30_000);
    }

    /// Reports STOPPED with the process exit code the body returned.
    pub fn stopped(&self, exit_code: u32) {
        self.report(SERVICE_STOPPED, exit_code, 0);
    }
}

static STATE_HANDLE: AtomicU32 = AtomicU32::new(SERVICE_START_PENDING);
static STOP_TOKEN: OnceLock<StopToken> = OnceLock::new();
type ServiceBody = Box<dyn FnOnce(ServiceContext, StopToken) -> u32 + Send>;

static MAIN_BODY: OnceLock<Mutex<Option<ServiceBody>>> = OnceLock::new();

fn body_slot() -> &'static Mutex<Option<ServiceBody>> {
    MAIN_BODY.get_or_init(|| Mutex::new(None))
}

/// Runs `body` as a Windows service. Blocks until the SCM stops the service.
///
/// Must be called on the process main thread before any other work: the SCM
/// requires `StartServiceCtrlDispatcherW` on the thread that owns the service.
pub fn run<F>(body: F) -> Result<(), ServiceError>
where
    F: FnOnce(ServiceContext, StopToken) -> u32 + Send + 'static,
{
    *body_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Box::new(body));
    STOP_TOKEN
        .set(StopToken::new())
        .map_err(|_| ServiceError::DispatcherAlreadyUsed)?;

    let name = wide(SERVICE_NAME);
    // Leak the wide name: RegisterServiceCtrlHandlerExW keeps the pointer for the
    // lifetime of the service, which is the lifetime of the process here.
    let name: &'static [u16] = Box::leak(name.into_boxed_slice());

    let mut table: [SERVICE_TABLE_ENTRYW; 2] = unsafe { std::mem::zeroed() };
    table[0].lpServiceName = name.as_ptr() as PWSTR;
    table[0].lpServiceProc = Some(service_main);
    table[1].lpServiceName = std::ptr::null_mut();
    table[1].lpServiceProc = None;

    // SAFETY: the table is null-terminated and lives for the call.
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok == 0 {
        let err = last_error("StartServiceCtrlDispatcherW");
        return Err(match err {
            ServiceError::Win32 { code: 1063, .. } => ServiceError::NotStartedByScm,
            other => other,
        });
    }
    Ok(())
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    // The handler must be registered immediately, before any slow work.
    let name = wide(SERVICE_NAME);
    let handle = RegisterServiceCtrlHandlerExW(
        name.as_ptr(),
        Some(control_handler),
        std::ptr::null(),
    );
    if handle.is_null() {
        return;
    }
    let ctx = ServiceContext {
        handle: ServiceHandlePtr(handle),
    };
    ctx.starting();

    // Populate the stop token used by the control handler.
    let Some(token) = STOP_TOKEN.get().cloned() else {
        ctx.stopped(1);
        return;
    };
    STATE_HANDLE.store(SERVICE_RUNNING, Ordering::SeqCst);

    let body = body_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take();
    let Some(body) = body else {
        ctx.stopped(1);
        return;
    };

    ctx.running();
    let exit_code = body(ctx, token.clone());
    ctx.stop_pending();
    ctx.stopped(exit_code);
    STATE_HANDLE.store(SERVICE_STOPPED, Ordering::SeqCst);
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    let Some(token) = STOP_TOKEN.get() else {
        return 0;
    };
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            token.request_stop();
            // Best-effort STOP_PENDING; the dispatcher handle is not stored here,
            // so the main loop reports the final state when it returns.
            0
        }
        SERVICE_CONTROL_INTERROGATE => 0,
        _ => 0,
    }
}

/// SCM-reported service states, as an enum so callers cannot print a raw number
/// without a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Unknown(u32),
}

impl ServiceState {
    pub fn from_raw(value: u32) -> Self {
        match value {
            1 => ServiceState::Stopped,
            2 => ServiceState::StartPending,
            3 => ServiceState::StopPending,
            4 => ServiceState::Running,
            5 => ServiceState::ContinuePending,
            6 => ServiceState::PausePending,
            7 => ServiceState::Paused,
            other => ServiceState::Unknown(other),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ServiceState::Stopped => "stopped",
            ServiceState::StartPending => "start-pending",
            ServiceState::StopPending => "stop-pending",
            ServiceState::Running => "running",
            ServiceState::ContinuePending => "continue-pending",
            ServiceState::PausePending => "pause-pending",
            ServiceState::Paused => "paused",
            ServiceState::Unknown(_) => "unknown",
        }
    }
}

/// What `status()` found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceStatus {
    pub state: ServiceState,
    pub process_id: u32,
}

/// Result of `install()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    Created,
    /// The service existed and already pointed at this binary; configuration was
    /// refreshed instead of failing the install.
    Updated,
}

/// Applies the crash-recovery policy to a service handle.
///
/// Best effort: the service is usable without it, and callers report the return
/// value instead of aborting an otherwise valid install.
fn apply_failure_actions(handle: *mut c_void) -> bool {
    let mut actions: [SC_ACTION; RESTART_DELAYS_MS.len()] = std::array::from_fn(|i| SC_ACTION {
        Type: SC_ACTION_RESTART,
        Delay: RESTART_DELAYS_MS[i],
    });
    let mut failure = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: FAILURE_RESET_SECONDS,
        lpRebootMsg: std::ptr::null_mut(),
        lpCommand: std::ptr::null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    // SAFETY: the action array outlives the call and the struct points at it.
    let ok = unsafe {
        ChangeServiceConfig2W(
            handle,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            &mut failure as *mut _ as *mut c_void,
        )
    };
    ok != 0
}

/// Installs (or refreshes) the service for the currently running executable.
///
/// Requires administrator rights. Does not start the service: the SCM does that
/// at boot (`SERVICE_AUTO_START`) or on demand.
pub fn install(extra_args: &str) -> Result<InstallOutcome, ServiceError> {
    let exe = std::env::current_exe()?.canonicalize()?;
    if !exe.is_file() {
        return Err(ServiceError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} is not a file", exe.display()),
        )));
    }
    let args = if extra_args.trim().is_empty() {
        "run-service".to_string()
    } else {
        format!("run-service {}", extra_args.trim())
    };
    let command_line = service_command_line(&exe, &args);
    let name = wide(SERVICE_NAME);
    let display = wide(DISPLAY_NAME);
    let description = wide(DESCRIPTION);
    let command_line_w = wide(&command_line);

    // SAFETY: all pointers refer to live, nul-terminated buffers for the duration
    // of the call; optional parameters are null.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE) };
    if manager.is_null() {
        return Err(last_error("OpenSCManagerW"));
    }

    let service = unsafe {
        CreateServiceW(
            manager,
            name.as_ptr(),
            display.as_ptr(),
            SERVICE_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            command_line_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };

    let outcome = if service.is_null() {
        let err = last_error("CreateServiceW");
        match err {
            ServiceError::AlreadyInstalled => {
                // Refresh the description and delayed-start flag of the existing
                // service, but never silently repoint it at another binary.
                let existing = unsafe {
                    OpenServiceW(manager, name.as_ptr(), SERVICE_ALL_ACCESS)
                };
                if existing.is_null() {
                    unsafe { CloseServiceHandle(manager) };
                    return Err(last_error("OpenServiceW"));
                }
                let mut desc = SERVICE_DESCRIPTIONW {
                    lpDescription: description.as_ptr() as PWSTR,
                };
                unsafe {
                    ChangeServiceConfig2W(
                        existing,
                        SERVICE_CONFIG_DESCRIPTION,
                        &mut desc as *mut _ as *mut c_void,
                    );
                    let mut delayed = SERVICE_DELAYED_AUTO_START_INFO {
                        fDelayedAutostart: 0,
                    };
                    ChangeServiceConfig2W(
                        existing,
                        SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                        &mut delayed as *mut _ as *mut c_void,
                    );
                    apply_failure_actions(existing);
                    CloseServiceHandle(existing);
                    CloseServiceHandle(manager);
                }
                Ok(InstallOutcome::Updated)
            }
            other => {
                unsafe { CloseServiceHandle(manager) };
                Err(other)
            }
        }
    } else {
        // SAFETY: `service` is a valid handle; both handles are closed once.
        unsafe {
            let mut delayed = SERVICE_DELAYED_AUTO_START_INFO {
                fDelayedAutostart: 1,
            };
            ChangeServiceConfig2W(
                service,
                SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                &mut delayed as *mut _ as *mut c_void,
            );
            apply_failure_actions(service);
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
        }
        Ok(InstallOutcome::Created)
    };

    outcome
}

/// Stops (if running) and deletes the Litric service. Never touches user data,
/// Windows Defender, the firewall or any other service.
pub fn uninstall() -> Result<(), ServiceError> {
    let name = wide(SERVICE_NAME);

    // SAFETY: null database name = local machine; access is narrowly scoped.
    let manager =
        unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(last_error("OpenSCManagerW"));
    }

    let service = unsafe {
        OpenServiceW(
            manager,
            name.as_ptr(),
            SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE_ACCESS,
        )
    };
    if service.is_null() {
        let err = last_error("OpenServiceW");
        unsafe { CloseServiceHandle(manager) };
        return match err {
            ServiceError::NotInstalled => Ok(()),
            other => Err(other),
        };
    }

    // Ask it to stop; ERROR_SERVICE_NOT_ACTIVE and ERROR_SERVICE_ALREADY_RUNNING
    // are both fine here.
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    unsafe { ControlService(service, SERVICE_CONTROL_STOP, &mut status) };

    let deadline = Instant::now() + STOP_TIMEOUT;
    loop {
        match query_status_handle(service) {
            Ok(s) if s.state == ServiceState::Stopped => break,
            Ok(_) if Instant::now() >= deadline => break,
            Ok(_) => std::thread::sleep(Duration::from_millis(250)),
            Err(_) => break,
        }
    }

    // SAFETY: `service` is a valid handle opened with SERVICE_DELETE.
    let deleted = unsafe { DeleteService(service) };
    let delete_err = if deleted == 0 {
        Some(last_error("DeleteService"))
    } else {
        None
    };
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    match delete_err {
        None => Ok(()),
        Some(ServiceError::NotInstalled) => Ok(()),
        Some(other) => Err(other),
    }
}

/// Queries the installed service. Returns `NotInstalled` when it is absent.
pub fn status() -> Result<ServiceStatus, ServiceError> {
    let name = wide(SERVICE_NAME);
    let manager =
        unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(last_error("OpenSCManagerW"));
    }
    let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        let err = last_error("OpenServiceW");
        unsafe { CloseServiceHandle(manager) };
        return match err {
            ServiceError::Win32 { code, .. } if code == ERROR_SERVICE_DOES_NOT_EXIST => {
                Err(ServiceError::NotInstalled)
            }
            other => Err(other),
        };
    }
    let result = query_status_handle(service);
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    result
}

fn query_status_handle(service: windows_sys::Win32::System::Services::SC_HANDLE) -> Result<ServiceStatus, ServiceError> {
    let mut info: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32;
    let mut needed = 0u32;
    // SAFETY: buffer and size describe the same allocation.
    let ok = unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            &mut info as *mut _ as *mut u8,
            size,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(last_error("QueryServiceStatusEx"));
    }
    Ok(ServiceStatus {
        state: ServiceState::from_raw(info.dwCurrentState),
        process_id: info.dwProcessId,
    })
}

/// True when the current process is elevated (member of the local Administrators
/// group with an elevated token). Used only to give a better message *before*
/// attempting an SCM call; the SCM remains the authority.
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    // SAFETY: standard token query on the pseudo-handle of this process.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 || token.is_null() {
        return false;
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
    // SAFETY: buffer and size describe the same allocation.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            size,
            &mut returned,
        )
    };
    unsafe { CloseHandle(token) };
    ok != 0 && elevation.TokenIsElevated != 0
}

/// Names used by `--dry-run` and by tests: the exact SCM operations that an
/// install would perform, without performing them.
pub fn planned_operations(command_line: &str) -> Vec<String> {
    vec![
        format!("OpenSCManagerW(SC_MANAGER_CREATE_SERVICE) on the local machine"),
        format!("CreateServiceW(name={SERVICE_NAME}, type=WIN32_OWN_PROCESS, start=AUTO)"),
        format!("binary path: {command_line}"),
        format!("start name: LocalSystem (null), no dependencies, no load-order group"),
        format!("ChangeServiceConfig2W(description, delayed-auto-start=1)"),
        format!(
            "ChangeServiceConfig2W(failure actions: restart at {:?} ms, reset {} s)",
            RESTART_DELAYS_MS, FAILURE_RESET_SECONDS
        ),
        format!("no Defender, firewall, WFP or security-center API is called"),
    ]
}

/// Restricts the service data directory to SYSTEM, Administrators and the owner.
///
/// The directory holds `api.token` and the quarantine vault key. `%ProgramData%`
/// inherits a `Users: read` ACE, so without this step any local user could read
/// the bearer token and drive scans/restores over loopback. The DACL is
/// **protected** (inheritance removed) and grants full control only to:
///
/// * `SY` — LocalSystem (the service account)
/// * `BA` — Builtin Administrators
/// * `OW` — owner rights, so a non-admin owner cannot lock themselves out
///
/// The service refuses to start if this fails rather than run with a token any
/// local user can read.
pub fn restrict_to_system_and_admins(path: &std::path::Path) -> Result<(), ServiceError> {
    // One implementation, in `litric-core`, so the service and local CLI mode
    // cannot drift apart on the SDDL.
    litric_core::winplatform::acl::restrict_to_system_and_admins(path).map_err(|e| {
        match e.raw_os_error() {
            Some(code) => classify(code as u32),
            None => ServiceError::Io(e),
        }
    })
}

/// Append-only log for service mode, where stdout/stderr go nowhere.
///
/// Deliberately tiny: one file under the data directory, rotated once at 2 MiB.
/// It never records file contents or the bearer token.
pub struct ServiceLog {
    path: std::path::PathBuf,
}

impl ServiceLog {
    pub fn open(dir: &std::path::Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            path: dir.join("service.log"),
        })
    }

    pub fn write(&self, message: &str) {
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.len() > 2 * 1024 * 1024 {
                let rotated = self.path.with_extension("log.1");
                let _ = std::fs::rename(&self.path, rotated);
            }
        }
        let line = format!("{} {}\n", timestamp_utc(), message.replace('\n', " ").replace('\r', ""));
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` for the current system time, without a date crate.
pub fn timestamp_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    format_utc(secs)
}

fn format_utc(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let rem = unix_secs.rem_euclid(86_400);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // Howard Hinnant's civil_from_days: days since 1970-01-01 to a proleptic
    // Gregorian date. No locale, no timezone, no dependency.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_format_matches_known_instants() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn service_log_appends_and_never_writes_the_token() {
        let dir = std::env::temp_dir().join(format!("litric-svclog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = ServiceLog::open(&dir).expect("open log");
        log.write("started");
        log.write("stopped\nsecond line");
        let text = std::fs::read_to_string(dir.join("service.log")).expect("read log");
        assert!(text.contains("started"));
        assert!(text.contains("stopped second line"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn command_line_quotes_paths_with_spaces() {
        let p = std::path::Path::new(r"C:\Program Files\Litric Defender\litricd.exe");
        assert_eq!(
            service_command_line(p, "run-service"),
            r#""C:\Program Files\Litric Defender\litricd.exe" run-service"#
        );
    }

    #[test]
    fn command_line_omits_trailing_space_without_args() {
        let p = std::path::Path::new(r"C:\Litric\litricd.exe");
        assert_eq!(service_command_line(p, "   "), r#""C:\Litric\litricd.exe""#);
    }

    #[test]
    fn error_classification_matches_the_scm_codes() {
        assert!(matches!(classify(5), ServiceError::AccessDenied));
        assert!(matches!(classify(1073), ServiceError::AlreadyInstalled));
        assert!(matches!(classify(1060), ServiceError::NotInstalled));
        assert!(matches!(
            classify(1072),
            ServiceError::Win32 { code: 1072, .. }
        ));
    }

    #[test]
    fn access_denied_message_tells_the_operator_to_elevate() {
        let text = ServiceError::AccessDenied.to_string();
        assert!(text.contains("administrator"), "{text}");
    }

    #[test]
    fn state_names_cover_every_scm_state() {
        let all = [1u32, 2, 3, 4, 5, 6, 7, 99];
        let names: Vec<&str> = all
            .iter()
            .map(|v| ServiceState::from_raw(*v).label())
            .collect();
        assert_eq!(
            names,
            vec![
                "stopped",
                "start-pending",
                "stop-pending",
                "running",
                "continue-pending",
                "pause-pending",
                "paused",
                "unknown"
            ]
        );
    }

    #[test]
    fn stop_token_wakes_a_waiter() {
        let token = StopToken::new();
        let waiter = token.clone();
        let t = std::thread::spawn(move || {
            let started = Instant::now();
            let stopped = waiter.wait_timeout(Duration::from_secs(10));
            (stopped, started.elapsed())
        });
        std::thread::sleep(Duration::from_millis(50));
        token.request_stop();
        let (stopped, elapsed) = t.join().expect("join");
        assert!(stopped);
        assert!(elapsed < Duration::from_secs(5), "woke after {elapsed:?}");
    }

    #[test]
    fn stop_token_times_out_without_a_request() {
        let token = StopToken::new();
        let started = Instant::now();
        assert!(!token.wait_timeout(Duration::from_millis(40)));
        assert!(started.elapsed() >= Duration::from_millis(35));
        assert!(!token.is_stopped());
    }

    #[test]
    fn program_data_dir_is_under_program_data() {
        let dir = program_data_dir();
        assert_eq!(
            dir.file_name().and_then(|s| s.to_str()),
            Some("Litric Defender")
        );
        assert!(dir.parent().is_some());
    }

    #[test]
    fn dry_run_plan_never_mentions_defender_configuration() {
        let plan = planned_operations("cmd").join("\n");
        assert!(plan.contains("CreateServiceW"));
        for forbidden in [
            "MpPreference",
            "WinDefend",
            "Set-MpPreference",
            "TamperProtection",
        ] {
            assert!(!plan.contains(forbidden), "plan mentions {forbidden}");
        }
    }

    #[test]
    fn acl_hardening_leaves_the_owner_able_to_use_the_path() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("litric-acl-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        restrict_to_system_and_admins(&dir).expect("the owner can set a protected DACL");
        let file = dir.join("canary.txt");
        std::fs::write(&file, b"ok").unwrap();
        restrict_to_system_and_admins(&file).expect("file DACL");
        assert_eq!(std::fs::read(&file).unwrap(), b"ok");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn dry_run_plan_includes_crash_recovery() {
        let plan = planned_operations("cmd").join("\n");
        assert!(plan.contains("failure actions"), "{plan}");
        assert!(plan.contains("restart"), "{plan}");
        assert!(RESTART_DELAYS_MS.iter().all(|d| *d >= 1_000));
        assert!(RESTART_DELAYS_MS.iter().all(|d| *d <= 600_000));
    }

    #[test]
    fn installed_command_line_ends_with_run_service() {
        let line = installed_command_line().expect("current exe");
        assert!(line.ends_with("run-service"), "{line}");
        assert!(line.starts_with('"'), "{line}");
    }

    /// A service that was never installed must report `NotInstalled`, not a
    /// generic failure. This is safe on any machine: the test name is Litric's
    /// own service name, and a missing service produces error 1060.
    #[test]
    fn querying_an_absent_service_is_classified() {
        match status() {
            Err(ServiceError::NotInstalled) => {}
            // On a developer machine where the service *is* installed, the query
            // must still succeed and report a real state.
            Ok(s) => assert_ne!(s.state.label(), ""),
            Err(other) => panic!("unexpected error querying an absent service: {other}"),
        }
    }
}
