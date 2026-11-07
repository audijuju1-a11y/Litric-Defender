//! Malware category taxonomy and an honest coverage ledger.
//!
//! The 190 categories come from the product requirement list. For each one
//! this module records what Litric Defender can *actually* do today, on three
//! independent axes, and refuses to inflate it:
//!
//! * `signatures` — can the engine match this kind of sample from signature
//!   data (Litric native rules, ClamAV-derived data, YARA)? `Generic` means the
//!   *capability* exists; it says nothing about bundled coverage (the shipped
//!   database is nearly empty — see `docs/STATUS.md`).
//! * `behavior` — is there runtime/behavioural logic for it? `Tested` means
//!   decision logic with automated tests, not OS-level enforcement.
//! * `evidence` — built-in static signals / rules that are *specific* to the
//!   category. Every entry is verified by a test against the real heuristic
//!   and rule sources, so a name cannot be listed unless it exists.
//!
//! [`Category::coverage`] collapses this into one label:
//!
//! | label | meaning |
//! |---|---|
//! | `Specific` | at least one built-in signal/rule or tested behaviour targets this category |
//! | `GenericOnly` | only generic engine + whatever signature data is loaded; no category-specific logic |
//! | `Planned` / `Blocked` | not available; planned work or blocked on a platform constraint |
//! | `OutOfScope` | not meaningful for a Windows endpoint file scanner |
//!
//! No label means "detects all samples of this type".

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Group { A, B, C, D, E, F, G, H, I, J, K }

impl Group {
    pub fn title(&self) -> &'static str {
        match self {
            Group::A => "Traditional malware",
            Group::B => "Ransomware and destructive malware",
            Group::C => "Spyware and information theft",
            Group::D => "Rootkits and system-level malware",
            Group::E => "Fileless and script-based malware",
            Group::F => "Cryptomining and resource abuse",
            Group::G => "Adware and unwanted software",
            Group::H => "Network and remote-control malware",
            Group::I => "Mobile and cross-platform malware",
            Group::J => "Supply chain and application malware",
            Group::K => "Specialized malware",
        }
    }
    pub fn letter(&self) -> char {
        match self {
            Group::A => 'A', Group::B => 'B', Group::C => 'C', Group::D => 'D', Group::E => 'E',
            Group::F => 'F', Group::G => 'G', Group::H => 'H', Group::I => 'I', Group::J => 'J', Group::K => 'K',
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigSupport { Generic, Planned, Blocked, OutOfScope }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behavior { None, Tested, Planned, Blocked, OutOfScope }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Coverage { Specific, GenericOnly, Planned, Blocked, OutOfScope }

impl Coverage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Coverage::Specific => "Specific",
            Coverage::GenericOnly => "GenericOnly",
            Coverage::Planned => "Planned",
            Coverage::Blocked => "Blocked",
            Coverage::OutOfScope => "OutOfScope",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Category {
    pub id: u16,
    pub name: &'static str,
    pub group: Group,
    pub signatures: SigSupport,
    pub behavior: Behavior,
    /// Heuristic signal ids (lowercase, e.g. `ransom.note_text`) and rule names
    /// (e.g. `Ransom.RansomNoteText`) that specifically indicate this category.
    pub evidence: &'static [&'static str],
    pub note: &'static str,
}

impl Category {
    pub fn coverage(&self) -> Coverage {
        if !self.evidence.is_empty() || self.behavior == Behavior::Tested {
            return Coverage::Specific;
        }
        match self.signatures {
            SigSupport::Generic => Coverage::GenericOnly,
            SigSupport::Planned => Coverage::Planned,
            SigSupport::Blocked => Coverage::Blocked,
            SigSupport::OutOfScope => Coverage::OutOfScope,
        }
    }
}

/// The full ledger, in requirement order (ids 1..=190). The requirement list
/// repeats some names in sections C and K (POS, ATM); both entries are kept so
/// ids match the source list. The source's "Cl ฝoud Malware" is read as "Cloud Malware".
pub fn all() -> &'static [Category] {
    TABLE
}

pub fn get(id: u16) -> Option<&'static Category> {
    TABLE.iter().find(|c| c.id == id)
}

/// Categories a built-in signal id or rule name is specific evidence for.
pub fn by_evidence(evidence: &str) -> Vec<u16> {
    TABLE.iter().filter(|c| c.evidence.contains(&evidence)).map(|c| c.id).collect()
}

/// Best-effort mapping of a *detection name* (ClamAV-style `Win.Ransomware.Foo`,
/// YARA rule names, Litric families) to categories using its naming tokens.
///
/// This is a naming-convention heuristic, not ground truth: vendors name
/// loosely, and an unknown name maps to nothing rather than being guessed.
pub fn classify_name(name: &str) -> Vec<u16> {
    let lower = name.to_ascii_lowercase();
    let mut out: Vec<u16> = Vec::new();
    for tok in lower.split(|c: char| !c.is_ascii_alphanumeric()).filter(|t| !t.is_empty()) {
        let ids: &[u16] = match tok {
            "virus" => &[1],
            "worm" => &[2],
            "trojan" => &[3],
            "backdoor" => &[4],
            "rat" => &[5],
            "bot" => &[6],
            "botnet" => &[7],
            "dropper" => &[8],
            "downloader" => &[9],
            "loader" => &[10],
            "packed" | "packer" => &[20],
            "ransom" | "ransomware" => &[26],
            "locker" => &[27],
            "wiper" => &[35],
            "spyware" => &[45],
            "stealer" | "infostealer" | "pws" => &[46],
            "keylogger" | "keylog" => &[47],
            "banker" => &[48],
            "rootkit" => &[68],
            "bootkit" => &[70],
            "macro" => &[89],
            "powershell" | "ps" => &[83],
            "vbs" | "vbscript" => &[85],
            "js" | "javascript" => &[86],
            "bat" | "batch" => &[88],
            "hta" => &[92],
            "miner" | "coinminer" | "cryptominer" | "cryptojacker" => &[99],
            "adware" => &[106],
            "hijacker" => &[108],
            "pup" => &[112],
            "pua" => &[113],
            "fakeav" => &[115],
            "ddos" => &[122],
            "spam" | "spambot" => &[123],
            "irc" => &[125],
            "beacon" => &[121],
            "webshell" => &[133],
            "android" => &[138],
            "java" => &[148],
            "msil" | "dotnet" => &[149],
            "linux" => &[150],
            "osx" | "macos" => &[151],
            "apt" => &[190],
            _ => &[],
        };
        for id in ids {
            if !out.contains(id) {
                out.push(*id);
            }
        }
    }
    out
}

/// Counts per coverage label, in label order.
pub fn summary() -> Vec<(Coverage, usize)> {
    let mut v: Vec<(Coverage, usize)> = [Coverage::Specific, Coverage::GenericOnly, Coverage::Planned, Coverage::Blocked, Coverage::OutOfScope]
        .iter()
        .map(|c| (*c, TABLE.iter().filter(|t| t.coverage() == *c).count()))
        .collect();
    v.sort_by_key(|(c, _)| *c);
    v
}

/// Markdown ledger (used to generate `docs/MALWARE_COVERAGE_MATRIX.md`).
pub fn render_markdown() -> String {
    let mut s = String::new();
    s.push_str("| # | Category | Group | Coverage | Signatures | Behaviour | Built-in evidence | Note |\n|---|---|---|---|---|---|---|---|\n");
    for c in TABLE {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {:?} | {:?} | {} | {} |\n",
            c.id,
            c.name,
            c.group.letter(),
            c.coverage().as_str(),
            c.signatures,
            c.behavior,
            if c.evidence.is_empty() { "-".to_string() } else { c.evidence.iter().map(|e| format!("`{e}`")).collect::<Vec<_>>().join(", ") },
            c.note
        ));
    }
    s
}

static TABLE: &[Category] = &[
    Category { id: 1, name: "Virus", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "Generic family; relies on signature data" },
    Category { id: 2, name: "Worm", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Worm.SmbExploitReferences", "Worm.AutorunInf"], note: "Generic family; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 3, name: "Trojan Horse", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "Generic family; relies on signature data and generic heuristics" },
    Category { id: 4, name: "Backdoor", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Rat.MeterpreterMarkers", "Rat.NamedFamilyWithCapabilities"], note: "Generic family; relies on signature data and generic heuristics; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 5, name: "Remote Access Trojan (RAT)", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Rat.MeterpreterMarkers", "Rat.NamedFamilyWithCapabilities"], note: "Generic family; relies on signature data and generic heuristics; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 6, name: "Bot", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Bot.IrcCommandChannel", "Bot.FloodToolkit"], note: "Generic family; relies on signature data and generic heuristics; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 7, name: "Botnet Malware", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Bot.IrcCommandChannel", "Bot.FloodToolkit", "Iot.MiraiLikeMarkers"], note: "Generic family; relies on signature data and generic heuristics; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 8, name: "Dropper", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["api.download_and_execute", "script.download_cradle", "pe.overlay.embedded_exe", "PE.EmbeddedExecutableOverlay", "Linux.ShellDropperPersistence"], note: "Download/overlay indicators only; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 9, name: "Downloader", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["api.download_and_execute", "script.download_cradle", "pe.overlay.embedded_exe", "PE.EmbeddedExecutableOverlay", "Linux.ShellDropperPersistence"], note: "Download/overlay indicators only; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 10, name: "Loader", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["api.download_and_execute", "script.download_cradle", "pe.overlay.embedded_exe", "PE.EmbeddedExecutableOverlay"], note: "Download/overlay indicators only" },
    Category { id: 11, name: "Installer Malware", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["api.download_and_execute", "script.download_cradle", "pe.overlay.embedded_exe", "PE.EmbeddedExecutableOverlay", "Lolbin.MsiexecRemote"], note: "Download/overlay indicators only; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 12, name: "File Infector", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "No file-infector (PE entry-point tamper) detection yet" },
    Category { id: 13, name: "Companion Malware", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "No file-infector (PE entry-point tamper) detection yet" },
    Category { id: 14, name: "Multipartite Malware", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "No file-infector (PE entry-point tamper) detection yet" },
    Category { id: 15, name: "Memory-Resident Malware", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &[], note: "" },
    Category { id: 16, name: "Self-Replicating Malware", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Worm.SmbExploitReferences", "Worm.AutorunInf"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 17, name: "Polymorphic Malware", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "Polymorphism needs emulation/unpacking (UNSUPPORTED); only structural indicators and signature data" },
    Category { id: 18, name: "Metamorphic Malware", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "Polymorphism needs emulation/unpacking (UNSUPPORTED); only structural indicators and signature data" },
    Category { id: 19, name: "Encrypted Malware", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["pe.sections.high_entropy_many", "pe.entry.outside_sections"], note: "" },
    Category { id: 20, name: "Packed Malware", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["pe.packed.entropy_imports", "pe.packer.signature", "pe.sections.high_entropy_many", "PE.PackedHighEntropy"], note: "" },
    Category { id: 21, name: "Stealth Malware", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &[], note: "" },
    Category { id: 22, name: "Armored Malware", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["pe.sections.high_entropy_many", "pe.entry.outside_sections"], note: "" },
    Category { id: 23, name: "Logic Bomb", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "Trigger logic needs emulation (UNSUPPORTED); not detectable statically in general" },
    Category { id: 24, name: "Time Bomb", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "Trigger logic needs emulation (UNSUPPORTED); not detectable statically in general" },
    Category { id: 25, name: "Trigger-Based Malware", group: Group::A, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "Trigger logic needs emulation (UNSUPPORTED); not detectable statically in general" },
    Category { id: 26, name: "Crypto Ransomware", group: Group::B, signatures: SigSupport::Generic, behavior: Behavior::Tested, evidence: &["ransom.note_text", "ransom.shadow_copy_delete", "ransom.backup_disable", "Ransom.ShadowCopyDestruction", "Ransom.RansomNoteText", "api.crypto_enumeration", "Ransom.NetworkShareEncryption", "Ransom.TargetExtensionList"], note: "RansomShield scores write bursts, extension churn, entropy, decoy touches (decision logic tested; no kernel enforcement); Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 27, name: "Locker Ransomware", group: Group::B, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["ransom.note_text", "Ransom.RansomNoteText", "Ransom.LockerNote"], note: "Ransom-note text only; no screen-lock behaviour detection; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 28, name: "Screen Locker", group: Group::B, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["ransom.note_text", "Ransom.RansomNoteText", "Ransom.LockerNote"], note: "Ransom-note text only; no screen-lock behaviour detection; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 29, name: "Master Boot Record Ransomware", group: Group::B, signatures: SigSupport::Planned, behavior: Behavior::Blocked, evidence: &["Wiper.RawDiskWrite"], note: "Needs raw-disk/boot-sector scanning and boot-time driver (ELAM); not implemented; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples; Detects executables that write raw disk + boot-sector wording; boot-sector/MBR scanning itself is not implemented" },
    Category { id: 30, name: "Disk Encryption Ransomware", group: Group::B, signatures: SigSupport::Generic, behavior: Behavior::Tested, evidence: &["api.crypto_enumeration"], note: "Behavioural decision logic only; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 31, name: "Double-Extortion Ransomware", group: Group::B, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &[], note: "Extortion/exfiltration stage needs network telemetry; not implemented" },
    Category { id: 32, name: "Triple-Extortion Ransomware", group: Group::B, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &[], note: "Extortion/exfiltration stage needs network telemetry; not implemented" },
    Category { id: 33, name: "Leakware", group: Group::B, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &[], note: "Extortion/exfiltration stage needs network telemetry; not implemented" },
    Category { id: 34, name: "Doxware", group: Group::B, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &[], note: "Extortion/exfiltration stage needs network telemetry; not implemented" },
    Category { id: 35, name: "Data Wiper", group: Group::B, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["destructive.recursive_delete", "destructive.secure_delete", "Wiper.RawDiskWrite", "Wiper.CommandChain"], note: "Static command/API indicators only; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 36, name: "Disk Wiper", group: Group::B, signatures: SigSupport::Planned, behavior: Behavior::None, evidence: &["destructive.recursive_delete", "Wiper.RawDiskWrite", "Wiper.CommandChain"], note: "Raw-disk/partition access not monitored; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 37, name: "File Wiper", group: Group::B, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["destructive.recursive_delete", "destructive.secure_delete", "Wiper.CommandChain"], note: "Static command/API indicators only; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 38, name: "Partition Wiper", group: Group::B, signatures: SigSupport::Planned, behavior: Behavior::None, evidence: &["destructive.recursive_delete", "Wiper.RawDiskWrite", "Wiper.CommandChain"], note: "Raw-disk/partition access not monitored; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 39, name: "Firmware Wiper", group: Group::B, signatures: SigSupport::Blocked, behavior: Behavior::Blocked, evidence: &[], note: "Firmware/UEFI scanning not implemented; needs vendor/firmware access" },
    Category { id: 40, name: "Backup Destruction Malware", group: Group::B, signatures: SigSupport::Generic, behavior: Behavior::Tested, evidence: &["ransom.backup_disable", "ransom.shadow_copy_delete", "Ransom.ShadowCopyDestruction"], note: "vssadmin/wbadmin/bcdedit recovery destruction is critical in RansomShield" },
    Category { id: 41, name: "Destructive Malware", group: Group::B, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["destructive.recursive_delete", "destructive.secure_delete", "Wiper.CommandChain"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 42, name: "Data Corruption Malware", group: Group::B, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "" },
    Category { id: 43, name: "Recovery Sabotage Malware", group: Group::B, signatures: SigSupport::Generic, behavior: Behavior::Tested, evidence: &["ransom.backup_disable", "ransom.shadow_copy_delete", "Ransom.ShadowCopyDestruction"], note: "vssadmin/wbadmin/bcdedit recovery destruction is critical in RansomShield" },
    Category { id: 44, name: "Network-Share Ransomware", group: Group::B, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Ransom.NetworkShareEncryption", "Ransom.TargetExtensionList"], note: "Needs SMB/network-share write telemetry; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 45, name: "Spyware", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Spy.KeyboardHookLogger", "Spy.WebcamCapture", "Spy.MicrophoneRecord", "Spy.ScreenCaptureExfil", "Spy.ClipboardMonitor"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 46, name: "Infostealer", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["api.credential_dump", "Stealer.BrowserCredentials", "Stealer.BrowserCookies", "Stealer.DiscordToken", "Stealer.CryptoWallets", "Macos.KeychainOsascriptStealer"], note: "Credential-dump indicators only; no browser-profile theft detection; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 47, name: "Keylogger", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["api.keylogger", "Spy.KeyboardHookLogger", "Rat.NamedFamilyWithCapabilities"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 48, name: "Banker Trojan", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "" },
    Category { id: 49, name: "Banking Malware", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "" },
    Category { id: 50, name: "Credential Stealer", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["api.credential_dump", "credential.lsass_access", "credential.registry_hive_dump", "Credential.LsassDumpArtefacts", "Stealer.BrowserCredentials", "Stealer.DiscordToken", "Credential.NtdsDitAccess", "Macos.KeychainOsascriptStealer"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 51, name: "Password Stealer", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["api.credential_dump", "credential.lsass_access", "credential.registry_hive_dump", "Credential.LsassDumpArtefacts", "Stealer.BrowserCredentials", "Credential.NtdsDitAccess"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 52, name: "Cookie Stealer", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Stealer.BrowserCookies"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 53, name: "Session Token Stealer", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Stealer.BrowserCookies", "Stealer.DiscordToken"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 54, name: "Browser Stealer", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Stealer.BrowserCredentials", "Stealer.BrowserCookies"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 55, name: "Clipboard Spyware", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Spy.ClipboardMonitor"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 56, name: "Screen Capture Spyware", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Spy.ScreenCaptureExfil"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 57, name: "Webcam Spyware", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Spy.WebcamCapture", "Rat.NamedFamilyWithCapabilities"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 58, name: "Microphone Spyware", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Spy.MicrophoneRecord"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 59, name: "Form Grabber", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "No category-specific static or behavioural detection; relies on signature data" },
    Category { id: 60, name: "Information Harvester", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["api.credential_dump", "Spy.KeyboardHookLogger", "Stealer.BrowserCredentials", "Credential.NtdsDitAccess"], note: "Credential-dump indicators only; no browser-profile theft detection; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 61, name: "Financial Data Stealer", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Spy.ClipboardMonitor", "Stealer.CryptoWallets"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 62, name: "Identity Theft Malware", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["api.credential_dump", "Stealer.BrowserCredentials", "Stealer.CryptoWallets"], note: "Credential-dump indicators only; no browser-profile theft detection; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 63, name: "Stalkerware", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "No category-specific static or behavioural detection; relies on signature data" },
    Category { id: 64, name: "Surveillance Malware", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Spy.KeyboardHookLogger", "Spy.WebcamCapture", "Spy.MicrophoneRecord", "Spy.ScreenCaptureExfil"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 65, name: "POS Malware", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "No POS-specific memory-scraping detection; relies on signature data" },
    Category { id: 66, name: "Payment Card Malware", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "No POS-specific memory-scraping detection; relies on signature data" },
    Category { id: 67, name: "ATM Malware", group: Group::C, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "No ATM-specific detection (XFS API) ; relies on signature data" },
    Category { id: 68, name: "User-Mode Rootkit", group: Group::D, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &[], note: "" },
    Category { id: 69, name: "Kernel-Mode Rootkit", group: Group::D, signatures: SigSupport::Generic, behavior: Behavior::Blocked, evidence: &[], note: "Runtime kernel/driver detection needs minifilter/ELAM/PPL (BLOCKED); only file-level signatures" },
    Category { id: 70, name: "Bootkit", group: Group::D, signatures: SigSupport::Planned, behavior: Behavior::Blocked, evidence: &[], note: "Needs raw-disk/boot-sector scanning and boot-time driver (ELAM); not implemented" },
    Category { id: 71, name: "Bootloader Malware", group: Group::D, signatures: SigSupport::Planned, behavior: Behavior::Blocked, evidence: &[], note: "Needs raw-disk/boot-sector scanning and boot-time driver (ELAM); not implemented" },
    Category { id: 72, name: "Firmware Rootkit", group: Group::D, signatures: SigSupport::Blocked, behavior: Behavior::Blocked, evidence: &[], note: "Firmware/UEFI scanning not implemented; needs vendor/firmware access" },
    Category { id: 73, name: "UEFI Malware", group: Group::D, signatures: SigSupport::Blocked, behavior: Behavior::Blocked, evidence: &["Boot.FirmwareVariableWrite"], note: "Firmware/UEFI scanning not implemented; needs vendor/firmware access; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples; Detects OS-level tools writing UEFI variables only; firmware images are not scanned" },
    Category { id: 74, name: "MBR Rootkit", group: Group::D, signatures: SigSupport::Planned, behavior: Behavior::Blocked, evidence: &["Wiper.RawDiskWrite"], note: "Needs raw-disk/boot-sector scanning and boot-time driver (ELAM); not implemented; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 75, name: "Driver-Based Malware", group: Group::D, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["api.service_install", "Driver.VulnerableDriverLoad"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 76, name: "Malicious Kernel Driver", group: Group::D, signatures: SigSupport::Generic, behavior: Behavior::Blocked, evidence: &["Driver.VulnerableDriverLoad"], note: "Runtime kernel/driver detection needs minifilter/ELAM/PPL (BLOCKED); only file-level signatures; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 77, name: "Hardware-Level Malware", group: Group::D, signatures: SigSupport::OutOfScope, behavior: Behavior::OutOfScope, evidence: &[], note: "Hardware/hypervisor layer is outside a user-mode Windows scanner" },
    Category { id: 78, name: "Hypervisor-Based Malware", group: Group::D, signatures: SigSupport::OutOfScope, behavior: Behavior::OutOfScope, evidence: &[], note: "Hardware/hypervisor layer is outside a user-mode Windows scanner" },
    Category { id: 79, name: "System Integrity Tampering Malware", group: Group::D, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["tamper.defender_exclusion", "tamper.defender_realtime", "script.defender_tamper", "Tamper.DefenderExclusion", "Tamper.SecurityServiceStop", "Boot.IntegrityDisable", "Persist.RegistryAutorunsAdvanced", "Evasion.UacBypassRegistryHijack", "Evasion.AmsiBypass"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 80, name: "Fileless Rootkit Indicators", group: Group::D, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &[], note: "Needs memory scanning (PLANNED)" },
    Category { id: 81, name: "Fileless Malware", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["script.encoded_payload", "script.download_cradle", "script.hidden_execution", "Persist.WmiEventSubscription", "Inject.ProcessHollowing", "Inject.ReflectiveLoaderExport", "Evasion.AmsiBypass"], note: "Script-borne indicators only; memory scanning PLANNED; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 82, name: "Memory-Only Malware", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &[], note: "Needs memory scanning (PLANNED)" },
    Category { id: 83, name: "PowerShell Malware", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["script.encoded_payload", "script.download_cradle", "script.obfuscation", "script.batch_powershell_chain", "Exec.PowerShellEncodedCommand", "Script.PowerShellDownloadCradle", "Evasion.AmsiBypass"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 84, name: "Windows Script Host Malware", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["script.wsh_shell", "script.hidden_execution", "script.adodb_stream", "script.obfuscation"], note: "" },
    Category { id: 85, name: "VBScript Malware", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["script.wsh_shell", "script.hidden_execution", "script.adodb_stream", "script.obfuscation"], note: "" },
    Category { id: 86, name: "JavaScript Malware", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["script.obfuscation", "script.hidden_execution", "lolbin.rundll32_js"], note: "" },
    Category { id: 87, name: "JScript Malware", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["script.wsh_shell", "script.hidden_execution", "script.adodb_stream", "script.obfuscation"], note: "" },
    Category { id: 88, name: "Batch Script Malware", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["script.batch_powershell_chain", "script.hidden_execution"], note: "" },
    Category { id: 89, name: "Macro Malware", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["format.office_macro_capable", "Macro.AutoExecLauncher", "Macro.ShellExecution", "Macro.RemotePayload", "Xlm.Exec", "Xlm.RegisterCall", "Xlm.FileWrite", "Xlm.Download"], note: "VBA and Excel 4.0 macro extraction implemented; p-code not decompiled" },
    Category { id: 90, name: "Office Document Malware", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["format.office_macro_capable", "Macro.AutoExecLauncher", "Macro.ShellExecution", "Macro.RemotePayload", "Xlm.Exec", "Xlm.RegisterCall", "Xlm.FileWrite", "Xlm.Download"], note: "VBA and Excel 4.0 macro extraction implemented; p-code not decompiled" },
    Category { id: 91, name: "HTML Application Malware", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["lolbin.mshta_remote", "Exec.MshtaRemotePayload"], note: "" },
    Category { id: 92, name: "HTA-Based Malware", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["lolbin.mshta_remote", "Exec.MshtaRemotePayload"], note: "" },
    Category { id: 93, name: "WMI-Based Malware", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Persist.WmiEventSubscription"], note: "No WMI-persistence detection yet; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 94, name: "LOLBin-Abusing Malware", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["lolbin.bitsadmin_transfer", "lolbin.certutil_download", "lolbin.mshta_remote", "lolbin.regsvr32_scrobj", "lolbin.rundll32_js", "Exec.Squiblydoo", "Exec.MshtaRemotePayload", "Lolbin.WmicXslRemote", "Lolbin.MsiexecRemote", "Evasion.UacBypassRegistryHijack"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 95, name: "Living-off-the-Land Malware", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["lolbin.bitsadmin_transfer", "lolbin.certutil_download", "lolbin.mshta_remote", "lolbin.regsvr32_scrobj", "lolbin.rundll32_js", "Exec.Squiblydoo", "Exec.MshtaRemotePayload", "Lolbin.WmicXslRemote", "Lolbin.MsiexecRemote", "Evasion.UacBypassRegistryHijack"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 96, name: "Registry-Based Malware", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["persistence.run_key", "Persist.RunKeyInstaller", "Persist.WmiEventSubscription", "Persist.RegistryAutorunsAdvanced", "Evasion.UacBypassRegistryHijack"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 97, name: "Reflective Loading Malware Indicators", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["api.injection.ntapi", "api.injection.remote_thread", "Inject.ProcessHollowing", "Inject.ReflectiveLoaderExport"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 98, name: "In-Memory Execution Malware Indicators", group: Group::E, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Inject.ProcessHollowing", "Inject.ReflectiveLoaderExport"], note: "Needs memory scanning (PLANNED); Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 99, name: "Cryptominer Malware", group: Group::F, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Miner.StratumConfig"], note: "No miner-specific heuristics (stratum strings, CPU use) implemented; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 100, name: "Cryptojacking Malware", group: Group::F, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Miner.StratumConfig", "Miner.BrowserScript"], note: "No miner-specific heuristics (stratum strings, CPU use) implemented; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 101, name: "CPU Miner", group: Group::F, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Miner.StratumConfig"], note: "No miner-specific heuristics (stratum strings, CPU use) implemented; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 102, name: "GPU Miner", group: Group::F, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Miner.StratumConfig"], note: "No miner-specific heuristics (stratum strings, CPU use) implemented; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 103, name: "Browser Cryptominer", group: Group::F, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Miner.BrowserScript"], note: "No miner-specific heuristics (stratum strings, CPU use) implemented; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 104, name: "Resource Hijacking Malware", group: Group::F, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Miner.StratumConfig", "Miner.BrowserScript"], note: "No miner-specific heuristics (stratum strings, CPU use) implemented; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 105, name: "Unauthorized Computing Malware", group: Group::F, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Miner.StratumConfig"], note: "No miner-specific heuristics (stratum strings, CPU use) implemented; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 106, name: "Adware", group: Group::G, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "No PUP/PUA reputation or classification; relies on signature data" },
    Category { id: 107, name: "Aggressive Adware", group: Group::G, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "No PUP/PUA reputation or classification; relies on signature data" },
    Category { id: 108, name: "Browser Hijacker", group: Group::G, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Hijack.BrowserSettings", "Pup.ToolbarSearchHijackers"], note: "No PUP/PUA reputation or classification; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 109, name: "Search Hijacker", group: Group::G, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Hijack.BrowserSettings", "Pup.ToolbarSearchHijackers"], note: "No PUP/PUA reputation or classification; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 110, name: "Browser Redirector", group: Group::G, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Hijack.BrowserSettings"], note: "No PUP/PUA reputation or classification; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 111, name: "Homepage Hijacker", group: Group::G, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Hijack.BrowserSettings"], note: "No PUP/PUA reputation or classification; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 112, name: "Potentially Unwanted Program (PUP)", group: Group::G, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Pup.BundlerFrameworks", "Pup.ToolbarSearchHijackers"], note: "No PUP/PUA reputation or classification; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 113, name: "Potentially Unwanted Application (PUA)", group: Group::G, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Pup.BundlerFrameworks", "Pup.ToolbarSearchHijackers"], note: "No PUP/PUA reputation or classification; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 114, name: "Rogue Security Software", group: Group::G, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Scam.FakeAvAlerts"], note: "No PUP/PUA reputation or classification; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 115, name: "Fake Antivirus", group: Group::G, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Scam.FakeAvAlerts"], note: "No PUP/PUA reputation or classification; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 116, name: "Scareware", group: Group::G, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Scam.FakeAvAlerts"], note: "No PUP/PUA reputation or classification; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 117, name: "Bundled Unwanted Software", group: Group::G, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Pup.BundlerFrameworks"], note: "No PUP/PUA reputation or classification; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 118, name: "Unwanted Toolbar", group: Group::G, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Pup.ToolbarSearchHijackers"], note: "No PUP/PUA reputation or classification; relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 119, name: "Tracking Software", group: Group::G, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "No PUP/PUA reputation or classification; relies on signature data" },
    Category { id: 120, name: "Command-and-Control Malware", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Network.CobaltStrikeDefaultProfile", "Rat.MeterpreterMarkers"], note: "Default Cobalt Strike profile only; no traffic analysis; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 121, name: "C2 Beacon Malware", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Network.CobaltStrikeDefaultProfile"], note: "Default Cobalt Strike profile only; no traffic analysis" },
    Category { id: 122, name: "DDoS Bot", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Bot.IrcCommandChannel", "Bot.FloodToolkit", "Iot.MiraiLikeMarkers"], note: "Needs network telemetry; static relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 123, name: "Spam Bot", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Bot.IrcCommandChannel"], note: "Needs network telemetry; static relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 124, name: "Proxy Bot", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Network.ProxyHijack"], note: "Needs network telemetry; static relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 125, name: "IRC Bot", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Bot.IrcCommandChannel"], note: "Needs network telemetry; static relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 126, name: "DNS-Based Malware", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Tunnel.DnsToolMarkers"], note: "DNS telemetry not collected; only file signatures; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 127, name: "DNS Tunneling Malware Indicators", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Tunnel.DnsToolMarkers"], note: "DNS telemetry not collected; only file signatures; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 128, name: "Network Worm", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Lateral.RemoteExecTools", "Worm.SmbExploitReferences", "Worm.AutorunInf"], note: "Needs network telemetry; static relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 129, name: "Lateral Movement Malware", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Lateral.RemoteExecTools"], note: "Needs network telemetry; static relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 130, name: "SMB-Propagating Malware", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Lateral.RemoteExecTools", "Worm.SmbExploitReferences"], note: "Needs network telemetry; static relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 131, name: "Network Share Malware", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Lateral.RemoteExecTools"], note: "Needs network telemetry; static relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 132, name: "Remote Access Malware", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Rat.MeterpreterMarkers", "Rat.NamedFamilyWithCapabilities"], note: "Needs network telemetry; static relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 133, name: "Webshell", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Webshell.PhpEval", "Webshell.AspxExec"], note: "No web-shell specific content rules bundled; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 134, name: "Web Server Backdoor", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Webshell.PhpEval", "Webshell.AspxExec"], note: "No web-shell specific content rules bundled; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 135, name: "Network Sniffer Malware", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Sniffer.PromiscuousSocket"], note: "Needs network telemetry; static relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 136, name: "Man-in-the-Middle Malware Components", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Network.ProxyHijack"], note: "Needs network telemetry; static relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 137, name: "Rogue Proxy Malware", group: Group::H, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &["Network.ProxyHijack"], note: "Needs network telemetry; static relies on signature data; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 138, name: "Android Trojan", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &["Android.SmsBankerPermissions"], note: "APK/IPA are ZIP containers: container bytes only, members not matched by imported signatures; no mobile runtime; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 139, name: "Android Spyware", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &[], note: "APK/IPA are ZIP containers: container bytes only, members not matched by imported signatures; no mobile runtime" },
    Category { id: 140, name: "Android Ransomware", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &[], note: "APK/IPA are ZIP containers: container bytes only, members not matched by imported signatures; no mobile runtime" },
    Category { id: 141, name: "Android Banking Trojan", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &["Android.SmsBankerPermissions"], note: "APK/IPA are ZIP containers: container bytes only, members not matched by imported signatures; no mobile runtime; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 142, name: "Mobile Infostealer", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &["Android.SmsBankerPermissions"], note: "APK/IPA are ZIP containers: container bytes only, members not matched by imported signatures; no mobile runtime; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 143, name: "SMS Trojan", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &["Android.SmsBankerPermissions"], note: "APK/IPA are ZIP containers: container bytes only, members not matched by imported signatures; no mobile runtime; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 144, name: "Mobile Adware", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &[], note: "APK/IPA are ZIP containers: container bytes only, members not matched by imported signatures; no mobile runtime" },
    Category { id: 145, name: "iOS Spyware", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &[], note: "APK/IPA are ZIP containers: container bytes only, members not matched by imported signatures; no mobile runtime" },
    Category { id: 146, name: "Mobile RAT", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &[], note: "APK/IPA are ZIP containers: container bytes only, members not matched by imported signatures; no mobile runtime" },
    Category { id: 147, name: "Cross-Platform Malware", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "File signatures only" },
    Category { id: 148, name: "Java-Based Malware", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "JAR identified; no Java-specific analysis" },
    Category { id: 149, name: ".NET Malware", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["pe.dotnet.thin_imports"], note: ".NET metadata analysis NOT DONE" },
    Category { id: 150, name: "Linux Malware", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &["Linux.ShellDropperPersistence"], note: "Non-Windows payload: ELF/Mach-O file signatures only; ELF target supported by pattern rules; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 151, name: "macOS Malware", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &["Macos.KeychainOsascriptStealer"], note: "Non-Windows payload: ELF/Mach-O file signatures only; ELF target supported by pattern rules; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 152, name: "IoT Malware", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &["Linux.ShellDropperPersistence", "Iot.MiraiLikeMarkers"], note: "Target is not a Windows endpoint; only samples that reach this machine as files can be matched; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 153, name: "Embedded Device Malware", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &[], note: "Target is not a Windows endpoint; only samples that reach this machine as files can be matched" },
    Category { id: 154, name: "Router Malware", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &["Iot.MiraiLikeMarkers"], note: "Target is not a Windows endpoint; only samples that reach this machine as files can be matched; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 155, name: "Smart Device Botnet Malware", group: Group::I, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &["Iot.MiraiLikeMarkers"], note: "Target is not a Windows endpoint; only samples that reach this machine as files can be matched; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 156, name: "Supply Chain Malware", group: Group::J, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["pe.unsigned", "pe.signature.no_subject", "pe.signature.no_codesigning_eku", "Pkg.NpmInstallScriptDownloader", "Pkg.PythonSetupExec"], note: "Authenticode chain/revocation verification is UNPROVEN (WinVerifyTrust wiring untested); Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 157, name: "Trojanized Software", group: Group::J, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["pe.unsigned", "pe.signature.no_subject", "pe.signature.no_codesigning_eku"], note: "Authenticode chain/revocation verification is UNPROVEN (WinVerifyTrust wiring untested)" },
    Category { id: 158, name: "Malicious Installer", group: Group::J, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["pe.unsigned", "pe.signature.no_subject", "pe.signature.no_codesigning_eku", "Lolbin.MsiexecRemote", "Pup.BundlerFrameworks"], note: "Authenticode chain/revocation verification is UNPROVEN (WinVerifyTrust wiring untested); Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 159, name: "Malicious Software Update", group: Group::J, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["pe.unsigned", "pe.signature.no_subject", "pe.signature.no_codesigning_eku"], note: "Authenticode chain/revocation verification is UNPROVEN (WinVerifyTrust wiring untested)" },
    Category { id: 160, name: "Compromised Package", group: Group::J, signatures: SigSupport::Planned, behavior: Behavior::None, evidence: &["Pkg.NpmInstallScriptDownloader", "Pkg.PythonSetupExec"], note: "Package-manager (npm/PyPI/NuGet) scanners not implemented; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples; Detects malicious package.json/setup.py content when scanned as files; no package-manager or registry integration" },
    Category { id: 161, name: "Malicious Dependency", group: Group::J, signatures: SigSupport::Planned, behavior: Behavior::None, evidence: &["Pkg.NpmInstallScriptDownloader", "Pkg.PythonSetupExec"], note: "Package-manager (npm/PyPI/NuGet) scanners not implemented; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 162, name: "Dependency Confusion Malware", group: Group::J, signatures: SigSupport::Planned, behavior: Behavior::None, evidence: &["Pkg.NpmInstallScriptDownloader", "Pkg.PythonSetupExec"], note: "Package-manager (npm/PyPI/NuGet) scanners not implemented; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 163, name: "Package Repository Malware", group: Group::J, signatures: SigSupport::Planned, behavior: Behavior::None, evidence: &["Pkg.NpmInstallScriptDownloader", "Pkg.PythonSetupExec"], note: "Package-manager (npm/PyPI/NuGet) scanners not implemented; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 164, name: "Malicious Browser Extension", group: Group::J, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["Extension.OverBroadPermissions"], note: "CRX/XPI treated as ZIP; no extension-manifest analysis; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 165, name: "Malicious DLL", group: Group::J, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["pe.unsigned", "pe.signature.no_subject", "name.masquerade_system_binary"], note: "" },
    Category { id: 166, name: "DLL Hijacking Malware", group: Group::J, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["pe.unsigned", "pe.signature.no_subject", "name.masquerade_system_binary", "Persist.RegistryAutorunsAdvanced"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 167, name: "Malicious Executable", group: Group::J, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["pe.unsigned", "pe.signature.no_subject", "name.masquerade_system_binary"], note: "" },
    Category { id: 168, name: "Compromised Signed Binary", group: Group::J, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "Needs signature-chain verification (UNPROVEN) and reputation data" },
    Category { id: 169, name: "Malicious Driver Package", group: Group::J, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["pe.unsigned", "api.service_install"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 170, name: "Malicious Firmware Update", group: Group::J, signatures: SigSupport::Planned, behavior: Behavior::None, evidence: &[], note: "Firmware image analysis not implemented" },
    Category { id: 171, name: "POS Malware", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "No POS-specific memory-scraping detection; relies on signature data" },
    Category { id: 172, name: "ATM Malware", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "No ATM-specific detection (XFS API) ; relies on signature data" },
    Category { id: 173, name: "Industrial Control System Malware", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &[], note: "Target is not a Windows endpoint; only samples that reach this machine as files can be matched" },
    Category { id: 174, name: "ICS Malware", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &[], note: "Target is not a Windows endpoint; only samples that reach this machine as files can be matched" },
    Category { id: 175, name: "SCADA Malware", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &[], note: "Target is not a Windows endpoint; only samples that reach this machine as files can be matched" },
    Category { id: 176, name: "OT Malware", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &[], note: "Target is not a Windows endpoint; only samples that reach this machine as files can be matched" },
    Category { id: 177, name: "IoT Bot Malware", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &["Iot.MiraiLikeMarkers"], note: "Target is not a Windows endpoint; only samples that reach this machine as files can be matched; Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 178, name: "Router Backdoor", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &[], note: "Target is not a Windows endpoint; only samples that reach this machine as files can be matched" },
    Category { id: 179, name: "NAS Malware", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &[], note: "Target is not a Windows endpoint; only samples that reach this machine as files can be matched" },
    Category { id: 180, name: "Hypervisor Malware", group: Group::K, signatures: SigSupport::OutOfScope, behavior: Behavior::OutOfScope, evidence: &[], note: "Hardware/hypervisor layer is outside a user-mode Windows scanner" },
    Category { id: 181, name: "Virtual Machine Malware", group: Group::K, signatures: SigSupport::OutOfScope, behavior: Behavior::OutOfScope, evidence: &[], note: "Hardware/hypervisor layer is outside a user-mode Windows scanner" },
    Category { id: 182, name: "Container Malware", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &[], note: "Target is not a Windows endpoint; only samples that reach this machine as files can be matched" },
    Category { id: 183, name: "Cloud Malware", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::OutOfScope, evidence: &[], note: "Target is not a Windows endpoint; only samples that reach this machine as files can be matched" },
    Category { id: 184, name: "Cryptographic Theft Malware", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["api.crypto_enumeration", "Stealer.CryptoWallets"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 185, name: "Data Exfiltration Malware", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::Planned, evidence: &[], note: "Needs network/egress telemetry" },
    Category { id: 186, name: "Destruction-Oriented Malware", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &["destructive.recursive_delete", "destructive.secure_delete", "Wiper.CommandChain"], note: "Static string-combination rules only (rules/extended.lrs); misses packed/obfuscated samples" },
    Category { id: 187, name: "Espionage Malware", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "Attribution needs curated threat intelligence; none bundled" },
    Category { id: 188, name: "Targeted Surveillance Malware", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "Attribution needs curated threat intelligence; none bundled" },
    Category { id: 189, name: "Espionage Implant", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "Attribution needs curated threat intelligence; none bundled" },
    Category { id: 190, name: "Advanced Persistent Threat (APT) Malware", group: Group::K, signatures: SigSupport::Generic, behavior: Behavior::None, evidence: &[], note: "Attribution needs curated threat intelligence; none bundled" },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const HEURISTICS_SRC: &str = include_str!("heuristics.rs");
    const CORE_RULES: &str = concat!(include_str!("../../../rules/core.lrs"), "\n", include_str!("../../../rules/extended.lrs"));

    #[test]
    fn has_exactly_190_sequential_entries() {
        let t = all();
        assert_eq!(t.len(), 190);
        for (i, c) in t.iter().enumerate() {
            assert_eq!(c.id as usize, i + 1);
            assert!(!c.name.is_empty());
        }
        // the only repeated names are the ones the requirement list repeats
        let mut seen = HashSet::new();
        let dups: Vec<&str> = t.iter().filter(|c| !seen.insert(c.name)).map(|c| c.name).collect();
        assert_eq!(dups, vec!["POS Malware", "ATM Malware"]);
    }

    #[test]
    fn every_evidence_entry_exists_in_the_real_engine() {
        for c in all() {
            for e in c.evidence {
                let first_upper = e.chars().next().map_or(false, |ch| ch.is_ascii_uppercase());
                if first_upper {
                    assert!(CORE_RULES.contains(&format!("rule {e} ")), "category {} cites rule {e} which is not in rules/*.lrs", c.id);
                } else {
                    assert!(HEURISTICS_SRC.contains(&format!("\"{e}\"")), "category {} cites signal {e} which is not in heuristics.rs", c.id);
                }
            }
        }
    }

    #[test]
    fn specific_coverage_is_never_claimed_without_evidence_or_tested_behaviour() {
        for c in all() {
            if c.coverage() == Coverage::Specific {
                assert!(!c.evidence.is_empty() || c.behavior == Behavior::Tested, "{}", c.name);
            }
        }
    }

    #[test]
    fn unavailable_categories_are_labelled_unavailable() {
        for id in [39u16, 72, 77, 78] {
            let c = get(id).unwrap();
            assert!(matches!(c.coverage(), Coverage::Planned | Coverage::Blocked | Coverage::OutOfScope), "{} -> {:?}", c.name, c.coverage());
        }
    }

    #[test]
    fn summary_adds_up() {
        let total: usize = summary().iter().map(|(_, n)| n).sum();
        assert_eq!(total, 190);
    }

    #[test]
    fn evidence_reverse_lookup_and_name_classification() {
        assert!(by_evidence("ransom.shadow_copy_delete").contains(&26));
        assert!(by_evidence("ransom.shadow_copy_delete").contains(&40));
        assert!(by_evidence("no.such.signal").is_empty());
        assert!(classify_name("Win.Ransomware.Foo-1234").contains(&26));
        assert!(classify_name("Win.Trojan.Agent").contains(&3));
        assert!(classify_name("Eicar-Test-Signature").is_empty(), "unknown names map to nothing");
    }

    #[test]
    fn markdown_has_a_row_per_category() {
        let md = render_markdown();
        assert_eq!(md.lines().count(), 192);
    }
}
