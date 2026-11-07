//! Tests for rules/extended.lrs: every rule has a positive fixture (harmless text that
//! contains its indicators) and the whole set is checked against benign negatives.
use litric_core::rules::{parse_rule_file, RuleSet};

const EXTENDED: &str = include_str!("../../../rules/extended.lrs");

fn set() -> RuleSet {
    RuleSet::compile(parse_rule_file(EXTENDED, "extended.lrs").expect("extended.lrs parses")).expect("compiles")
}

fn fired(rs: &RuleSet, data: &[u8]) -> Vec<String> {
    rs.scan(data, None, "text", "txt").into_iter().map(|m| m.name).collect()
}

const POSITIVE: &[(&str, &str)] = &[
    ("Miner.StratumConfig", "stratum+tcp://\x0axmrig"),
    ("Miner.BrowserScript", "CoinHive.Anonymous"),
    ("Webshell.PhpEval", "<?php\x0aeval($_POST"),
    ("Webshell.AspxExec", "<%@ Page\x0aRequest.Item[\x0aProcess.Start"),
    ("Spy.KeyboardHookLogger", "SetWindowsHookEx\x0aWH_KEYBOARD_LL\x0aGetForegroundWindow"),
    ("Spy.WebcamCapture", "capCreateCaptureWindow\x0aavicap32\x0acapGrabFrame"),
    ("Spy.MicrophoneRecord", "waveInOpen\x0awaveInStart\x0awaveInAddBuffer"),
    ("Spy.ScreenCaptureExfil", "CreateCompatibleBitmap\x0aBitBlt\x0aGetDC\x0aapi.telegram.org"),
    ("Spy.ClipboardMonitor", "AddClipboardFormatListener\x0aSetClipboardData\x0awallet"),
    ("Stealer.BrowserCredentials", "Login Data\x0aencrypted_key\x0aUser Data\\Default"),
    ("Stealer.BrowserCookies", "cookies.sqlite\x0aCryptUnprotectData"),
    ("Stealer.DiscordToken", "discord\x0aLocal Storage\\leveldb\x0adQw4w9WgXcQ"),
    ("Stealer.CryptoWallets", "wallet.dat\x0a\\Electrum\\wallets\x0aMetaMask"),
    ("Persist.WmiEventSubscription", "__EventFilter\x0aCommandLineEventConsumer\x0a__FilterToConsumerBinding"),
    ("Bot.IrcCommandChannel", "PRIVMSG\x0aJOIN #\x0aNICK \x0a!ddos"),
    ("Bot.FloodToolkit", "syn flood\x0audp flood\x0aslowloris"),
    ("Hijack.BrowserSettings", "SearchScopes\x0aDefaultScope"),
    ("Scam.FakeAvAlerts", "your computer is infected\x0aviruses detected\x0acall toll free"),
    ("Ransom.LockerNote", "your computer has been locked\x0aunlock code"),
    ("Wiper.RawDiskWrite", "\\\\.\\PhysicalDrive\x0aWriteFile\x0aSetFilePointer\x0aboot sector"),
    ("Wiper.CommandChain", "format c: /y"),
    ("Boot.IntegrityDisable", "bcdedit\x0atestsigning on"),
    ("Boot.FirmwareVariableWrite", "SetFirmwareEnvironmentVariable\x0aSeSystemEnvironmentPrivilege"),
    ("Driver.VulnerableDriverLoad", "RTCore64.sys\x0aSERVICE_KERNEL_DRIVER"),
    ("Inject.ProcessHollowing", "NtUnmapViewOfSection\x0aWriteProcessMemory\x0aSetThreadContext\x0aResumeThread"),
    ("Inject.ReflectiveLoaderExport", "ReflectiveLoader\x0aVirtualAlloc\x0aGetProcAddress"),
    ("Rat.MeterpreterMarkers", "meterpreter\x0ametsrv"),
    ("Rat.NamedFamilyWithCapabilities", "QuasarRAT\x0akeylogger\x0aremote desktop"),
    ("Lolbin.WmicXslRemote", "wmic\x0a/format:\x0ahttp"),
    ("Lolbin.MsiexecRemote", "msiexec\x0a/i http\x0a/q"),
    ("Persist.RegistryAutorunsAdvanced", "AppInit_DLLs\x0areg add"),
    ("Evasion.UacBypassRegistryHijack", "ms-settings\\shell\\open\\command\x0aDelegateExecute\x0afodhelper"),
    ("Evasion.AmsiBypass", "amsiInitFailed"),
    ("Credential.NtdsDitAccess", "ntds.dit\x0antdsutil"),
    ("Lateral.RemoteExecTools", "PSEXESVC"),
    ("Worm.SmbExploitReferences", "eternalblue\x0adoublepulsar\x0ams17-010"),
    ("Worm.AutorunInf", "[autorun]\x0aopen="),
    ("Tunnel.DnsToolMarkers", "dnscat2"),
    ("Sniffer.PromiscuousSocket", "SIO_RCVALL\x0aWSAIoctl"),
    ("Network.ProxyHijack", "Internet Settings\x0aProxyEnable\x0areg add"),
    ("Extension.OverBroadPermissions", "webRequestBlocking\x0a<all_urls>\x0a\"cookies\"\x0amanifest_version"),
    ("Pkg.NpmInstallScriptDownloader", "\"scripts\"\x0a\"postinstall\"\x0acurl "),
    ("Pkg.PythonSetupExec", "setup(\x0acmdclass\x0aos.system(\x0aurllib.request"),
    ("Pup.BundlerFrameworks", "InstallCore"),
    ("Pup.ToolbarSearchHijackers", "Delta Search"),
    ("Android.SmsBankerPermissions", "AndroidManifest\x0aandroid.permission.RECEIVE_SMS\x0aBIND_ACCESSIBILITY_SERVICE\x0aSYSTEM_ALERT_WINDOW\x0aandroid.permission.READ_SMS"),
    ("Linux.ShellDropperPersistence", "wget http\x0achmod +x\x0a/tmp/\x0acrontab"),
    ("Iot.MiraiLikeMarkers", "/bin/busybox\x0aMIRAI"),
    ("Macos.KeychainOsascriptStealer", "osascript\x0asecurity find-generic-password\x0adisplay dialog"),
    ("Ransom.NetworkShareEncryption", "NetShareEnum\x0aCryptEncrypt\x0aFindFirstFile"),
    ("Ransom.TargetExtensionList", "CryptEncrypt\x0a.docx\x0a.xlsx\x0a.pdf\x0a.sql\x0a.mdb\x0a.vmdk\x0a.bak"),
];

const NEGATIVE: &[(&str, &str)] = &[
    ("lone stratum URL in docs", "see stratum+tcp://pool.example for the protocol description"),
    ("miner word only", "The xmrig project is open source."),
    ("keyboard hook only (accessibility)", "SetWindowsHookEx is documented in the Win32 API reference."),
    ("BitBlt screen recorder, no upload", "CreateCompatibleBitmap BitBlt GetDC are GDI calls used by screenshot tools"),
    ("Login Data mentioned alone", "Chrome keeps a file named Login Data in the profile directory."),
    ("PRIVMSG protocol text only", "IRC clients send PRIVMSG, JOIN #channel and NICK commands."),
    ("wmic only", "wmic os get caption"),
    ("sc create service alone", "sc create MyService binPath= C:\\\\app\\\\svc.exe"),
    ("bcdedit alone", "bcdedit /enum all"),
    ("php without eval", "<?php echo htmlspecialchars($_GET['q']); ?>"),
    ("msiexec local install", "msiexec /i C:\\\\setup\\\\app.msi /qn"),
    ("npm install script building", "{\"scripts\": {\"postinstall\": \"node build.js\"}}"),
    ("ordinary readme", "Litric README: install, configure and run. Run diagnostics with --verbose."),
    ("source code comment", "// TODO: handle clipboard events and keyboard focus changes"),
    ("html page", "<html><body><h1>Welcome</h1><p>Contact us today.</p></body></html>"),
    ("manifest with few permissions", "{\"manifest_version\": 3, \"permissions\": [\"storage\"]}"),
    ("setup.py benign", "from setuptools import setup\x0asetup(name='demo', version='1.0')"),
    ("autorun word in prose", "The [autorun] section is explained in the Windows documentation."),
];

#[test]
fn every_extended_rule_has_a_positive_fixture_that_fires_it() {
    let rs = set();
    let names: Vec<String> = rs.rules.iter().map(|r| r.name.clone()).collect();
    assert_eq!(names.len(), POSITIVE.len(), "a rule was added or removed without a fixture");
    for (rule, fixture) in POSITIVE {
        assert!(names.iter().any(|n| n == rule), "{rule} missing from extended.lrs");
        let hits = fired(&rs, fixture.as_bytes());
        assert!(hits.iter().any(|h| h == rule), "{rule} did not fire on its fixture; fired: {hits:?}");
    }
}

#[test]
fn benign_negatives_do_not_fire_any_extended_rule() {
    let rs = set();
    for (label, text) in NEGATIVE {
        let hits = fired(&rs, text.as_bytes());
        assert!(hits.is_empty(), "false positive on `{label}`: {hits:?}");
    }
}

#[test]
fn removing_the_corroborating_indicator_stops_the_rule() {
    // Each of these fixtures needs BOTH halves; one half alone must not fire.
    let rs = set();
    let cases: &[(&str, &str)] = &[
        ("Miner.StratumConfig", "stratum+tcp://pool.example:3333"),
        ("Stealer.BrowserCookies", "cookies.sqlite"),
        ("Webshell.PhpEval", "<?php // nothing dangerous here ?>"),
        ("Inject.ProcessHollowing", "NtUnmapViewOfSection WriteProcessMemory SetThreadContext"),
        ("Persist.WmiEventSubscription", "__EventFilter CommandLineEventConsumer"),
        ("Linux.ShellDropperPersistence", "wget http://example.invalid/a.sh; chmod +x a.sh"),
    ];
    for (rule, text) in cases {
        let hits = fired(&rs, text.as_bytes());
        assert!(!hits.iter().any(|h| h == rule), "{rule} fired on a partial fixture");
    }
}

#[test]
fn injection_api_names_alone_do_not_convict_a_large_system_like_binary() {
    // Regression: kernel32.dll exports every name this rule looks for. A large
    // binary that merely contains the API strings must not be convicted.
    let rs = set();
    let mut data = vec![b' '; 200 * 1024];
    let api = b"NtUnmapViewOfSection WriteProcessMemory SetThreadContext ResumeThread";
    data[1024..1024 + api.len()].copy_from_slice(api);
    let hits = fired(&rs, &data);
    assert!(
        !hits.iter().any(|h| h == "Inject.ProcessHollowing"),
        "API presence convicted a 200 KiB binary: {hits:?}"
    );
}

#[test]
fn rules_fire_through_the_full_engine_with_a_verdict() {
    use litric_core::engine::{Engine, EngineConfig, Verdict};
    use litric_core::threatdb::ThreatDb;
    let e = Engine::new(set(), ThreatDb::empty(), EngineConfig::default());
    let (_, miner) = POSITIVE.iter().find(|(n, _)| *n == "Miner.StratumConfig").unwrap();
    let r = e.analyze_bytes("cfg.json", miner.as_bytes());
    assert!(r.rules.iter().any(|m| m.name == "Miner.StratumConfig"));
    assert!(r.verdict >= Verdict::Suspicious, "{:?}", r.verdict);
    let r = e.analyze_bytes("readme.txt", b"hello world");
    assert!(!r.is_threat());
}
