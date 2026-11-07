#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser is total over bytes: malformed input must return an error,
    // never panic. The result is intentionally discarded; libFuzzer observes
    // coverage and crashes, not verdicts.
    let _ = litric_core::pe::parse(data);
});
