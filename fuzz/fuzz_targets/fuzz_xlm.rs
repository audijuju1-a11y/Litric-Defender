#![no_main]

use libfuzzer_sys::fuzz_target;

use litric_core::xlm::{extract, XlmLimits};

fuzz_target!(|data: &[u8]| {
    // Covers OOXML macrosheets and legacy BIFF5/7/8 FORMULA decoding.
    let _ = extract(data, &XlmLimits::default());
});
