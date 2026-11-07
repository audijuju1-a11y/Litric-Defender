#![no_main]

use libfuzzer_sys::fuzz_target;

use litric_core::vba::{extract, VbaLimits};

fuzz_target!(|data: &[u8]| {
    // Covers OOXML (ZIP) and legacy OLE2/CFB input paths in one target.
    let _ = extract(data, &VbaLimits::default());
});
