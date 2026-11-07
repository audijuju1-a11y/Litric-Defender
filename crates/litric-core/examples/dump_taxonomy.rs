//! Prints the malware coverage ledger as Markdown (used to generate docs/MALWARE_COVERAGE_MATRIX.md).
use litric_core::taxonomy;
fn main() {
    println!("# Malware coverage matrix (generated)\n");
    println!("Generated from `crates/litric-core/src/taxonomy.rs`. Do not edit by hand.\n");
    println!("## Summary\n\n| Label | Categories |\n|---|---|");
    for (c, n) in taxonomy::summary() {
        println!("| {} | {} |", c.as_str(), n);
    }
    println!("\nLabels: **Specific** = at least one built-in signal/rule or tested behaviour targets the category; **GenericOnly** = engine capability plus whatever signature data is loaded, nothing category-specific; **Planned/Blocked** = not available; **OutOfScope** = not meaningful for a Windows file scanner. **Specific means a rule exists and passes synthetic fixtures; it is NOT a measured detection rate.** No label means every sample is detected. The bundled signature database is empty.\n");
    println!("## Ledger\n");
    print!("{}", taxonomy::render_markdown());
}
