/*
 * rustc/LLVM emits SanitizerCoverage data for the COFF target in sections
 * `.SCOV$CM` (8-bit counters) and `.SCOVP$M` (PC table), but the generated
 * module constructor still references the ELF-style linker symbols
 * `__start___sancov_cntrs` / `__stop___sancov_pcs`.
 *
 * GNU ld does not synthesize those symbols for COFF sections, and the section
 * names are not valid C identifiers, so `__start_.SCOV$CM` is unavailable.
 * This fragment collects both input sections into one output section and
 * defines the four symbols at the real boundaries.
 *
 * Used only by fuzz/build.sh and fuzz/build.ps1 on windows-gnu. It is not part
 * of the product linker setup.
 */
SECTIONS
{
  .sancov ALIGN(0x1000) :
  {
    __start___sancov_cntrs = .;
    /* LLVM's COFF ctor passes (__start + 8), not __start. Reserve the
       8-byte header it expects so the range begins at the first counter. */
    LONG(0);
    LONG(0);
    KEEP(*(.SCOV$CM))
    __stop___sancov_cntrs = .;
    . = ALIGN(8);
    __start___sancov_pcs = .;
    /* Same 8-byte header for the PC table. */
    LONG(0);
    LONG(0);
    KEEP(*(.SCOVP$M))
    __stop___sancov_pcs = .;
  }
}
INSERT AFTER .rdata;
