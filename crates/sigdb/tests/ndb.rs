use sigdb::ndb::*;
use sigdb::Database;

fn ok(s: &str) -> Sig {
    parse_sig(s).unwrap_or_else(|e| panic!("{s}: {e}"))
}
fn is_unsupported(s: &str) -> bool {
    matches!(parse_sig(s), Err(SigError::Unsupported(_)))
}
fn is_malformed(s: &str) -> bool {
    matches!(parse_sig(s), Err(SigError::Malformed(_)))
}

#[test]
fn hex_tokens_wildcards_and_masks() {
    let s = ok("deadbeef??a??bff");
    assert_eq!(
        s.toks,
        vec![
            Tok::Byte(0xde), Tok::Byte(0xad), Tok::Byte(0xbe), Tok::Byte(0xef),
            Tok::Masked { val: 0, mask: 0 },
            Tok::Masked { val: 0xa0, mask: 0xF0 },
            Tok::Masked { val: 0x0b, mask: 0x0F },
            Tok::Byte(0xff),
        ]
    );
    assert_eq!(s.anchor, Some((0, vec![0xde, 0xad, 0xbe, 0xef])));
}

#[test]
fn gaps_any_and_alternatives() {
    let s = ok("aabb{2}ccdd{-3}eeff{4-}0011{1-5}2233*4455(66|7788)99aa");
    let gaps: Vec<_> = s.toks.iter().filter_map(|t| if let Tok::Gap { min, max } = t { Some((*min, *max)) } else { None }).collect();
    assert_eq!(gaps, vec![(2, Some(2)), (0, Some(3)), (4, None), (1, Some(5))]);
    assert!(s.toks.contains(&Tok::Any));
    assert!(s.toks.contains(&Tok::Alt(vec![vec![0x66], vec![0x77, 0x88]])));
    assert_eq!(s.anchor, Some((0, vec![0xaa, 0xbb])), "anchor is the longest run in the fixed-width prefix");
}

#[test]
fn anchor_skips_masked_bytes_and_stops_at_first_gap() {
    assert_eq!(ok("e8??????ffd0cc").anchor, Some((4, vec![0xff, 0xd0, 0xcc])));
    assert_eq!(ok("aa??bb{2}ccddeeff").anchor, None, "single exact bytes only, run after the gap is not in the fixed prefix");
    assert_eq!(ok("aabbcc(11|22)ddee").anchor, Some((0, vec![0xaa, 0xbb, 0xcc])));
    assert!(ok("aabbcc(1122|33)ddee").anchor.is_some());
}

#[test]
fn unsupported_syntax_is_classified_not_accepted() {
    for s in ["aabb!(11|22)ccdd", "aabb(B)ccdd", "aabb(L)ccdd", "aabb[2-4]ccdd", "aabb(1?|22)ccdd"] {
        assert!(is_unsupported(s), "{s}");
    }
    let many = format!("aabb{}", "{1}cc".repeat(70));
    assert!(is_unsupported(&many), "too many wildcard segments");
}

#[test]
fn malformed_syntax_is_rejected() {
    for s in ["", "a", "aab", "zz", "aabb{2", "aabb{x}cc", "aabb{5-2}cc", "aabb{-}cc", "*aabb", "aabb*", "aabb{3}", "aabb(11|)cc", "aabb(1)cc", "aabb(11cc", "aa bb"] {
        assert!(is_malformed(s), "should be malformed: {s}");
    }
    assert!(is_malformed(&"aa".repeat(5000)));
}

#[test]
fn offsets_parse_all_supported_forms_and_flag_the_rest() {
    let p = |s| parse_offset(s).unwrap_or_else(|e| panic!("{s}: {e}"));
    assert_eq!(p("*"), Offset { base: Base::Anywhere, maxshift: 0 });
    assert_eq!(p("0"), Offset { base: Base::Abs(0), maxshift: 0 });
    assert_eq!(p("100,16"), Offset { base: Base::Abs(100), maxshift: 16 });
    assert_eq!(p("EOF-32"), Offset { base: Base::Eof(32), maxshift: 0 });
    assert_eq!(p("EP+4"), Offset { base: Base::Ep(4), maxshift: 0 });
    assert_eq!(p("EP-8,2"), Offset { base: Base::Ep(-8), maxshift: 2 });
    assert_eq!(p("S2+16"), Offset { base: Base::Section(2, 16), maxshift: 0 });
    assert_eq!(p("SL+0"), Offset { base: Base::LastSection(0), maxshift: 0 });
    assert!(p("EP+0").needs_pe() && p("EP+0").is_positional() && !p("*").is_positional() && !p("5,3").is_positional());
    assert!(matches!(parse_offset("VI"), Err(SigError::Unsupported(_))));
    assert!(matches!(parse_offset("SE1"), Err(SigError::Unsupported(_))));
    assert!(matches!(parse_offset("S1-4"), Err(SigError::Unsupported(_))));
    assert!(matches!(parse_offset("EOF-4,2"), Err(SigError::Unsupported(_))));
    for bad in ["", "abc", "*,5", "EP+x", "12,x", "EP*4"] {
        assert!(matches!(parse_offset(bad), Err(SigError::Malformed(_))), "{bad}");
    }
}

#[test]
fn locatable_requires_anchor_or_exact_offset() {
    let no_anchor = ok("aa??bb{2}ccddeeff");
    assert!(locatable(&no_anchor, &parse_offset("*").unwrap()).is_err());
    assert!(locatable(&no_anchor, &parse_offset("0").unwrap()).is_ok());
    assert!(locatable(&no_anchor, &parse_offset("0,4").unwrap()).is_err());
    assert!(locatable(&ok("aabbcc"), &parse_offset("*").unwrap()).is_ok());
}

fn v2(rec: &str) -> Vec<u8> {
    format!("LITRIC-SIGDB 2\nserial 1\ncreated 1\nmin-engine 2\nrule-count 1\n{rec}\nEND\n").into_bytes()
}

#[test]
fn ndb_records_load_validate_and_count() {
    let db = Database::parse(&v2("NDB r.1 Fam high 90 pe EP+0 e8??????ffd0")).unwrap();
    assert_eq!((db.ndb.len(), db.rule_count()), (1, 1));
    assert_eq!(db.ndb[0].offset.base, Base::Ep(0));
    for bad in [
        "NDB r Fam high 90 zip * aabbcc",                // target not allowed
        "NDB r Fam high 90 any EP+0 aabbcc",             // EP needs pe
        "NDB r Fam high 90 any * aa??bb{2}ccddeeff",     // not locatable
        "NDB r Fam high 90 any * aabb!(11|22)cc",        // unsupported syntax
    ] {
        assert!(Database::parse(&v2(bad)).is_err(), "should reject: {bad}");
    }
    assert!(Database::parse(&v2("NDB r Fam high 90 any * aabbcc")).is_ok(), "control: same shape, valid");
    let v1 = "LITRIC-SIGDB 1\nserial 1\ncreated 1\nmin-engine 1\nrule-count 1\nNDB r Fam high 90 any * aabbcc\nEND\n";
    assert!(Database::parse(v1.as_bytes()).is_err());
    let rev = Database::parse(&format!("LITRIC-SIGDB 2\nserial 1\ncreated 1\nmin-engine 2\nrule-count 1\nNDB r.x Fam high 90 any * aabbcc\nR r.x\nEND\n").into_bytes()).unwrap();
    assert_eq!(rev.ndb.len(), 0);
}

#[test]
fn bytecode_roundtrips_validates_and_agrees_with_the_token_anchor() {
    for s in [
        "deadbeef??a??bff",
        "aabb{2}ccdd{-3}eeff{4-}0011{1-5}2233*4455(66|7788)99aa",
        "e8??????ffd0cc",
        "aa??bb{2}ccddeeff",
        "aabbcc(11|22)ddee",
        "aabbcc(1122|33)ddee",
        "0102",
    ] {
        let sig = parse_sig(s).unwrap();
        let code = compile(&sig.toks);
        validate_code(&code).unwrap_or_else(|e| panic!("{s}: {e}"));
        assert_eq!(anchor_of_code(&code), sig.anchor, "{s}");
    }
}

#[test]
fn malformed_bytecode_is_rejected_without_panicking() {
    assert!(validate_code(&[]).is_err());
    assert!(validate_code(&[0x09]).is_err(), "unknown opcode");
    assert!(validate_code(&[OP_BYTE]).is_err(), "truncated byte");
    assert!(validate_code(&[OP_GAP, 1, 0, 0, 0]).is_err(), "truncated gap");
    assert!(validate_code(&[OP_BYTE, 1, OP_ANY]).is_err(), "trailing wildcard");
    assert!(validate_code(&[OP_ANY, OP_BYTE, 1]).is_err(), "leading wildcard");
    assert!(validate_code(&[OP_BYTE, 1, OP_ALT, 0, 0, OP_BYTE, 2]).is_err(), "zero alternatives");
    assert!(validate_code(&[OP_BYTE, 1, OP_ALT, 1, 0, 5, 0, 1, OP_BYTE, 2]).is_err(), "alternative length runs past the end");
    let mut x: u64 = 0xBADC0FFEE0DDF00D;
    for _ in 0..20_000 {
        let n = 1 + (x % 24) as usize;
        let c: Vec<u8> = (0..n).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; (x >> 24) as u8 % 7 }).collect();
        let _ = validate_code(&c);
        let _ = anchor_of_code(&c);
    }
}
