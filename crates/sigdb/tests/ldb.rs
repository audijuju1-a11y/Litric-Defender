use sigdb::ldb::*;
use sigdb::ndb::SigError;
use sigdb::{Database, Target};

fn ok(s: &str) -> Expr {
    parse_expr(s).unwrap_or_else(|e| panic!("{s}: {e}"))
}
fn kind(s: &str) -> &'static str {
    match parse_expr(s) {
        Ok(_) => "ok",
        Err(SigError::Malformed(_)) => "malformed",
        Err(SigError::Unsupported(_)) => "unsupported",
    }
}

#[test]
fn expressions_parse_and_evaluate() {
    let t = |s: &str, c: &[u32]| ok(s).eval(c);
    assert!(t("0&1", &[1, 2]) && !t("0&1", &[1, 0]) && !t("0&1", &[0, 1]));
    assert!(t("0|1", &[0, 1]) && !t("0|1", &[0, 0]));
    assert!(t("(0|1)&2", &[1, 0, 1]) && !t("(0|1)&2", &[1, 1, 0]));
    assert!(t("0&(1|2)", &[1, 0, 3]) && !t("0&(1|2)", &[0, 1, 1]));
    assert!(t("0=3", &[3]) && !t("0=3", &[2]) && !t("0=3", &[4]));
    assert!(t("0>3", &[4]) && !t("0>3", &[3]));
    assert!(t("0<3", &[2]) && !t("0<3", &[3]));
    assert!(t("0>1&1=2", &[2, 2]) && !t("0>1&1=2", &[2, 1]));
    assert!(t("((0&1)|(2&3))", &[0, 0, 1, 1]));
    assert!(!t("5", &[1]), "missing count behaves as zero");
    assert_eq!(ok("(0|1)&2").max_index(), 2);
    assert_eq!(ok("0>5&63").max_index(), 63);
}

#[test]
fn unsupported_and_malformed_expressions_are_classified() {
    for s in ["0&1|2", "0|1&2", "(0|1)>2", "(0&1)=1", "0>5,2", "(0|1)>2,3", "0,2"] {
        assert_eq!(kind(s), "unsupported", "{s}");
    }
    for s in ["", "0&", "&0", "(0", "0)", "a", "0 & 1", "64", "0>", "0>>1", "0&&1", "()", "123456789", "0=a"] {
        assert_eq!(kind(s), "malformed", "{s}");
    }
    assert_eq!(kind(&format!("{}0{}", "(".repeat(20), ")".repeat(20))), "unsupported", "nesting too deep");
    // the 512-character length limit is reached before the 256-node limit can be (the node limit is a second line of defence)
    assert_eq!(kind(&vec!["0"; 300].join("&")), "malformed", "expression longer than 512 characters");
    assert_eq!(kind(&vec!["0"; 256].join("&")), "ok", "256 terms fit in 511 characters");
    assert_eq!(kind(&"0".repeat(600)), "malformed");
}

#[test]
fn target_blocks_and_constraints() {
    let (t, c) = parse_target_block("Target:1,FileSize:10-20,NumberOfSections:2-5,Engine:51-255").unwrap();
    assert_eq!((t, c.filesize, c.sections), (Target::Pe, Some((10, 20)), Some((2, 5))));
    assert_eq!(parse_target_block("Target:0").unwrap().0, Target::Any);
    assert_eq!(parse_target_block("Target:6").unwrap().0, Target::Elf);
    assert_eq!(parse_target_block("Target:10").unwrap().0, Target::Pdf);
    for bad in ["Target:3", "Target:9", "EntryPoint:1-2", "Container:CL_TYPE_PDF", "Intermediates:CL_TYPE_ZIP", "IconGroup1:x", "Weird:1"] {
        assert!(matches!(parse_target_block(bad), Err(SigError::Unsupported(_))), "{bad}");
    }
    for bad in ["Target", "FileSize:5-1", "FileSize:x", "FileSize:1", "Target:1,Target:0", "FileSize:1-2,FileSize:3-4", "Target:abc"] {
        assert!(matches!(parse_target_block(bad), Err(SigError::Malformed(_))), "{bad}");
    }
    let c = parse_constraints("FileSize:10-20,NumberOfSections:2-3").unwrap();
    assert_eq!(c.to_text(), "FileSize:10-20,NumberOfSections:2-3");
    assert_eq!(parse_constraints("-").unwrap(), Constraints::default());
    assert!(parse_constraints("Target:1").is_err(), "no Target inside a constraint list");
    assert!(c.check(10, Some(2)) && c.check(20, Some(3)));
    assert!(!c.check(9, Some(2)) && !c.check(21, Some(2)) && !c.check(15, Some(4)) && !c.check(15, None));
    assert!(Constraints::default().check(0, None));
}

fn v2(rec: &str) -> Vec<u8> {
    format!("LITRIC-SIGDB 2\nserial 1\ncreated 1\nmin-engine 2\nrule-count 1\n{rec}\nEND\n").into_bytes()
}

#[test]
fn ldb_records_load_and_are_validated() {
    let good = "LDB l.1 Win.A high 90 pe FileSize:10-20 (0&1)|2 *:11223344 EP+0:e8??????ffd0 S1+0:aabbccdd";
    let db = Database::parse(&v2(good)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((db.ldb.len(), db.rule_count()), (1, 1));
    assert_eq!(db.ldb[0].subs.len(), 3);
    assert_eq!(db.ldb[0].expr_text, "(0&1)|2");
    assert_eq!(db.ldb_rule(0).family, "Win.A");
    for bad in [
        "LDB l Fam high 90 any - 0&1 *:11223344",                          // expression past subsignatures
        "LDB l Fam high 90 any - 0 11223344",                              // missing offset:
        "LDB l Fam high 90 any - 0 *:aa??bb{2}ccddeeff",                   // unlocatable subsignature
        "LDB l Fam high 90 any - 0 EP+0:11223344",                         // EP offset on non-PE target
        "LDB l Fam high 90 any - 0&1|2 *:11223344 *:55667788 *:99aabbcc",  // mixed precedence
        "LDB l Fam high 90 any - 0>1,2 *:11223344",                        // distinct-count modifier
        "LDB l Fam high 90 zip - 0 *:11223344",                            // target not allowed
        "LDB l Fam high 90 any Target:1 0 *:11223344",                     // Target inside constraints
        "LDB l Fam high 90 any - 0",                                       // no subsignatures
        "LDB l Fam high 90 any FileSize:5-1 0 *:11223344",                 // bad range
    ] {
        assert!(Database::parse(&v2(bad)).is_err(), "should reject: {bad}");
    }
    let many = format!("LDB l Fam high 90 any - 0 {}", vec!["*:11223344"; 65].join(" "));
    assert!(Database::parse(&v2(&many)).is_err(), "more than 64 subsignatures");
    let v1 = "LITRIC-SIGDB 1\nserial 1\ncreated 1\nmin-engine 1\nrule-count 1\nLDB l Fam high 90 any - 0 *:11223344\nEND\n";
    assert!(Database::parse(v1.as_bytes()).is_err());
    let rev = Database::parse("LITRIC-SIGDB 2\nserial 1\ncreated 1\nmin-engine 2\nrule-count 1\nLDB l.x Fam high 90 any - 0 *:11223344\nR l.x\nEND\n".as_bytes()).unwrap();
    assert_eq!(rev.ldb.len(), 0);
}
