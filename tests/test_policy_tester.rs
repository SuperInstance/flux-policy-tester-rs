//! Tests for the FLUX Policy Tester itself.
//!
//! These verify that the testing framework works correctly using
//! known-good and known-bad policies.

use flux_policy_tester::*;
use flux_policy_tester::{assemble, PolicyTester, TestResult, SuiteResult, PolicyVm};
use flux_policy_tester::suite::*;
use flux_policy_tester::runner::*;
use flux_policy_tester::fuzzer::*;

// ── Test policies ──────────────────────────────────────────────────────────

fn always_allow() -> Vec<u8> {
    assemble("MOVI R0, 0\nHALT").unwrap()
}

fn always_block() -> Vec<u8> {
    assemble("MOVI R0, 1\nHALT").unwrap()
}

fn length_budget_500() -> Vec<u8> {
    // Check output length against budget:
    // R0=5 (GET_OUTPUT_LEN), R2 = output_len
    // R0=10 (GET_BUDGET), R3 = budget
    // if output_len > budget → block
    assemble(r#"
        MOVI R0, 2
        SYSCALL
        MOV  R2, R0
        MOVI R0, 10
        SYSCALL
        MOV  R3, R0
        CMP  R2, R3
        JGT  R2, R3, block
        MOVI R0, 0
        HALT
    block:
        MOVI R1, 1
        MOVI R0, 8
        SYSCALL
        MOVI R0, 1
        HALT
    "#).unwrap()
}

fn division_policy() -> Vec<u8> {
    // Deliberately divides by zero
    assemble(r#"
        MOVI R0, 3
        SYSCALL
        MOV  R2, R0
        MOVI R3, 0
        DIV  R4, R2, R3
        MOVI R0, 0
        HALT
    "#).unwrap()
}

// ── PolicyTester tests ───────────────────────────────────────────────────

#[test]
fn test_always_allow_policy() {
    let policy = always_allow();
    let mut tester = PolicyTester::new(&policy, 1000);
    let result = tester.test_input("hello world", 0, "", "", "");
    assert!(result.passed);
}

#[test]
fn test_always_block_policy() {
    let policy = always_block();
    let mut tester = PolicyTester::new(&policy, 1000);
    let result = tester.test_input("hello", 0, "", "", "");
    assert!(!result.passed);
}

#[test]
fn test_expected_block() {
    let policy = always_block();
    let mut tester = PolicyTester::new(&policy, 1000);
    let result = tester.test_input("hello", 1, "", "", "");
    assert!(result.passed);
}

#[test]
fn test_length_budget_short_output() {
    let policy = length_budget_500();
    let mut tester = PolicyTester::new(&policy, 500);
    let result = tester.test_input(
        "What is AI?", 0, "short output", "", "AI is artificial intelligence."
    );
    assert!(result.passed);
}

#[test]
fn test_length_budget_long_output() {
    let policy = length_budget_500();
    let mut tester = PolicyTester::new(&policy, 500);
    let long_output: String = std::iter::repeat("word ").take(5000).collect();
    let result = tester.test_input(
        "question", 1, "long output should block", "", &long_output
    );
    assert!(result.passed, "Expected block (1), got error or wrong result: {:?}", result.error);
}

#[test]
fn test_adversarial_no_crash() {
    let policy = always_allow();
    let mut tester = PolicyTester::new(&policy, 1000);
    let result = tester.test_adversarial("EXTREME!!! input", "extreme input", "");
    assert!(result.passed);
}

#[test]
fn test_adversarial_with_extreme_values() {
    let policy = always_allow();
    let mut tester = PolicyTester::new(&policy, 1000);
    let result = tester.test_adversarial("value=99999999", "large number", "");
    assert!(result.passed);
}

#[test]
fn test_adversarial_empty_input() {
    let policy = always_allow();
    let mut tester = PolicyTester::new(&policy, 1000);
    let result = tester.test_adversarial("", "empty input", "");
    assert!(result.passed);
}

#[test]
fn test_division_by_zero_caught() {
    let policy = division_policy();
    let mut tester = PolicyTester::new(&policy, 1000);
    let result = tester.test_input("test", 0, "", "", "");
    assert!(!result.passed);
    assert!(result.error.is_some());
}

#[test]
fn test_results_accumulate() {
    let policy = always_allow();
    let mut tester = PolicyTester::new(&policy, 1000);
    tester.test_input("test1", 0, "", "", "");
    tester.test_input("test2", 0, "", "", "");
    assert_eq!(tester.results().len(), 2);
}

#[test]
fn test_clear_results() {
    let policy = always_allow();
    let mut tester = PolicyTester::new(&policy, 1000);
    tester.test_input("test", 0, "", "", "");
    tester.clear_results();
    assert_eq!(tester.results().len(), 0);
}

#[test]
fn test_summary() {
    let policy = always_allow();
    let mut tester = PolicyTester::new(&policy, 1000);
    tester.test_input("pass", 0, "should pass", "", "");
    tester.test_input("fail", 1, "should fail", "", "");
    let summary = tester.summary();
    assert!(summary.contains("1/2 passed"));
}

// ── Conservation bounds tests ───────────────────────────────────────────

#[test]
fn test_all_within_bounds() {
    let policy = always_allow();
    let inputs: Vec<&str> = (0..100).map(|_| "x=1").collect();
    let mut tester = PolicyTester::new(&policy, 1000);
    let result = tester.test_conservation_bounds(&inputs, 1000, 100_000);
    assert!(result.passed);
}

#[test]
fn test_infinite_loop_detected() {
    let infinite_policy = assemble("loop:\n    JMP loop").unwrap();
    let mut tester = PolicyTester::new(&infinite_policy, 100);
    let result = tester.test_conservation_bounds(&["test"], 100, 500);
    assert!(!result.passed);
    let err = result.error.unwrap();
    assert!(
        err.to_lowercase().contains("cycle exhaustion") || err.contains("Near-limit"),
        "Expected cycle exhaustion message, got: {}", err
    );
}

// ── Suite parsing tests ────────────────────────────────────────────────────

#[test]
fn test_parse_minimal_suite() {
    let yaml = "suite: minimal\n";
    let config = parse_suite_str(yaml, std::path::Path::new("minimal.yaml")).unwrap();
    assert_eq!(config.name, "minimal");
    assert!(config.tests.is_empty());
    assert!(config.adversarial.is_empty());
}

#[test]
fn test_parse_full_suite() {
    let yaml = r#"
suite: test-policy
policy: policies/test.bin
tests:
  - name: "basic"
    input: {x: 1}
    expected: {action: 0}
  - name: "block case"
    input: {x: 2}
    expected: {action: 1}
adversarial:
  - name: "extreme"
    input: {x: 999999}
conservation:
  max_budget: 100
  max_steps: 50
"#;
    let config = parse_suite_str(yaml, std::path::Path::new("full.yaml")).unwrap();
    assert_eq!(config.name, "test-policy");
    assert_eq!(config.policy_file, Some("policies/test.bin".to_string()));
    assert_eq!(config.tests.len(), 2);
    assert_eq!(config.tests[0].name, "basic");
    assert_eq!(config.tests[0].expected_action, Some(0));
    assert_eq!(config.tests[1].expected_action, Some(1));
    assert_eq!(config.adversarial.len(), 1);
    assert_eq!(config.conservation.max_budget, 100);
    assert_eq!(config.conservation.max_steps, 50);
}

#[test]
fn test_serialize_roundtrip() {
    let config = SuiteConfig {
        name: "roundtrip".to_string(),
        policy_file: None,
        tests: vec![TestCase {
            name: "t1".to_string(),
            input: serde_yaml::Value::Null,
            expected_action: Some(0),
            description: String::new(),
        }],
        adversarial: vec![TestCase {
            name: "a1".to_string(),
            input: serde_yaml::Value::Null,
            expected_action: None,
            description: String::new(),
        }],
        conservation: ConservationConfig { max_budget: 50, max_steps: 25 },
        fuzz: None,
    };
    let yaml_text = serialize_suite(&config);
    let parsed = parse_suite_str(&yaml_text, std::path::Path::new("roundtrip.yaml")).unwrap();
    assert_eq!(parsed.name, "roundtrip");
    assert_eq!(parsed.tests.len(), 1);
    assert_eq!(parsed.adversarial.len(), 1);
    assert_eq!(parsed.conservation.max_budget, 50);
}

// ── Runner tests ───────────────────────────────────────────────────────────

#[test]
fn test_run_suite_all_pass() {
    let yaml = r#"
suite: always-allow
tests:
  - name: "test 1"
    input: "hello"
    expected: {action: 0}
  - name: "test 2"
    input: "world"
    expected: {action: 0}
adversarial:
  - name: "empty"
    input: ""
conservation:
  max_budget: 1000
  max_steps: 10000
"#;
    let config = parse_suite_str(yaml, std::path::Path::new("passing.yaml")).unwrap();
    let policy = always_allow();
    let result = run_suite(&config, &policy);
    assert_eq!(result.passed, result.total);
    assert_eq!(result.failed, 0);
}

#[test]
fn test_run_suite_with_failure() {
    let yaml = r#"
suite: always-block
tests:
  - name: "should allow but won't"
    input: "hello"
    expected: {action: 0}
conservation:
  max_budget: 1000
  max_steps: 10000
"#;
    let config = parse_suite_str(yaml, std::path::Path::new("failing.yaml")).unwrap();
    let policy = always_block();
    let result = run_suite(&config, &policy);
    assert!(result.failed >= 1);
}

#[test]
fn test_junit_xml_generation() {
    let mut sr = SuiteResult::new("test");
    sr.total = 2;
    sr.passed = 1;
    sr.failed = 1;
    sr.results = vec![
        TestResult {
            name: "pass".to_string(),
            passed: true,
            description: String::new(),
            expected: "0".to_string(),
            actual: "0".to_string(),
            error: None,
            cycles: 5,
            violation_reason: String::new(),
        },
        TestResult {
            name: "fail".to_string(),
            passed: false,
            description: String::new(),
            expected: "0".to_string(),
            actual: "1".to_string(),
            error: None,
            cycles: 3,
            violation_reason: String::new(),
        },
    ];
    let xml = generate_junit_xml(&sr);
    assert!(xml.contains("testsuite"));
    assert!(xml.contains(r#"tests="2""#));
    assert!(xml.contains(r#"failures="1""#));
    assert!(xml.contains("pass"));
    assert!(xml.contains("fail"));
}

#[test]
fn test_markdown_report_generation() {
    let mut sr = SuiteResult::new("test-md");
    sr.total = 1;
    sr.passed = 1;
    sr.results = vec![
        TestResult {
            name: "test1".to_string(),
            passed: true,
            description: String::new(),
            expected: "0".to_string(),
            actual: "0".to_string(),
            error: None,
            cycles: 3,
            violation_reason: String::new(),
        },
    ];
    let md = generate_markdown_report(&sr);
    assert!(md.contains("# FLUX Policy Test Report"));
    assert!(md.contains("test-md"));
    assert!(md.contains("test1"));
}

#[test]
fn test_write_reports() {
    use tempfile::tempdir;
    let mut sr = SuiteResult::new("file-test");
    sr.total = 1;
    sr.passed = 1;
    sr.results = vec![
        TestResult {
            name: "t1".to_string(),
            passed: true,
            description: String::new(),
            expected: "0".to_string(),
            actual: "0".to_string(),
            error: None,
            cycles: 1,
            violation_reason: String::new(),
        },
    ];

    let dir = tempdir().unwrap();
    let (xml_path, md_path) = write_reports(&sr, dir.path(), None).unwrap();
    assert!(xml_path.exists());
    assert!(md_path.exists());
    assert!(xml_path.file_name().unwrap().to_str().unwrap().contains("file-test"));
    assert!(md_path.file_name().unwrap().to_str().unwrap().contains("file-test"));
}

// ── Fuzzer tests ───────────────────────────────────────────────────────────

#[test]
fn test_fuzz_never_crashes_simple_policy() {
    let policy = always_allow();
    let config = FuzzConfig { seed: Some(42), ..Default::default() };
    let mut fuzzer = PolicyFuzzer::new(&policy, config);
    let summary = fuzzer.fuzz(100);
    assert_eq!(summary.crashes, 0);
    assert_eq!(summary.total_runs, 100);
}

#[test]
fn test_fuzz_tracks_allow_block() {
    let policy = always_allow();
    let config = FuzzConfig { seed: Some(42), ..Default::default() };
    let mut fuzzer = PolicyFuzzer::new(&policy, config);
    let summary = fuzzer.fuzz(50);
    assert_eq!(summary.allows, 50);
    assert_eq!(summary.blocks, 0);
}

#[test]
fn test_fuzz_block_policy() {
    let policy = always_block();
    let config = FuzzConfig { seed: Some(42), ..Default::default() };
    let mut fuzzer = PolicyFuzzer::new(&policy, config);
    let summary = fuzzer.fuzz(50);
    assert_eq!(summary.blocks, 50);
    assert_eq!(summary.allows, 0);
}

#[test]
fn test_fuzz_tracks_cycles() {
    let policy = always_allow();
    let config = FuzzConfig { seed: Some(42), ..Default::default() };
    let mut fuzzer = PolicyFuzzer::new(&policy, config);
    let summary = fuzzer.fuzz(100);
    assert!(summary.min_cycles > 0);
    assert!(summary.max_cycles > 0);
}

#[test]
fn test_fuzz_coverage() {
    let policy = always_allow();
    let config = FuzzConfig { seed: Some(42), ..Default::default() };
    let mut fuzzer = PolicyFuzzer::new(&policy, config);
    let summary = fuzzer.fuzz(10);
    // ALWAYS_ALLOW uses MOVI and HALT at minimum
    assert!(summary.opcodes_seen.len() >= 2);
}

#[test]
fn test_find_crash_returns_none_for_safe_policy() {
    let policy = always_allow();
    let config = FuzzConfig { seed: Some(42), ..Default::default() };
    let mut fuzzer = PolicyFuzzer::new(&policy, config);
    let result = fuzzer.find_crash(100);
    assert!(result.is_none());
}

#[test]
fn test_fuzz_with_custom_ranges() {
    let policy = always_allow();
    let mut ranges = std::collections::HashMap::new();
    ranges.insert("temperature".to_string(), (-100, 200));
    let config = FuzzConfig {
        seed: Some(42),
        input_ranges: ranges,
        ..Default::default()
    };
    let mut fuzzer = PolicyFuzzer::new(&policy, config);
    let summary = fuzzer.fuzz(20);
    assert_eq!(summary.total_runs, 20);
}

#[test]
fn test_fuzz_summary_string() {
    let policy = always_allow();
    let config = FuzzConfig { seed: Some(42), ..Default::default() };
    let mut fuzzer = PolicyFuzzer::new(&policy, config);
    let summary = fuzzer.fuzz(10);
    let s = format!("{}", summary);
    assert!(s.contains("Fuzz Summary"));
    assert!(s.contains("Crashes"));
    assert!(s.contains("Opcode coverage"));
}

// ── VM tests ───────────────────────────────────────────────────────────────

#[test]
fn test_vm_syscall_input_len() {
    let policy = assemble("MOVI R0, 1\nSYSCALL\nHALT").unwrap();
    let mut vm = PolicyVm::new();
    vm.load_input("hello world");
    let result = vm.run(&policy).unwrap();
    assert_eq!(result, 11); // len("hello world")
}

#[test]
fn test_vm_syscall_output_words() {
    let policy = assemble("MOVI R0, 4\nSYSCALL\nHALT").unwrap();
    let mut vm = PolicyVm::new();
    vm.load_output("the quick brown fox");
    let result = vm.run(&policy).unwrap();
    assert_eq!(result, 4);
}

#[test]
fn test_vm_set_violation() {
    let policy = assemble(r#"
        MOVI R1, 1
        MOVI R0, 8
        SYSCALL
        MOVI R0, 1
        HALT
    "#).unwrap();
    let mut vm = PolicyVm::new();
    vm.run(&policy).unwrap();
    assert!(vm.is_violated());
    assert_eq!(vm.violation_reason(), "Length budget exceeded");
}
