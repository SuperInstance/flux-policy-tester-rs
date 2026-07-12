//! Test suite runner — executes suites and produces reports.
//!
//! Produces JUnit-style XML (for CI integration) and Markdown reports.

use std::path::{Path, PathBuf};
use chrono::Utc;

use crate::{
    PolicyTester, SuiteResult, SuiteConfig, input_to_string,
};

/// Execute all tests in a suite configuration.
pub fn run_suite(config: &SuiteConfig, policy_bytecode: &[u8]) -> SuiteResult {
    let mut result = SuiteResult::new(&config.name);
    let mut tester = PolicyTester::new(policy_bytecode, config.conservation.max_budget);

    // ── Normal tests ──
    for tc in &config.tests {
        let input_str = input_to_string(&tc.input);
        let expected = tc.expected_action.unwrap_or(0);
        let tr = tester.test_input(
            &input_str,
            expected,
            &tc.description,
            &tc.name,
            "",
        );
        result.total += 1;
        if tr.passed { result.passed += 1; }
        else if tr.error.is_some() { result.errored += 1; }
        else { result.failed += 1; }
        result.results.push(tr);
    }

    // ── Adversarial tests ──
    for tc in &config.adversarial {
        let input_str = input_to_string(&tc.input);
        let tr = if let Some(expected_action) = tc.expected_action {
            tester.test_input(
                &input_str,
                expected_action,
                &tc.description,
                &tc.name,
                "",
            )
        } else {
            let mut t = tester.test_adversarial(&input_str, &tc.description, "");
            t.name = tc.name.clone();
            t
        };

        result.total += 1;
        if tr.passed { result.passed += 1; }
        else if tr.error.is_some() { result.errored += 1; }
        else { result.failed += 1; }
        result.results.push(tr);
    }

    // ── Conservation bounds check ──
    if !config.tests.is_empty() || !config.adversarial.is_empty() {
        let all_inputs: Vec<String> = config.tests.iter()
            .chain(config.adversarial.iter())
            .map(|tc| input_to_string(&tc.input))
            .collect();
        let input_refs: Vec<&str> = all_inputs.iter().map(|s| s.as_str()).collect();

        let cons_result = tester.test_conservation_bounds(
            &input_refs,
            config.conservation.max_budget,
            config.conservation.max_steps,
        );

        if !cons_result.passed {
            result.conservation_passed = false;
            result.total += 1;
            result.failed += 1;
        } else {
            result.total += 1;
            result.passed += 1;
        }
        result.results.push(cons_result);
    }

    result
}

/// Generate JUnit-style XML report.
pub fn generate_junit_xml(result: &SuiteResult) -> String {
    let timestamp = Utc::now().to_rfc3339();

    let mut xml = String::new();
    xml.push_str(&format!(
        r#"<testsuite name="{}" tests="{}" failures="{}" errors="{}" time="0" timestamp="{}">"#,
        escape_xml(&result.suite_name),
        result.total,
        result.failed,
        result.errored,
        timestamp,
    ));

    for tr in &result.results {
        xml.push_str(&format!(
            r#"<testcase name="{}" classname="{}" time="0">"#,
            escape_xml(&tr.name),
            escape_xml(&result.suite_name),
        ));

        if !tr.passed {
            if let Some(ref err) = tr.error {
                xml.push_str(&format!(
                    r#"<error message="{}">{}</error>"#,
                    escape_xml(err),
                    escape_xml(err),
                ));
            } else {
                let msg = format!("expected={} actual={}", tr.expected, tr.actual);
                let mut body = format!("Expected: {}\n  Actual: {}\n  Cycles: {}", tr.expected, tr.actual, tr.cycles);
                if !tr.violation_reason.is_empty() {
                    body.push_str(&format!("\n  Violation: {}", tr.violation_reason));
                }
                xml.push_str(&format!(
                    r#"<failure message="{}">{}</failure>"#,
                    escape_xml(&msg),
                    escape_xml(&body),
                ));
            }
        }

        xml.push_str(&format!(
            "<system-out>cycles={}</system-out>",
            tr.cycles
        ));
        xml.push_str("</testcase>");
    }

    xml.push_str("</testsuite>");
    xml
}

/// Generate a human-readable Markdown report.
pub fn generate_markdown_report(result: &SuiteResult) -> String {
    let mut lines = Vec::new();

    lines.push(format!("# FLUX Policy Test Report: {}", result.suite_name));
    lines.push(String::new());
    lines.push(format!("**Generated:** {}Z", Utc::now().to_rfc3339()));
    lines.push(String::new());
    lines.push("## Summary".to_string());
    lines.push(String::new());
    lines.push("| Metric | Value |".to_string());
    lines.push("|--------|-------|".to_string());
    lines.push(format!("| Total tests | {} |", result.total));
    lines.push(format!("| Passed | {} ✅ |", result.passed));
    lines.push(format!("| Failed | {} ❌ |", result.failed));
    lines.push(format!("| Errored | {} |", result.errored));
    lines.push(format!("| Success rate | {:.1}% |", result.success_rate()));
    let cons_icon = if result.conservation_passed { "✅ Within bounds" } else { "⚠️ VIOLATED" };
    lines.push(format!("| Conservation | {} |", cons_icon));
    lines.push(String::new());
    lines.push("## Test Details".to_string());
    lines.push(String::new());

    for tr in &result.results {
        let icon = if tr.passed { "✅" } else { "❌" };
        lines.push(format!("### {} {}", icon, tr.name));
        lines.push(String::new());
        if !tr.description.is_empty() {
            lines.push(format!("*{}*", tr.description));
            lines.push(String::new());
        }
        lines.push("| Field | Value |".to_string());
        lines.push("|-------|-------|".to_string());
        lines.push(format!("| Expected | `{}` |", tr.expected));
        lines.push(format!("| Actual | `{}` |", tr.actual));
        lines.push(format!("| Cycles | {} |", tr.cycles));
        if let Some(ref err) = tr.error {
            lines.push(format!("| Error | `{}` |", err));
        }
        if !tr.violation_reason.is_empty() {
            lines.push(format!("| Violation | {} |", tr.violation_reason));
        }
        lines.push(String::new());
    }

    // Conservation analysis
    lines.push("## Conservation Analysis".to_string());
    lines.push(String::new());
    if result.conservation_passed {
        lines.push("All executions stayed within declared conservation bounds. ✅".to_string());
    } else {
        lines.push("⚠️ **Conservation bounds were violated!**".to_string());
        lines.push(String::new());
        lines.push("This means the policy either:".to_string());
        lines.push("- Exceeded the cycle budget (possible infinite loop)".to_string());
        lines.push("- Exceeded the conservation budget".to_string());
        lines.push("- Failed to terminate on some inputs".to_string());
    }
    lines.push(String::new());

    // Cycle statistics
    let all_cycles: Vec<u64> = result.results.iter()
        .filter(|tr| tr.cycles > 0)
        .map(|tr| tr.cycles)
        .collect();
    if !all_cycles.is_empty() {
        let min = *all_cycles.iter().min().unwrap();
        let max = *all_cycles.iter().max().unwrap();
        let mean = all_cycles.iter().sum::<u64>() as f64 / all_cycles.len() as f64;
        lines.push("### Cycle Statistics".to_string());
        lines.push(String::new());
        lines.push("| Stat | Value |".to_string());
        lines.push("|------|-------|".to_string());
        lines.push(format!("| Min | {} |", min));
        lines.push(format!("| Max | {} |", max));
        lines.push(format!("| Mean | {:.1} |", mean));
    }

    lines.join("\n")
}

/// Write both XML and Markdown reports to files.
pub fn write_reports(
    result: &SuiteResult,
    output_dir: &Path,
    suite_name: Option<&str>,
) -> Result<(PathBuf, PathBuf), String> {
    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("Failed to create output dir: {}", e))?;

    let name = suite_name.unwrap_or(&result.suite_name);
    let xml_path = output_dir.join(format!("{}-junit.xml", name));
    let md_path = output_dir.join(format!("{}-report.md", name));

    std::fs::write(&xml_path, generate_junit_xml(result))
        .map_err(|e| format!("Failed to write XML: {}", e))?;
    std::fs::write(&md_path, generate_markdown_report(result))
        .map_err(|e| format!("Failed to write Markdown: {}", e))?;

    Ok((xml_path, md_path))
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
