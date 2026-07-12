//! YAML test suite format for FLUX policy testing.
//!
//! Suite files are YAML documents that define a complete test suite:
//! normal test cases, adversarial cases, and conservation bounds.

use std::collections::HashMap;
use std::path::Path;

/// A single test case in a suite.
#[derive(Debug, Clone)]
pub struct TestCase {
    pub name: String,
    pub input: serde_yaml::Value,
    pub expected_action: Option<i32>,
    pub description: String,
}

/// Conservation bounds for a suite.
#[derive(Debug, Clone)]
pub struct ConservationConfig {
    pub max_budget: i32,
    pub max_steps: u64,
}

impl Default for ConservationConfig {
    fn default() -> Self {
        Self { max_budget: 1000, max_steps: 100_000 }
    }
}

/// Parsed test suite configuration.
#[derive(Debug, Clone)]
pub struct SuiteConfig {
    pub name: String,
    pub policy_file: Option<String>,
    pub tests: Vec<TestCase>,
    pub adversarial: Vec<TestCase>,
    pub conservation: ConservationConfig,
    pub fuzz: Option<FuzzSuiteConfig>,
}

/// Fuzz configuration parsed from a suite file.
#[derive(Debug, Clone)]
pub struct FuzzSuiteConfig {
    pub input_ranges: HashMap<String, (i32, i32)>,
    pub output_text_length: Option<(u32, u32)>,
    pub budget_range: Option<(i32, i32)>,
    pub iterations: u32,
    pub seed: Option<u64>,
}

impl SuiteConfig {
    pub fn total_cases(&self) -> usize {
        self.tests.len() + self.adversarial.len()
    }
}

/// Parse a YAML suite file into a `SuiteConfig`.
pub fn parse_suite(path: &Path) -> Result<SuiteConfig, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    parse_suite_str(&contents, path)
}

/// Parse YAML suite from a string (with path for error messages).
pub fn parse_suite_str(contents: &str, path: &Path) -> Result<SuiteConfig, String> {
    let data: serde_yaml::Value = serde_yaml::from_str(contents)
        .map_err(|e| format!("YAML parse error in {}: {}", path.display(), e))?;

    let name = data.get("suite")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| path.file_stem().and_then(|s| s.to_str()).unwrap_or("unnamed"))
        .to_string();

    let policy_file = data.get("policy")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && *s != "null")
        .map(|s| s.to_string());

    let mut tests = Vec::new();
    if let Some(tests_seq) = data.get("tests").and_then(|v| v.as_sequence()) {
        for t in tests_seq {
            let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let input = t.get("input").cloned().unwrap_or(serde_yaml::Value::Null);
            let expected = t.get("expected").cloned();
            let expected_action = extract_expected_action(expected);
            let description = t.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
            tests.push(TestCase { name, input, expected_action, description });
        }
    }

    let mut adversarial = Vec::new();
    if let Some(adv_seq) = data.get("adversarial").and_then(|v| v.as_sequence()) {
        for t in adv_seq {
            let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let input = t.get("input").cloned().unwrap_or(serde_yaml::Value::Null);
            let expected = t.get("expected").cloned();
            let expected_action = extract_expected_action(expected);
            let description = t.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
            adversarial.push(TestCase { name, input, expected_action, description });
        }
    }

    let conservation = data.get("conservation").map(|c| {
        ConservationConfig {
            max_budget: c.get("max_budget").and_then(|v| v.as_i64()).unwrap_or(1000) as i32,
            max_steps: c.get("max_steps").and_then(|v| v.as_i64()).unwrap_or(100_000) as u64,
        }
    }).unwrap_or_default();

    let fuzz = data.get("fuzz").map(|f| {
        let input_ranges = f.get("input_ranges")
            .and_then(|v| v.as_mapping())
            .map(|m| {
                let mut ranges = HashMap::new();
                for (k, v) in m {
                    if let (Some(key), Some(arr)) = (k.as_str(), v.as_sequence()) {
                        if arr.len() == 2 {
                            let lo = arr[0].as_i64().unwrap_or(0) as i32;
                            let hi = arr[1].as_i64().unwrap_or(0) as i32;
                            ranges.insert(key.to_string(), (lo, hi));
                        }
                    }
                }
                ranges
            }).unwrap_or_default();

        let output_text_length = f.get("output_text_length")
            .and_then(|v| v.as_sequence())
            .and_then(|s| {
                if s.len() == 2 {
                    Some((s[0].as_u64()? as u32, s[1].as_u64()? as u32))
                } else { None }
            });

        let budget_range = f.get("budget_range")
            .and_then(|v| v.as_sequence())
            .and_then(|s| {
                if s.len() == 2 {
                    Some((s[0].as_i64()? as i32, s[1].as_i64()? as i32))
                } else { None }
            });

        let iterations = f.get("iterations").and_then(|v| v.as_u64()).unwrap_or(1000) as u32;
        let seed = f.get("seed").and_then(|v| v.as_u64());

        FuzzSuiteConfig { input_ranges, output_text_length, budget_range, iterations, seed }
    });

    Ok(SuiteConfig { name, policy_file, tests, adversarial, conservation, fuzz })
}

fn extract_expected_action(expected: Option<serde_yaml::Value>) -> Option<i32> {
    expected.and_then(|e| {
        if let Some(map) = e.as_mapping() {
            map.get("action").and_then(|v| v.as_i64()).map(|v| v as i32)
        } else if let Some(n) = e.as_i64() {
            Some(n as i32)
        } else { None }
    })
}

/// Serialize a `SuiteConfig` to YAML.
pub fn serialize_suite(config: &SuiteConfig) -> String {
    let mut out = String::new();
    out.push_str(&format!("suite: {}\n", config.name));

    if let Some(ref pf) = config.policy_file {
        out.push_str(&format!("policy: {}\n", pf));
    }

    if !config.tests.is_empty() {
        out.push_str("tests:\n");
        for t in &config.tests {
            out.push_str(&format!("  - name: \"{}\"\n", t.name));
            if !t.input.is_null() {
                out.push_str(&format!("    input: {}\n", yaml_value(&t.input)));
            }
            if let Some(a) = t.expected_action {
                out.push_str(&format!("    expected: {{action: {}}}\n", a));
            }
            if !t.description.is_empty() {
                out.push_str(&format!("    description: \"{}\"\n", t.description));
            }
        }
    }

    if !config.adversarial.is_empty() {
        out.push_str("adversarial:\n");
        for t in &config.adversarial {
            out.push_str(&format!("  - name: \"{}\"\n", t.name));
            if !t.input.is_null() {
                out.push_str(&format!("    input: {}\n", yaml_value(&t.input)));
            }
            if let Some(a) = t.expected_action {
                out.push_str(&format!("    expected: {{action: {}}}\n", a));
            }
            if !t.description.is_empty() {
                out.push_str(&format!("    description: \"{}\"\n", t.description));
            }
        }
    }

    out.push_str(&format!(
        "conservation:\n  max_budget: {}\n  max_steps: {}\n",
        config.conservation.max_budget, config.conservation.max_steps
    ));

    if let Some(ref fuzz) = config.fuzz {
        out.push_str("fuzz:\n");
        if !fuzz.input_ranges.is_empty() {
            out.push_str("  input_ranges:\n");
            for (k, v) in &fuzz.input_ranges {
                out.push_str(&format!("    {}: [{}, {}]\n", k, v.0, v.1));
            }
        }
        if let Some(otl) = fuzz.output_text_length {
            out.push_str(&format!("  output_text_length: [{}, {}]\n", otl.0, otl.1));
        }
        if let Some(br) = fuzz.budget_range {
            out.push_str(&format!("  budget_range: [{}, {}]\n", br.0, br.1));
        }
        out.push_str(&format!("  iterations: {}\n", fuzz.iterations));
        if let Some(seed) = fuzz.seed {
            out.push_str(&format!("  seed: {}\n", seed));
        }
    }

    out
}

fn yaml_value(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => format!("\"{}\"", s),
        serde_yaml::Value::Null => "null".to_string(),
        other => format!("{:?}", other),
    }
}
