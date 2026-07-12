# 🧪 FLUX Policy Tester (Rust)

> Testing framework for FLUX bytecode agent policies — verify behavior, fuzz edge cases, enforce conservation bounds.

A Rust implementation of the [FLUX Policy Tester](https://github.com/SuperInstance/flux-policy-tester), providing unit tests, property-based tests, and fuzz tests for FLUX bytecode policies.

## What Is This?

This crate lets you write comprehensive tests for FLUX bytecode policies — the conservation laws and agent guardrails that run on the FLUX VM. Ensure your policies behave correctly under all conditions, including adversarial inputs and edge cases.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
flux-policy-tester = "0.1"
```

## Quick Start

```rust
use flux_policy_tester::{PolicyTester, assemble};

// Assemble a simple policy
let policy = assemble("MOVI R0, 0\nHALT").unwrap();

// Test it
let mut tester = PolicyTester::new(&policy, 1000);
let result = tester.test_input("hello", 0, "basic test", "", "");
assert!(result.passed);

// Adversarial testing
let adv_result = tester.test_adversarial("EXTREME!!! input", "extreme input", "");
assert!(adv_result.passed);

// Conservation bounds
let inputs = vec!["test1", "test2", "test3"];
let cons_result = tester.test_conservation_bounds(&inputs, 1000, 100_000);
assert!(cons_result.passed);
```

## YAML Test Suites

Define test suites in YAML:

```yaml
suite: my-policy
tests:
  - name: "normal case"
    input: {temperature: 70}
    expected: {action: 0}
  - name: "above threshold"
    input: {temperature: 80}
    expected: {action: 1}
adversarial:
  - name: "extreme high"
    input: {temperature: 99999}
    expected: {action: 1}
conservation:
  max_budget: 1000
  max_steps: 10000
fuzz:
  input_ranges:
    temperature: [-273, 1000]
  iterations: 5000
  seed: 42
```

Run a suite:

```rust
use flux_policy_tester::suite::parse_suite;
use flux_policy_tester::runner::run_suite;
use std::path::Path;

let config = parse_suite(Path::new("suites/my-policy.yaml")).unwrap();
let policy = include_bytes!("../policies/my-policy.bin");
let result = run_suite(&config, policy);
println!("{}", result);

// Generate reports
use flux_policy_tester::runner::write_reports;
write_reports(&result, Path::new("reports/"), None).unwrap();
```

## Fuzz Testing

```rust
use flux_policy_tester::{PolicyFuzzer, FuzzConfig};
use std::collections::HashMap;

let mut ranges = HashMap::new();
ranges.insert("temperature".to_string(), (-100, 200));

let config = FuzzConfig {
    seed: Some(42),
    input_ranges: ranges,
    max_cycles: 100_000,
    ..Default::default()
};

let mut fuzzer = PolicyFuzzer::new(&policy, config);
let summary = fuzzer.fuzz(10_000);
println!("{}", summary);

if summary.crashes > 0 {
    println!("⚠️  Found {} crashes!", summary.crashes);
} else {
    println!("✅ No crashes — policy is robust.");
}
```

## API Overview

### `PolicyTester`
- `test_input(input, expected, desc, name, output)` — Run policy against input, assert expected action
- `test_adversarial(input, desc, output)` — Verify graceful handling of edge cases
- `test_conservation_bounds(inputs, max_budget, max_steps)` — Check all inputs stay within bounds
- `results()` — Access accumulated results
- `summary()` — Get text summary of all tests

### `PolicyVm`
A FLUX VM with conservation-enforcer syscall support:
- `GET_INPUT_LEN`, `GET_OUTPUT_LEN`, `GET_INPUT_WORDS`, `GET_OUTPUT_WORDS`
- `GET_TOKEN_COUNT`, `GET_REPETITION`, `GET_CATEGORY`
- `SET_VIOLATION`, `GET_BUDGET`, `GET_UNIQUE_RATIO`, `GET_ENTROPY`

### Suite Runner
- `run_suite(config, policy)` — Execute a YAML test suite
- `generate_junit_xml(result)` — JUnit XML for CI integration
- `generate_markdown_report(result)` — Human-readable Markdown report
- `write_reports(result, dir, name)` — Write both to files

### Fuzzer
- `PolicyFuzzer::new(policy, config)` — Create a fuzzer
- `fuzz(iterations)` — Run N random inputs
- `find_crash(max_iterations)` — Stop at first crash

## Assembler

The built-in assembler supports the full FLUX instruction set:

```rust
use flux_policy_tester::assemble;

let policy = assemble(r#"
    MOVI R0, 5        ; GET_OUTPUT_LEN
    SYSCALL
    MOV  R2, R0
    MOVI R0, 10       ; GET_BUDGET
    SYSCALL
    MOV  R3, R0
    CMP  R2, R3       ; compare output_len vs budget
    JGT  R2, R3, block
    MOVI R0, 0        ; allow
    HALT
block:
    MOVI R1, 1        ; reason: length budget
    MOVI R0, 8        ; SET_VIOLATION
    SYSCALL
    MOVI R0, 1        ; block
    HALT
"#).unwrap();
```

Supported pseudo-instructions: `JGE`, `JGT`, `JLE`, `JLT`

## Ecosystem

### FLUX Runtime
- [flux-vm](https://github.com/SuperInstance/flux-vm) — Python VM (`pip install flux-vm`)
- [flux-core](https://github.com/SuperInstance/flux-core) — Rust VM (`cargo add fluxvm`)
- [flux-js](https://github.com/SuperInstance/flux-js) — JavaScript VM (`npm install flux-js`)

### Testing
- [flux-policy-tester](https://github.com/SuperInstance/flux-policy-tester) — Python version (`pip install flux-policy-tester`)
- [flux-policy-tester-rs](https://github.com/SuperInstance/flux-policy-tester-rs) — Rust version (this crate)

### Conservation
- [flux-registry](https://github.com/SuperInstance/flux-registry) — Pre-compiled policy registry
- [conservation-enforcer](https://github.com/SuperInstance/conservation-enforcer) — Conservation-law enforcement

## License

MIT
