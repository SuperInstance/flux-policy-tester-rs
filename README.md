# 🧪 FLUX Policy Tester (Rust)

![Crates.io](https://img.shields.io/crates/v/flux-policy-tester)
![Rust](https://img.shields.io/badge/rust-stable-orange)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

> Testing framework for FLUX bytecode agent policies — verify behavior, fuzz edge cases, enforce conservation bounds.

A Rust testing framework for FLUX bytecode policies: unit tests, property-based tests, fuzz tests, and YAML-driven test suites. Ensure your conservation laws and agent guardrails behave correctly under all conditions — including adversarial inputs.

---

## Philosophy

Part of [Working Animal Architecture](https://github.com/SuperInstance/AI-Writings), where **γ + η = C** (genome + nurture = capability). The policy tester is the **training ground** — where working animals prove they can work within the fence before being released to pasture. Every policy is stress-tested, fuzzed, and verified against conservation bounds. A working dog that can't pass the training ground doesn't go to work.

> *Test the fence before you trust the dog.*

## Installation

```bash
cargo add flux-policy-tester
```

Or in `Cargo.toml`:

```toml
[dependencies]
flux-policy-tester = "0.1"
```

## Quick Start

### Basic policy testing

```rust
use flux_policy_tester::{PolicyTester, assemble};

// Assemble a simple policy
let policy = assemble("MOVI R0, 0\nHALT").unwrap();

// Test it
let mut tester = PolicyTester::new(&policy, 1000);
let result = tester.test_input("hello", 0, "basic test", "", "");
assert!(result.passed);

// Adversarial testing — verify graceful handling of edge cases
let adv_result = tester.test_adversarial("EXTREME!!! input", "extreme input", "");
assert!(adv_result.passed);

// Conservation bounds — verify all inputs stay within budget
let inputs = vec!["test1", "test2", "test3"];
let cons_result = tester.test_conservation_bounds(&inputs, 1000, 100_000);
assert!(cons_result.passed);
```

### Fuzz testing

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

if summary.crashes > 0 {
    println!("⚠️  Found {} crashes!", summary.crashes);
} else {
    println!("✅ No crashes — policy is robust.");
}
```

## YAML Test Suites

Define comprehensive test suites in YAML:

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

Run a suite programmatically:

```rust
use flux_policy_tester::suite::parse_suite;
use flux_policy_tester::runner::{run_suite, write_reports};
use std::path::Path;

let config = parse_suite(Path::new("suites/my-policy.yaml")).unwrap();
let policy = include_bytes!("../policies/my-policy.bin");
let result = run_suite(&config, policy);

println!("{}", result);

// Generate CI-ready reports
write_reports(&result, Path::new("reports/"), None).unwrap();
```

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

## API Reference

### `PolicyTester`

| Method | Description |
|--------|-------------|
| `new(policy, budget)` | Create tester with bytecode and conservation budget |
| `test_input(input, expected, desc, name, output)` | Run policy, assert expected action code |
| `test_adversarial(input, desc, output)` | Verify graceful handling of extreme inputs |
| `test_conservation_bounds(inputs, max_budget, max_steps)` | Check all inputs stay within bounds |
| `results()` | Access accumulated test results |
| `summary()` | Get text summary of all tests |

### `PolicyVm`

A FLUX VM with conservation-enforcer syscall support:

| Syscall | Number | Returns |
|---------|--------|---------|
| `GET_INPUT_LEN` | 1 | Length of input text |
| `GET_OUTPUT_LEN` | 2 | Length of output text |
| `GET_INPUT_WORDS` | 3 | Word count of input |
| `GET_OUTPUT_WORDS` | 4 | Word count of output |
| `GET_TOKEN_COUNT` | 5 | Approximate token count |
| `GET_REPETITION` | 6 | Max word frequency ratio × 1000 |
| `GET_CATEGORY` | 7 | Input/output word overlap × 1000 |
| `SET_VIOLATION` | 8 | Sets violation flag (R1 = reason code) |
| `GET_BUDGET` | 10 | Conservation budget |
| `GET_UNIQUE_RATIO` | 11 | Unique/total words × 1000 |
| `GET_ENTROPY` | 12 | Shannon entropy × 1000 |

### Suite Runner

| Function | Description |
|----------|-------------|
| `run_suite(config, policy)` | Execute a YAML test suite |
| `generate_junit_xml(result)` | JUnit XML for CI integration |
| `generate_markdown_report(result)` | Human-readable Markdown report |
| `write_reports(result, dir, name)` | Write both XML and Markdown to files |

### Fuzzer

| Type/Method | Description |
|-------------|-------------|
| `PolicyFuzzer::new(policy, config)` | Create a fuzzer with configuration |
| `fuzzer.fuzz(iterations)` | Run N random inputs, return summary |
| `fuzzer.find_crash(max_iterations)` | Run until first crash or limit reached |
| `FuzzConfig` | Configure seed, input ranges, max cycles |
| `FuzzSummary` | Results: total runs, crashes, unique crashes |
| `FuzzResult` | Individual fuzz result with input and output |

## Architecture

```
┌─────────────────── FLUX Policy Tester ───────────────────┐
│                                                           │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐   │
│  │ PolicyTester │  │ Suite Runner  │  │    Fuzzer      │   │
│  │              │  │               │  │                │   │
│  │ test_input() │  │ YAML → Tests  │  │ random inputs  │   │
│  │ test_adv()   │  │ JUnit XML     │  │ crash detect   │   │
│  │ test_cons()  │  │ Markdown rpt  │  │ seed reproducible│ │
│  └──────┬───────┘  └───────┬───────┘  └───────┬────────┘   │
│         │                  │                  │            │
│         ▼                  ▼                  ▼            │
│  ┌────────────────────────────────────────────────────┐   │
│  │                   PolicyVm                          │   │
│  │  (FLUX VM with conservation-enforcer syscalls)     │   │
│  │                                                    │   │
│  │  Registers: R0–R15   Memory: byte-addressable      │   │
│  │  Opcodes: 33 instrs  Syscalls: 11 conservation     │   │
│  │  Assembler: FLUX assembly → bytecode               │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  ┌────────────────────────────────────────────────────┐   │
│  │               Built-in Assembler                    │   │
│  │  Full FLUX ISA + pseudo-instructions (JGE/JGT/...)  │   │
│  │  Labels, comments (; and //), hex/binary immediates │   │
│  └────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────┘
```

## Testing

```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run only fuzzer tests
cargo test fuzzer::

# Run only suite tests
cargo test suite::
```

## Cross-Implementation

| Aspect | Python | Rust |
|--------|--------|------|
| Package | `pip install flux-policy-tester` | `cargo add flux-policy-tester` |
| Repo | [flux-policy-tester](https://github.com/SuperInstance/flux-policy-tester) | [flux-policy-tester-rs](https://github.com/SuperInstance/flux-policy-tester-rs) (this) |
| YAML suites | ✅ Same format | ✅ Same format |
| Fuzzer seeds | Reproducible | Reproducible (same `rand` crate) |

Both implementations accept the same YAML test suite format. A suite written for the Python tester runs unchanged on the Rust tester.

## Ecosystem

### FLUX Runtime
- [flux-vm](https://github.com/SuperInstance/flux-vm) — Python VM (`pip install flux-vm`)
- [flux-core](https://github.com/SuperInstance/flux-core) — Rust VM (`cargo add fluxvm`)
- [flux-js](https://github.com/SuperInstance/flux-js) — JavaScript VM (`npm install flux-js`)

### Conservation
- [conservation-enforcer-rs](https://github.com/SuperInstance/conservation-enforcer-rs) — Conservation-law enforcement for LLM outputs
- [flux-registry-rs](https://github.com/SuperInstance/flux-registry-rs) — Pre-compiled policy registry

### Tooling
- [flux-compiler-rs](https://github.com/SuperInstance/flux-compiler-rs) — Bytecode assembler, disassembler, validator

### Theory
- [AI-Writings](https://github.com/SuperInstance/AI-Writings) — Paradigm essays

## License

MIT
