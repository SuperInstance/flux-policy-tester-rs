//! Fuzz testing for FLUX bytecode policies.
//!
//! Generates random inputs within declared ranges and runs the policy against
//! each, checking for crashes, infinite loops, budget violations, and coverage.

use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::HashMap;

use crate::{PolicyVm, Op};

/// Configuration for a fuzzing session.
#[derive(Debug, Clone)]
pub struct FuzzConfig {
    pub input_ranges: HashMap<String, (i32, i32)>,
    pub output_text_length: (u32, u32),
    pub output_vocab: Vec<String>,
    pub budget_range: (i32, i32),
    pub max_cycles: u64,
    pub seed: Option<u64>,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        let vocab = vec![
            "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
            "hello", "world", "test", "flux", "policy", "agent", "conservation",
            "law", "budget", "enforce", "block", "allow", "violation", "energy",
        ]
        .iter().map(|s| s.to_string()).collect();

        Self {
            input_ranges: HashMap::new(),
            output_text_length: (0, 500),
            output_vocab: vocab,
            budget_range: (10, 10000),
            max_cycles: 50_000,
            seed: None,
        }
    }
}

/// Result of a single fuzz iteration.
#[derive(Debug, Clone)]
pub struct FuzzResult {
    pub iteration: u32,
    pub input_text: String,
    pub output_text: String,
    pub budget: i32,
    pub result_code: u32,
    pub cycles: u64,
    pub crashed: bool,
    pub error: Option<String>,
    pub violation_reason: String,
}

/// Aggregate summary of a fuzzing session.
#[derive(Debug, Clone)]
pub struct FuzzSummary {
    pub total_runs: u32,
    pub crashes: u32,
    pub cycle_exhaustions: u32,
    pub violations: u32,
    pub allows: u32,
    pub blocks: u32,
    pub min_cycles: u64,
    pub max_cycles: u64,
    pub total_cycles: u64,
    pub opcodes_seen: Vec<u8>,
    pub crash_examples: Vec<FuzzResult>,
    pub cycle_exhaustion_examples: Vec<FuzzResult>,
    pub violation_examples: Vec<FuzzResult>,
}

impl FuzzSummary {
    pub fn new() -> Self {
        Self {
            total_runs: 0,
            crashes: 0,
            cycle_exhaustions: 0,
            violations: 0,
            allows: 0,
            blocks: 0,
            min_cycles: u64::MAX,
            max_cycles: 0,
            total_cycles: 0,
            opcodes_seen: Vec::new(),
            crash_examples: Vec::new(),
            cycle_exhaustion_examples: Vec::new(),
            violation_examples: Vec::new(),
        }
    }

    pub fn mean_cycles(&self) -> f64 {
        if self.total_runs == 0 { 0.0 }
        else { self.total_cycles as f64 / self.total_runs as f64 }
    }

    pub fn crash_rate(&self) -> f64 {
        if self.total_runs == 0 { 0.0 }
        else { (self.crashes as f64 / self.total_runs as f64) * 100.0 }
    }

    pub fn coverage(&self) -> f64 {
        let total_opcodes = count_opcodes();
        if total_opcodes == 0 { 0.0 }
        else { (self.opcodes_seen.len() as f64 / total_opcodes as f64) * 100.0 }
    }
}

impl Default for FuzzSummary {
    fn default() -> Self { Self::new() }
}

impl std::fmt::Display for FuzzSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Fuzz Summary: {} runs", self.total_runs)?;
        writeln!(f, "  Crashes: {} ({:.1}%)", self.crashes, self.crash_rate())?;
        writeln!(f, "  Cycle exhaustions: {}", self.cycle_exhaustions)?;
        writeln!(f, "  Allows: {} | Blocks: {} | Violations: {}", self.allows, self.blocks, self.violations)?;
        let min = if self.min_cycles == u64::MAX { 0 } else { self.min_cycles };
        writeln!(f, "  Cycles — min={} max={} mean={:.1}", min, self.max_cycles, self.mean_cycles())?;
        writeln!(f, "  Opcode coverage: {:.1}% ({}/{})", self.coverage(), self.opcodes_seen.len(), count_opcodes())?;

        if !self.crash_examples.is_empty() {
            writeln!(f, "  Crash examples:")?;
            for ex in &self.crash_examples[..self.crash_examples.len().min(3)] {
                writeln!(f, "    #{}: {}", ex.iteration, ex.error.as_deref().unwrap_or("unknown"))?;
            }
        }
        if !self.cycle_exhaustion_examples.is_empty() {
            writeln!(f, "  Cycle exhaustion examples:")?;
            for ex in &self.cycle_exhaustion_examples[..self.cycle_exhaustion_examples.len().min(3)] {
                writeln!(f, "    #{}: {} cycles", ex.iteration, ex.cycles)?;
            }
        }
        Ok(())
    }
}

fn count_opcodes() -> usize {
    // Count of valid opcodes in the policy VM
    let mut count = 0;
    for b in 0u8..=255 {
        if Op::from_byte(b).is_some() {
            count += 1;
        }
    }
    count
}

/// Fuzz test a FLUX policy by generating random inputs.
pub struct PolicyFuzzer<'a> {
    policy: &'a [u8],
    config: FuzzConfig,
    rng: StdRng,
}

impl<'a> PolicyFuzzer<'a> {
    pub fn new(policy: &'a [u8], config: FuzzConfig) -> Self {
        let rng = config.seed
            .map(StdRng::seed_from_u64)
            .unwrap_or_else(StdRng::from_entropy);
        Self { policy, config, rng }
    }

    fn generate_input_text(&mut self) -> String {
        if self.config.input_ranges.is_empty() {
            // Default: random gibberish
            let n_words = self.rng.gen_range(1..=20);
            let chars: String = (0..n_words)
                .map(|_| {
                    let c = self.rng.gen_range(b'a'..=b'z');
                    c as char
                })
                .collect();
            return chars;
        }

        let parts: Vec<String> = self.config.input_ranges.iter()
            .map(|(k, (lo, hi))| {
                let val = self.rng.gen_range(*lo..=*hi);
                format!("{}={}", k, val)
            })
            .collect();
        parts.join(" ")
    }

    fn generate_output_text(&mut self) -> String {
        let (lo, hi) = self.config.output_text_length;
        let length = self.rng.gen_range(lo..=hi);
        if length == 0 { return String::new(); }

        let n_words = std::cmp::max(1, length / 5);
        (0..n_words)
            .map(|_| {
                let idx = self.rng.gen_range(0..self.config.output_vocab.len());
                self.config.output_vocab[idx].as_str()
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn generate_budget(&mut self) -> i32 {
        let (lo, hi) = self.config.budget_range;
        self.rng.gen_range(lo..=hi)
    }

    fn trace_opcodes(policy: &[u8]) -> Vec<u8> {
        let mut seen: Vec<u8> = Vec::new();
        for &byte in policy {
            if Op::from_byte(byte).is_some() && !seen.contains(&byte) {
                seen.push(byte);
            }
        }
        seen.sort();
        seen
    }

    /// Run the fuzzer for N iterations.
    pub fn fuzz(&mut self, num_iterations: u32) -> FuzzSummary {
        let mut summary = FuzzSummary::new();
        summary.opcodes_seen = Self::trace_opcodes(self.policy);

        for i in 0..num_iterations {
            let input_text = self.generate_input_text();
            let output_text = self.generate_output_text();
            let budget = self.generate_budget();

            let mut vm = PolicyVm::new();
            vm.load_input(&input_text);
            vm.load_output(&output_text);
            vm.set_budget(budget);
            vm.set_max_cycles(self.config.max_cycles);

            let (result_code, crashed, error) = match vm.run(self.policy) {
                Ok(code) => (code, false, None),
                Err(e) => (0u32, true, Some(e.to_string())),
            };

            let fr = FuzzResult {
                iteration: i,
                input_text: truncate(&input_text, 100),
                output_text: truncate(&output_text, 100),
                budget,
                result_code,
                cycles: vm.cycle_count(),
                crashed,
                error: error.clone(),
                violation_reason: if vm.is_violated() {
                    vm.violation_reason().to_string()
                } else {
                    String::new()
                },
            };

            summary.total_runs += 1;
            summary.total_cycles += fr.cycles;
            if fr.cycles < summary.min_cycles { summary.min_cycles = fr.cycles; }
            if fr.cycles > summary.max_cycles { summary.max_cycles = fr.cycles; }

            if crashed {
                summary.crashes += 1;
                if error.as_deref().map(|e| e.contains("Cycle budget")).unwrap_or(false) {
                    summary.cycle_exhaustions += 1;
                    if summary.cycle_exhaustion_examples.len() < 5 {
                        summary.cycle_exhaustion_examples.push(fr.clone());
                    }
                }
                if summary.crash_examples.len() < 5 {
                    summary.crash_examples.push(fr);
                }
            } else {
                if result_code == 0 { summary.allows += 1; }
                else { summary.blocks += 1; }
                if vm.is_violated() {
                    summary.violations += 1;
                    if summary.violation_examples.len() < 5 {
                        summary.violation_examples.push(fr);
                    }
                }
            }
        }

        // Handle case of zero runs
        if summary.total_runs == 0 {
            summary.min_cycles = 0;
        }

        summary
    }

    /// Run until a crash is found or max_iterations reached.
    pub fn find_crash(&mut self, max_iterations: u32) -> Option<FuzzResult> {
        for i in 0..max_iterations {
            let input_text = self.generate_input_text();
            let output_text = self.generate_output_text();
            let budget = self.generate_budget();

            let mut vm = PolicyVm::new();
            vm.load_input(&input_text);
            vm.load_output(&output_text);
            vm.set_budget(budget);
            vm.set_max_cycles(self.config.max_cycles);

            match vm.run(self.policy) {
                Ok(_) => {}
                Err(e) => {
                    return Some(FuzzResult {
                        iteration: i,
                        input_text: truncate(&input_text, 100),
                        output_text: truncate(&output_text, 100),
                        budget,
                        result_code: 0,
                        cycles: vm.cycle_count(),
                        crashed: true,
                        error: Some(e.to_string()),
                        violation_reason: String::new(),
                    });
                }
            }
        }
        None
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        s[..max_len].to_string()
    }
}
