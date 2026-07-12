//! # FLUX Policy Tester
//!
//! Testing framework for FLUX bytecode agent policies — verify behavior,
//! fuzz edge cases, enforce conservation bounds.
//!
//! ## Quick Start
//!
//! ```no_run
//! use flux_policy_tester::{PolicyTester, assemble};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let policy = assemble("MOVI R0, 0\nHALT")?;
//! let mut tester = PolicyTester::new(&policy, 1000);
//! let result = tester.test_input("hello", 0, "basic test", "", "");
//! assert!(result.passed);
//! # Ok(())
//! # }
//! ```

pub mod suite;
pub mod runner;
pub mod fuzzer;

pub use suite::{SuiteConfig, TestCase, ConservationConfig, parse_suite, serialize_suite};
pub use runner::{run_suite, generate_junit_xml, generate_markdown_report, write_reports};
pub use fuzzer::{PolicyFuzzer, FuzzConfig, FuzzResult, FuzzSummary};

use std::collections::HashMap;
use std::fmt;

// ── Opcodes (mirrors fluxvm with policy-specific extensions) ───────────────

/// Policy-specific opcodes that extend the base FLUX instruction set.
/// These match the conservation-enforcer VM convention.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    NOP   = 0x00, MOV = 0x01, LOAD = 0x02, STORE = 0x03,
    JMP   = 0x04, JZ  = 0x05, JNZ  = 0x06, CALL  = 0x07,
    IADD  = 0x08, ISUB = 0x09, IMUL = 0x0A, IDIV  = 0x0B,
    IMOD  = 0x0C, INEG = 0x0D, INC  = 0x0E, DEC   = 0x0F,
    IAND  = 0x10, IOR  = 0x11, IXOR = 0x12, INOT  = 0x13,
    ISHL  = 0x14, ISHR = 0x15,
    PUSH  = 0x20, POP  = 0x21, DUP  = 0x22, RET   = 0x28,
    MOVI  = 0x2B, CMP  = 0x2D, JE   = 0x2E, JNE   = 0x2F,
    JSGE  = 0x30, JSLT = 0x31,
    HALT  = 0x80, YIELD = 0x81, SYSCALL = 0xF0,
}

impl Op {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::NOP), 0x01 => Some(Self::MOV),
            0x02 => Some(Self::LOAD), 0x03 => Some(Self::STORE),
            0x04 => Some(Self::JMP), 0x05 => Some(Self::JZ), 0x06 => Some(Self::JNZ),
            0x07 => Some(Self::CALL), 0x08 => Some(Self::IADD), 0x09 => Some(Self::ISUB),
            0x0A => Some(Self::IMUL), 0x0B => Some(Self::IDIV), 0x0C => Some(Self::IMOD),
            0x0D => Some(Self::INEG), 0x0E => Some(Self::INC), 0x0F => Some(Self::DEC),
            0x10 => Some(Self::IAND), 0x11 => Some(Self::IOR), 0x12 => Some(Self::IXOR),
            0x13 => Some(Self::INOT), 0x14 => Some(Self::ISHL), 0x15 => Some(Self::ISHR),
            0x20 => Some(Self::PUSH), 0x21 => Some(Self::POP), 0x22 => Some(Self::DUP),
            0x28 => Some(Self::RET), 0x2B => Some(Self::MOVI), 0x2D => Some(Self::CMP),
            0x2E => Some(Self::JE), 0x2F => Some(Self::JNE),
            0x30 => Some(Self::JSGE), 0x31 => Some(Self::JSLT),
            0x80 => Some(Self::HALT), 0x81 => Some(Self::YIELD),
            0xF0 => Some(Self::SYSCALL),
            _ => None,
        }
    }
}

// ── Syscall numbers ────────────────────────────────────────────────────────

/// Conservation-enforcer syscall numbers. These match the Python VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Syscall {
    GetInputLen    = 1,
    GetOutputLen   = 2,
    GetInputWords  = 3,
    GetOutputWords = 4,
    GetTokenCount  = 5,
    GetRepetition  = 6,
    GetCategory    = 7,
    SetViolation   = 8,
    GetBudget      = 10,
    GetUniqueRatio = 11,
    GetEntropy     = 12,
}

/// Violation reason codes.
pub static VIOLATION_REASONS: &[(u8, &str)] = &[
    (1, "Length budget exceeded"),
    (2, "Excessive repetition detected"),
    (3, "Category confinement violation"),
    (4, "Information entropy violation"),
    (99, "Custom conservation law violation"),
];

pub fn violation_reason_str(code: u8) -> String {
    VIOLATION_REASONS
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, s)| s.to_string())
        .unwrap_or_else(|| format!("Violation code {}", code))
}

// ── VM Error ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum VmError {
    Halt,
    DivisionByZero,
    InvalidOpcode(u8),
    CycleBudgetExceeded(u64),
    Other(String),
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Halt => write!(f, "HALT instruction"),
            Self::DivisionByZero => write!(f, "Division by zero"),
            Self::InvalidOpcode(op) => write!(f, "Invalid opcode: 0x{:02X}", op),
            Self::CycleBudgetExceeded(budget) => {
                write!(f, "Cycle budget exhausted ({})", budget)
            }
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for VmError {}

// ── Policy VM ──────────────────────────────────────────────────────────────

const NUM_REGISTERS: usize = 16;
const MEMORY_SIZE: usize = 65_536;
const DEFAULT_MAX_CYCLES: u64 = 1_000_000;

/// A FLUX VM with conservation-enforcer syscall support.
///
/// This VM implements the full instruction set including SYSCALL (0xF0)
/// for conservation policy testing. It maintains input text, output text,
/// and budget state for syscall handlers.
pub struct PolicyVm {
    regs: [u32; NUM_REGISTERS],
    flag_zero: bool,
    flag_sign: bool,
    memory: Vec<u8>,
    pc: usize,
    bytecode: Vec<u8>,
    cycle_count: u64,
    max_cycles: u64,
    stack: Vec<u32>,
    input_text: String,
    output_text: String,
    budget: i32,
    violated: bool,
    violation_reason: String,
}

impl Default for PolicyVm {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyVm {
    pub fn new() -> Self {
        Self {
            regs: [0u32; NUM_REGISTERS],
            flag_zero: false,
            flag_sign: false,
            memory: vec![0u8; MEMORY_SIZE],
            pc: 0,
            bytecode: Vec::new(),
            cycle_count: 0,
            max_cycles: DEFAULT_MAX_CYCLES,
            stack: Vec::with_capacity(1024),
            input_text: String::new(),
            output_text: String::new(),
            budget: 1000,
            violated: false,
            violation_reason: String::new(),
        }
    }

    pub fn load_input(&mut self, text: &str) {
        self.input_text = text.to_string();
    }

    pub fn load_output(&mut self, text: &str) {
        self.output_text = text.to_string();
    }

    pub fn set_budget(&mut self, budget: i32) {
        self.budget = budget;
    }

    pub fn set_max_cycles(&mut self, max: u64) {
        self.max_cycles = max;
    }

    pub fn is_violated(&self) -> bool {
        self.violated
    }

    pub fn violation_reason(&self) -> &str {
        &self.violation_reason
    }

    pub fn cycle_count(&self) -> u64 {
        self.cycle_count
    }

    fn reg_get(&self, idx: usize) -> u32 {
        self.regs.get(idx).copied().unwrap_or(0)
    }

    fn reg_set(&mut self, idx: usize, val: u32) {
        if idx < NUM_REGISTERS {
            self.regs[idx] = val & 0xFFFFFFFF;
            self.update_flags(self.regs[idx]);
        }
    }

    fn update_flags(&mut self, uval: u32) {
        self.flag_zero = uval == 0;
        let signed = uval as i32;
        self.flag_sign = signed < 0;
    }

    fn store_i32(&mut self, addr: usize, val: i32) {
        if addr + 4 <= self.memory.len() {
            self.memory[addr..addr + 4].copy_from_slice(&val.to_le_bytes());
        }
    }

    fn load_i32(&self, addr: usize) -> i32 {
        if addr + 4 <= self.memory.len() {
            i32::from_le_bytes([
                self.memory[addr],
                self.memory[addr + 1],
                self.memory[addr + 2],
                self.memory[addr + 3],
            ])
        } else {
            0
        }
    }

    fn reset(&mut self) {
        self.regs = [0u32; NUM_REGISTERS];
        self.flag_zero = false;
        self.flag_sign = false;
        self.pc = 0;
        self.cycle_count = 0;
        self.stack.clear();
        self.violated = false;
        self.violation_reason.clear();
    }

    /// Run the bytecode and return (R0 value, error if any).
    pub fn run(&mut self, bytecode: &[u8]) -> Result<u32, VmError> {
        self.bytecode = bytecode.to_vec();
        self.reset();

        loop {
            if self.cycle_count >= self.max_cycles {
                return Err(VmError::CycleBudgetExceeded(self.max_cycles));
            }
            if self.pc >= self.bytecode.len() {
                break;
            }
            match self.step() {
                Ok(()) => {}
                Err(VmError::Halt) => break,
                Err(e) => return Err(e),
            }
            self.cycle_count += 1;
        }

        Ok(self.reg_get(0))
    }

    fn step(&mut self) -> Result<(), VmError> {
        let opcode = self.bytecode[self.pc];
        let op = Op::from_byte(opcode)
            .ok_or(VmError::InvalidOpcode(opcode))?;

        match op {
            Op::NOP => { self.pc += 1; }
            Op::MOV => {
                let (rd, rs) = self.decode_c();
                let val = self.reg_get(rs);
                self.reg_set(rd, val);
            }
            Op::LOAD => {
                let (rd, rs) = self.decode_c();
                let addr = self.reg_get(rs) as usize;
                let val = self.load_i32(addr);
                self.reg_set(rd, val as u32);
            }
            Op::STORE => {
                let (rd, rs) = self.decode_c();
                let addr = self.reg_get(rs) as usize;
                let val = self.reg_get(rd) as i32;
                self.store_i32(addr, val);
            }
            Op::JMP => {
                let (_, off) = self.decode_d();
                self.pc = offset_pc(self.pc, off);
            }
            Op::JZ => {
                let (reg, off) = self.decode_d();
                if self.reg_get(reg) == 0 {
                    self.pc = offset_pc(self.pc, off);
                }
            }
            Op::JNZ => {
                let (reg, off) = self.decode_d();
                if self.reg_get(reg) != 0 {
                    self.pc = offset_pc(self.pc, off);
                }
            }
            Op::CALL => {
                let (_, off) = self.decode_d();
                self.stack.push(self.pc as u32);
                self.pc = offset_pc(self.pc, off);
            }
            Op::IADD => {
                let (rd, rs1, rs2) = self.decode_e();
                let r = self.reg_get(rs1).wrapping_add(self.reg_get(rs2));
                self.reg_set(rd, r);
            }
            Op::ISUB => {
                let (rd, rs1, rs2) = self.decode_e();
                let r = self.reg_get(rs1).wrapping_sub(self.reg_get(rs2));
                self.reg_set(rd, r);
            }
            Op::IMUL => {
                let (rd, rs1, rs2) = self.decode_e();
                let r = self.reg_get(rs1).wrapping_mul(self.reg_get(rs2));
                self.reg_set(rd, r);
            }
            Op::IDIV => {
                let (rd, rs1, rs2) = self.decode_e();
                let d = self.reg_get(rs2);
                if d == 0 { return Err(VmError::DivisionByZero); }
                let r = self.reg_get(rs1) / d;
                self.reg_set(rd, r);
            }
            Op::IMOD => {
                let (rd, rs1, rs2) = self.decode_e();
                let d = self.reg_get(rs2);
                if d == 0 { return Err(VmError::DivisionByZero); }
                let r = self.reg_get(rs1) % d;
                self.reg_set(rd, r);
            }
            Op::INEG => {
                let (rd, rs) = self.decode_c();
                let val = self.reg_get(rs);
                self.reg_set(rd, val.wrapping_neg());
            }
            Op::INC => {
                let reg = self.decode_b();
                let val = self.reg_get(reg).wrapping_add(1);
                self.reg_set(reg, val);
            }
            Op::DEC => {
                let reg = self.decode_b();
                let val = self.reg_get(reg).wrapping_sub(1);
                self.reg_set(reg, val);
            }
            Op::IAND => {
                let (rd, rs1, rs2) = self.decode_e();
                let r = self.reg_get(rs1) & self.reg_get(rs2);
                self.reg_set(rd, r);
            }
            Op::IOR => {
                let (rd, rs1, rs2) = self.decode_e();
                let r = self.reg_get(rs1) | self.reg_get(rs2);
                self.reg_set(rd, r);
            }
            Op::IXOR => {
                let (rd, rs1, rs2) = self.decode_e();
                let r = self.reg_get(rs1) ^ self.reg_get(rs2);
                self.reg_set(rd, r);
            }
            Op::INOT => {
                let (rd, rs) = self.decode_c();
                let r = !self.reg_get(rs);
                self.reg_set(rd, r);
            }
            Op::ISHL => {
                let (rd, rs1, rs2) = self.decode_e();
                let shift = self.reg_get(rs2) & 0x1F;
                let r = self.reg_get(rs1) << shift;
                self.reg_set(rd, r);
            }
            Op::ISHR => {
                let (rd, rs1, rs2) = self.decode_e();
                let shift = self.reg_get(rs2) & 0x1F;
                let r = self.reg_get(rs1) >> shift;
                self.reg_set(rd, r);
            }
            Op::PUSH => {
                let reg = self.decode_b();
                self.stack.push(self.reg_get(reg));
            }
            Op::POP => {
                let reg = self.decode_b();
                let val = self.stack.pop().unwrap_or(0);
                self.reg_set(reg, val);
            }
            Op::DUP => {
                self.pc += 1;
                if let Some(&v) = self.stack.last() {
                    self.stack.push(v);
                }
            }
            Op::RET => {
                self.pc += 1;
                if let Some(ret_pc) = self.stack.pop() {
                    self.pc = ret_pc as usize;
                }
            }
            Op::MOVI => {
                let (reg, off) = self.decode_d();
                self.reg_set(reg, (off as i16 as i32 as u32) & 0xFFFF);
            }
            Op::CMP => {
                let (rd, rs) = self.decode_c();
                let a = self.reg_get(rd);
                let b = self.reg_get(rs);
                let diff = a.wrapping_sub(b);
                self.flag_zero = diff == 0;
                let signed_diff = diff as i32;
                self.flag_sign = signed_diff < 0;
            }
            Op::JE => {
                let (_, off) = self.decode_d();
                if self.flag_zero {
                    self.pc = offset_pc(self.pc, off);
                }
            }
            Op::JNE => {
                let (_, off) = self.decode_d();
                if !self.flag_zero {
                    self.pc = offset_pc(self.pc, off);
                }
            }
            Op::JSGE => {
                let (_, off) = self.decode_d();
                if !self.flag_sign {
                    self.pc = offset_pc(self.pc, off);
                }
            }
            Op::JSLT => {
                let (_, off) = self.decode_d();
                if self.flag_sign {
                    self.pc = offset_pc(self.pc, off);
                }
            }
            Op::SYSCALL => {
                self.pc += 1;
                self.do_syscall();
            }
            Op::HALT => {
                self.pc += 1;
                return Err(VmError::Halt);
            }
            Op::YIELD => {
                self.pc += 1;
            }
        }
        Ok(())
    }

    fn do_syscall(&mut self) {
        let num = self.reg_get(0);
        match num {
            1 => { // GET_INPUT_LEN
                self.reg_set(0, self.input_text.len() as u32);
            }
            2 => { // GET_OUTPUT_LEN
                self.reg_set(0, self.output_text.len() as u32);
            }
            3 => { // GET_INPUT_WORDS
                self.reg_set(0, self.input_text.split_whitespace().count() as u32);
            }
            4 => { // GET_OUTPUT_WORDS
                self.reg_set(0, self.output_text.split_whitespace().count() as u32);
            }
            5 => { // GET_TOKEN_COUNT
                let count = std::cmp::max(1, self.output_text.len() / 4) as u32;
                self.reg_set(0, count);
            }
            6 => { // GET_REPETITION
                let lowered = self.output_text.to_lowercase();
                let words: Vec<&str> = lowered.split_whitespace().collect();
                if words.is_empty() {
                    self.reg_set(0, 0);
                } else {
                    let mut counts: HashMap<&str, u32> = HashMap::new();
                    for w in &words {
                        *counts.entry(w).or_insert(0) += 1;
                    }
                    let mx = *counts.values().max().unwrap_or(&0);
                    self.reg_set(0, (mx * 1000) / words.len() as u32);
                }
            }
            7 => { // GET_CATEGORY
                let input_lower = self.input_text.to_lowercase();
                let output_lower = self.output_text.to_lowercase();
                let iw: std::collections::HashSet<&str> =
                    input_lower.split_whitespace().collect();
                let ow: std::collections::HashSet<&str> =
                    output_lower.split_whitespace().collect();
                if ow.is_empty() {
                    self.reg_set(0, 0);
                } else {
                    let overlap = iw.intersection(&ow).count();
                    self.reg_set(0, std::cmp::min(1000, (overlap * 1000) / ow.len()) as u32);
                }
            }
            8 => { // SET_VIOLATION
                self.violated = true;
                let code = self.reg_get(1) as u8;
                self.violation_reason = violation_reason_str(code);
            }
            10 => { // GET_BUDGET
                self.reg_set(0, self.budget as u32);
            }
            11 => { // GET_UNIQUE_RATIO
                let lowered = self.output_text.to_lowercase();
                let words: Vec<&str> = lowered.split_whitespace().collect();
                if words.is_empty() {
                    self.reg_set(0, 1000);
                } else {
                    let unique: std::collections::HashSet<&str> = words.iter().copied().collect();
                    self.reg_set(0, (unique.len() * 1000 / words.len()) as u32);
                }
            }
            12 => { // GET_ENTROPY
                let lowered = self.output_text.to_lowercase();
                let words: Vec<&str> = lowered.split_whitespace().collect();
                if words.is_empty() {
                    self.reg_set(0, 0);
                } else {
                    let total = words.len();
                    let mut counts: HashMap<&str, u32> = HashMap::new();
                    for w in &words {
                        *counts.entry(w).or_insert(0) += 1;
                    }
                    let mut ent = 0.0_f64;
                    for &c in counts.values() {
                        let p = c as f64 / total as f64;
                        ent -= p * p.log2();
                    }
                    self.reg_set(0, (ent * 1000.0) as u32);
                }
            }
            _ => {}
        }
    }

    // ── Decoding helpers ──

    fn decode_b(&mut self) -> usize {
        let r = self.bytecode.get(self.pc + 1).copied().unwrap_or(0) as usize;
        self.pc += 2;
        r
    }

    fn decode_c(&mut self) -> (usize, usize) {
        let rd = self.bytecode.get(self.pc + 1).copied().unwrap_or(0) as usize;
        let rs = self.bytecode.get(self.pc + 2).copied().unwrap_or(0) as usize;
        self.pc += 3;
        (rd, rs)
    }

    fn decode_d(&mut self) -> (usize, i16) {
        let reg = self.bytecode.get(self.pc + 1).copied().unwrap_or(0) as usize;
        let lo = self.bytecode.get(self.pc + 2).copied().unwrap_or(0) as u16;
        let hi = self.bytecode.get(self.pc + 3).copied().unwrap_or(0) as u16;
        let off = (lo | (hi << 8)) as i16;
        self.pc += 4;
        (reg, off)
    }

    fn decode_e(&mut self) -> (usize, usize, usize) {
        let rd = self.bytecode.get(self.pc + 1).copied().unwrap_or(0) as usize;
        let rs1 = self.bytecode.get(self.pc + 2).copied().unwrap_or(0) as usize;
        let rs2 = self.bytecode.get(self.pc + 3).copied().unwrap_or(0) as usize;
        self.pc += 4;
        (rd, rs1, rs2)
    }
}

fn offset_pc(pc: usize, off: i16) -> usize {
    ((pc as i64) + (off as i64)) as usize
}

// ── Assembler ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AssemblerError(pub String);

impl fmt::Display for AssemblerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AssemblerError {}

/// Assemble FLUX assembly source into bytecode.
///
/// Supports the full instruction set including pseudo-instructions
/// (JGE, JGT, JLE, JLT) and SYSCALL.
pub fn assemble(source: &str) -> Result<Vec<u8>, AssemblerError> {
    let mut raw: Vec<RawInstr> = Vec::new();
    let mut labels: HashMap<String, usize> = HashMap::new();

    for (line_num, line) in source.lines().enumerate() {
        let text = strip_comment(line).trim().to_string();
        if text.is_empty() {
            continue;
        }

        // Check for label
        if let Some(colon_pos) = find_label(&text) {
            let label = text[..colon_pos].trim().to_string();
            if labels.contains_key(&label) {
                return Err(AssemblerError(format!("Duplicate label '{}'", label)));
            }
            labels.insert(label, raw.len());
            let rest = text[colon_pos + 1..].trim();
            if rest.is_empty() {
                continue;
            }
            parse_instruction(rest, &mut raw, line_num + 1)?;
        } else {
            parse_instruction(&text, &mut raw, line_num + 1)?;
        }
    }

    // Calculate offsets
    let mut offset = 0usize;
    for instr in &mut raw {
        instr.offset = offset;
        offset += instr.size;
    }

    // Resolve labels to byte offsets
    let label_bytes: HashMap<String, usize> = labels
        .iter()
        .map(|(k, &idx)| {
            let byte_off = raw.get(idx).map(|i| i.offset).unwrap_or(offset);
            (k.clone(), byte_off)
        })
        .collect();

    // Emit bytecode
    let mut out = Vec::new();
    for instr in &raw {
        instr.emit(&mut out, &label_bytes)?;
    }

    Ok(out)
}

fn strip_comment(line: &str) -> &str {
    if let Some(pos) = line.find(';') {
        &line[..pos]
    } else if let Some(pos) = line.find('#') {
        &line[..pos]
    } else {
        line
    }
}

fn find_label(text: &str) -> Option<usize> {
    // Find colon that's a label delimiter (not inside a string)
    // Label: starts at beginning, followed by identifier and colon
    let bytes = text.as_bytes();
    if bytes.is_empty() { return None; }
    if !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_') { return None; }
    for (i, &b) in bytes.iter().enumerate() {
        if b == b':' {
            return Some(i);
        }
        if !(b.is_ascii_alphanumeric() || b == b'_') {
            break;
        }
    }
    None
}

#[derive(Debug)]
struct RawInstr {
    op: Op,
    fmt: &'static str,
    rd: usize,
    rs: usize,
    rs2: usize,
    label: Option<String>,
    imm: i32,
    size: usize,
    offset: usize,
    // For pseudo-instructions that expand to two
    extra: Option<Box<RawInstr>>,
}

impl RawInstr {
    fn emit(&self, out: &mut Vec<u8>, labels: &HashMap<String, usize>) -> Result<(), AssemblerError> {
        out.push(self.op as u8);
        match self.fmt {
            "A" => {}
            "B" => { out.push(self.rd as u8); }
            "C" => { out.push(self.rd as u8); out.push(self.rs as u8); }
            "D" => {
                out.push(self.rd as u8);
                if let Some(ref lbl) = self.label {
                    let target = labels.get(lbl)
                        .ok_or_else(|| AssemblerError(format!("Undefined label: '{}'", lbl)))?;
                    let rel = (*target as i64) - ((self.offset + 4) as i64);
                    let rel_i16 = rel as i16;
                    out.push((rel_i16 & 0xFF) as u8);
                    out.push(((rel_i16 >> 8) & 0xFF) as u8);
                } else {
                    let imm = self.imm as i16;
                    out.push((imm & 0xFF) as u8);
                    out.push(((imm >> 8) & 0xFF) as u8);
                }
            }
            "E" => {
                out.push(self.rd as u8);
                out.push(self.rs as u8);
                out.push(self.rs2 as u8);
            }
            _ => {}
        }
        if let Some(ref extra) = self.extra {
            extra.emit(out, labels)?;
        }
        Ok(())
    }
}

fn parse_reg(tok: &str, line_num: usize) -> Result<usize, AssemblerError> {
    let tok = tok.trim().trim_end_matches(',').to_uppercase();
    if !tok.starts_with('R') {
        return Err(AssemblerError(format!(
            "Line {}: expected register, got '{}'",
            line_num, tok
        )));
    }
    let n: usize = tok[1..]
        .parse()
        .map_err(|_| AssemblerError(format!("Line {}: invalid register '{}'", line_num, tok)))?;
    if n >= NUM_REGISTERS {
        return Err(AssemblerError(format!("Line {}: R{} out of range", line_num, n)));
    }
    Ok(n)
}

fn parse_int_or_label(tok: &str) -> (Option<i32>, Option<String>) {
    let tok = tok.trim().trim_end_matches(',');
    if tok.is_empty() {
        return (None, None);
    }
    if tok.chars().next().map(|c| c.is_ascii_digit() || c == '-').unwrap_or(false) {
        if let Ok(v) = tok.parse::<i32>() {
            return (Some(v), None);
        }
    }
    (None, Some(tok.to_string()))
}

fn parse_instruction(text: &str, raw: &mut Vec<RawInstr>, line_num: usize) -> Result<(), AssemblerError> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }
    let mnem = parts[0].to_uppercase();
    let rest = if parts.len() > 1 { parts[1..].join(" ") } else { String::new() };
    let args: Vec<&str> = if rest.is_empty() {
        Vec::new()
    } else {
        rest.split(',').map(|s| s.trim()).collect()
    };

    match mnem.as_str() {
        "NOP" | "HALT" | "YIELD" | "DUP" | "SYSCALL" => {
            let op = match mnem.as_str() {
                "NOP" => Op::NOP, "HALT" => Op::HALT, "YIELD" => Op::YIELD,
                "DUP" => Op::DUP, "SYSCALL" => Op::SYSCALL, _ => unreachable!(),
            };
            raw.push(RawInstr { op, fmt: "A", rd: 0, rs: 0, rs2: 0, label: None, imm: 0, size: 1, offset: 0, extra: None });
        }
        "RET" => {
            raw.push(RawInstr { op: Op::RET, fmt: "A", rd: 0, rs: 0, rs2: 0, label: None, imm: 0, size: 1, offset: 0, extra: None });
        }
        "INC" | "DEC" | "PUSH" | "POP" => {
            let rd = parse_reg(args.get(0).ok_or_else(|| AssemblerError(format!("Line {}: {} needs register", line_num, mnem)))?, line_num)?;
            let op = match mnem.as_str() {
                "INC" => Op::INC, "DEC" => Op::DEC, "PUSH" => Op::PUSH, "POP" => Op::POP, _ => unreachable!(),
            };
            raw.push(RawInstr { op, fmt: "B", rd, rs: 0, rs2: 0, label: None, imm: 0, size: 2, offset: 0, extra: None });
        }
        "MOV" | "LOAD" | "STORE" | "NEG" | "INEG" | "NOT" | "INOT" | "CMP" => {
            let rd = parse_reg(args.get(0).ok_or_else(|| AssemblerError(format!("Line {}: {} needs Rd, Rs", line_num, mnem)))?, line_num)?;
            let rs = parse_reg(args.get(1).ok_or_else(|| AssemblerError(format!("Line {}: {} needs Rd, Rs", line_num, mnem)))?, line_num)?;
            let op = match mnem.as_str() {
                "MOV" => Op::MOV, "LOAD" => Op::LOAD, "STORE" => Op::STORE,
                "NEG" | "INEG" => Op::INEG, "NOT" | "INOT" => Op::INOT,
                "CMP" => Op::CMP, _ => unreachable!(),
            };
            raw.push(RawInstr { op, fmt: "C", rd, rs, rs2: 0, label: None, imm: 0, size: 3, offset: 0, extra: None });
        }
        "MOVI" => {
            let rd = parse_reg(args.get(0).ok_or_else(|| AssemblerError(format!("Line {}: MOVI needs Rd, imm", line_num)))?, line_num)?;
            let (imm, label) = parse_int_or_label(args.get(1).unwrap_or(&""));
            raw.push(RawInstr { op: Op::MOVI, fmt: "D", rd, rs: 0, rs2: 0, label, imm: imm.unwrap_or(0), size: 4, offset: 0, extra: None });
        }
        "JMP" | "JZ" | "JNZ" | "CALL" | "JE" | "JNE" | "JSGE" | "JSLT" => {
            let op = match mnem.as_str() {
                "JMP" => Op::JMP, "JZ" => Op::JZ, "JNZ" => Op::JNZ,
                "CALL" => Op::CALL, "JE" => Op::JE, "JNE" => Op::JNE,
                "JSGE" => Op::JSGE, "JSLT" => Op::JSLT, _ => unreachable!(),
            };
            if args.len() == 1 {
                // Just a label
                let label = args[0].to_string();
                raw.push(RawInstr { op, fmt: "D", rd: 0, rs: 0, rs2: 0, label: Some(label), imm: 0, size: 4, offset: 0, extra: None });
            } else if args.len() >= 2 {
                let rd = parse_reg(args[0], line_num)?;
                let (imm, label) = parse_int_or_label(args[1]);
                raw.push(RawInstr { op, fmt: "D", rd, rs: 0, rs2: 0, label, imm: imm.unwrap_or(0), size: 4, offset: 0, extra: None });
            } else {
                return Err(AssemblerError(format!("Line {}: {} needs argument", line_num, mnem)));
            }
        }
        "ADD" | "IADD" | "SUB" | "ISUB" | "MUL" | "IMUL" |
        "DIV" | "IDIV" | "MOD" | "IMOD" | "AND" | "IAND" |
        "OR" | "IOR" | "XOR" | "IXOR" | "SHL" | "ISHL" | "SHR" | "ISHR" => {
            let rd = parse_reg(args.get(0).ok_or_else(|| AssemblerError(format!("Line {}: {} needs Rd, Rs1, Rs2", line_num, mnem)))?, line_num)?;
            let rs1 = parse_reg(args.get(1).ok_or_else(|| AssemblerError(format!("Line {}: {} needs Rd, Rs1, Rs2", line_num, mnem)))?, line_num)?;
            let rs2 = parse_reg(args.get(2).ok_or_else(|| AssemblerError(format!("Line {}: {} needs Rd, Rs1, Rs2", line_num, mnem)))?, line_num)?;
            let op = match mnem.as_str() {
                "ADD" | "IADD" => Op::IADD, "SUB" | "ISUB" => Op::ISUB,
                "MUL" | "IMUL" => Op::IMUL, "DIV" | "IDIV" => Op::IDIV,
                "MOD" | "IMOD" => Op::IMOD, "AND" | "IAND" => Op::IAND,
                "OR" | "IOR" => Op::IOR, "XOR" | "IXOR" => Op::IXOR,
                "SHL" | "ISHL" => Op::ISHL, "SHR" | "ISHR" => Op::ISHR,
                _ => unreachable!(),
            };
            raw.push(RawInstr { op, fmt: "E", rd, rs: rs1, rs2, label: None, imm: 0, size: 4, offset: 0, extra: None });
        }
        // Pseudo-instructions — each expands to CMP + conditional jump(s)
        "JGE" | "JLT" => {
            let rd = parse_reg(args.get(0).ok_or_else(|| AssemblerError(format!("Line {}: {} needs Rd, Rs, label", line_num, mnem)))?, line_num)?;
            let rs = parse_reg(args.get(1).ok_or_else(|| AssemblerError(format!("Line {}: {} needs Rd, Rs, label", line_num, mnem)))?, line_num)?;
            let label = args.get(2).ok_or_else(|| AssemblerError(format!("Line {}: {} needs label", line_num, mnem)))?.to_string();

            // CMP rd, rs (3 bytes)
            raw.push(RawInstr { op: Op::CMP, fmt: "C", rd, rs, rs2: 0, label: None, imm: 0, size: 3, offset: 0, extra: None });
            // Conditional jump (4 bytes)
            let jump_op = if mnem == "JGE" { Op::JSGE } else { Op::JSLT };
            raw.push(RawInstr { op: jump_op, fmt: "D", rd: 0, rs: 0, rs2: 0, label: Some(label), imm: 0, size: 4, offset: 0, extra: None });
        }
        "JLE" | "JGT" => {
            let rd = parse_reg(args.get(0).ok_or_else(|| AssemblerError(format!("Line {}: {} needs Rd, Rs, label", line_num, mnem)))?, line_num)?;
            let rs = parse_reg(args.get(1).ok_or_else(|| AssemblerError(format!("Line {}: {} needs Rd, Rs, label", line_num, mnem)))?, line_num)?;
            let label = args.get(2).ok_or_else(|| AssemblerError(format!("Line {}: {} needs label", line_num, mnem)))?.to_string();

            // CMP rd, rs (3 bytes)
            raw.push(RawInstr { op: Op::CMP, fmt: "C", rd, rs, rs2: 0, label: None, imm: 0, size: 3, offset: 0, extra: None });
            // JLE: JE label + JSLT label
            // JGT: JE +4 (skip) + JSGE label
            if mnem == "JLE" {
                raw.push(RawInstr { op: Op::JE, fmt: "D", rd: 0, rs: 0, rs2: 0, label: Some(label.clone()), imm: 0, size: 4, offset: 0, extra: None });
                raw.push(RawInstr { op: Op::JSLT, fmt: "D", rd: 0, rs: 0, rs2: 0, label: Some(label), imm: 0, size: 4, offset: 0, extra: None });
            } else {
                // JGT: if equal, skip past JSGE (JE +4), then JSGE label
                raw.push(RawInstr { op: Op::JE, fmt: "D", rd: 0, rs: 0, rs2: 0, label: None, imm: 4, size: 4, offset: 0, extra: None });
                raw.push(RawInstr { op: Op::JSGE, fmt: "D", rd: 0, rs: 0, rs2: 0, label: Some(label), imm: 0, size: 4, offset: 0, extra: None });
            }
        }
        _ => {
            return Err(AssemblerError(format!(
                "Line {}: unknown instruction '{}'",
                line_num, mnem
            )));
        }
    }

    Ok(())
}

// ── Test Result ────────────────────────────────────────────────────────────

/// Result of a single policy test.
#[derive(Debug, Clone)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub description: String,
    pub expected: String,
    pub actual: String,
    pub error: Option<String>,
    pub cycles: u64,
    pub violation_reason: String,
}

impl fmt::Display for TestResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.passed { "✅ PASS" } else { "❌ FAIL" };
        write!(f, "{} {}", status, self.name)?;
        if !self.description.is_empty() {
            write!(f, " — {}", self.description)?;
        }
        if !self.passed {
            write!(f, "\n   expected={} actual={}", self.expected, self.actual)?;
            if let Some(ref err) = self.error {
                write!(f, "\n   error: {}", err)?;
            }
            if !self.violation_reason.is_empty() {
                write!(f, "\n   violation: {}", self.violation_reason)?;
            }
        }
        Ok(())
    }
}

/// Aggregate result of a full test suite.
#[derive(Debug, Clone)]
pub struct SuiteResult {
    pub suite_name: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub errored: usize,
    pub results: Vec<TestResult>,
    pub conservation_passed: bool,
}

impl SuiteResult {
    pub fn new(suite_name: &str) -> Self {
        Self {
            suite_name: suite_name.to_string(),
            total: 0,
            passed: 0,
            failed: 0,
            errored: 0,
            results: Vec::new(),
            conservation_passed: true,
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.total == 0 { 0.0 } else { (self.passed as f64 / self.total as f64) * 100.0 }
    }
}

impl fmt::Display for SuiteResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Suite: {}", self.suite_name)?;
        write!(f, "  {}/{} passed ({:.1}%)", self.passed, self.total, self.success_rate())?;
        if self.failed > 0 { write!(f, " — {} failed", self.failed)?; }
        if self.errored > 0 { write!(f, " — {} errored", self.errored)?; }
        if !self.conservation_passed { write!(f, " — ⚠️ CONSERVATION BOUNDS VIOLATED")?; }
        writeln!(f)?;
        for r in &self.results {
            writeln!(f, "  {}", r)?;
        }
        Ok(())
    }
}

// ── Policy Tester ──────────────────────────────────────────────────────────

/// Test FLUX bytecode policies for correctness, robustness, and conservation.
///
/// Convention: R0=0 means ALLOW, R0≠0 means BLOCK.
pub struct PolicyTester<'a> {
    pub policy: &'a [u8],
    pub budget: i32,
    results: Vec<TestResult>,
}

impl<'a> PolicyTester<'a> {
    pub fn new(policy: &'a [u8], budget: i32) -> Self {
        Self { policy, budget, results: Vec::new() }
    }

    /// Run policy against input and assert expected action.
    pub fn test_input(
        &mut self,
        input: &str,
        expected_action: i32,
        description: &str,
        name: &str,
        output_text: &str,
    ) -> TestResult {
        let (result_code, cycles, violation, error) =
            self.run_policy(input, output_text, None, None);

        let passed = error.is_none() && result_code as i32 == expected_action;
        let test_name = if name.is_empty() {
            if description.is_empty() {
                format!("test_input({})", input)
            } else {
                description.to_string()
            }
        } else {
            name.to_string()
        };

        let tr = TestResult {
            name: test_name,
            passed,
            description: description.to_string(),
            expected: expected_action.to_string(),
            actual: if error.is_some() {
                "error".to_string()
            } else {
                result_code.to_string()
            },
            error: error.clone(),
            cycles,
            violation_reason: violation,
        };
        self.results.push(tr.clone());
        tr
    }

    /// Test that policy handles edge cases gracefully.
    pub fn test_adversarial(
        &mut self,
        input: &str,
        description: &str,
        output_text: &str,
    ) -> TestResult {
        let (result_code, cycles, violation, error) =
            self.run_policy(input, output_text, None, Some(100_000));

        let passed = error.is_none();
        let test_name = if description.is_empty() {
            format!("adversarial({})", input)
        } else {
            description.to_string()
        };

        let tr = TestResult {
            name: test_name,
            passed,
            description: description.to_string(),
            expected: "no crash".to_string(),
            actual: if error.is_some() {
                format!("error: {}", error.as_ref().unwrap())
            } else {
                format!("R0={}", result_code)
            },
            error,
            cycles,
            violation_reason: violation,
        };
        self.results.push(tr.clone());
        tr
    }

    /// Verify policy stays within conservation budget across all inputs.
    pub fn test_conservation_bounds(
        &mut self,
        inputs: &[&str],
        max_budget: i32,
        max_steps: u64,
    ) -> TestResult {
        let mut violations: Vec<String> = Vec::new();
        let mut max_cycles_observed: u64 = 0;

        for (i, inp) in inputs.iter().enumerate() {
            let (result_code, cycles, _violation, error) =
                self.run_policy(inp, "", Some(max_budget), Some(max_steps));

            if cycles > max_cycles_observed {
                max_cycles_observed = cycles;
            }

            if let Some(ref err) = error {
                if err.contains("Cycle budget") {
                    violations.push(format!(
                        "Input {}: Infinite loop / cycle exhaustion ({} cycles)",
                        i, cycles
                    ));
                } else {
                    violations.push(format!("Input {}: Error: {}", i, err));
                }
            } else if cycles > (max_steps as f64 * 0.9) as u64 {
                violations.push(format!(
                    "Input {}: Near-limit cycles ({}/{})",
                    i, cycles, max_steps
                ));
            }

            let _ = result_code;
        }

        let passed = violations.is_empty();
        let tr = TestResult {
            name: format!("conservation_bounds({} inputs, budget={})", inputs.len(), max_budget),
            passed,
            description: format!("Max cycles observed: {}", max_cycles_observed),
            expected: format!("All within {} cycles, budget={}", max_steps, max_budget),
            actual: if violations.is_empty() {
                "All within bounds".to_string()
            } else {
                format!("{} violations", violations.len())
            },
            error: if violations.is_empty() { None } else { Some(violations.join("; ")) },
            cycles: max_cycles_observed,
            violation_reason: String::new(),
        };
        self.results.push(tr.clone());
        tr
    }

    /// Low-level policy execution.
    fn run_policy(
        &self,
        input_text: &str,
        output_text: &str,
        budget: Option<i32>,
        max_cycles: Option<u64>,
    ) -> (u32, u64, String, Option<String>) {
        let mut vm = PolicyVm::new();
        vm.load_input(input_text);
        vm.load_output(output_text);
        vm.set_budget(budget.unwrap_or(self.budget));
        if let Some(mc) = max_cycles {
            vm.set_max_cycles(mc);
        }

        match vm.run(self.policy) {
            Ok(result) => (result, vm.cycle_count(), vm.violation_reason().to_string(), None),
            Err(e) => (0, vm.cycle_count(), vm.violation_reason().to_string(), Some(e.to_string())),
        }
    }

    pub fn results(&self) -> &[TestResult] {
        &self.results
    }

    pub fn clear_results(&mut self) {
        self.results.clear();
    }

    pub fn summary(&self) -> String {
        let total = self.results.len();
        let passed = self.results.iter().filter(|r| r.passed).count();
        let mut lines = vec![format!("Policy Test Summary: {}/{} passed\n", passed, total)];
        for r in &self.results {
            lines.push(r.to_string());
        }
        lines.join("\n")
    }
}

pub fn input_to_string(input: &serde_yaml::Value) -> String {
    match input {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Mapping(m) => {
            let pairs: Vec<String> = m.iter()
                .map(|(k, v)| {
                    let key = k.as_str().unwrap_or("?");
                    let val = match v {
                        serde_yaml::Value::String(s) => s.clone(),
                        serde_yaml::Value::Number(n) => n.to_string(),
                        serde_yaml::Value::Bool(b) => b.to_string(),
                        other => format!("{:?}", other),
                    };
                    format!("{}={}", key, val)
                })
                .collect();
            pairs.join(" ")
        }
        serde_yaml::Value::Null => String::new(),
        other => format!("{:?}", other),
    }
}
