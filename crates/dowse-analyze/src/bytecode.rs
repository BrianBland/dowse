use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use alloy_primitives::{Address, FixedBytes, B256, U256};
use dowse_types::{PrefetchItem, SlotExpression};
use revm::bytecode::opcode::*;

// ─── SymVal: internal symbolic value representation ──────────────────────────

/// A symbolic value tracked during abstract interpretation.
///
/// Richer than `SlotExpression` because it must track operations irrelevant to
/// storage access (e.g., boolean ops, comparisons) while maintaining correct
/// stack balance.
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum SymVal {
    Concrete(U256),
    CalldataWord {
        offset: usize,
    },
    Caller,
    CallValue,
    CalldataSize,
    Keccak256 {
        inputs: Vec<SymVal>,
    },
    SLoad {
        key: Box<SymVal>,
    },
    Add(Box<SymVal>, Box<SymVal>),
    Sub(Box<SymVal>, Box<SymVal>),
    Mul(Box<SymVal>, Box<SymVal>),
    Div(Box<SymVal>, Box<SymVal>),
    Mod(Box<SymVal>, Box<SymVal>),
    And(Box<SymVal>, Box<SymVal>),
    Or(Box<SymVal>, Box<SymVal>),
    Xor(Box<SymVal>, Box<SymVal>),
    Not(Box<SymVal>),
    Shl(Box<SymVal>, Box<SymVal>),
    Shr(Box<SymVal>, Box<SymVal>),
    Eq(Box<SymVal>, Box<SymVal>),
    Lt(Box<SymVal>, Box<SymVal>),
    Gt(Box<SymVal>, Box<SymVal>),
    IsZero(Box<SymVal>),
    SignExtend(Box<SymVal>, Box<SymVal>),
    Byte(Box<SymVal>, Box<SymVal>),
    /// Untrackable value (result of external calls, etc.)
    Unknown,
}

/// Address mask: 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
const ADDRESS_MASK: U256 = {
    let mut bytes = [0u8; 32];
    bytes[12] = 0xff;
    bytes[13] = 0xff;
    bytes[14] = 0xff;
    bytes[15] = 0xff;
    bytes[16] = 0xff;
    bytes[17] = 0xff;
    bytes[18] = 0xff;
    bytes[19] = 0xff;
    bytes[20] = 0xff;
    bytes[21] = 0xff;
    bytes[22] = 0xff;
    bytes[23] = 0xff;
    bytes[24] = 0xff;
    bytes[25] = 0xff;
    bytes[26] = 0xff;
    bytes[27] = 0xff;
    bytes[28] = 0xff;
    bytes[29] = 0xff;
    bytes[30] = 0xff;
    bytes[31] = 0xff;
    U256::from_be_bytes(bytes)
};

impl SymVal {
    /// Try constant folding for binary operations.
    fn try_concrete_binary(a: &SymVal, b: &SymVal, op: fn(U256, U256) -> U256) -> Option<U256> {
        match (a, b) {
            (SymVal::Concrete(a), SymVal::Concrete(b)) => Some(op(*a, *b)),
            _ => None,
        }
    }

    fn add(a: SymVal, b: SymVal) -> SymVal {
        if let Some(v) = Self::try_concrete_binary(&a, &b, |a, b| a.wrapping_add(b)) {
            return SymVal::Concrete(v);
        }
        SymVal::Add(Box::new(a), Box::new(b))
    }

    fn sub(a: SymVal, b: SymVal) -> SymVal {
        if let Some(v) = Self::try_concrete_binary(&a, &b, |a, b| a.wrapping_sub(b)) {
            return SymVal::Concrete(v);
        }
        SymVal::Sub(Box::new(a), Box::new(b))
    }

    fn mul(a: SymVal, b: SymVal) -> SymVal {
        if let Some(v) = Self::try_concrete_binary(&a, &b, |a, b| a.wrapping_mul(b)) {
            return SymVal::Concrete(v);
        }
        SymVal::Mul(Box::new(a), Box::new(b))
    }

    fn div(a: SymVal, b: SymVal) -> SymVal {
        if let Some(v) =
            Self::try_concrete_binary(&a, &b, |a, b| if b.is_zero() { U256::ZERO } else { a / b })
        {
            return SymVal::Concrete(v);
        }
        SymVal::Div(Box::new(a), Box::new(b))
    }

    fn modulo(a: SymVal, b: SymVal) -> SymVal {
        if let Some(v) =
            Self::try_concrete_binary(&a, &b, |a, b| if b.is_zero() { U256::ZERO } else { a % b })
        {
            return SymVal::Concrete(v);
        }
        SymVal::Mod(Box::new(a), Box::new(b))
    }

    fn and(a: SymVal, b: SymVal) -> SymVal {
        // Simplification: AND(x, address_mask) → x when x is CalldataWord or Caller
        // (Solidity's address cleaning pattern)
        if let SymVal::Concrete(mask) = &b {
            if *mask == ADDRESS_MASK {
                match &a {
                    SymVal::CalldataWord { .. } | SymVal::Caller => return a,
                    _ => {}
                }
            }
        }
        if let SymVal::Concrete(mask) = &a {
            if *mask == ADDRESS_MASK {
                match &b {
                    SymVal::CalldataWord { .. } | SymVal::Caller => return b,
                    _ => {}
                }
            }
        }
        if let Some(v) = Self::try_concrete_binary(&a, &b, |a, b| a & b) {
            return SymVal::Concrete(v);
        }
        SymVal::And(Box::new(a), Box::new(b))
    }

    fn or(a: SymVal, b: SymVal) -> SymVal {
        if let Some(v) = Self::try_concrete_binary(&a, &b, |a, b| a | b) {
            return SymVal::Concrete(v);
        }
        SymVal::Or(Box::new(a), Box::new(b))
    }

    fn xor(a: SymVal, b: SymVal) -> SymVal {
        if let Some(v) = Self::try_concrete_binary(&a, &b, |a, b| a ^ b) {
            return SymVal::Concrete(v);
        }
        SymVal::Xor(Box::new(a), Box::new(b))
    }

    fn not(a: SymVal) -> SymVal {
        if let SymVal::Concrete(v) = &a {
            return SymVal::Concrete(!v);
        }
        SymVal::Not(Box::new(a))
    }

    fn shl(shift: SymVal, value: SymVal) -> SymVal {
        if let Some(v) = Self::try_concrete_binary(&shift, &value, |shift, value| {
            if shift >= U256::from(256) {
                U256::ZERO
            } else {
                value << shift
            }
        }) {
            return SymVal::Concrete(v);
        }
        SymVal::Shl(Box::new(shift), Box::new(value))
    }

    fn shr(shift: SymVal, value: SymVal) -> SymVal {
        if let Some(v) = Self::try_concrete_binary(&shift, &value, |shift, value| {
            if shift >= U256::from(256) {
                U256::ZERO
            } else {
                value >> shift
            }
        }) {
            return SymVal::Concrete(v);
        }
        SymVal::Shr(Box::new(shift), Box::new(value))
    }

    fn eq(a: SymVal, b: SymVal) -> SymVal {
        if let Some(v) =
            Self::try_concrete_binary(
                &a,
                &b,
                |a, b| {
                    if a == b {
                        U256::from(1)
                    } else {
                        U256::ZERO
                    }
                },
            )
        {
            return SymVal::Concrete(v);
        }
        SymVal::Eq(Box::new(a), Box::new(b))
    }

    fn lt(a: SymVal, b: SymVal) -> SymVal {
        if let Some(v) =
            Self::try_concrete_binary(
                &a,
                &b,
                |a, b| {
                    if a < b {
                        U256::from(1)
                    } else {
                        U256::ZERO
                    }
                },
            )
        {
            return SymVal::Concrete(v);
        }
        SymVal::Lt(Box::new(a), Box::new(b))
    }

    fn gt(a: SymVal, b: SymVal) -> SymVal {
        if let Some(v) =
            Self::try_concrete_binary(
                &a,
                &b,
                |a, b| {
                    if a > b {
                        U256::from(1)
                    } else {
                        U256::ZERO
                    }
                },
            )
        {
            return SymVal::Concrete(v);
        }
        SymVal::Gt(Box::new(a), Box::new(b))
    }

    fn iszero(a: SymVal) -> SymVal {
        if let SymVal::Concrete(v) = &a {
            return SymVal::Concrete(if v.is_zero() {
                U256::from(1)
            } else {
                U256::ZERO
            });
        }
        SymVal::IsZero(Box::new(a))
    }

    /// Compute a fingerprint for visited-state deduplication.
    fn fingerprint(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::mem::discriminant(self).hash(&mut hasher);
        if let SymVal::Concrete(v) = self {
            v.as_limbs().hash(&mut hasher);
        }
        hasher.finish()
    }
}

// ─── Symbolic Memory ─────────────────────────────────────────────────────────

/// Sparse symbolic memory tracking 32-byte-aligned MSTORE writes.
#[derive(Debug, Clone)]
struct SymbolicMemory {
    /// Maps byte offset → symbolic value stored there (32-byte word).
    words: HashMap<usize, SymVal>,
}

impl SymbolicMemory {
    fn new() -> Self {
        Self {
            words: HashMap::new(),
        }
    }

    fn store(&mut self, offset: usize, value: SymVal) {
        self.words.insert(offset, value);
    }

    fn load(&self, offset: usize) -> SymVal {
        self.words
            .get(&offset)
            .cloned()
            .unwrap_or(SymVal::Concrete(U256::ZERO))
    }

    /// Read `size` bytes from memory starting at `offset`, returning a list of
    /// 32-byte symbolic words that cover the range.
    fn read_range(&self, offset: usize, size: usize) -> Vec<SymVal> {
        let num_words = (size + 31) / 32;
        (0..num_words).map(|i| self.load(offset + i * 32)).collect()
    }
}

// ─── Symbolic EVM ────────────────────────────────────────────────────────────

const MAX_BRANCH_DEPTH: usize = 32;
const MAX_STEPS_PER_SELECTOR: usize = 50_000;

/// The symbolic executor: interprets EVM bytecode abstractly, tracking the
/// provenance of every value through stack and memory operations.
struct SymbolicEvm<'a> {
    bytecode: &'a [u8],
    stack: Vec<SymVal>,
    memory: SymbolicMemory,
    /// Collected SLOAD slot expressions.
    sload_keys: Vec<SymVal>,
    /// Collected concrete CALL/STATICCALL/DELEGATECALL target addresses with optional selectors.
    call_targets: Vec<(Address, Option<FixedBytes<4>>)>,
    /// Collected non-concrete (symbolic) CALL/STATICCALL/DELEGATECALL targets with optional selectors.
    symbolic_call_targets: Vec<(SymVal, Option<FixedBytes<4>>)>,
    /// Valid jump targets (JUMPDEST positions).
    jumpdests: HashSet<usize>,
    /// Visited states: (pc, stack_fingerprint) for loop prevention.
    visited: HashSet<(usize, u64)>,
    /// Current branch depth.
    depth: usize,
    /// Step budget remaining.
    steps_remaining: usize,
}

impl<'a> SymbolicEvm<'a> {
    fn new(bytecode: &'a [u8], jumpdests: HashSet<usize>) -> Self {
        Self {
            bytecode,
            stack: Vec::new(),
            memory: SymbolicMemory::new(),
            sload_keys: Vec::new(),
            call_targets: Vec::new(),
            symbolic_call_targets: Vec::new(),
            jumpdests,
            visited: HashSet::new(),
            depth: 0,
            steps_remaining: MAX_STEPS_PER_SELECTOR,
        }
    }

    fn push(&mut self, val: SymVal) {
        self.stack.push(val);
    }

    fn pop(&mut self) -> SymVal {
        self.stack.pop().unwrap_or(SymVal::Unknown)
    }

    fn stack_fingerprint(&self) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.stack.len().hash(&mut hasher);
        // Hash top 3 elements for dedup
        for val in self.stack.iter().rev().take(3) {
            val.fingerprint().hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Execute from the given PC, collecting SLOAD keys.
    fn execute(&mut self, start_pc: usize) {
        let len = self.bytecode.len();
        let mut pc = start_pc;

        while pc < len && self.steps_remaining > 0 {
            self.steps_remaining -= 1;

            // Loop detection
            let fp = self.stack_fingerprint();
            if !self.visited.insert((pc, fp)) {
                return;
            }

            let op = self.bytecode[pc];

            match op {
                // ── Terminators ──
                STOP | RETURN | REVERT | INVALID | SELFDESTRUCT => return,

                // ── Push ──
                PUSH0 => {
                    self.push(SymVal::Concrete(U256::ZERO));
                    pc += 1;
                }
                op if op >= PUSH1 && op <= PUSH32 => {
                    let n = (op - PUSH1 + 1) as usize;
                    if pc + 1 + n > len {
                        return;
                    }
                    let bytes = &self.bytecode[pc + 1..pc + 1 + n];
                    let val = U256::from_be_slice(bytes);
                    self.push(SymVal::Concrete(val));
                    pc += 1 + n;
                }

                // ── Dup ──
                op if op >= DUP1 && op <= DUP16 => {
                    let n = (op - DUP1 + 1) as usize;
                    let val = if self.stack.len() >= n {
                        self.stack[self.stack.len() - n].clone()
                    } else {
                        SymVal::Unknown
                    };
                    self.push(val);
                    pc += 1;
                }

                // ── Swap ──
                op if op >= SWAP1 && op <= SWAP16 => {
                    let n = (op - SWAP1 + 1) as usize;
                    let slen = self.stack.len();
                    if slen > n {
                        let top = slen - 1;
                        let other = slen - 1 - n;
                        self.stack.swap(top, other);
                    }
                    pc += 1;
                }

                POP => {
                    self.pop();
                    pc += 1;
                }

                // ── Arithmetic ──
                ADD => {
                    let a = self.pop();
                    let b = self.pop();
                    self.push(SymVal::add(a, b));
                    pc += 1;
                }
                SUB => {
                    let a = self.pop();
                    let b = self.pop();
                    self.push(SymVal::sub(a, b));
                    pc += 1;
                }
                MUL => {
                    let a = self.pop();
                    let b = self.pop();
                    self.push(SymVal::mul(a, b));
                    pc += 1;
                }
                DIV | SDIV => {
                    let a = self.pop();
                    let b = self.pop();
                    self.push(SymVal::div(a, b));
                    pc += 1;
                }
                MOD | SMOD => {
                    let a = self.pop();
                    let b = self.pop();
                    self.push(SymVal::modulo(a, b));
                    pc += 1;
                }
                ADDMOD => {
                    let a = self.pop();
                    let b = self.pop();
                    let n = self.pop();
                    if let (SymVal::Concrete(a), SymVal::Concrete(b), SymVal::Concrete(n)) =
                        (&a, &b, &n)
                    {
                        if n.is_zero() {
                            self.push(SymVal::Concrete(U256::ZERO));
                        } else {
                            self.push(SymVal::Concrete(a.add_mod(*b, *n)));
                        }
                    } else {
                        self.push(SymVal::Unknown);
                    }
                    pc += 1;
                }
                MULMOD => {
                    let a = self.pop();
                    let b = self.pop();
                    let n = self.pop();
                    if let (SymVal::Concrete(a), SymVal::Concrete(b), SymVal::Concrete(n)) =
                        (&a, &b, &n)
                    {
                        if n.is_zero() {
                            self.push(SymVal::Concrete(U256::ZERO));
                        } else {
                            self.push(SymVal::Concrete(a.mul_mod(*b, *n)));
                        }
                    } else {
                        self.push(SymVal::Unknown);
                    }
                    pc += 1;
                }
                EXP => {
                    let base = self.pop();
                    let exp = self.pop();
                    if let (SymVal::Concrete(b), SymVal::Concrete(e)) = (&base, &exp) {
                        self.push(SymVal::Concrete(b.pow(*e)));
                    } else {
                        self.push(SymVal::Unknown);
                    }
                    pc += 1;
                }
                SIGNEXTEND => {
                    let b = self.pop();
                    let x = self.pop();
                    if let (SymVal::Concrete(b), SymVal::Concrete(x)) = (&b, &x) {
                        if *b < U256::from(31) {
                            let bit = b.as_limbs()[0] as usize;
                            let sign_bit = U256::from(1) << (bit * 8 + 7);
                            let mask = sign_bit - U256::from(1);
                            if (*x & sign_bit) != U256::ZERO {
                                self.push(SymVal::Concrete(*x | !mask));
                            } else {
                                self.push(SymVal::Concrete(*x & mask));
                            }
                        } else {
                            self.push(SymVal::Concrete(*x));
                        }
                    } else {
                        self.push(SymVal::SignExtend(Box::new(b), Box::new(x)));
                    }
                    pc += 1;
                }

                // ── Comparison / Bitwise ──
                LT | SLT => {
                    let a = self.pop();
                    let b = self.pop();
                    self.push(SymVal::lt(a, b));
                    pc += 1;
                }
                GT | SGT => {
                    let a = self.pop();
                    let b = self.pop();
                    self.push(SymVal::gt(a, b));
                    pc += 1;
                }
                EQ => {
                    let a = self.pop();
                    let b = self.pop();
                    self.push(SymVal::eq(a, b));
                    pc += 1;
                }
                ISZERO => {
                    let a = self.pop();
                    self.push(SymVal::iszero(a));
                    pc += 1;
                }
                AND => {
                    let a = self.pop();
                    let b = self.pop();
                    self.push(SymVal::and(a, b));
                    pc += 1;
                }
                OR => {
                    let a = self.pop();
                    let b = self.pop();
                    self.push(SymVal::or(a, b));
                    pc += 1;
                }
                XOR => {
                    let a = self.pop();
                    let b = self.pop();
                    self.push(SymVal::xor(a, b));
                    pc += 1;
                }
                NOT => {
                    let a = self.pop();
                    self.push(SymVal::not(a));
                    pc += 1;
                }
                BYTE => {
                    let i = self.pop();
                    let x = self.pop();
                    if let (SymVal::Concrete(i), SymVal::Concrete(x)) = (&i, &x) {
                        if *i < U256::from(32) {
                            let byte_idx = i.as_limbs()[0] as usize;
                            let result = (*x >> ((31 - byte_idx) * 8)) & U256::from(0xFF);
                            self.push(SymVal::Concrete(result));
                        } else {
                            self.push(SymVal::Concrete(U256::ZERO));
                        }
                    } else {
                        self.push(SymVal::Byte(Box::new(i), Box::new(x)));
                    }
                    pc += 1;
                }
                SHL => {
                    let shift = self.pop();
                    let value = self.pop();
                    self.push(SymVal::shl(shift, value));
                    pc += 1;
                }
                SHR => {
                    let shift = self.pop();
                    let value = self.pop();
                    self.push(SymVal::shr(shift, value));
                    pc += 1;
                }
                SAR => {
                    let shift = self.pop();
                    let value = self.pop();
                    if let (SymVal::Concrete(s), SymVal::Concrete(v)) = (&shift, &value) {
                        if *s >= U256::from(256) {
                            // Sign-extend: if top bit set, result is all 1s; else all 0s
                            if v.bit(255) {
                                self.push(SymVal::Concrete(U256::MAX));
                            } else {
                                self.push(SymVal::Concrete(U256::ZERO));
                            }
                        } else {
                            let shift_amt = s.as_limbs()[0] as usize;
                            if v.bit(255) {
                                // Arithmetic shift: fill with 1s
                                let shifted = *v >> shift_amt;
                                let mask = U256::MAX << (256 - shift_amt);
                                self.push(SymVal::Concrete(shifted | mask));
                            } else {
                                self.push(SymVal::Concrete(*v >> shift_amt));
                            }
                        }
                    } else {
                        self.push(SymVal::Unknown);
                    }
                    pc += 1;
                }

                // ── Environment ──
                CALLER => {
                    self.push(SymVal::Caller);
                    pc += 1;
                }
                CALLVALUE => {
                    self.push(SymVal::CallValue);
                    pc += 1;
                }
                CALLDATASIZE => {
                    self.push(SymVal::CalldataSize);
                    pc += 1;
                }
                CALLDATALOAD => {
                    let offset = self.pop();
                    if let SymVal::Concrete(off) = &offset {
                        let off = off.as_limbs()[0] as usize;
                        self.push(SymVal::CalldataWord { offset: off });
                    } else {
                        self.push(SymVal::Unknown);
                    }
                    pc += 1;
                }
                CALLDATACOPY => {
                    let dest_offset = self.pop();
                    let data_offset = self.pop();
                    let size = self.pop();
                    // If all concrete and size == 32, write a CalldataWord
                    if let (SymVal::Concrete(dest), SymVal::Concrete(src), SymVal::Concrete(sz)) =
                        (&dest_offset, &data_offset, &size)
                    {
                        let dest = dest.as_limbs()[0] as usize;
                        let src = src.as_limbs()[0] as usize;
                        let sz = sz.as_limbs()[0] as usize;
                        if sz == 32 {
                            self.memory
                                .store(dest, SymVal::CalldataWord { offset: src });
                        }
                    }
                    pc += 1;
                }

                // Environment ops that push Unknown
                ADDRESS | ORIGIN | GASPRICE | EXTCODESIZE | BLOCKHASH | COINBASE | TIMESTAMP
                | NUMBER | DIFFICULTY | GASLIMIT | CHAINID | SELFBALANCE | BASEFEE
                | RETURNDATASIZE | CODESIZE | MSIZE | GAS | EXTCODEHASH => {
                    // Some of these pop args first
                    match op {
                        BALANCE | EXTCODESIZE | EXTCODEHASH => {
                            self.pop();
                        }
                        BLOCKHASH => {
                            self.pop();
                        }
                        _ => {}
                    }
                    self.push(SymVal::Unknown);
                    pc += 1;
                }

                // ── Memory ──
                MSTORE => {
                    let offset = self.pop();
                    let value = self.pop();
                    if let SymVal::Concrete(off) = &offset {
                        let off = off.as_limbs()[0] as usize;
                        self.memory.store(off, value);
                    }
                    // Non-concrete offset: we lose track of where this went
                    pc += 1;
                }
                MSTORE8 => {
                    self.pop(); // offset
                    self.pop(); // value
                                // We don't track byte-level memory writes
                    pc += 1;
                }
                MLOAD => {
                    let offset = self.pop();
                    if let SymVal::Concrete(off) = &offset {
                        let off = off.as_limbs()[0] as usize;
                        self.push(self.memory.load(off));
                    } else {
                        self.push(SymVal::Unknown);
                    }
                    pc += 1;
                }

                // ── KECCAK256 ──
                KECCAK256 => {
                    let offset = self.pop();
                    let size = self.pop();
                    if let (SymVal::Concrete(off), SymVal::Concrete(sz)) = (&offset, &size) {
                        let off = off.as_limbs()[0] as usize;
                        let sz = sz.as_limbs()[0] as usize;
                        if sz > 0 && sz <= 256 {
                            let inputs = self.memory.read_range(off, sz);
                            // Try to compute concrete hash if all inputs are concrete
                            if inputs.iter().all(|v| matches!(v, SymVal::Concrete(_))) {
                                let mut preimage = Vec::with_capacity(sz);
                                for input in &inputs {
                                    if let SymVal::Concrete(v) = input {
                                        let bytes: B256 = (*v).into();
                                        preimage.extend_from_slice(&bytes.0);
                                    }
                                }
                                preimage.truncate(sz);
                                let hash = alloy_primitives::keccak256(&preimage);
                                self.push(SymVal::Concrete(hash.into()));
                            } else {
                                self.push(SymVal::Keccak256 { inputs });
                            }
                        } else {
                            self.push(SymVal::Unknown);
                        }
                    } else {
                        self.push(SymVal::Unknown);
                    }
                    pc += 1;
                }

                // ── Storage ──
                SLOAD => {
                    let key = self.pop();
                    self.sload_keys.push(key.clone());
                    self.push(SymVal::SLoad { key: Box::new(key) });
                    pc += 1;
                }
                SSTORE => {
                    self.pop(); // key
                    self.pop(); // value
                                // Don't record writes — we only need reads for prefetching
                    pc += 1;
                }

                // ── Control flow ──
                JUMP => {
                    let target = self.pop();
                    if let SymVal::Concrete(t) = &target {
                        let dest = t.as_limbs()[0] as usize;
                        if self.jumpdests.contains(&dest) {
                            // Iterative: just redirect PC — no recursion needed
                            pc = dest;
                            continue;
                        }
                    }
                    return;
                }
                JUMPI => {
                    let target = self.pop();
                    let _condition = self.pop();

                    // Save state for branch exploration BEFORE fall-through
                    let branch_target = if self.depth < MAX_BRANCH_DEPTH {
                        if let SymVal::Concrete(t) = &target {
                            let dest = t.as_limbs()[0] as usize;
                            if self.jumpdests.contains(&dest) {
                                Some((
                                    dest,
                                    self.stack.clone(),
                                    self.memory.clone(),
                                    self.steps_remaining,
                                ))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    // Fall-through first: continue at pc+1 with full budget.
                    // This ensures the main execution path always gets priority.
                    pc += 1;

                    // After fall-through completes (or this loop iteration),
                    // explore the taken branch with a discounted budget.
                    // Forward branches (guards, if-else) get gentler decay (/2).
                    // Backward branches (loops) keep aggressive decay (/4).
                    if let Some((dest, saved_stack, saved_memory, saved_remaining)) = branch_target
                    {
                        let after_fallthrough_stack = self.stack.clone();
                        let after_fallthrough_memory = self.memory.clone();
                        let after_fallthrough_remaining = self.steps_remaining;

                        // Restore pre-branch state for the taken branch
                        self.stack = saved_stack;
                        self.memory = saved_memory;
                        self.steps_remaining = if dest > pc {
                            saved_remaining // forward branch: full budget
                        } else {
                            saved_remaining / 4 // backward branch: likely loop
                        };
                        self.depth += 1;
                        self.execute(dest);
                        self.depth -= 1;

                        // Restore fall-through state to continue
                        self.stack = after_fallthrough_stack;
                        self.memory = after_fallthrough_memory;
                        self.steps_remaining = after_fallthrough_remaining;
                    }
                }
                JUMPDEST => {
                    pc += 1;
                }
                PC => {
                    self.push(SymVal::Concrete(U256::from(pc)));
                    pc += 1;
                }

                // ── Logging (terminators for our purposes — pop args and continue) ──
                op if op >= LOG0 && op <= LOG4 => {
                    let n_topics = (op - LOG0) as usize;
                    self.pop(); // offset
                    self.pop(); // size
                    for _ in 0..n_topics {
                        self.pop();
                    }
                    pc += 1;
                }

                // ── External calls (pop args, push Unknown) ──
                CALL | CALLCODE => {
                    // CALL: gas, addr, value, argsOffset, argsLength, retOffset, retLength
                    let _gas = self.pop();
                    let addr_val = self.pop();
                    let _value = self.pop();
                    let args_offset = self.pop();
                    let _args_length = self.pop();
                    for _ in 0..2 {
                        self.pop(); // retOffset, retLength
                    }

                    let selector = extract_call_selector(&args_offset, &self.memory);

                    // Record call targets for Account prefetching
                    match &addr_val {
                        SymVal::Concrete(a) => {
                            let addr = Address::from_word((*a).into());
                            if addr != Address::ZERO && !is_precompile(addr) {
                                self.call_targets.push((addr, selector));
                            }
                        }
                        _ => {
                            self.symbolic_call_targets.push((addr_val, selector));
                        }
                    }

                    self.push(SymVal::Unknown); // success
                    pc += 1;
                }
                STATICCALL | DELEGATECALL => {
                    // 6 args: gas, addr, argsOffset, argsLength, retOffset, retLength
                    let _gas = self.pop();
                    let addr_val = self.pop();
                    let args_offset = self.pop();
                    let _args_length = self.pop();
                    for _ in 0..2 {
                        self.pop(); // retOffset, retLength
                    }

                    let selector = extract_call_selector(&args_offset, &self.memory);

                    // Record call targets for Account prefetching
                    match &addr_val {
                        SymVal::Concrete(a) => {
                            let addr = Address::from_word((*a).into());
                            if addr != Address::ZERO && !is_precompile(addr) {
                                self.call_targets.push((addr, selector));
                            }
                        }
                        _ => {
                            self.symbolic_call_targets.push((addr_val, selector));
                        }
                    }

                    self.push(SymVal::Unknown); // success
                    pc += 1;
                }
                CREATE => {
                    // value, offset, length
                    for _ in 0..3 {
                        self.pop();
                    }
                    self.push(SymVal::Unknown); // address
                    pc += 1;
                }
                CREATE2 => {
                    // value, offset, length, salt
                    for _ in 0..4 {
                        self.pop();
                    }
                    self.push(SymVal::Unknown); // address
                    pc += 1;
                }

                // ── Misc ──
                CODECOPY | RETURNDATACOPY => {
                    self.pop(); // destOffset
                    self.pop(); // offset
                    self.pop(); // length
                    pc += 1;
                }
                EXTCODECOPY => {
                    self.pop(); // address
                    self.pop(); // destOffset
                    self.pop(); // offset
                    self.pop(); // length
                    pc += 1;
                }

                _ => {
                    // Unknown opcode — skip
                    pc += 1;
                }
            }
        }
    }
}

/// Returns true for precompile addresses (0x01 through 0x0a).
fn is_precompile(addr: Address) -> bool {
    let bytes = addr.as_slice();
    // All leading 19 bytes must be zero, and last byte must be 0x01..=0x0a
    bytes[..19].iter().all(|&b| b == 0) && (1..=0x0a).contains(&bytes[19])
}

/// Extract the 4-byte function selector from symbolic memory at the call's argsOffset.
fn extract_call_selector(args_offset: &SymVal, memory: &SymbolicMemory) -> Option<FixedBytes<4>> {
    if let SymVal::Concrete(off) = args_offset {
        let offset: usize = off.try_into().ok()?;
        let word = memory.load(offset);
        if let SymVal::Concrete(v) = word {
            let bytes: [u8; 32] = v.to_be_bytes();
            let sel = FixedBytes::<4>::from_slice(&bytes[..4]);
            if sel != FixedBytes::ZERO {
                return Some(sel);
            }
        }
    }
    None
}

// ─── SymVal → SlotExpression conversion ──────────────────────────────────────

/// Convert a `SymVal` to a `SlotExpression`, returning `None` if the value
/// contains unresolvable components (Unknown, CallValue, boolean ops, etc.).
fn symval_to_slot_expr(val: &SymVal) -> Option<SlotExpression> {
    match val {
        SymVal::Concrete(v) => Some(SlotExpression::Concrete {
            value: B256::from(*v),
        }),
        SymVal::CalldataWord { offset } => Some(SlotExpression::CalldataWord { offset: *offset }),
        SymVal::Caller => Some(SlotExpression::Caller),
        SymVal::Keccak256 { inputs } => {
            let converted: Option<Vec<SlotExpression>> =
                inputs.iter().map(symval_to_slot_expr).collect();
            Some(SlotExpression::Keccak256 { inputs: converted? })
        }
        SymVal::Add(left, right) => {
            let l = symval_to_slot_expr(left)?;
            let r = symval_to_slot_expr(right)?;
            Some(SlotExpression::Add {
                left: Box::new(l),
                right: Box::new(r),
            })
        }
        SymVal::SLoad { key } => {
            let k = symval_to_slot_expr(key)?;
            Some(SlotExpression::SLoad { key: Box::new(k) })
        }
        // AND(x, address_mask) → x  (Solidity address cleaning)
        SymVal::And(a, b) => {
            if let SymVal::Concrete(mask) = a.as_ref() {
                if *mask == ADDRESS_MASK {
                    return symval_to_slot_expr(b);
                }
            }
            if let SymVal::Concrete(mask) = b.as_ref() {
                if *mask == ADDRESS_MASK {
                    return symval_to_slot_expr(a);
                }
            }
            // Other AND operations are not resolvable as slot expressions
            None
        }
        // These cannot be resolved at prefetch time
        SymVal::CallValue
        | SymVal::CalldataSize
        | SymVal::Unknown
        | SymVal::Sub(..)
        | SymVal::Mul(..)
        | SymVal::Div(..)
        | SymVal::Mod(..)
        | SymVal::Or(..)
        | SymVal::Xor(..)
        | SymVal::Not(..)
        | SymVal::Shl(..)
        | SymVal::Shr(..)
        | SymVal::Eq(..)
        | SymVal::Lt(..)
        | SymVal::Gt(..)
        | SymVal::IsZero(..)
        | SymVal::SignExtend(..)
        | SymVal::Byte(..) => None,
    }
}

// ─── Dispatch table extraction (kept from original) ──────────────────────────

/// A selector with its dispatch jump destination.
#[derive(Debug, Clone)]
struct DispatchEntry {
    selector: FixedBytes<4>,
    dest: usize,
}

/// Result of bytecode analysis for a single selector.
#[derive(Debug, Clone)]
pub struct AnalyzedSelector {
    pub selector: FixedBytes<4>,
    pub items: Vec<PrefetchItem>,
    pub confidence: f64,
}

/// Extract the selector dispatch table: selector -> jump destination PC.
fn extract_dispatch_table(bytecode: &[u8]) -> Vec<DispatchEntry> {
    let mut entries = Vec::new();
    let len = bytecode.len();
    let mut i = 0;
    const PUSH4: u8 = 0x63;

    while i < len {
        let op = bytecode[i];

        if op == PUSH4 && i + 5 < len {
            let sel = FixedBytes::<4>::from_slice(&bytecode[i + 1..i + 5]);

            let scan_end = std::cmp::min(i + 14, len);
            let mut j = i + 5;
            let mut found_eq = false;

            while j < scan_end {
                let ahead_op = bytecode[j];
                if ahead_op == EQ {
                    found_eq = true;
                    j += 1;
                } else if (ahead_op == XOR || ahead_op == SUB)
                    && j + 1 < scan_end
                    && bytecode[j + 1] == ISZERO
                {
                    // Vyper / optimized Solidity: XOR ISZERO or SUB ISZERO
                    // is semantically equivalent to EQ
                    found_eq = true;
                    j += 2;
                } else if found_eq && ahead_op >= PUSH1 && ahead_op <= PUSH32 {
                    let push_size = (ahead_op - PUSH1 + 1) as usize;
                    if j + 1 + push_size < len && bytecode.get(j + 1 + push_size) == Some(&JUMPI) {
                        let mut dest = 0usize;
                        for k in 0..push_size {
                            dest = (dest << 8) | (bytecode[j + 1 + k] as usize);
                        }
                        entries.push(DispatchEntry {
                            selector: sel,
                            dest,
                        });
                    }
                    break;
                } else if ahead_op >= PUSH1 && ahead_op <= PUSH32 {
                    // Skip PUSH instruction data to avoid misinterpreting
                    // operand bytes as opcodes (e.g., 0x14 in data ≠ EQ)
                    let push_size = (ahead_op - PUSH1 + 1) as usize;
                    j += 1 + push_size;
                } else {
                    j += 1;
                }
            }
            i += 5;
        } else if op >= PUSH1 && op <= PUSH32 {
            let push_size = (op - PUSH1 + 1) as usize;
            i += 1 + push_size;
        } else {
            i += 1;
        }
    }

    entries
}

/// Collect all JUMPDEST positions in the bytecode.
fn collect_jumpdests(bytecode: &[u8]) -> HashSet<usize> {
    let mut dests = HashSet::new();
    let mut i = 0;
    while i < bytecode.len() {
        let op = bytecode[i];
        if op == JUMPDEST {
            dests.insert(i);
        }
        if op >= PUSH1 && op <= PUSH32 {
            let push_size = (op - PUSH1 + 1) as usize;
            i += 1 + push_size;
        } else {
            i += 1;
        }
    }
    dests
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Analyze deployed EVM bytecode to extract per-selector storage access patterns.
///
/// Uses symbolic execution to track value provenance through the EVM stack and
/// memory, producing `SlotExpression` trees that describe how each SLOAD key
/// is derived from runtime inputs (calldata, msg.sender, etc.).
pub fn analyze_bytecode(bytecode: &[u8]) -> Vec<AnalyzedSelector> {
    let dispatch = extract_dispatch_table(bytecode);
    let jumpdests = collect_jumpdests(bytecode);

    // Always analyze from PC 0 to capture fallback/default behavior.
    // The executor prioritizes fall-through (not-taken) at each JUMPI, so it
    // naturally follows the "no selector matched" path through the dispatch
    // table to reach the fallback code. Taken branches (selector handlers)
    // get geometrically discounted budgets.
    let mut fallback_evm = SymbolicEvm::new(bytecode, jumpdests.clone());
    fallback_evm.execute(0);

    let mut fallback_items = convert_sload_keys(&fallback_evm.sload_keys);
    append_call_target_items(&fallback_evm.call_targets, &mut fallback_items);
    append_computed_call_items(&fallback_evm.symbolic_call_targets, &mut fallback_items);

    if dispatch.is_empty() {
        // No dispatch table — use PC-0 analysis as the only entry
        if fallback_items.is_empty() {
            return Vec::new();
        }
        return vec![AnalyzedSelector {
            selector: FixedBytes::default(),
            items: fallback_items,
            confidence: 0.3,
        }];
    }

    let mut results = Vec::new();

    for entry in &dispatch {
        if entry.dest >= bytecode.len() {
            continue;
        }

        // Run symbolic execution from this selector's entry point
        let mut evm = SymbolicEvm::new(bytecode, jumpdests.clone());
        evm.execute(entry.dest);

        let mut items = convert_sload_keys(&evm.sload_keys);
        append_call_target_items(&evm.call_targets, &mut items);
        append_computed_call_items(&evm.symbolic_call_targets, &mut items);

        if !items.is_empty() {
            results.push(AnalyzedSelector {
                selector: entry.selector,
                items,
                confidence: 0.8,
            });
        }
    }

    // Add fallback/default entry — captures behavior when no selector matches,
    // including fallback functions and selectors missed by the dispatch scanner
    // (e.g., Vyper XOR-without-ISZERO patterns).
    if !fallback_items.is_empty() {
        results.push(AnalyzedSelector {
            selector: FixedBytes::default(),
            items: fallback_items,
            confidence: 0.3,
        });
    }

    results
}

/// Maximum number of prefetch items per selector.
/// Beyond this, we keep only non-Concrete items (dynamic expressions are more valuable).
const MAX_ITEMS_PER_SELECTOR: usize = 64;

/// Maximum number of concrete slot items before we stop adding more.
/// A real function typically accesses at most ~10 fixed storage slots.
const MAX_CONCRETE_ITEMS: usize = 16;

/// Convert collected SLOAD keys from SymVal to PrefetchItem via SlotExpression.
fn convert_sload_keys(sload_keys: &[SymVal]) -> Vec<PrefetchItem> {
    let mut items = Vec::new();
    let mut seen = HashSet::new();
    let mut concrete_count = 0usize;

    for key in sload_keys {
        if let Some(expr) = symval_to_slot_expr(key) {
            // Deduplicate by serializing to a string
            let key_str = format!("{expr:?}");
            if !seen.insert(key_str) {
                continue;
            }

            // Limit concrete items to avoid bloat from exploring many code paths
            if matches!(&expr, SlotExpression::Concrete { value } if is_likely_storage_slot(value))
            {
                if concrete_count >= MAX_CONCRETE_ITEMS {
                    continue;
                }
                concrete_count += 1;
            } else if matches!(&expr, SlotExpression::Concrete { .. }) {
                // Skip concrete values that don't look like storage slots
                continue;
            }

            items.push(PrefetchItem::Storage { slot: expr });

            if items.len() >= MAX_ITEMS_PER_SELECTOR {
                break;
            }
        }
    }

    items
}

/// Append `PrefetchItem::Account` entries for unique call targets.
fn append_call_target_items(
    call_targets: &[(Address, Option<FixedBytes<4>>)],
    items: &mut Vec<PrefetchItem>,
) {
    let mut seen = HashSet::new();
    for (addr, selector) in call_targets {
        if seen.insert(*addr) {
            items.push(PrefetchItem::Account {
                address: *addr,
                selector: *selector,
            });
        }
    }
}

/// Append `PrefetchItem::ComputedAccount` entries for symbolic (non-concrete) call targets.
fn append_computed_call_items(
    symbolic_targets: &[(SymVal, Option<FixedBytes<4>>)],
    items: &mut Vec<PrefetchItem>,
) {
    let mut seen = HashSet::new();
    for (target, selector) in symbolic_targets {
        if let Some(expr) = symval_to_slot_expr(target) {
            let key_str = format!("{expr:?}");
            if seen.insert(key_str) {
                items.push(PrefetchItem::ComputedAccount {
                    address: expr,
                    selector: *selector,
                });
            }
        }
    }
}

/// Heuristic: is this concrete value likely an actual storage slot?
///
/// Filters out keccak256 hashes of compile-time constants, error selectors,
/// address masks, and other values that aren't meaningful slot indices.
fn is_likely_storage_slot(value: &B256) -> bool {
    let bytes = value.as_slice();

    // Small values (0..256) are almost always real storage slots
    let u: U256 = (*value).into();
    if u < U256::from(256) {
        return true;
    }

    // Values where most leading bytes are zero are likely small slot numbers
    let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
    if leading_zeros >= 24 {
        return true;
    }

    // Skip values that look like error selectors (0x08c379a0...)
    if bytes[0] == 0x08 && bytes[1] == 0xc3 {
        return false;
    }

    // Skip values with many 0xff bytes (address masks)
    let ff_count = bytes.iter().filter(|&&b| b == 0xff).count();
    if ff_count > 12 {
        return false;
    }

    // Large "random-looking" values (high entropy) are likely keccak256 hashes
    // of compile-time constants — not useful for prefetching
    let nonzero = bytes.iter().filter(|&&b| b != 0).count();
    if nonzero > 20 && leading_zeros < 4 {
        return false;
    }

    true
}

/// Convert analyzed selectors into `(Selector, Vec<PrefetchItem>)` pairs
/// suitable for inserting into a `HintTable` at a specific address.
pub fn analyzed_to_entries(
    analyzed: &[AnalyzedSelector],
) -> Vec<(dowse_types::Selector, Vec<PrefetchItem>)> {
    analyzed
        .iter()
        .map(|a| {
            let selector: dowse_types::Selector = if a.selector == FixedBytes::default() {
                None
            } else {
                Some(a.selector)
            };
            (
                selector,
                a.items
                    .iter()
                    .cloned()
                    .map(|item| item.with_confidence(a.confidence))
                    .collect(),
            )
        })
        .collect()
}

/// Extract just the selectors for public API compatibility.
pub fn extract_selectors(bytecode: &[u8]) -> Vec<FixedBytes<4>> {
    let dispatch = extract_dispatch_table(bytecode);
    let mut sels: Vec<_> = dispatch.iter().map(|e| e.selector).collect();
    sels.sort();
    sels.dedup();
    sels
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn entries_retain_analyzer_confidence() {
        let analyzed = vec![AnalyzedSelector {
            selector: FixedBytes::from([1, 2, 3, 4]),
            items: vec![PrefetchItem::Storage {
                slot: SlotExpression::Concrete { value: B256::ZERO },
            }],
            confidence: 0.8,
        }];

        let entries = analyzed_to_entries(&analyzed);
        assert_eq!(entries[0].1[0].scored().1, 0.8);
    }

    #[test]
    fn binary_search_dispatch_table() {
        let bytecode = decode_hex("608060405234801561001057600080fd5b506004361061036d5760003560e01c80638456cb59116101d3578063b7b7289911610104578063e3ee160e116100a2578063ef55bec61161007c578063ef55bec614611122578063f2fde38b1461118e578063f9f92be4146111c1578063fe575a87146111f45761036d565b8063e3ee160e14611075578063e5a6b10f146110e1578063e94a0102146110e95761036d565b8063d505accf116100de578063d505accf14610f64578063d608ea641461\
0fc2578063d916948614610ffe578063dd62ed3e1461103e5761036d");

        let table = extract_dispatch_table(&bytecode);
        assert!(
            table.len() >= 10,
            "Expected >= 10 selectors, got {}",
            table.len(),
        );
        assert!(table
            .iter()
            .any(|e| e.selector == FixedBytes::from([0xdd, 0x62, 0xed, 0x3e])));
    }

    #[test]
    fn extract_selectors_from_dispatch() {
        let mut bytecode = Vec::new();
        let push4: u8 = 0x63;
        bytecode.push(push4);
        bytecode.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        bytecode.push(EQ);
        bytecode.push(PUSH2);
        bytecode.extend_from_slice(&[0x00, 0x42]);
        bytecode.push(JUMPI);

        bytecode.push(push4);
        bytecode.extend_from_slice(&[0x70, 0xa0, 0x82, 0x31]);
        bytecode.push(EQ);
        bytecode.push(PUSH2);
        bytecode.extend_from_slice(&[0x00, 0x56]);
        bytecode.push(JUMPI);

        let sels = extract_selectors(&bytecode);
        assert_eq!(sels.len(), 2);
        assert!(sels.contains(&FixedBytes::from([0x70, 0xa0, 0x82, 0x31])));
        assert!(sels.contains(&FixedBytes::from([0xa9, 0x05, 0x9c, 0xbb])));
    }

    #[test]
    fn per_selector_constant_sload() {
        let mut bytecode = vec![0u8; 512];

        // Dispatch: selector A -> offset 64, selector B -> offset 128
        let push4: u8 = 0x63;
        bytecode[0] = push4;
        bytecode[1..5].copy_from_slice(&[0xaa, 0xaa, 0xaa, 0xaa]);
        bytecode[5] = EQ;
        bytecode[6] = PUSH2;
        bytecode[7..9].copy_from_slice(&[0x00, 0x40]);
        bytecode[9] = JUMPI;

        bytecode[10] = push4;
        bytecode[11..15].copy_from_slice(&[0xbb, 0xbb, 0xbb, 0xbb]);
        bytecode[15] = EQ;
        bytecode[16] = PUSH2;
        bytecode[17..19].copy_from_slice(&[0x00, 0x80]);
        bytecode[19] = JUMPI;

        // Selector A at offset 64: JUMPDEST PUSH32 <slot 5> SLOAD STOP
        bytecode[64] = JUMPDEST;
        bytecode[65] = PUSH32;
        let mut slot5 = [0u8; 32];
        slot5[31] = 5;
        bytecode[66..98].copy_from_slice(&slot5);
        bytecode[98] = SLOAD;
        bytecode[99] = STOP;

        // Selector B at offset 128: JUMPDEST PUSH32 <slot 10> SLOAD STOP
        bytecode[128] = JUMPDEST;
        bytecode[129] = PUSH32;
        let mut slot10 = [0u8; 32];
        slot10[31] = 10;
        bytecode[130..162].copy_from_slice(&slot10);
        bytecode[162] = SLOAD;
        bytecode[163] = STOP;

        let results = analyze_bytecode(&bytecode);
        // 2 selectors + 1 fallback/default entry
        assert!(
            results.len() >= 2,
            "Expected at least 2 results, got {}",
            results.len()
        );

        let sel_a = results
            .iter()
            .find(|r| r.selector == FixedBytes::from([0xaa, 0xaa, 0xaa, 0xaa]))
            .expect("Should find selector A");
        let sel_b = results
            .iter()
            .find(|r| r.selector == FixedBytes::from([0xbb, 0xbb, 0xbb, 0xbb]))
            .expect("Should find selector B");

        assert!(sel_a.items.iter().any(|item| matches!(
            item,
            PrefetchItem::Storage { slot: SlotExpression::Concrete { value }, .. }
            if *value == B256::with_last_byte(5)
        )));
        assert!(!sel_a.items.iter().any(|item| matches!(
            item,
            PrefetchItem::Storage { slot: SlotExpression::Concrete { value }, .. }
            if *value == B256::with_last_byte(10)
        )));
        assert!(sel_b.items.iter().any(|item| matches!(
            item,
            PrefetchItem::Storage { slot: SlotExpression::Concrete { value }, .. }
            if *value == B256::with_last_byte(10)
        )));
    }

    #[test]
    fn symbolic_mapping_pattern() {
        // Build bytecode for a simple mapping access:
        // PUSH1 0x04 CALLDATALOAD    -- load arg0
        // PUSH1 0x00 MSTORE          -- store arg0 at mem[0]
        // PUSH1 0x00 PUSH1 0x20 MSTORE  -- store base_slot=0 at mem[32]
        // PUSH1 0x40 PUSH1 0x00 KECCAK256 -- keccak256(mem[0..64])
        // SLOAD                       -- load the mapping slot
        // STOP
        let bytecode: Vec<u8> = vec![
            JUMPDEST, // 0: JUMPDEST
            PUSH1,
            0x04,         // 1: PUSH1 0x04
            CALLDATALOAD, // 3: CALLDATALOAD
            PUSH1,
            0x00,   // 4: PUSH1 0x00
            MSTORE, // 6: MSTORE (mem[0] = calldataload(4))
            PUSH1,
            0x00, // 7: PUSH1 0x00
            PUSH1,
            0x20,   // 9: PUSH1 0x20
            MSTORE, // 11: MSTORE (mem[32] = 0)
            PUSH1,
            0x40, // 12: PUSH1 0x40
            PUSH1,
            0x00,      // 14: PUSH1 0x00
            KECCAK256, // 16: KECCAK256(0, 64)
            SLOAD,     // 17: SLOAD
            STOP,      // 18: STOP
        ];

        let jumpdests = collect_jumpdests(&bytecode);
        let mut evm = SymbolicEvm::new(&bytecode, jumpdests);
        evm.execute(0);

        assert_eq!(evm.sload_keys.len(), 1);

        // Should produce Keccak256 { [CalldataWord{4}, Concrete(0)] }
        let expr =
            symval_to_slot_expr(&evm.sload_keys[0]).expect("Should convert to SlotExpression");
        match &expr {
            SlotExpression::Keccak256 { inputs } => {
                assert_eq!(inputs.len(), 2);
                assert!(matches!(
                    &inputs[0],
                    SlotExpression::CalldataWord { offset: 4 }
                ));
                assert!(matches!(
                    &inputs[1],
                    SlotExpression::Concrete { value } if *value == B256::ZERO
                ));
            }
            other => panic!("Expected Keccak256, got: {other:?}"),
        }
    }

    #[test]
    fn symbolic_caller_mapping() {
        // Build bytecode that loads a mapping keyed by msg.sender:
        // CALLER
        // PUSH1 0x00 MSTORE          -- store caller at mem[0]
        // PUSH1 0x09 PUSH1 0x20 MSTORE  -- store base_slot=9 at mem[32]
        // PUSH1 0x40 PUSH1 0x00 KECCAK256
        // SLOAD
        // STOP
        let bytecode: Vec<u8> = vec![
            JUMPDEST, // 0
            CALLER,   // 1
            PUSH1, 0x00,   // 2
            MSTORE, // 4
            PUSH1, 0x09, // 5
            PUSH1, 0x20,   // 7
            MSTORE, // 9
            PUSH1, 0x40, // 10
            PUSH1, 0x00,      // 12
            KECCAK256, // 14
            SLOAD,     // 15
            STOP,      // 16
        ];

        let jumpdests = collect_jumpdests(&bytecode);
        let mut evm = SymbolicEvm::new(&bytecode, jumpdests);
        evm.execute(0);

        assert_eq!(evm.sload_keys.len(), 1);

        let expr = symval_to_slot_expr(&evm.sload_keys[0]).expect("Should convert");
        match &expr {
            SlotExpression::Keccak256 { inputs } => {
                assert_eq!(inputs.len(), 2);
                assert!(matches!(&inputs[0], SlotExpression::Caller));
                assert!(matches!(
                    &inputs[1],
                    SlotExpression::Concrete { value } if *value == B256::with_last_byte(9)
                ));
            }
            other => panic!("Expected Keccak256, got: {other:?}"),
        }
    }

    #[test]
    fn symbolic_constant_fold() {
        // PUSH1 3 PUSH1 5 ADD SLOAD STOP
        let bytecode: Vec<u8> = vec![JUMPDEST, PUSH1, 3, PUSH1, 5, ADD, SLOAD, STOP];

        let jumpdests = collect_jumpdests(&bytecode);
        let mut evm = SymbolicEvm::new(&bytecode, jumpdests);
        evm.execute(0);

        assert_eq!(evm.sload_keys.len(), 1);
        let expr = symval_to_slot_expr(&evm.sload_keys[0]).unwrap();
        assert!(matches!(
            &expr,
            SlotExpression::Concrete { value } if *value == B256::with_last_byte(8)
        ));
    }

    #[test]
    fn symbolic_branching() {
        // JUMPDEST
        // PUSH1 0x01             -- condition
        // PUSH1 <target> JUMPI  -- jump to target if condition
        // PUSH1 0x05 SLOAD STOP -- fall-through: SLOAD(5)
        // JUMPDEST               -- target
        // PUSH1 0x0A SLOAD STOP -- taken: SLOAD(10)
        let target: u8 = 10;
        let bytecode: Vec<u8> = vec![
            JUMPDEST, // 0
            PUSH1, 0x01, // 1: condition = 1
            PUSH1, target, // 3: push target
            JUMPI,  // 5
            PUSH1, 0x05,     // 6: fall-through
            SLOAD,    // 8
            STOP,     // 9
            JUMPDEST, // 10: target
            PUSH1, 0x0A,  // 11
            SLOAD, // 13
            STOP,  // 14
        ];

        let jumpdests = collect_jumpdests(&bytecode);
        let mut evm = SymbolicEvm::new(&bytecode, jumpdests);
        evm.execute(0);

        // Should find both SLOAD(5) and SLOAD(10) from both branches
        assert!(
            evm.sload_keys.len() >= 2,
            "Should explore both branches, got {} keys",
            evm.sload_keys.len()
        );

        let items = convert_sload_keys(&evm.sload_keys);
        assert!(items.iter().any(|item| matches!(
            item,
            PrefetchItem::Storage { slot: SlotExpression::Concrete { value }, .. }
            if *value == B256::with_last_byte(5)
        )));
        assert!(items.iter().any(|item| matches!(
            item,
            PrefetchItem::Storage { slot: SlotExpression::Concrete { value }, .. }
            if *value == B256::with_last_byte(10)
        )));
    }

    #[test]
    fn call_target_extraction() {
        // Build bytecode that does STATICCALL to a concrete address with a selector
        // stored in memory. The selector 0xd0e30db0 (deposit()) is written to mem[0x80]
        // via MSTORE, then argsOffset=0x80 is passed to STATICCALL.
        let target = Address::from_slice(&[
            0xde, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);
        let expected_selector = FixedBytes::<4>::from([0xd0, 0xe3, 0x0d, 0xb0]);
        // Selector left-padded into a 32-byte word (big-endian, high bytes)
        let mut selector_word = [0u8; 32];
        selector_word[0] = 0xd0;
        selector_word[1] = 0xe3;
        selector_word[2] = 0x0d;
        selector_word[3] = 0xb0;

        let mut bytecode = vec![JUMPDEST]; // 0
                                           // Store selector into memory at offset 0x80:
                                           // PUSH32 <selector_word> PUSH1 0x80 MSTORE
        bytecode.push(PUSH32);
        bytecode.extend_from_slice(&selector_word);
        bytecode.push(PUSH1);
        bytecode.push(0x80);
        bytecode.push(MSTORE);
        // Stack args for STATICCALL (pushed in reverse):
        // retLength=0, retOffset=0, argsLength=4, argsOffset=0x80
        bytecode.push(PUSH1);
        bytecode.push(0x00); // retLength
        bytecode.push(PUSH1);
        bytecode.push(0x00); // retOffset
        bytecode.push(PUSH1);
        bytecode.push(0x04); // argsLength
        bytecode.push(PUSH1);
        bytecode.push(0x80); // argsOffset
                             // Push target address (PUSH20)
        bytecode.push(0x73); // PUSH20
        bytecode.extend_from_slice(target.as_slice());
        // Push gas
        bytecode.push(GAS);
        // STATICCALL(gas, addr, argsOffset, argsLength, retOffset, retLength)
        bytecode.push(STATICCALL);
        bytecode.push(STOP);

        let results = analyze_bytecode(&bytecode);
        // No dispatch table, so should get wildcard entry
        assert!(!results.is_empty());
        let items = &results[0].items;
        let account_item = items.iter().find(|item| {
            matches!(
                item,
                PrefetchItem::Account { address, .. } if *address == target
            )
        });
        assert!(
            account_item.is_some(),
            "Should find Account item for STATICCALL target, got: {items:?}",
        );
        // Verify selector was extracted
        match account_item.unwrap() {
            PrefetchItem::Account { selector, .. } => {
                assert_eq!(
                    *selector,
                    Some(expected_selector),
                    "Should extract selector from memory"
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn precompile_addresses_filtered() {
        // STATICCALL to address 0x01 (ecrecover precompile) should not produce Account item
        let mut bytecode = vec![JUMPDEST];
        for _ in 0..4 {
            bytecode.push(PUSH1);
            bytecode.push(0x00);
        }
        bytecode.push(PUSH1);
        bytecode.push(0x01); // precompile address
        bytecode.push(GAS);
        bytecode.push(STATICCALL);
        bytecode.push(STOP);

        let results = analyze_bytecode(&bytecode);
        // Should not have any Account items
        for result in &results {
            assert!(
                !result
                    .items
                    .iter()
                    .any(|item| matches!(item, PrefetchItem::Account { .. })),
                "Precompile addresses should be filtered out",
            );
        }
    }

    #[test]
    fn symbolic_call_target_produces_computed_account() {
        // Build bytecode that does STATICCALL to a keccak256-computed address.
        // Push the 4 trailing args first, then compute the address, then push gas.
        let bytecode: Vec<u8> = vec![
            JUMPDEST, // 0
            // Push 4 zeros for retLength, retOffset, argsLength, argsOffset
            PUSH1,
            0x00, // 1
            PUSH1,
            0x00, // 3
            PUSH1,
            0x00, // 5
            PUSH1,
            0x00, // 7
            // Compute keccak256(calldataload(4), 42) for the address
            PUSH1,
            0x04,         // 9
            CALLDATALOAD, // 11: calldataload(4)
            PUSH1,
            0x00,   // 12
            MSTORE, // 14: mem[0] = calldataload(4)
            PUSH1,
            0x2a, // 15: 42
            PUSH1,
            0x20,   // 17
            MSTORE, // 19: mem[32] = 42
            PUSH1,
            0x40, // 20: size = 64
            PUSH1,
            0x00,      // 22: offset = 0
            KECCAK256, // 24: keccak256(mem[0..64]) -> stack has address
            // Push gas
            GAS, // 25
            // STATICCALL(gas, addr, argsOff, argsLen, retOff, retLen)
            STATICCALL, // 26
            STOP,       // 27
        ];

        let results = analyze_bytecode(&bytecode);
        assert!(!results.is_empty(), "Should produce at least one result");
        let items = &results[0].items;
        assert!(
            items
                .iter()
                .any(|item| matches!(item, PrefetchItem::ComputedAccount { .. })),
            "Should find ComputedAccount item for symbolic STATICCALL target, got: {items:?}",
        );
        // Verify it's a Keccak256 expression
        let computed = items
            .iter()
            .find(|item| matches!(item, PrefetchItem::ComputedAccount { .. }))
            .unwrap();
        if let PrefetchItem::ComputedAccount { address: expr, .. } = computed {
            assert!(
                matches!(expr, SlotExpression::Keccak256 { .. }),
                "Expected Keccak256 expression, got: {expr:?}"
            );
        }
    }

    #[test]
    fn fuzz_random_bytecodes() {
        use rand::Rng;
        let mut rng = rand::rng();
        for _ in 0..100 {
            let len: usize = rng.random_range(0..10_000);
            let bytecode: Vec<u8> = (0..len).map(|_| rng.random::<u8>()).collect();
            let _ = analyze_bytecode(&bytecode);
            let _ = extract_selectors(&bytecode);
        }
    }

    // ── Dispatch table detection ─────────────────────────────────────────

    /// Binary search dispatch: GT pivots split the selector space,
    /// EQ leaves identify actual selectors. All leaf selectors must be found.
    #[test]
    fn dispatch_binary_search_gt_eq() {
        // Build a binary search dispatch:
        //   DUP1 PUSH4 <mid> GT PUSH2 <right_half> JUMPI
        //   DUP1 PUSH4 <sel_a> EQ PUSH2 <dest_a> JUMPI
        //   STOP
        //   JUMPDEST  <- right_half
        //   DUP1 PUSH4 <sel_b> EQ PUSH2 <dest_b> JUMPI
        //   STOP
        //   JUMPDEST  <- dest_a (0x80)
        //   PUSH1 5 SLOAD STOP
        //   JUMPDEST  <- dest_b (0x90)
        //   PUSH1 10 SLOAD STOP
        let sel_a = [0x11, 0x11, 0x11, 0x11];
        let sel_b = [0xbb, 0xbb, 0xbb, 0xbb];
        let mid = [0x80, 0x00, 0x00, 0x00]; // midpoint for GT

        let mut bc = vec![0u8; 256];
        let mut p = 0;

        // calldataload(0) >> 224 → selector on stack
        bc[p] = PUSH1;
        bc[p + 1] = 0x00;
        p += 2; // push 0
        bc[p] = CALLDATALOAD;
        p += 1; // calldataload(0)
        bc[p] = PUSH1;
        bc[p + 1] = 0xe0;
        p += 2; // push 224
        bc[p] = SHR;
        p += 1; // shr

        // DUP1 PUSH4 <mid> GT PUSH2 <right_half=0x20> JUMPI
        bc[p] = DUP1;
        p += 1;
        bc[p] = 0x63;
        p += 1; // PUSH4
        bc[p..p + 4].copy_from_slice(&mid);
        p += 4;
        bc[p] = GT;
        p += 1;
        bc[p] = PUSH1;
        bc[p + 1] = 0x20;
        p += 2; // right half at 0x20
        bc[p] = JUMPI;
        p += 1;

        // Left half: DUP1 PUSH4 <sel_a> EQ PUSH1 <0x80> JUMPI
        bc[p] = DUP1;
        p += 1;
        bc[p] = 0x63;
        p += 1;
        bc[p..p + 4].copy_from_slice(&sel_a);
        p += 4;
        bc[p] = EQ;
        p += 1;
        bc[p] = PUSH1;
        bc[p + 1] = 0x80;
        p += 2;
        bc[p] = JUMPI;
        p += 1;
        bc[p] = STOP;
        p += 1;

        // Right half at 0x20
        let right_half = 0x20;
        bc[right_half] = JUMPDEST;
        let mut p = right_half + 1;
        bc[p] = DUP1;
        p += 1;
        bc[p] = 0x63;
        p += 1;
        bc[p..p + 4].copy_from_slice(&sel_b);
        p += 4;
        bc[p] = EQ;
        p += 1;
        bc[p] = PUSH1;
        bc[p + 1] = 0x90;
        p += 2;
        bc[p] = JUMPI;
        p += 1;
        bc[p] = STOP;

        // dest_a at 0x80: JUMPDEST PUSH1 5 SLOAD STOP
        bc[0x80] = JUMPDEST;
        bc[0x81] = PUSH1;
        bc[0x82] = 5;
        bc[0x83] = SLOAD;
        bc[0x84] = STOP;

        // dest_b at 0x90: JUMPDEST PUSH1 10 SLOAD STOP
        bc[0x90] = JUMPDEST;
        bc[0x91] = PUSH1;
        bc[0x92] = 10;
        bc[0x93] = SLOAD;
        bc[0x94] = STOP;

        let sels = extract_selectors(&bc);
        assert!(
            sels.contains(&FixedBytes::from(sel_a)),
            "Should find sel_a in binary search dispatch, got: {sels:?}",
        );
        assert!(
            sels.contains(&FixedBytes::from(sel_b)),
            "Should find sel_b in binary search dispatch, got: {sels:?}",
        );
        // The GT midpoint should NOT be a dispatch entry
        // (no EQ follows it, only GT)
    }

    /// Vyper-style dispatch: XOR ISZERO is semantically equivalent to EQ.
    #[test]
    fn dispatch_xor_iszero_pattern() {
        // PUSH4 <sel> DUP2 XOR ISZERO PUSH1 <dest=0x20> JUMPI STOP
        // JUMPDEST at 0x20: PUSH1 3 SLOAD STOP
        let sel = [0xaa, 0xbb, 0xcc, 0xdd];
        let mut bc = vec![0u8; 64];
        let mut p = 0;
        bc[p] = 0x63;
        p += 1; // PUSH4
        bc[p..p + 4].copy_from_slice(&sel);
        p += 4;
        bc[p] = DUP1;
        p += 1; // stand-in for DUP2
        bc[p] = XOR;
        p += 1;
        bc[p] = ISZERO;
        p += 1;
        bc[p] = PUSH1;
        bc[p + 1] = 0x20;
        p += 2;
        bc[p] = JUMPI;
        p += 1;
        bc[p] = STOP;

        bc[0x20] = JUMPDEST;
        bc[0x21] = PUSH1;
        bc[0x22] = 3;
        bc[0x23] = SLOAD;
        bc[0x24] = STOP;

        let sels = extract_selectors(&bc);
        assert!(
            sels.contains(&FixedBytes::from(sel)),
            "XOR ISZERO pattern should be detected as dispatch entry, got: {sels:?}",
        );
    }

    /// SUB ISZERO is also semantically equivalent to EQ.
    #[test]
    fn dispatch_sub_iszero_pattern() {
        let sel = [0x12, 0x34, 0x56, 0x78];
        let mut bc = vec![0u8; 64];
        let mut p = 0;
        bc[p] = 0x63;
        p += 1; // PUSH4
        bc[p..p + 4].copy_from_slice(&sel);
        p += 4;
        bc[p] = DUP1;
        p += 1;
        bc[p] = SUB;
        p += 1;
        bc[p] = ISZERO;
        p += 1;
        bc[p] = PUSH1;
        bc[p + 1] = 0x20;
        p += 2;
        bc[p] = JUMPI;
        p += 1;
        bc[p] = STOP;

        bc[0x20] = JUMPDEST;
        bc[0x21] = PUSH1;
        bc[0x22] = 7;
        bc[0x23] = SLOAD;
        bc[0x24] = STOP;

        let sels = extract_selectors(&bc);
        assert!(
            sels.contains(&FixedBytes::from(sel)),
            "SUB ISZERO pattern should be detected as dispatch entry, got: {sels:?}",
        );
    }

    /// Inner scan must skip PUSH instruction data to avoid interpreting
    /// operand bytes as opcodes (e.g., 0x14 in PUSH data ≠ EQ opcode).
    #[test]
    fn dispatch_inner_scan_skips_push_data() {
        // Construct: PUSH4 <sel> PUSH2 [0x14, 0x61] EQ PUSH1 <dest=0x30> JUMPI STOP
        // The PUSH2 data contains 0x14 (EQ byte) — scanner must not be fooled.
        let sel = [0xde, 0xad, 0xbe, 0xef];
        let mut bc = vec![0u8; 64];
        let mut p = 0;
        bc[p] = 0x63;
        p += 1; // PUSH4
        bc[p..p + 4].copy_from_slice(&sel);
        p += 4;
        // PUSH2 with data containing 0x14 (EQ byte value) and 0x61 (PUSH2 byte value)
        bc[p] = PUSH1 + 1;
        p += 1; // PUSH2 = 0x61
        bc[p] = EQ;
        p += 1; // 0x14 as DATA, not opcode
        bc[p] = PUSH1 + 1;
        p += 1; // 0x61 as DATA, not opcode
                // Now the real EQ
        bc[p] = EQ;
        p += 1;
        bc[p] = PUSH1;
        bc[p + 1] = 0x30;
        p += 2;
        bc[p] = JUMPI;
        p += 1;
        bc[p] = STOP;

        bc[0x30] = JUMPDEST;
        bc[0x31] = PUSH1;
        bc[0x32] = 1;
        bc[0x33] = SLOAD;
        bc[0x34] = STOP;

        let sels = extract_selectors(&bc);
        assert!(
            sels.contains(&FixedBytes::from(sel)),
            "Scanner should skip PUSH2 data and find real EQ, got: {sels:?}",
        );

        // Verify the destination is correct (0x30, not a garbage value from PUSH data)
        let table = extract_dispatch_table(&bc);
        let entry = table
            .iter()
            .find(|e| e.selector == FixedBytes::from(sel))
            .unwrap();
        assert_eq!(
            entry.dest, 0x30,
            "Destination should be 0x30, not from PUSH data"
        );
    }

    /// PUSH3 jump destination for large contracts (> 64KB).
    #[test]
    fn dispatch_push3_destination() {
        // PUSH4 <sel> EQ PUSH3 <3-byte dest> JUMPI
        let sel = [0x11, 0x22, 0x33, 0x44];
        let dest: usize = 0x01_00_80; // 65664, needs PUSH3
        let mut bc = vec![0u8; 16];
        let mut p = 0;
        bc[p] = 0x63;
        p += 1; // PUSH4
        bc[p..p + 4].copy_from_slice(&sel);
        p += 4;
        bc[p] = EQ;
        p += 1;
        bc[p] = PUSH1 + 2;
        p += 1; // PUSH3 = 0x62
        bc[p] = ((dest >> 16) & 0xff) as u8;
        p += 1;
        bc[p] = ((dest >> 8) & 0xff) as u8;
        p += 1;
        bc[p] = (dest & 0xff) as u8;
        p += 1;
        bc[p] = JUMPI;

        let table = extract_dispatch_table(&bc);
        assert_eq!(table.len(), 1, "Should find one dispatch entry");
        assert_eq!(
            table[0].dest, dest,
            "Should decode PUSH3 destination correctly"
        );
    }

    // ── Fallback / default path analysis ─────────────────────────────────

    /// When a dispatch table exists, analyze_bytecode should ALSO produce
    /// a wildcard (default) entry from PC-0 fallback analysis.
    #[test]
    fn fallback_entry_with_dispatch_table() {
        // Build bytecode with:
        //   - Dispatch: selector A at offset 64
        //   - Fallback: code after dispatch that does SLOAD(99)
        let mut bytecode = vec![0u8; 256];

        // Dispatch: PUSH4 <sel_a> EQ PUSH2 0x0040 JUMPI
        bytecode[0] = 0x63; // PUSH4
        bytecode[1..5].copy_from_slice(&[0xaa, 0xaa, 0xaa, 0xaa]);
        bytecode[5] = EQ;
        bytecode[6] = PUSH1 + 1; // PUSH2
        bytecode[7] = 0x00;
        bytecode[8] = 0x40; // dest = 64
        bytecode[9] = JUMPI;

        // Fallback path (no selector matched): PUSH1 99 SLOAD STOP
        bytecode[10] = PUSH1;
        bytecode[11] = 99;
        bytecode[12] = SLOAD;
        bytecode[13] = STOP;

        // Selector A handler: JUMPDEST PUSH1 5 SLOAD STOP
        bytecode[64] = JUMPDEST;
        bytecode[65] = PUSH1;
        bytecode[66] = 5;
        bytecode[67] = SLOAD;
        bytecode[68] = STOP;

        let results = analyze_bytecode(&bytecode);

        // Should have selector A entry
        let sel_a = results
            .iter()
            .find(|r| r.selector == FixedBytes::from([0xaa, 0xaa, 0xaa, 0xaa]));
        assert!(sel_a.is_some(), "Should find selector A");

        // Should have a wildcard/fallback entry (FixedBytes::default() = 0x00000000)
        let fallback = results.iter().find(|r| r.selector == FixedBytes::default());
        assert!(
            fallback.is_some(),
            "Should produce a fallback/default entry"
        );

        // Fallback should contain slot(99) from the fallback path
        let fb_items = &fallback.unwrap().items;
        assert!(
            fb_items.iter().any(|item| matches!(
                item,
                PrefetchItem::Storage { slot: SlotExpression::Concrete { value } }
                if *value == B256::with_last_byte(99)
            )),
            "Fallback entry should contain SLOAD(99), got: {fb_items:?}",
        );
    }

    // ── Call selector extraction ─────────────────────────────────────────

    /// CALL with no selector in memory should produce Account with selector: None.
    #[test]
    fn call_without_memory_selector() {
        let target = Address::from_slice(&[
            0xde, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);
        let mut bytecode = vec![JUMPDEST];
        // argsOffset=0, nothing written to mem[0] → selector is zero → None
        bytecode.push(PUSH1);
        bytecode.push(0x00); // retLength
        bytecode.push(PUSH1);
        bytecode.push(0x00); // retOffset
        bytecode.push(PUSH1);
        bytecode.push(0x00); // argsLength
        bytecode.push(PUSH1);
        bytecode.push(0x00); // argsOffset = 0 (mem[0] = 0)
        bytecode.push(0x73); // PUSH20
        bytecode.extend_from_slice(target.as_slice());
        bytecode.push(GAS);
        bytecode.push(STATICCALL);
        bytecode.push(STOP);

        let results = analyze_bytecode(&bytecode);
        assert!(!results.is_empty());
        let account_item = results.iter().flat_map(|r| &r.items).find(
            |item| matches!(item, PrefetchItem::Account { address, .. } if *address == target),
        );
        assert!(account_item.is_some(), "Should find Account item");
        match account_item.unwrap() {
            PrefetchItem::Account { selector, .. } => {
                assert_eq!(
                    *selector, None,
                    "No selector in memory → selector should be None"
                );
            }
            _ => unreachable!(),
        }
    }

    /// CALL extracts selector from CALL (7 args) the same as STATICCALL (6 args).
    #[test]
    fn call_opcode_extracts_selector() {
        let target = Address::from_slice(&[
            0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);
        let expected_sel = FixedBytes::<4>::from([0xa9, 0x05, 0x9c, 0xbb]);
        let mut selector_word = [0u8; 32];
        selector_word[0..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);

        let mut bytecode = vec![JUMPDEST];
        // Store selector at mem[0x40]
        bytecode.push(PUSH32);
        bytecode.extend_from_slice(&selector_word);
        bytecode.push(PUSH1);
        bytecode.push(0x40);
        bytecode.push(MSTORE);
        // CALL args (pushed in reverse): retLen, retOff, argsLen, argsOff, value, addr, gas
        bytecode.push(PUSH1);
        bytecode.push(0x00); // retLength
        bytecode.push(PUSH1);
        bytecode.push(0x00); // retOffset
        bytecode.push(PUSH1);
        bytecode.push(0x04); // argsLength
        bytecode.push(PUSH1);
        bytecode.push(0x40); // argsOffset
        bytecode.push(PUSH1);
        bytecode.push(0x00); // value = 0
        bytecode.push(0x73); // PUSH20
        bytecode.extend_from_slice(target.as_slice());
        bytecode.push(GAS);
        bytecode.push(CALL);
        bytecode.push(STOP);

        let results = analyze_bytecode(&bytecode);
        let account_item = results.iter().flat_map(|r| &r.items).find(
            |item| matches!(item, PrefetchItem::Account { address, .. } if *address == target),
        );
        assert!(
            account_item.is_some(),
            "Should find Account item for CALL target"
        );
        match account_item.unwrap() {
            PrefetchItem::Account { selector, .. } => {
                assert_eq!(
                    *selector,
                    Some(expected_sel),
                    "CALL should extract selector from memory"
                );
            }
            _ => unreachable!(),
        }
    }

    /// DELEGATECALL extracts selector (6 args like STATICCALL, no value).
    #[test]
    fn delegatecall_extracts_selector() {
        let target = Address::from_slice(&[
            0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);
        let expected_sel = FixedBytes::<4>::from([0x70, 0xa0, 0x82, 0x31]);
        let mut selector_word = [0u8; 32];
        selector_word[0..4].copy_from_slice(&[0x70, 0xa0, 0x82, 0x31]);

        let mut bytecode = vec![JUMPDEST];
        // Store selector at mem[0x00]
        bytecode.push(PUSH32);
        bytecode.extend_from_slice(&selector_word);
        bytecode.push(PUSH1);
        bytecode.push(0x00);
        bytecode.push(MSTORE);
        // DELEGATECALL: retLen, retOff, argsLen, argsOff, addr, gas
        bytecode.push(PUSH1);
        bytecode.push(0x00); // retLength
        bytecode.push(PUSH1);
        bytecode.push(0x00); // retOffset
        bytecode.push(PUSH1);
        bytecode.push(0x04); // argsLength
        bytecode.push(PUSH1);
        bytecode.push(0x00); // argsOffset
        bytecode.push(0x73); // PUSH20
        bytecode.extend_from_slice(target.as_slice());
        bytecode.push(GAS);
        bytecode.push(DELEGATECALL);
        bytecode.push(STOP);

        let results = analyze_bytecode(&bytecode);
        let account_item = results.iter().flat_map(|r| &r.items).find(
            |item| matches!(item, PrefetchItem::Account { address, .. } if *address == target),
        );
        assert!(
            account_item.is_some(),
            "Should find Account item for DELEGATECALL target"
        );
        match account_item.unwrap() {
            PrefetchItem::Account { selector, .. } => {
                assert_eq!(*selector, Some(expected_sel));
            }
            _ => unreachable!(),
        }
    }

    // ── Stateless contract pattern ───────────────────────────────────────

    /// A contract that only does external CALLs (no SLOADs) should still
    /// produce Account items. Regression test for router-like contracts.
    #[test]
    fn stateless_contract_produces_account_items() {
        // Bytecode with dispatch → CALL to hardcoded address, no SLOAD
        let target = Address::from_slice(&[
            0xfa, 0xc7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]);
        let sel_word = [0xe6, 0xa4, 0x39, 0x05u8]; // getPair selector

        let mut bc = vec![0u8; 256];
        // Dispatch: PUSH4 <sel> EQ PUSH1 0x40 JUMPI STOP
        bc[0] = 0x63; // PUSH4
        bc[1..5].copy_from_slice(&[0xaa, 0xaa, 0xaa, 0xaa]);
        bc[5] = EQ;
        bc[6] = PUSH1;
        bc[7] = 0x40;
        bc[8] = JUMPI;
        bc[9] = STOP;

        // Handler at 0x40: store selector in mem, STATICCALL to target, STOP
        let mut p = 0x40;
        bc[p] = JUMPDEST;
        p += 1;
        // MSTORE selector at mem[0x80]
        bc[p] = PUSH32;
        p += 1;
        let mut sw = [0u8; 32];
        sw[0..4].copy_from_slice(&sel_word);
        bc[p..p + 32].copy_from_slice(&sw);
        p += 32;
        bc[p] = PUSH1;
        p += 1;
        bc[p] = 0x80;
        p += 1;
        bc[p] = MSTORE;
        p += 1;
        // STATICCALL(gas, target, argsOff=0x80, argsLen=4, retOff=0, retLen=0)
        bc[p] = PUSH1;
        p += 1;
        bc[p] = 0x00;
        p += 1; // retLen
        bc[p] = PUSH1;
        p += 1;
        bc[p] = 0x00;
        p += 1; // retOff
        bc[p] = PUSH1;
        p += 1;
        bc[p] = 0x04;
        p += 1; // argsLen
        bc[p] = PUSH1;
        p += 1;
        bc[p] = 0x80;
        p += 1; // argsOff
        bc[p] = 0x73;
        p += 1; // PUSH20
        bc[p..p + 20].copy_from_slice(target.as_slice());
        p += 20;
        bc[p] = GAS;
        p += 1;
        bc[p] = STATICCALL;
        p += 1;
        bc[p] = STOP;

        let results = analyze_bytecode(&bc);
        let sel_entry = results
            .iter()
            .find(|r| r.selector == FixedBytes::from([0xaa, 0xaa, 0xaa, 0xaa]));
        assert!(sel_entry.is_some(), "Should find selector entry");
        let items = &sel_entry.unwrap().items;
        // No SLOAD items expected (stateless)
        assert!(
            !items
                .iter()
                .any(|i| matches!(i, PrefetchItem::Storage { .. })),
            "Stateless contract should not have Storage items",
        );
        // Should have Account item with selector
        let acct = items
            .iter()
            .find(|i| matches!(i, PrefetchItem::Account { address, .. } if *address == target));
        assert!(acct.is_some(), "Should have Account item for CALL target");
        match acct.unwrap() {
            PrefetchItem::Account { selector, .. } => {
                assert_eq!(*selector, Some(FixedBytes::from(sel_word)));
            }
            _ => unreachable!(),
        }
    }

    /// 6 consecutive guard JUMPIs (each: condition PUSH2 <forward> JUMPI; REVERT; JUMPDEST)
    /// followed by PUSH1 42 SLOAD STOP. Forward branches get no decay (full budget),
    /// so the SLOAD is always discovered. MAX_BRANCH_DEPTH + visited set bound work.
    #[test]
    fn forward_branch_guards_discover_sload() {
        let mut code = Vec::new();

        // Fake dispatch: PUSH4 0x11223344 EQ ...
        // We'll craft a selector dispatch + 6 guards + SLOAD
        let sel: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

        // Dispatch: PUSH1 0 CALLDATALOAD PUSH1 0xe0 SHR
        code.extend_from_slice(&[0x60, 0x00, 0x35, 0x60, 0xe0, 0x1c]);
        // PUSH4 sel EQ PUSH2 <handler> JUMPI
        code.extend_from_slice(&[0x63, sel[0], sel[1], sel[2], sel[3], 0x14]);
        // We'll patch the handler address once we know it
        let handler_push_idx = code.len();
        code.extend_from_slice(&[0x61, 0x00, 0x00]); // PUSH2 placeholder
        code.push(0x57); // JUMPI
                         // Default: STOP
        code.push(0x00);

        // Handler starts here
        let handler_pc = code.len();
        code[handler_push_idx + 1] = ((handler_pc >> 8) & 0xff) as u8;
        code[handler_push_idx + 2] = (handler_pc & 0xff) as u8;
        code.push(0x5b); // JUMPDEST

        // 6 consecutive guard checks:
        // Each: PUSH1 1 PUSH2 <after_revert> JUMPI PUSH1 0 PUSH1 0 REVERT JUMPDEST
        for _ in 0..6 {
            code.push(0x60);
            code.push(0x01); // PUSH1 1 (nonzero = condition true)
            let jump_push_idx = code.len();
            code.extend_from_slice(&[0x61, 0x00, 0x00]); // PUSH2 placeholder
            code.push(0x57); // JUMPI
                             // Fallthrough = REVERT
            code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0xfd]); // PUSH1 0 PUSH1 0 REVERT
                                                                     // JUMPDEST (happy path target)
            let jumpdest_pc = code.len();
            code[jump_push_idx + 1] = ((jumpdest_pc >> 8) & 0xff) as u8;
            code[jump_push_idx + 2] = (jumpdest_pc & 0xff) as u8;
            code.push(0x5b); // JUMPDEST
        }

        // After all guards: PUSH1 42 SLOAD STOP
        code.extend_from_slice(&[0x60, 42, 0x54, 0x00]);

        let analyzed = analyze_bytecode(&code);

        // Find the entry for our selector
        let entry = analyzed
            .iter()
            .find(|a| a.selector == FixedBytes::from(sel));
        assert!(entry.is_some(), "Should find selector 0x11223344");

        let items = &entry.unwrap().items;
        let has_slot_42 = items.iter().any(|item| {
            matches!(item, PrefetchItem::Storage { slot: SlotExpression::Concrete { value } }
                if *value == B256::from(U256::from(42)))
        });
        assert!(
            has_slot_42,
            "After 6 forward guard JUMPIs, SLOAD(42) should be discovered. Items: {items:?}"
        );
    }
}
