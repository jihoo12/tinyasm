use crate::encoding::{modrm, rex, rex_w, sib};
use crate::registers::{Register, XmmRegister};
use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    UnsupportedOperand(String),
    InvalidScale(u8),
    InvalidDisplacement(String),
    Other(String),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::UnsupportedOperand(msg) => write!(f, "Unsupported operand: {}", msg),
            EncodeError::InvalidScale(scale)     => write!(f, "Invalid scale: {}", scale),
            EncodeError::InvalidDisplacement(msg)=> write!(f, "Invalid displacement: {}", msg),
            EncodeError::Other(msg)              => write!(f, "Encoding error: {}", msg),
        }
    }
}

impl std::error::Error for EncodeError {}

// ---------------------------------------------------------------------------
// Memory addressing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryAddr {
    pub base:  Option<Register>,
    pub index: Option<Register>,
    /// Must be 1, 2, 4, or 8.  Ignored when `index` is `None`.
    pub scale: u8,
    pub disp:  i32,
}

impl MemoryAddr {
    /// Convenience constructor for simple `[reg]` or `[reg + disp]` addressing.
    pub fn base_disp(base: Register, disp: i32) -> Self {
        Self { base: Some(base), index: None, scale: 1, disp }
    }
}

impl fmt::Display for MemoryAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        let mut parts: Vec<String> = Vec::new();
        if let Some(base) = self.base {
            parts.push(base.to_string());
        }
        if let Some(index) = self.index {
            parts.push(format!("{}*{}", index, self.scale));
        }
        if self.disp != 0 || parts.is_empty() {
            if self.disp > 0 && !parts.is_empty() {
                parts.push(format!("+{}", self.disp));
            } else {
                parts.push(self.disp.to_string());
            }
        }
        write!(f, "{}]", parts.join(" "))
    }
}

// ---------------------------------------------------------------------------
// Operand
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub enum Operand {
    Reg(Register),
    Imm64(u64),
    Imm32(i32),
    Mem(MemoryAddr),
    Xmm(XmmRegister),
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Reg(r)              => write!(f, "{}", r),
            Operand::Imm64(v)            => write!(f, "0x{:X}", v),
            Operand::Imm32(v) if *v < 0 => write!(f, "{}", v),
            Operand::Imm32(v)            => write!(f, "0x{:X}", v),
            Operand::Mem(m)              => write!(f, "qword {}", m),
            Operand::Xmm(r)              => write!(f, "{}", r),
        }
    }
}

// ---------------------------------------------------------------------------
// Instruction set
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Instruction {
    // Data movement
    Mov(Operand, Operand),
    Movsd(Operand, Operand),
    Addsd(Operand, Operand),
    Subsd(Operand, Operand),
    Mulsd(Operand, Operand),
    Divsd(Operand, Operand),
    Ucomisd(Operand, Operand),
    Push(Operand),
    Pop(Operand),

    // Arithmetic
    Add(Operand, Operand),
    Sub(Operand, Operand),
    IMul(Operand, Operand),   // signed multiply: dst *= src
    Mul(Operand),             // unsigned RDX:RAX = RAX * op
    Div(Operand),             // unsigned RAX / op

    // Bitwise / shift
    And(Operand, Operand),
    Or(Operand, Operand),
    Xor(Operand, Operand),
    Not(Operand),
    Shl(Operand, Operand),
    Shr(Operand, Operand),

    // Compare / test
    Cmp(Operand, Operand),
    Test(Operand, Operand),

    // Control flow (direct)
    Call(Operand),
    Ret,
    Syscall,

    // Labels and label-targeted jumps — resolved by Assembler, not Encoder.
    Label(String),
    JmpLabel(String),
    JeLabel(String),
    JneLabel(String),
    JlLabel(String),
    JleLabel(String),
    JgeLabel(String),
    JgLabel(String),
    JaLabel(String),
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Instruction::Mov(d, s)     => write!(f, "mov {}, {}", d, s),
            Instruction::Movsd(d, s)   => write!(f, "movsd {}, {}", d, s),
            Instruction::Addsd(d, s)   => write!(f, "addsd {}, {}", d, s),
            Instruction::Subsd(d, s)   => write!(f, "subsd {}, {}", d, s),
            Instruction::Mulsd(d, s)   => write!(f, "mulsd {}, {}", d, s),
            Instruction::Divsd(d, s)   => write!(f, "divsd {}, {}", d, s),
            Instruction::Ucomisd(d, s) => write!(f, "ucomisd {}, {}", d, s),
            Instruction::Push(o)       => write!(f, "push {}", o),
            Instruction::Pop(o)        => write!(f, "pop {}", o),
            Instruction::Add(d, s)     => write!(f, "add {}, {}", d, s),
            Instruction::Sub(d, s)     => write!(f, "sub {}, {}", d, s),
            Instruction::IMul(d, s)    => write!(f, "imul {}, {}", d, s),
            Instruction::Mul(o)        => write!(f, "mul {}", o),
            Instruction::Div(o)        => write!(f, "div {}", o),
            Instruction::And(d, s)     => write!(f, "and {}, {}", d, s),
            Instruction::Or(d, s)      => write!(f, "or {}, {}", d, s),
            Instruction::Xor(d, s)     => write!(f, "xor {}, {}", d, s),
            Instruction::Not(o)        => write!(f, "not {}", o),
            Instruction::Shl(d, c)     => write!(f, "shl {}, {}", d, c),
            Instruction::Shr(d, c)     => write!(f, "shr {}, {}", d, c),
            Instruction::Cmp(d, s)     => write!(f, "cmp {}, {}", d, s),
            Instruction::Test(d, s)    => write!(f, "test {}, {}", d, s),
            Instruction::Call(o)       => write!(f, "call {}", o),
            Instruction::Ret           => write!(f, "ret"),
            Instruction::Syscall       => write!(f, "syscall"),
            Instruction::Label(n)      => write!(f, "{}:", n),
            Instruction::JmpLabel(t)   => write!(f, "jmp {}", t),
            Instruction::JeLabel(t)    => write!(f, "je {}", t),
            Instruction::JneLabel(t)   => write!(f, "jne {}", t),
            Instruction::JlLabel(t)    => write!(f, "jl {}", t),
            Instruction::JleLabel(t)   => write!(f, "jle {}", t),
            Instruction::JgeLabel(t)   => write!(f, "jge {}", t),
            Instruction::JgLabel(t)    => write!(f, "jg {}", t),
            Instruction::JaLabel(t)    => write!(f, "ja {}", t),
        }
    }
}

// ---------------------------------------------------------------------------
// ModR/M + SIB encoding for memory operands
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EncodedMemory {
    modrm: u8,
    sib: Option<u8>,
    disp: i32,
    disp_size: usize,
    rex_b: bool,
    rex_x: bool,
}

impl EncodedMemory {
    fn emit(self, bytes: &mut Vec<u8>) {
        bytes.push(self.modrm);
        if let Some(sib) = self.sib {
            bytes.push(sib);
        }
        match self.disp_size {
            1 => bytes.push(self.disp as u8),
            4 => bytes.extend_from_slice(&self.disp.to_le_bytes()),
            _ => {}
        }
    }
}

/// Encode the ModR/M, optional SIB, displacement, and REX extension bits for
/// a memory operand. `reg_field` is either a register code or opcode extension.
fn encode_memory(reg_field: u8, mem: MemoryAddr) -> Result<EncodedMemory, EncodeError> {
    // Choose mod bits and displacement size.
    let (mod_bits, disp_size) = if let Some(base) = mem.base {
        // RBP/R13 with mod=00 would be interpreted as RIP-relative, so force
        // at least an 8-bit displacement.
        let bp_family = base == Register::RBP || base == Register::R13;
        if mem.disp == 0 && !bp_family {
            (0x00, 0)
        } else if (-128..=127).contains(&mem.disp) {
            (0x01, 1)
        } else {
            (0x02, 4)
        }
    } else {
        // No base → disp32 only.
        (0x00, 4)
    };

    // RSP/R12 share the 3-bit code 0b100 with the "SIB follows" sentinel, so
    // any addressing using them as the base *must* include a SIB byte.
    let use_sib = mem.index.is_some()
        || mem.base == Some(Register::RSP)
        || mem.base == Some(Register::R12);

    let rm_bits = if use_sib {
        0x04 // "SIB byte present"
    } else {
        mem.base
            .ok_or_else(|| EncodeError::Other(
                "Memory operand with no base register and no SIB".into()
            ))?
            .code()
    };

    let modrm = modrm(mod_bits, reg_field, rm_bits);
    let rex_b = mem.base.is_some_and(|r| r.is_extended());
    let rex_x = mem.index.is_some_and(|r| r.is_extended());

    let sib = if use_sib {
        let scale_bits = match mem.scale {
            1 => 0u8, 2 => 1, 4 => 2, 8 => 3,
            s => return Err(EncodeError::InvalidScale(s)),
        };
        // No index → encode index field as 0b100 (no-index sentinel).
        let index_bits = mem.index.map(|r| r.code()).unwrap_or(0x04);
        let base_bits  = mem.base.map(|r| r.code()).unwrap_or(0x05);
        Some(sib(scale_bits, index_bits, base_bits))
    } else {
        None
    };

    Ok(EncodedMemory { modrm, sib, disp: mem.disp, disp_size, rex_b, rex_x })
}

// ---------------------------------------------------------------------------
// Public encode entry point
// ---------------------------------------------------------------------------

/// Encode a single instruction to machine bytes.
///
/// Label-related variants (`Label`, `Jxx Label`) **must** be resolved by the
/// [`Assembler`] before calling this function; they return an error here.
pub fn encode_instruction(instr: Instruction) -> Result<Vec<u8>, EncodeError> {
    let mut bytes = Vec::new();
    match instr {
        // Data movement
        Instruction::Mov(dst, src)  => encode_mov(dst, src, &mut bytes)?,
        Instruction::Movsd(dst, src) => encode_movsd(dst, src, &mut bytes)?,
        Instruction::Addsd(dst, src) => encode_scalar_sse2(0x58, "ADDSD", dst, src, &mut bytes)?,
        Instruction::Subsd(dst, src) => encode_scalar_sse2(0x5C, "SUBSD", dst, src, &mut bytes)?,
        Instruction::Mulsd(dst, src) => encode_scalar_sse2(0x59, "MULSD", dst, src, &mut bytes)?,
        Instruction::Divsd(dst, src) => encode_scalar_sse2(0x5E, "DIVSD", dst, src, &mut bytes)?,
        Instruction::Ucomisd(lhs, rhs) => encode_ucomisd(lhs, rhs, &mut bytes)?,
        Instruction::Push(op)       => encode_push(op, &mut bytes)?,
        Instruction::Pop(op)        => encode_pop(op, &mut bytes)?,

        // Arithmetic
        Instruction::Add(d, s)      => encode_arithmetic(0x01, 0x03, 0, d, s, &mut bytes)?,
        Instruction::Sub(d, s)      => encode_arithmetic(0x29, 0x2B, 5, d, s, &mut bytes)?,
        Instruction::IMul(d, s)     => encode_imul(d, s, &mut bytes)?,
        Instruction::Mul(op)        => encode_unary(0xF7, 4, op, &mut bytes)?,
        Instruction::Div(op)        => encode_unary(0xF7, 6, op, &mut bytes)?,

        // Bitwise / shift
        Instruction::And(d, s)      => encode_arithmetic(0x21, 0x23, 4, d, s, &mut bytes)?,
        Instruction::Or(d, s)       => encode_arithmetic(0x09, 0x0B, 1, d, s, &mut bytes)?,
        Instruction::Xor(d, s)      => encode_arithmetic(0x31, 0x33, 6, d, s, &mut bytes)?,
        Instruction::Not(op)        => encode_unary(0xF7, 2, op, &mut bytes)?,
        Instruction::Shl(d, c)      => encode_shift(4, d, c, &mut bytes)?,
        Instruction::Shr(d, c)      => encode_shift(5, d, c, &mut bytes)?,

        // Compare / test
        Instruction::Cmp(d, s)      => encode_arithmetic(0x39, 0x3B, 7, d, s, &mut bytes)?,
        Instruction::Test(d, s)     => encode_test(d, s, &mut bytes)?,

        // Control flow
        Instruction::Call(op)       => encode_call(op, &mut bytes)?,
        Instruction::Ret            => bytes.push(0xC3),
        Instruction::Syscall        => bytes.extend_from_slice(&[0x0F, 0x05]),

        // Labels / jumps — must be handled by Assembler.
        Instruction::Label(_)
        | Instruction::JmpLabel(_)
        | Instruction::JeLabel(_)
        | Instruction::JneLabel(_)
        | Instruction::JlLabel(_)
        | Instruction::JleLabel(_)
        | Instruction::JgeLabel(_)
        | Instruction::JgLabel(_) => {
            return Err(EncodeError::Other(
                "Label/jump instructions must be handled by Assembler, not Encoder".into(),
            ));
        }
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// MOV
// ---------------------------------------------------------------------------

fn encode_mov(dst: Operand, src: Operand, bytes: &mut Vec<u8>) -> Result<(), EncodeError> {
    match (dst, src) {
        // MOV r64, imm64  →  REX.W B8+rd  id
        (Operand::Reg(r), Operand::Imm64(imm)) => {
            bytes.push(rex_w(false, false, r.is_extended()));
            bytes.push(0xB8 + r.code());
            bytes.extend_from_slice(&imm.to_le_bytes());
        }
        // MOV r64, imm32 (sign-extended)  →  REX.W C7 /0 id
        (Operand::Reg(r), Operand::Imm32(imm)) => {
            bytes.push(rex_w(false, false, r.is_extended()));
            bytes.push(0xC7);
            bytes.push(modrm(0b11, 0, r.code()));
            bytes.extend_from_slice(&imm.to_le_bytes());
        }
        // MOV r64, r64  →  REX.W 89 /r   (opcode 89: MOV r/m64, r64)
        // ModR/M: reg = src (the "reg" field), rm = dst
        (Operand::Reg(dst_r), Operand::Reg(src_r)) => {
            bytes.push(rex_w(src_r.is_extended(), false, dst_r.is_extended()));
            bytes.push(0x89);
            bytes.push(modrm(0b11, src_r.code(), dst_r.code()));
        }
        // MOV r64, [mem]  →  REX.W 8B /r
        (Operand::Reg(dst_r), Operand::Mem(mem)) => {
            let encoded = encode_memory(dst_r.code(), mem)?;
            bytes.push(rex_w(dst_r.is_extended(), encoded.rex_x, encoded.rex_b));
            bytes.push(0x8B);
            encoded.emit(bytes);
        }
        // MOV [mem], r64  →  REX.W 89 /r
        (Operand::Mem(mem), Operand::Reg(src_r)) => {
            let encoded = encode_memory(src_r.code(), mem)?;
            bytes.push(rex_w(src_r.is_extended(), encoded.rex_x, encoded.rex_b));
            bytes.push(0x89);
            encoded.emit(bytes);
        }
        _ => return Err(EncodeError::UnsupportedOperand(
            "MOV: unsupported operand combination".into()
        )),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MOVSD
// ---------------------------------------------------------------------------

fn emit_optional_rex(r: bool, x: bool, b: bool, bytes: &mut Vec<u8>) {
    if r || x || b {
        bytes.push(rex(false, r, x, b));
    }
}

fn encode_movsd(dst: Operand, src: Operand, bytes: &mut Vec<u8>) -> Result<(), EncodeError> {
    match (dst, src) {
        // MOVSD xmm, xmm/m64 -> F2 [REX] 0F 10 /r
        (Operand::Xmm(dst_r), Operand::Xmm(src_r)) => {
            bytes.push(0xF2);
            emit_optional_rex(dst_r.is_extended(), false, src_r.is_extended(), bytes);
            bytes.extend_from_slice(&[0x0F, 0x10]);
            bytes.push(modrm(0b11, dst_r.code(), src_r.code()));
        }
        (Operand::Xmm(dst_r), Operand::Mem(mem)) => {
            let encoded = encode_memory(dst_r.code(), mem)?;
            bytes.push(0xF2);
            emit_optional_rex(dst_r.is_extended(), encoded.rex_x, encoded.rex_b, bytes);
            bytes.extend_from_slice(&[0x0F, 0x10]);
            encoded.emit(bytes);
        }
        // MOVSD xmm/m64, xmm -> F2 [REX] 0F 11 /r
        (Operand::Mem(mem), Operand::Xmm(src_r)) => {
            let encoded = encode_memory(src_r.code(), mem)?;
            bytes.push(0xF2);
            emit_optional_rex(src_r.is_extended(), encoded.rex_x, encoded.rex_b, bytes);
            bytes.extend_from_slice(&[0x0F, 0x11]);
            encoded.emit(bytes);
        }
        _ => return Err(EncodeError::UnsupportedOperand(
            "MOVSD: expected xmm/xmm or xmm/memory operands".into()
        )),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Scalar SSE2 arithmetic
// ---------------------------------------------------------------------------

fn encode_scalar_sse2(
    opcode: u8,
    name: &str,
    dst: Operand,
    src: Operand,
    bytes: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let dst_r = match dst {
        Operand::Xmm(r) => r,
        _ => return Err(EncodeError::UnsupportedOperand(
            format!("{}: destination must be an XMM register", name)
        )),
    };

    bytes.push(0xF2);
    match src {
        Operand::Xmm(src_r) => {
            emit_optional_rex(dst_r.is_extended(), false, src_r.is_extended(), bytes);
            bytes.extend_from_slice(&[0x0F, opcode]);
            bytes.push(modrm(0b11, dst_r.code(), src_r.code()));
        }
        Operand::Mem(mem) => {
            let encoded = encode_memory(dst_r.code(), mem)?;
            emit_optional_rex(dst_r.is_extended(), encoded.rex_x, encoded.rex_b, bytes);
            bytes.extend_from_slice(&[0x0F, opcode]);
            encoded.emit(bytes);
        }
        _ => return Err(EncodeError::UnsupportedOperand(
            format!("{}: source must be an XMM register or memory", name)
        )),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SSE2 compare
// ---------------------------------------------------------------------------

fn encode_ucomisd(lhs: Operand, rhs: Operand, bytes: &mut Vec<u8>) -> Result<(), EncodeError> {
    let lhs_r = match lhs {
        Operand::Xmm(r) => r,
        _ => return Err(EncodeError::UnsupportedOperand(
            "UCOMISD: left operand must be an XMM register".into()
        )),
    };

    bytes.push(0x66);
    match rhs {
        Operand::Xmm(rhs_r) => {
            emit_optional_rex(lhs_r.is_extended(), false, rhs_r.is_extended(), bytes);
            bytes.extend_from_slice(&[0x0F, 0x2E]);
            bytes.push(modrm(0b11, lhs_r.code(), rhs_r.code()));
        }
        Operand::Mem(mem) => {
            let encoded = encode_memory(lhs_r.code(), mem)?;
            emit_optional_rex(lhs_r.is_extended(), encoded.rex_x, encoded.rex_b, bytes);
            bytes.extend_from_slice(&[0x0F, 0x2E]);
            encoded.emit(bytes);
        }
        _ => return Err(EncodeError::UnsupportedOperand(
            "UCOMISD: right operand must be an XMM register or memory".into()
        )),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PUSH / POP
// ---------------------------------------------------------------------------

fn encode_push(op: Operand, bytes: &mut Vec<u8>) -> Result<(), EncodeError> {
    match op {
        // PUSH r64  →  (REX.B?) 50+rd
        Operand::Reg(r) => {
            if r.is_extended() { bytes.push(0x41); } // REX.B
            bytes.push(0x50 + r.code());
        }
        // PUSH imm32 (sign-extended to 64 bits)  →  68 id
        Operand::Imm32(imm) => {
            if (-128..=127).contains(&imm) {
                bytes.push(0x6A);
                bytes.push(imm as u8);
            } else {
                bytes.push(0x68);
                bytes.extend_from_slice(&imm.to_le_bytes());
            }
        }
        // PUSH [mem]  →  REX.W FF /6
        Operand::Mem(mem) => {
            let encoded = encode_memory(6, mem)?;
            bytes.push(rex_w(false, encoded.rex_x, encoded.rex_b));
            bytes.push(0xFF);
            encoded.emit(bytes);
        }
        _ => return Err(EncodeError::UnsupportedOperand("PUSH: unsupported operand".into())),
    }
    Ok(())
}

fn encode_pop(op: Operand, bytes: &mut Vec<u8>) -> Result<(), EncodeError> {
    match op {
        // POP r64  →  (REX.B?) 58+rd
        Operand::Reg(r) => {
            if r.is_extended() { bytes.push(0x41); } // REX.B
            bytes.push(0x58 + r.code());
        }
        // POP [mem]  →  REX.W 8F /0
        Operand::Mem(mem) => {
            let encoded = encode_memory(0, mem)?;
            bytes.push(rex_w(false, encoded.rex_x, encoded.rex_b));
            bytes.push(0x8F);
            encoded.emit(bytes);
        }
        _ => return Err(EncodeError::UnsupportedOperand("POP: unsupported operand".into())),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// IMUL (two-operand: dst r64 *= src r/m64)
// ---------------------------------------------------------------------------

fn encode_imul(dst: Operand, src: Operand, bytes: &mut Vec<u8>) -> Result<(), EncodeError> {
    match (dst, src) {
        // IMUL r64, r/m64  →  REX.W 0F AF /r
        (Operand::Reg(dst_r), Operand::Reg(src_r)) => {
            bytes.push(rex_w(dst_r.is_extended(), false, src_r.is_extended()));
            bytes.extend_from_slice(&[0x0F, 0xAF]);
            bytes.push(modrm(0b11, dst_r.code(), src_r.code()));
        }
        (Operand::Reg(dst_r), Operand::Mem(mem)) => {
            let encoded = encode_memory(dst_r.code(), mem)?;
            bytes.push(rex_w(dst_r.is_extended(), encoded.rex_x, encoded.rex_b));
            bytes.extend_from_slice(&[0x0F, 0xAF]);
            encoded.emit(bytes);
        }
        // IMUL r64, r/m64, imm8  →  REX.W 6B /r ib
        (Operand::Reg(dst_r), Operand::Imm32(imm)) if (-128..=127).contains(&imm) => {
            bytes.push(rex_w(dst_r.is_extended(), false, false));
            bytes.push(0x6B);
            // Self-multiply: dst = dst * imm  (src same as dst in ModR/M)
            bytes.push(modrm(0b11, dst_r.code(), dst_r.code()));
            bytes.push(imm as u8);
        }
        // IMUL r64, r/m64, imm32  →  REX.W 69 /r id
        (Operand::Reg(dst_r), Operand::Imm32(imm)) => {
            bytes.push(rex_w(dst_r.is_extended(), false, false));
            bytes.push(0x69);
            bytes.push(modrm(0b11, dst_r.code(), dst_r.code()));
            bytes.extend_from_slice(&imm.to_le_bytes());
        }
        _ => return Err(EncodeError::UnsupportedOperand(
            "IMUL: destination must be a register".into()
        )),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CALL
// ---------------------------------------------------------------------------

fn encode_call(op: Operand, bytes: &mut Vec<u8>) -> Result<(), EncodeError> {
    match op {
        // CALL r64  →  (REX.B?) FF /2
        Operand::Reg(r) => {
            if r.is_extended() { bytes.push(0x41); }
            bytes.push(0xFF);
            bytes.push(modrm(0b11, 2, r.code())); // ModR/M: mod=11, reg=2, rm=r
        }
        // CALL [mem]  →  REX.W FF /2
        Operand::Mem(mem) => {
            let encoded = encode_memory(2, mem)?;
            bytes.push(rex_w(false, encoded.rex_x, encoded.rex_b));
            bytes.push(0xFF);
            encoded.emit(bytes);
        }
        _ => return Err(EncodeError::UnsupportedOperand(
            "CALL: operand must be a register or memory".into()
        )),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Generic arithmetic (ADD / SUB / AND / OR / XOR / CMP)
// ---------------------------------------------------------------------------

/// Encode a two-operand arithmetic instruction.
///
/// - `op_mr`   — opcode for `reg/mem, reg`  (e.g. `0x01` for ADD)
/// - `op_rm`   — opcode for `reg, reg/mem`  (e.g. `0x03` for ADD)
/// - `ext_idx` — `/digit` extension for the immediate form (e.g. `0` for ADD)
fn encode_arithmetic(
    op_mr:   u8,
    op_rm:   u8,
    ext_idx: u8,
    dst: Operand,
    src: Operand,
    bytes: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    match (dst, src) {
        // op r64, r64
        (Operand::Reg(dst_r), Operand::Reg(src_r)) => {
            bytes.push(rex_w(src_r.is_extended(), false, dst_r.is_extended()));
            bytes.push(op_mr);
            bytes.push(modrm(0b11, src_r.code(), dst_r.code()));
        }
        // op r64, [mem]
        (Operand::Reg(dst_r), Operand::Mem(mem)) => {
            let encoded = encode_memory(dst_r.code(), mem)?;
            bytes.push(rex_w(dst_r.is_extended(), encoded.rex_x, encoded.rex_b));
            bytes.push(op_rm);
            encoded.emit(bytes);
        }
        // op [mem], r64
        (Operand::Mem(mem), Operand::Reg(src_r)) => {
            let encoded = encode_memory(src_r.code(), mem)?;
            bytes.push(rex_w(src_r.is_extended(), encoded.rex_x, encoded.rex_b));
            bytes.push(op_mr);
            encoded.emit(bytes);
        }
        // op r/m64, imm8 (sign-extended) or imm32
        (dst, Operand::Imm32(imm)) => {
            let (opcode, is_imm8) = if (-128..=127).contains(&imm) {
                (0x83u8, true)
            } else {
                (0x81u8, false)
            };
            match dst {
                Operand::Reg(r) => {
                    bytes.push(rex_w(false, false, r.is_extended()));
                    bytes.push(opcode);
                    bytes.push(modrm(0b11, ext_idx, r.code()));
                }
                Operand::Mem(mem) => {
                    let encoded = encode_memory(ext_idx, mem)?;
                    bytes.push(rex_w(false, encoded.rex_x, encoded.rex_b));
                    bytes.push(opcode);
                    encoded.emit(bytes);
                }
                _ => return Err(EncodeError::UnsupportedOperand(
                    "Arithmetic Imm: destination must be register or memory".into()
                )),
            }
            if is_imm8 {
                bytes.push(imm as u8);
            } else {
                bytes.extend_from_slice(&imm.to_le_bytes());
            }
        }
        _ => return Err(EncodeError::UnsupportedOperand("Arithmetic: unsupported operands".into())),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TEST
// ---------------------------------------------------------------------------

fn encode_test(dst: Operand, src: Operand, bytes: &mut Vec<u8>) -> Result<(), EncodeError> {
    match (dst, src) {
        // TEST r/m64, r64  →  REX.W 85 /r
        (Operand::Reg(dst_r), Operand::Reg(src_r)) => {
            bytes.push(rex_w(src_r.is_extended(), false, dst_r.is_extended()));
            bytes.push(0x85);
            bytes.push(modrm(0b11, src_r.code(), dst_r.code()));
        }
        // TEST r/m64, imm32  →  REX.W F7 /0 id
        (Operand::Reg(r), Operand::Imm32(imm)) => {
            bytes.push(rex_w(false, false, r.is_extended()));
            bytes.push(0xF7);
            bytes.push(modrm(0b11, 0, r.code())); // /0
            bytes.extend_from_slice(&imm.to_le_bytes());
        }
        _ => return Err(EncodeError::UnsupportedOperand("TEST: unsupported operands".into())),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shifts
// ---------------------------------------------------------------------------

fn encode_shift(
    ext_idx: u8,
    dst:   Operand,
    count: Operand,
    bytes: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    let (opcode, emit_imm) = match count {
        Operand::Reg(Register::RCX) => (0xD3u8, false), // shift by CL
        Operand::Imm32(1)           => (0xD1,   false), // shift by 1 (implicit)
        Operand::Imm32(_)           => (0xC1,   true),  // shift by imm8
        _ => return Err(EncodeError::UnsupportedOperand(
            "Shift count must be CL register or an immediate".into()
        )),
    };

    match dst {
        Operand::Reg(r) => {
            bytes.push(rex_w(false, false, r.is_extended()));
            bytes.push(opcode);
            bytes.push(modrm(0b11, ext_idx, r.code()));
        }
        Operand::Mem(mem) => {
            let encoded = encode_memory(ext_idx, mem)?;
            bytes.push(rex_w(false, encoded.rex_x, encoded.rex_b));
            bytes.push(opcode);
            encoded.emit(bytes);
        }
        _ => return Err(EncodeError::UnsupportedOperand("Shift dst must be register or memory".into())),
    }

    if emit_imm {
        if let Operand::Imm32(imm) = count {
            bytes.push(imm as u8);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unary (NOT / MUL / DIV)
// ---------------------------------------------------------------------------

fn encode_unary(opcode: u8, ext_idx: u8, op: Operand, bytes: &mut Vec<u8>) -> Result<(), EncodeError> {
    match op {
        Operand::Reg(r) => {
            bytes.push(rex_w(false, false, r.is_extended()));
            bytes.push(opcode);
            bytes.push(modrm(0b11, ext_idx, r.code()));
        }
        Operand::Mem(mem) => {
            let encoded = encode_memory(ext_idx, mem)?;
            bytes.push(rex_w(false, encoded.rex_x, encoded.rex_b));
            bytes.push(opcode);
            encoded.emit(bytes);
        }
        _ => return Err(EncodeError::UnsupportedOperand("Unary: operand must be register or memory".into())),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registers::Register::*;

    fn enc(instr: Instruction) -> Vec<u8> {
        encode_instruction(instr).unwrap()
    }

    #[test]
    fn mov_register_and_immediate_encodings() {
        assert_eq!(enc(Instruction::Mov(Operand::Reg(RAX), Operand::Reg(RCX))), vec![0x48, 0x89, 0xC8]);
        assert_eq!(enc(Instruction::Mov(Operand::Reg(R8), Operand::Reg(R9))), vec![0x4D, 0x89, 0xC8]);
        assert_eq!(enc(Instruction::Mov(Operand::Reg(RAX), Operand::Imm32(-1))), vec![0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn memory_addressing_covers_sib_and_special_bases() {
        let rsp = MemoryAddr::base_disp(RSP, 0);
        assert_eq!(enc(Instruction::Mov(Operand::Reg(RAX), Operand::Mem(rsp))), vec![0x48, 0x8B, 0x04, 0x24]);

        let r12 = MemoryAddr::base_disp(R12, 0);
        assert_eq!(enc(Instruction::Mov(Operand::Reg(RAX), Operand::Mem(r12))), vec![0x49, 0x8B, 0x04, 0x24]);

        let rbp = MemoryAddr::base_disp(RBP, 0);
        assert_eq!(enc(Instruction::Mov(Operand::Reg(RAX), Operand::Mem(rbp))), vec![0x48, 0x8B, 0x45, 0x00]);

        let r13 = MemoryAddr::base_disp(R13, 0);
        assert_eq!(enc(Instruction::Mov(Operand::Reg(RAX), Operand::Mem(r13))), vec![0x49, 0x8B, 0x45, 0x00]);
    }

    #[test]
    fn indexed_memory_encodes_scale_index_base_and_displacement() {
        let mem = MemoryAddr { base: Some(RAX), index: Some(RCX), scale: 4, disp: 16 };
        assert_eq!(enc(Instruction::Mov(Operand::Reg(RDX), Operand::Mem(mem))), vec![0x48, 0x8B, 0x54, 0x88, 0x10]);

        let extended = MemoryAddr { base: Some(R12), index: Some(R9), scale: 8, disp: 0x1234 };
        assert_eq!(enc(Instruction::Mov(Operand::Reg(R10), Operand::Mem(extended))), vec![0x4F, 0x8B, 0x94, 0xCC, 0x34, 0x12, 0x00, 0x00]);
    }

    #[test]
    fn arithmetic_selects_imm8_or_imm32_at_boundary() {
        assert_eq!(enc(Instruction::Add(Operand::Reg(RAX), Operand::Imm32(127))), vec![0x48, 0x83, 0xC0, 0x7F]);
        assert_eq!(enc(Instruction::Add(Operand::Reg(RAX), Operand::Imm32(128))), vec![0x48, 0x81, 0xC0, 0x80, 0x00, 0x00, 0x00]);
        assert_eq!(enc(Instruction::Sub(Operand::Reg(R8), Operand::Imm32(-128))), vec![0x49, 0x83, 0xE8, 0x80]);
        assert_eq!(enc(Instruction::Sub(Operand::Reg(R8), Operand::Imm32(-129))), vec![0x49, 0x81, 0xE8, 0x7F, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn representative_instruction_families_encode_stably() {
        assert_eq!(enc(Instruction::IMul(Operand::Reg(R10), Operand::Reg(R11))), vec![0x4D, 0x0F, 0xAF, 0xD3]);
        assert_eq!(enc(Instruction::Xor(Operand::Reg(RAX), Operand::Reg(RAX))), vec![0x48, 0x31, 0xC0]);
        assert_eq!(enc(Instruction::Test(Operand::Reg(R8), Operand::Reg(R9))), vec![0x4D, 0x85, 0xC8]);
        assert_eq!(enc(Instruction::Not(Operand::Reg(R12))), vec![0x49, 0xF7, 0xD4]);
        assert_eq!(enc(Instruction::Shl(Operand::Reg(RAX), Operand::Imm32(1))), vec![0x48, 0xD1, 0xE0]);
        assert_eq!(enc(Instruction::Shr(Operand::Reg(R9), Operand::Reg(RCX))), vec![0x49, 0xD3, 0xE9]);
        assert_eq!(enc(Instruction::Call(Operand::Reg(R10))), vec![0x41, 0xFF, 0xD2]);
        assert_eq!(enc(Instruction::Ret), vec![0xC3]);
        assert_eq!(enc(Instruction::Syscall), vec![0x0F, 0x05]);
    }

    #[test]
    fn movsd_encodes_register_forms() {
        use crate::registers::XmmRegister::*;

        assert_eq!(enc(Instruction::Movsd(Operand::Xmm(XMM0), Operand::Xmm(XMM1))), vec![0xF2, 0x0F, 0x10, 0xC1]);
        assert_eq!(enc(Instruction::Movsd(Operand::Xmm(XMM8), Operand::Xmm(XMM9))), vec![0xF2, 0x45, 0x0F, 0x10, 0xC1]);
    }

    #[test]
    fn movsd_encodes_memory_load_and_store() {
        use crate::registers::XmmRegister::*;

        let load = MemoryAddr::base_disp(R12, 16);
        assert_eq!(enc(Instruction::Movsd(Operand::Xmm(XMM10), Operand::Mem(load))), vec![0xF2, 0x45, 0x0F, 0x10, 0x54, 0x24, 0x10]);

        let store = MemoryAddr::base_disp(R13, 0);
        assert_eq!(enc(Instruction::Movsd(Operand::Mem(store), Operand::Xmm(XMM15))), vec![0xF2, 0x45, 0x0F, 0x11, 0x7D, 0x00]);
    }

    #[test]
    fn scalar_sse2_arithmetic_encodes_register_forms() {
        use crate::registers::XmmRegister::*;

        assert_eq!(enc(Instruction::Addsd(Operand::Xmm(XMM0), Operand::Xmm(XMM1))), vec![0xF2, 0x0F, 0x58, 0xC1]);
        assert_eq!(enc(Instruction::Mulsd(Operand::Xmm(XMM8), Operand::Xmm(XMM9))), vec![0xF2, 0x45, 0x0F, 0x59, 0xC1]);
        assert_eq!(enc(Instruction::Subsd(Operand::Xmm(XMM2), Operand::Xmm(XMM3))), vec![0xF2, 0x0F, 0x5C, 0xD3]);
        assert_eq!(enc(Instruction::Divsd(Operand::Xmm(XMM15), Operand::Xmm(XMM14))), vec![0xF2, 0x45, 0x0F, 0x5E, 0xFE]);
    }

    #[test]
    fn scalar_sse2_arithmetic_encodes_memory_forms() {
        use crate::registers::XmmRegister::*;

        let simple = MemoryAddr::base_disp(RAX, 8);
        assert_eq!(enc(Instruction::Addsd(Operand::Xmm(XMM1), Operand::Mem(simple))), vec![0xF2, 0x0F, 0x58, 0x48, 0x08]);

        let extended = MemoryAddr { base: Some(R12), index: Some(R9), scale: 8, disp: 32 };
        assert_eq!(enc(Instruction::Divsd(Operand::Xmm(XMM10), Operand::Mem(extended))), vec![0xF2, 0x47, 0x0F, 0x5E, 0x54, 0xCC, 0x20]);
    }

    #[test]
    fn scalar_sse2_arithmetic_rejects_invalid_operands() {
        use crate::registers::XmmRegister::XMM0;

        assert!(matches!(
            encode_instruction(Instruction::Addsd(Operand::Reg(RAX), Operand::Xmm(XMM0))),
            Err(EncodeError::UnsupportedOperand(_))
        ));
        assert!(matches!(
            encode_instruction(Instruction::Addsd(Operand::Xmm(XMM0), Operand::Imm32(1))),
            Err(EncodeError::UnsupportedOperand(_))
        ));
    }

    #[test]
    fn ucomisd_encodes_register_and_memory_forms() {
        use crate::registers::XmmRegister::*;

        assert_eq!(enc(Instruction::Ucomisd(Operand::Xmm(XMM0), Operand::Xmm(XMM1))), vec![0x66, 0x0F, 0x2E, 0xC1]);
        assert_eq!(enc(Instruction::Ucomisd(Operand::Xmm(XMM10), Operand::Xmm(XMM9))), vec![0x66, 0x45, 0x0F, 0x2E, 0xD1]);

        let mem = MemoryAddr::base_disp(R12, 16);
        assert_eq!(enc(Instruction::Ucomisd(Operand::Xmm(XMM8), Operand::Mem(mem))), vec![0x66, 0x45, 0x0F, 0x2E, 0x44, 0x24, 0x10]);
    }

    #[test]
    fn invalid_scale_is_rejected() {
        let mem = MemoryAddr { base: Some(RAX), index: Some(RCX), scale: 3, disp: 0 };
        assert_eq!(
            encode_instruction(Instruction::Mov(Operand::Reg(RDX), Operand::Mem(mem))),
            Err(EncodeError::InvalidScale(3))
        );
    }
}
