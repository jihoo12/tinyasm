use crate::registers::Register;
use std::fmt;

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
            EncodeError::InvalidScale(scale) => write!(f, "Invalid scale: {}", scale),
            EncodeError::InvalidDisplacement(msg) => write!(f, "Invalid displacement: {}", msg),
            EncodeError::Other(msg) => write!(f, "Encoding error: {}", msg),
        }
    }
}

impl std::error::Error for EncodeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryAddr {
    pub base: Option<Register>,
    pub index: Option<Register>,
    pub scale: u8,
    pub disp: i32,
}

impl fmt::Display for MemoryAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        let mut parts = Vec::new();
        if let Some(base) = self.base {
            parts.push(format!("{}", base));
        }
        if let Some(index) = self.index {
            parts.push(format!("{}*{}", index, self.scale));
        }
        if self.disp != 0 || parts.is_empty() {
            if self.disp > 0 && !parts.is_empty() {
                parts.push(format!("+{}", self.disp));
            } else {
                parts.push(format!("{}", self.disp));
            }
        }
        write!(f, "{}]", parts.join(" "))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Operand {
    Reg(Register),
    Imm64(u64),
    Imm32(i32),
    Mem(MemoryAddr),
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Reg(r) => write!(f, "{}", r),
            Operand::Imm64(val) => write!(f, "0x{:X}", val),
            // FIX: Show negative immediates in decimal for readability
            Operand::Imm32(val) if *val < 0 => write!(f, "{}", val),
            Operand::Imm32(val) => write!(f, "0x{:X}", val),
            Operand::Mem(mem) => write!(f, "qword {}", mem),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Instruction {
    Mov(Operand, Operand),
    Add(Operand, Operand),
    Sub(Operand, Operand),
    And(Operand, Operand),
    Or(Operand, Operand),
    Xor(Operand, Operand),
    Not(Operand),
    Shl(Operand, Operand),
    Shr(Operand, Operand),
    Mul(Operand),
    Div(Operand),
    Syscall,
    Ret,
    // Label / jump variants (resolved by Assembler, not Encoder)
    Label(String),
    JmpLabel(String),
    JeLabel(String),
    JneLabel(String),
    JlLabel(String),
    JgeLabel(String),
    Cmp(Operand, Operand),
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Instruction::Mov(dst, src)      => write!(f, "mov {}, {}", dst, src),
            Instruction::Add(dst, src)      => write!(f, "add {}, {}", dst, src),
            Instruction::Sub(dst, src)      => write!(f, "sub {}, {}", dst, src),
            Instruction::And(dst, src)      => write!(f, "and {}, {}", dst, src),
            Instruction::Or(dst, src)       => write!(f, "or {}, {}", dst, src),
            Instruction::Xor(dst, src)      => write!(f, "xor {}, {}", dst, src),
            Instruction::Not(op)            => write!(f, "not {}", op),
            Instruction::Shl(dst, count)    => write!(f, "shl {}, {}", dst, count),
            Instruction::Shr(dst, count)    => write!(f, "shr {}, {}", dst, count),
            Instruction::Mul(op)            => write!(f, "mul {}", op),
            Instruction::Div(op)            => write!(f, "div {}", op),
            Instruction::Syscall            => write!(f, "syscall"),
            Instruction::Ret                => write!(f, "ret"),
            Instruction::Label(name)        => write!(f, "{}:", name),
            Instruction::JmpLabel(t)        => write!(f, "jmp {}", t),
            Instruction::JeLabel(t)         => write!(f, "je {}", t),
            Instruction::JneLabel(t)        => write!(f, "jne {}", t),
            Instruction::JlLabel(t)         => write!(f, "jl {}", t),
            Instruction::JgeLabel(t)        => write!(f, "jge {}", t),
            Instruction::Cmp(dst, src)      => write!(f, "cmp {}, {}", dst, src),
        }
    }
}

// --- Encoding utilities ---

fn push_displacement(disp: i32, size: usize, bytes: &mut Vec<u8>) {
    match size {
        1 => bytes.push(disp as u8),
        4 => bytes.extend_from_slice(&disp.to_le_bytes()),
        _ => {}
    }
}

/// Encodes the ModR/M + optional SIB for a memory operand.
///
/// Returns `(modrm, sib, disp_size, rex_b, rex_x)`.
fn encode_mem_parts(
    reg_val_code: u8,
    mem: MemoryAddr,
) -> Result<(u8, Option<u8>, usize, bool, bool), EncodeError> {
    let (mod_bits, disp_size) = if let Some(base) = mem.base {
        // RBP/R13 can't use mod=00 (would be interpreted as RIP-relative),
        // so force at least an 8-bit displacement of 0.
        let is_bp_family = base == Register::RBP || base == Register::R13;
        if mem.disp == 0 && !is_bp_family {
            (0x00, 0)
        } else if (-128..=127).contains(&mem.disp) {
            (0x01, 1)
        } else {
            (0x02, 4)
        }
    } else {
        // No base register → disp32 only addressing
        (0x00, 4)
    };

    // FIX: The original code had a stray semicolon that split the boolean
    // expression into two statements, silently ignoring the R12 check.
    // R12 shares its 3-bit code with RSP (0b100), so the processor always
    // interprets rm=0b100 as "SIB follows" — we must use SIB for both.
    let use_sib = mem.index.is_some()
        || mem.base == Some(Register::RSP)
        || mem.base == Some(Register::R12);

    let rm_bits = if use_sib {
        0x04 // signals "SIB byte present"
    } else {
        // Safe unwrap: if !use_sib there must be a base register.
        mem.base
            .ok_or_else(|| EncodeError::Other("Memory operand with no base and no SIB".into()))?
            .code()
    };

    let modrm = (mod_bits << 6) | (reg_val_code << 3) | rm_bits;

    let rex_b = mem.base.map_or(false, |r| r.is_extended());
    let rex_x = mem.index.map_or(false, |r| r.is_extended());

    if use_sib {
        let scale_bits = match mem.scale {
            1 => 0u8,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => return Err(EncodeError::InvalidScale(mem.scale)),
        };
        // No index → encode index field as 0b100 (no-index sentinel)
        let index_bits = mem.index.map(|r| r.code()).unwrap_or(0x04);
        let base_bits = mem.base.map(|r| r.code()).unwrap_or(0x05);
        let sib = (scale_bits << 6) | (index_bits << 3) | base_bits;
        Ok((modrm, Some(sib), disp_size, rex_b, rex_x))
    } else {
        Ok((modrm, None, disp_size, rex_b, rex_x))
    }
}

/// Encode a single instruction to machine bytes.
///
/// Label-related variants (`Label`, `JmpLabel`, `JeLabel`, `JneLabel`,
/// `JlLabel`, `JgeLabel`) **must** be resolved by the `Assembler` before
/// calling this function and will return an error if encountered here.
pub fn encode_instruction(instr: Instruction) -> Result<Vec<u8>, EncodeError> {
    let mut bytes = Vec::new();
    match instr {
        Instruction::Mov(dst, src)      => encode_mov(dst, src, &mut bytes)?,
        Instruction::Add(dst, src)      => encode_arithmetic(0x01, 0x03, 0, dst, src, &mut bytes)?,
        Instruction::Sub(dst, src)      => encode_arithmetic(0x29, 0x2B, 5, dst, src, &mut bytes)?,
        Instruction::And(dst, src)      => encode_arithmetic(0x21, 0x23, 4, dst, src, &mut bytes)?,
        Instruction::Or(dst, src)       => encode_arithmetic(0x09, 0x0B, 1, dst, src, &mut bytes)?,
        Instruction::Xor(dst, src)      => encode_arithmetic(0x31, 0x33, 6, dst, src, &mut bytes)?,
        Instruction::Shl(dst, count)    => encode_shift(4, dst, count, &mut bytes)?,
        Instruction::Shr(dst, count)    => encode_shift(5, dst, count, &mut bytes)?,
        Instruction::Not(op)            => encode_unary(0xF7, 2, op, &mut bytes)?,
        Instruction::Mul(op)            => encode_unary(0xF7, 4, op, &mut bytes)?,
        Instruction::Div(op)            => encode_unary(0xF7, 6, op, &mut bytes)?,
        Instruction::Syscall            => bytes.extend_from_slice(&[0x0F, 0x05]),
        Instruction::Ret                => bytes.push(0xC3),
        Instruction::Cmp(dst, src)      => encode_arithmetic(0x39, 0x3B, 7, dst, src, &mut bytes)?,

        // Label / jump variants are resolved by Assembler — reject here.
        Instruction::Label(_)
        | Instruction::JmpLabel(_)
        | Instruction::JeLabel(_)
        | Instruction::JneLabel(_)
        | Instruction::JlLabel(_)
        | Instruction::JgeLabel(_) => {
            return Err(EncodeError::Other(
                "Label/jump instructions must be handled by Assembler, not Encoder".into(),
            ));
        }
    }
    Ok(bytes)
}

fn encode_mov(dst: Operand, src: Operand, bytes: &mut Vec<u8>) -> Result<(), EncodeError> {
    match (dst, src) {
        // MOV r64, imm64  (REX.W B8+rd)
        (Operand::Reg(r), Operand::Imm64(imm)) => {
            let mut rex = 0x48u8;
            if r.is_extended() { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(0xB8 + r.code());
            bytes.extend_from_slice(&imm.to_le_bytes());
        }
        // MOV r64, imm32 sign-extended  (REX.W C7 /0 id)
        (Operand::Reg(r), Operand::Imm32(imm)) => {
            let mut rex = 0x48u8;
            if r.is_extended() { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(0xC7);
            bytes.push(0xC0 | r.code());
            bytes.extend_from_slice(&imm.to_le_bytes());
        }
        // MOV r64, r64
        (Operand::Reg(dst_r), Operand::Reg(src_r)) => {
            let mut rex = 0x48u8;
            if src_r.is_extended() { rex |= 0x04; }
            if dst_r.is_extended() { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(0x89);
            bytes.push(0xC0 | (src_r.code() << 3) | dst_r.code());
        }
        // MOV r64, [mem]
        (Operand::Reg(dst_r), Operand::Mem(mem)) => {
            let (modrm, sib, disp_sz, rex_b, rex_x) = encode_mem_parts(dst_r.code(), mem)?;
            let mut rex = 0x48u8;
            if dst_r.is_extended() { rex |= 0x04; }
            if rex_x { rex |= 0x02; }
            if rex_b { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(0x8B);
            bytes.push(modrm);
            if let Some(s) = sib { bytes.push(s); }
            push_displacement(mem.disp, disp_sz, bytes);
        }
        // MOV [mem], r64
        (Operand::Mem(mem), Operand::Reg(src_r)) => {
            let (modrm, sib, disp_sz, rex_b, rex_x) = encode_mem_parts(src_r.code(), mem)?;
            let mut rex = 0x48u8;
            if src_r.is_extended() { rex |= 0x04; }
            if rex_x { rex |= 0x02; }
            if rex_b { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(0x89);
            bytes.push(modrm);
            if let Some(s) = sib { bytes.push(s); }
            push_displacement(mem.disp, disp_sz, bytes);
        }
        _ => return Err(EncodeError::UnsupportedOperand("MOV".into())),
    }
    Ok(())
}

fn encode_arithmetic(
    op_mr: u8,
    op_rm: u8,
    ext_idx: u8,
    dst: Operand,
    src: Operand,
    bytes: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    match (dst, src) {
        (Operand::Reg(dst_r), Operand::Reg(src_r)) => {
            let mut rex = 0x48u8;
            if src_r.is_extended() { rex |= 0x04; }
            if dst_r.is_extended() { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(op_mr);
            bytes.push(0xC0 | (src_r.code() << 3) | dst_r.code());
        }
        (Operand::Reg(dst_r), Operand::Mem(mem)) => {
            let (modrm, sib, disp_sz, rex_b, rex_x) = encode_mem_parts(dst_r.code(), mem)?;
            let mut rex = 0x48u8;
            if dst_r.is_extended() { rex |= 0x04; }
            if rex_x { rex |= 0x02; }
            if rex_b { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(op_rm);
            bytes.push(modrm);
            if let Some(s) = sib { bytes.push(s); }
            push_displacement(mem.disp, disp_sz, bytes);
        }
        (Operand::Mem(mem), Operand::Reg(src_r)) => {
            let (modrm, sib, disp_sz, rex_b, rex_x) = encode_mem_parts(src_r.code(), mem)?;
            let mut rex = 0x48u8;
            if src_r.is_extended() { rex |= 0x04; }
            if rex_x { rex |= 0x02; }
            if rex_b { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(op_mr);
            bytes.push(modrm);
            if let Some(s) = sib { bytes.push(s); }
            push_displacement(mem.disp, disp_sz, bytes);
        }
        (dst, Operand::Imm32(imm)) => {
            // Use 0x83 (sign-extended imm8) when the immediate fits in a byte —
            // saves 3 bytes per instruction for small constants.
            let (opcode, is_8bit) = if (-128..=127).contains(&imm) {
                (0x83u8, true)
            } else {
                (0x81u8, false)
            };
            match dst {
                Operand::Reg(r) => {
                    let mut rex = 0x48u8;
                    if r.is_extended() { rex |= 0x01; }
                    bytes.push(rex);
                    bytes.push(opcode);
                    bytes.push(0xC0 | (ext_idx << 3) | r.code());
                }
                Operand::Mem(mem) => {
                    let (modrm, sib, disp_sz, rex_b, rex_x) = encode_mem_parts(ext_idx, mem)?;
                    let mut rex = 0x48u8;
                    if rex_x { rex |= 0x02; }
                    if rex_b { rex |= 0x01; }
                    bytes.push(rex);
                    bytes.push(opcode);
                    bytes.push(modrm);
                    if let Some(s) = sib { bytes.push(s); }
                    push_displacement(mem.disp, disp_sz, bytes);
                }
                _ => return Err(EncodeError::UnsupportedOperand("Arithmetic Imm dst".into())),
            }
            if is_8bit {
                bytes.push(imm as u8);
            } else {
                bytes.extend_from_slice(&imm.to_le_bytes());
            }
        }
        _ => return Err(EncodeError::UnsupportedOperand("Arithmetic".into())),
    }
    Ok(())
}

fn encode_shift(ext_idx: u8, dst: Operand, count: Operand, bytes: &mut Vec<u8>) -> Result<(), EncodeError> {
    let opcode = match count {
        Operand::Reg(Register::RCX) => 0xD3u8,
        Operand::Imm32(1)           => 0xD1,
        Operand::Imm32(_)           => 0xC1,
        _ => return Err(EncodeError::UnsupportedOperand("Shift count must be CL or imm8".into())),
    };

    match dst {
        Operand::Reg(r) => {
            let mut rex = 0x48u8;
            if r.is_extended() { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(opcode);
            bytes.push(0xC0 | (ext_idx << 3) | r.code());
        }
        Operand::Mem(mem) => {
            let (modrm, sib, disp_sz, rex_b, rex_x) = encode_mem_parts(ext_idx, mem)?;
            let mut rex = 0x48u8;
            if rex_x { rex |= 0x02; }
            if rex_b { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(opcode);
            bytes.push(modrm);
            if let Some(s) = sib { bytes.push(s); }
            push_displacement(mem.disp, disp_sz, bytes);
        }
        _ => return Err(EncodeError::UnsupportedOperand("Shift dst".into())),
    }

    if let Operand::Imm32(imm) = count {
        if imm != 1 { bytes.push(imm as u8); }
    }
    Ok(())
}

fn encode_unary(opcode: u8, ext_idx: u8, op: Operand, bytes: &mut Vec<u8>) -> Result<(), EncodeError> {
    match op {
        Operand::Reg(r) => {
            let mut rex = 0x48u8;
            if r.is_extended() { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(opcode);
            bytes.push(0xC0 | (ext_idx << 3) | r.code());
        }
        Operand::Mem(mem) => {
            let (modrm, sib, disp_sz, rex_b, rex_x) = encode_mem_parts(ext_idx, mem)?;
            let mut rex = 0x48u8;
            if rex_x { rex |= 0x02; }
            if rex_b { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(opcode);
            bytes.push(modrm);
            if let Some(s) = sib { bytes.push(s); }
            push_displacement(mem.disp, disp_sz, bytes);
        }
        _ => return Err(EncodeError::UnsupportedOperand("Unary".into())),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registers::Register::*;

    #[test]
    fn test_basic_mov_rax_rbx() {
        // mov rax, rbx -> 48 89 D8
        let instr = Instruction::Mov(Operand::Reg(RAX), Operand::Reg(RBX));
        assert_eq!(encode_instruction(instr).unwrap(), vec![0x48, 0x89, 0xD8]);
    }

    #[test]
    fn test_rex_extended_registers() {
        // mov r8, r9 -> 4D 89 C8
        let instr = Instruction::Mov(Operand::Reg(R8), Operand::Reg(R9));
        assert_eq!(encode_instruction(instr).unwrap(), vec![0x4D, 0x89, 0xC8]);
    }

    #[test]
    fn test_rsp_sib_encoding() {
        // mov rax, [rsp] -> 48 8B 04 24
        let mem = MemoryAddr { base: Some(RSP), index: None, scale: 1, disp: 0 };
        let instr = Instruction::Mov(Operand::Reg(RAX), Operand::Mem(mem));
        assert_eq!(encode_instruction(instr).unwrap(), vec![0x48, 0x8B, 0x04, 0x24]);
    }

    #[test]
    fn test_rbp_displacement_encoding() {
        // mov rax, [rbp] -> 48 8B 45 00
        let mem = MemoryAddr { base: Some(RBP), index: None, scale: 1, disp: 0 };
        let instr = Instruction::Mov(Operand::Reg(RAX), Operand::Mem(mem));
        assert_eq!(encode_instruction(instr).unwrap(), vec![0x48, 0x8B, 0x45, 0x00]);
    }

    #[test]
    fn test_r12_r13_special_cases() {
        // R12 requires SIB: mov rax, [r12] -> 49 8B 04 24
        let mem12 = MemoryAddr { base: Some(R12), index: None, scale: 1, disp: 0 };
        assert_eq!(
            encode_instruction(Instruction::Mov(Operand::Reg(RAX), Operand::Mem(mem12))).unwrap(),
            vec![0x49, 0x8B, 0x04, 0x24]
        );

        // R13 requires disp8=0: mov rax, [r13] -> 49 8B 45 00
        let mem13 = MemoryAddr { base: Some(R13), index: None, scale: 1, disp: 0 };
        assert_eq!(
            encode_instruction(Instruction::Mov(Operand::Reg(RAX), Operand::Mem(mem13))).unwrap(),
            vec![0x49, 0x8B, 0x45, 0x00]
        );
    }

    #[test]
    fn test_complex_sib_addressing() {
        // mov [rax + rcx*4 + 0x12345678], rdx
        let mem = MemoryAddr { base: Some(RAX), index: Some(RCX), scale: 4, disp: 0x12345678 };
        let bytes = encode_instruction(Instruction::Mov(Operand::Mem(mem), Operand::Reg(RDX))).unwrap();
        assert_eq!(bytes[0..4], [0x48, 0x89, 0x94, 0x88]);
        assert_eq!(bytes[4..8], 0x12345678i32.to_le_bytes());
    }

    #[test]
    fn test_arithmetic_imm8_optimization() {
        // add rax, 10 -> 48 83 C0 0A
        let instr = Instruction::Add(Operand::Reg(RAX), Operand::Imm32(10));
        assert_eq!(encode_instruction(instr).unwrap(), vec![0x48, 0x83, 0xC0, 0x0A]);

        // add rax, 0x1000 -> 48 81 C0 00 10 00 00
        let instr2 = Instruction::Add(Operand::Reg(RAX), Operand::Imm32(0x1000));
        assert_eq!(encode_instruction(instr2).unwrap(), vec![0x48, 0x81, 0xC0, 0x00, 0x10, 0x00, 0x00]);
    }

    #[test]
    fn test_unary_and_shifts() {
        // not qword [rdi] -> 48 F7 17
        let mem = MemoryAddr { base: Some(RDI), index: None, scale: 1, disp: 0 };
        assert_eq!(
            encode_instruction(Instruction::Not(Operand::Mem(mem))).unwrap(),
            vec![0x48, 0xF7, 0x17]
        );

        // shl rax, cl -> 48 D3 E0
        assert_eq!(
            encode_instruction(Instruction::Shl(Operand::Reg(RAX), Operand::Reg(RCX))).unwrap(),
            vec![0x48, 0xD3, 0xE0]
        );
    }

    #[test]
    fn test_label_rejected_by_encoder() {
        // Labels must not be passed directly to encode_instruction
        assert!(encode_instruction(Instruction::Label("foo".into())).is_err());
        assert!(encode_instruction(Instruction::JmpLabel("foo".into())).is_err());
    }

    #[test]
    fn test_mov_imm64() {
        // mov rax, 0xDEADBEEFCAFEBABE -> 48 B8 BE BA FE CA EF BE AD DE
        let instr = Instruction::Mov(Operand::Reg(RAX), Operand::Imm64(0xDEAD_BEEF_CAFE_BABE));
        let bytes = encode_instruction(instr).unwrap();
        assert_eq!(bytes[0..2], [0x48, 0xB8]);
        assert_eq!(bytes[2..10], 0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
    }
}