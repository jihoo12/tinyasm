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
        write!(f, "{}]", parts.join(" + "))
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
            Operand::Imm32(val) => write!(f, "0x{:X}", val),
            Operand::Mem(mem) => write!(f, "qword {}", mem),
        }
    }
}

// ⚠️ 수정됨: Clone만 유지 (String 때문에 Copy 불가)
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
    // 라벨 관련 명령어들
    Label(String),
    JmpLabel(String),
    JeLabel(String),
    JneLabel(String),
    Cmp(Operand,Operand),
}

// ⚠️ 수정됨: Label 관련 출력 포맷 추가 (E0004 에러 해결)
impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Instruction::Mov(dst, src) => write!(f, "mov {}, {}", dst, src),
            Instruction::Add(dst, src) => write!(f, "add {}, {}", dst, src),
            Instruction::Sub(dst, src) => write!(f, "sub {}, {}", dst, src),
            Instruction::And(dst, src) => write!(f, "and {}, {}", dst, src),
            Instruction::Or(dst, src) => write!(f, "or {}, {}", dst, src),
            Instruction::Xor(dst, src) => write!(f, "xor {}, {}", dst, src),
            Instruction::Not(op) => write!(f, "not {}", op),
            Instruction::Shl(dst, count) => write!(f, "shl {}, {}", dst, count),
            Instruction::Shr(dst, count) => write!(f, "shr {}, {}", dst, count),
            Instruction::Mul(op) => write!(f, "mul {}", op),
            Instruction::Div(op) => write!(f, "div {}", op),
            Instruction::Syscall => write!(f, "syscall"),
            Instruction::Ret => write!(f, "ret"),
            // 추가된 부분
            Instruction::Label(name) => write!(f, "{}:", name),
            Instruction::JmpLabel(target) => write!(f, "jmp {}", target),
            Instruction::JeLabel(target) => write!(f, "je {}", target),
            Instruction::JneLabel(target) => write!(f, "jne {}", target),
            Instruction::Cmp(dst, src) => write!(f, "cmp {}, {}", dst, src),
        }
    }
}

// --- 인코딩 유틸리티 ---

fn push_displacement(disp: i32, size: usize, bytes: &mut Vec<u8>) {
    if size == 1 {
        bytes.push(disp as u8);
    } else if size == 4 {
        bytes.extend_from_slice(&disp.to_le_bytes());
    }
}

fn encode_mem_parts(
    reg_val_code: u8,
    mem: MemoryAddr,
) -> Result<(u8, Option<u8>, usize, bool, bool), EncodeError> {
    let (mod_bits, disp_size) = if let Some(base) = mem.base {
        let is_bp_family = base == Register::RBP || base == Register::R13;
        if mem.disp == 0 && !is_bp_family {
            (0x00, 0)
        } else if mem.disp >= -128 && mem.disp <= 127 {
            (0x01, 1)
        } else {
            (0x02, 4) // 0x10 -> 0x02 수정됨 (32bit disp)
        }
    } else {
        (0x00, 4)
    };

    let use_sib = mem.index.is_some() 
        || mem.base == Some(Register::RSP);
        || mem.base == Some(Register::R12);

    let rm_bits = if use_sib { 0x04 } else { mem.base.unwrap().code() };
    let modrm = (mod_bits << 6) | (reg_val_code << 3) | rm_bits;

    let rex_b = mem.base.map_or(false, |r| r.is_extended());
    let rex_x = mem.index.map_or(false, |r| r.is_extended());

    if use_sib {
        let scale_bits = match mem.scale {
            1 => 0, 2 => 1, 4 => 2, 8 => 3,
            _ => return Err(EncodeError::InvalidScale(mem.scale)),
        };
        let index_bits = mem.index.map(|r| r.code()).unwrap_or(0x04);
        let base_bits = mem.base.map(|r| r.code()).unwrap_or(0x05);
        let sib = (scale_bits << 6) | (index_bits << 3) | base_bits;
        Ok((modrm, Some(sib), disp_size, rex_b, rex_x))
    } else {
        Ok((modrm, None, disp_size, rex_b, rex_x))
    }
}

// ⚠️ 수정됨: Label 처리 추가 및 중복 정의 제거 (E0428, E0004 해결)
pub fn encode_instruction(instr: Instruction) -> Result<Vec<u8>, EncodeError> {
    let mut bytes = Vec::new();
    match instr {
        Instruction::Mov(dst, src) => encode_mov(dst, src, &mut bytes)?,
        Instruction::Add(dst, src) => encode_arithmetic(0x01, 0x03, 0, dst, src, &mut bytes)?,
        Instruction::Sub(dst, src) => encode_arithmetic(0x29, 0x2B, 5, dst, src, &mut bytes)?,
        Instruction::And(dst, src) => encode_arithmetic(0x21, 0x23, 4, dst, src, &mut bytes)?,
        Instruction::Or(dst, src) => encode_arithmetic(0x09, 0x0B, 1, dst, src, &mut bytes)?,
        Instruction::Xor(dst, src) => encode_arithmetic(0x31, 0x33, 6, dst, src, &mut bytes)?,
        Instruction::Shl(dst, count) => encode_shift(4, dst, count, &mut bytes)?,
        Instruction::Shr(dst, count) => encode_shift(5, dst, count, &mut bytes)?,
        Instruction::Not(op) => encode_unary(0xF7, 2, op, &mut bytes)?,
        Instruction::Mul(op) => encode_unary(0xF7, 4, op, &mut bytes)?,
        Instruction::Div(op) => encode_unary(0xF7, 6, op, &mut bytes)?,
        Instruction::Syscall => bytes.extend_from_slice(&[0x0F, 0x05]),
        Instruction::Ret => bytes.push(0xC3),
        
        // 🔥 라벨 관련 명령어는 Encoder가 직접 처리하지 않고 Assembler가 처리해야 함
        // 따라서 여기로 들어오면 에러를 반환하여 Assembler 로직을 타도록 유도
        Instruction::Label(_) | Instruction::JmpLabel(_) | 
        Instruction::JeLabel(_) | Instruction::JneLabel(_) => {
            return Err(EncodeError::Other("Labels/Jumps should be handled by Assembler".into()));
        }
        Instruction::Cmp(dst, src) => encode_arithmetic(0x39, 0x3B, 7, dst, src, &mut bytes)?,
    }
    Ok(bytes)
}

fn encode_mov(dst: Operand, src: Operand, bytes: &mut Vec<u8>) -> Result<(), EncodeError> {
    match (dst, src) {
        (Operand::Reg(r), Operand::Imm64(imm)) => {
            let mut rex = 0x48;
            if r.is_extended() { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(0xB8 + r.code());
            bytes.extend_from_slice(&imm.to_le_bytes());
        }
        (Operand::Reg(dst_r), Operand::Reg(src_r)) => {
            let mut rex = 0x48;
            if src_r.is_extended() { rex |= 0x04; }
            if dst_r.is_extended() { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(0x89);
            bytes.push(0xC0 | (src_r.code() << 3) | dst_r.code());
        }
        (Operand::Reg(dst_r), Operand::Mem(mem)) => {
            let (modrm, sib, disp_sz, rex_b, rex_x) = encode_mem_parts(dst_r.code(), mem)?;
            let mut rex = 0x48;
            if dst_r.is_extended() { rex |= 0x04; }
            if rex_x { rex |= 0x02; }
            if rex_b { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(0x8B);
            bytes.push(modrm);
            if let Some(s) = sib { bytes.push(s); }
            push_displacement(mem.disp, disp_sz, bytes);
        }
        (Operand::Mem(mem), Operand::Reg(src_r)) => {
            let (modrm, sib, disp_sz, rex_b, rex_x) = encode_mem_parts(src_r.code(), mem)?;
            let mut rex = 0x48;
            if src_r.is_extended() { rex |= 0x04; }
            if rex_x { rex |= 0x02; }
            if rex_b { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(0x89);
            bytes.push(modrm);
            if let Some(s) = sib { bytes.push(s); }
            push_displacement(mem.disp, disp_sz, bytes);
        }
        (Operand::Reg(r), Operand::Imm32(imm)) => {
            // mov r64, imm32 (sign-extended) -> C7 /0 id
            // NOTE: 최적화된 MOV (ModR/M 사용)
            let mut rex = 0x48;
            if r.is_extended() { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(0xC7);
            bytes.push(0xC0 | r.code());
            bytes.extend_from_slice(&imm.to_le_bytes());
        }
        _ => return Err(EncodeError::UnsupportedOperand("MOV".into())),
    }
    Ok(())
}

fn encode_arithmetic(op_mr: u8, op_rm: u8, ext_idx: u8, dst: Operand, src: Operand, bytes: &mut Vec<u8>) -> Result<(), EncodeError> {
    match (dst, src) {
        (Operand::Reg(dst_r), Operand::Reg(src_r)) => {
            let mut rex = 0x48;
            if src_r.is_extended() { rex |= 0x04; }
            if dst_r.is_extended() { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(op_mr);
            bytes.push(0xC0 | (src_r.code() << 3) | dst_r.code());
        }
        (Operand::Reg(dst_r), Operand::Mem(mem)) => {
            let (modrm, sib, disp_sz, rex_b, rex_x) = encode_mem_parts(dst_r.code(), mem)?;
            let mut rex = 0x48;
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
            let mut rex = 0x48;
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
            let (opcode, is_8bit) = if imm >= -128 && imm <= 127 { (0x83, true) } else { (0x81, false) };
            match dst {
                Operand::Reg(r) => {
                    let mut rex = 0x48;
                    if r.is_extended() { rex |= 0x01; }
                    bytes.push(rex);
                    bytes.push(opcode);
                    bytes.push(0xC0 | (ext_idx << 3) | r.code());
                }
                Operand::Mem(mem) => {
                    let (modrm, sib, disp_sz, rex_b, rex_x) = encode_mem_parts(ext_idx, mem)?;
                    let mut rex = 0x48;
                    if rex_x { rex |= 0x02; }
                    if rex_b { rex |= 0x01; }
                    bytes.push(rex);
                    bytes.push(opcode);
                    bytes.push(modrm);
                    if let Some(s) = sib { bytes.push(s); }
                    push_displacement(mem.disp, disp_sz, bytes);
                }
                _ => return Err(EncodeError::UnsupportedOperand("Arithmetic Imm".into())),
            }
            if is_8bit { bytes.push(imm as u8); } else { bytes.extend_from_slice(&imm.to_le_bytes()); }
        }
        _ => return Err(EncodeError::UnsupportedOperand("Arithmetic".into())),
    }
    Ok(())
}

fn encode_shift(ext_idx: u8, dst: Operand, count: Operand, bytes: &mut Vec<u8>) -> Result<(), EncodeError> {
    let opcode = match count {
        Operand::Reg(Register::RCX) => 0xD3,
        Operand::Imm32(1) => 0xD1,
        Operand::Imm32(_) => 0xC1,
        _ => return Err(EncodeError::UnsupportedOperand("Shift count".into())),
    };

    match dst {
        Operand::Reg(r) => {
            let mut rex = 0x48;
            if r.is_extended() { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(opcode);
            bytes.push(0xC0 | (ext_idx << 3) | r.code());
        }
        Operand::Mem(mem) => {
            let (modrm, sib, disp_sz, rex_b, rex_x) = encode_mem_parts(ext_idx, mem)?;
            let mut rex = 0x48;
            if rex_x { rex |= 0x02; }
            if rex_b { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(opcode);
            bytes.push(modrm);
            if let Some(s) = sib { bytes.push(s); }
            push_displacement(mem.disp, disp_sz, bytes);
        }
        _ => return Err(EncodeError::UnsupportedOperand("Shift dest".into())),
    }

    if let Operand::Imm32(imm) = count {
        if imm != 1 { bytes.push(imm as u8); }
    }
    Ok(())
}

fn encode_unary(opcode: u8, ext_idx: u8, op: Operand, bytes: &mut Vec<u8>) -> Result<(), EncodeError> {
    match op {
        Operand::Reg(r) => {
            let mut rex = 0x48;
            if r.is_extended() { rex |= 0x01; }
            bytes.push(rex);
            bytes.push(opcode);
            bytes.push(0xC0 | (ext_idx << 3) | r.code());
        }
        Operand::Mem(mem) => {
            let (modrm, sib, disp_sz, rex_b, rex_x) = encode_mem_parts(ext_idx, mem)?;
            let mut rex = 0x48;
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
    // Registers를 사용하기 편리하도록 가져옵니다. 
    // 실제 Register 정의 위치에 맞춰 수정하세요 (예: crate::registers::Register::*)
    use crate::registers::Register::*; 

    #[test]
    fn test_basic_mov_rax_rbx() {
        // mov rax, rbx -> 48 89 D8
        let instr = Instruction::Mov(Operand::Reg(RAX), Operand::Reg(RBX));
        let bytes = encode_instruction(instr).unwrap();
        assert_eq!(bytes, vec![0x48, 0x89, 0xD8]);
    }

    #[test]
    fn test_rex_extended_registers() {
        // mov r8, r9 -> 4D 89 C8 (REX.W, REX.R, REX.B 설정됨)
        let instr = Instruction::Mov(Operand::Reg(R8), Operand::Reg(R9));
        let bytes = encode_instruction(instr).unwrap();
        assert_eq!(bytes, vec![0x4D, 0x89, 0xC8]);
    }

    #[test]
    fn test_rsp_sib_encoding() {
        // [RSP]는 인덱스가 없어도 반드시 SIB 바이트(0x24)가 필요함
        // mov rax, [rsp] -> 48 8B 04 24
        let mem = MemoryAddr { base: Some(RSP), index: None, scale: 1, disp: 0 };
        let instr = Instruction::Mov(Operand::Reg(RAX), Operand::Mem(mem));
        let bytes = encode_instruction(instr).unwrap();
        assert_eq!(bytes, vec![0x48, 0x8B, 0x04, 0x24]);
    }

    #[test]
    fn test_rbp_displacement_encoding() {
        // [RBP]는 disp가 0이라도 반드시 [RBP+0] (disp8) 형태로 인코딩되어야 함
        // mov rax, [rbp] -> 48 8B 45 00
        let mem = MemoryAddr { base: Some(RBP), index: None, scale: 1, disp: 0 };
        let instr = Instruction::Mov(Operand::Reg(RAX), Operand::Mem(mem));
        let bytes = encode_instruction(instr).unwrap();
        assert_eq!(bytes, vec![0x48, 0x8B, 0x45, 0x00]);
    }

    #[test]
    fn test_r12_r13_special_cases() {
        // R12는 RSP와 코드가 같으므로 SIB가 필요함
        // mov rax, [r12] -> 49 8B 04 24
        let mem12 = MemoryAddr { base: Some(R12), index: None, scale: 1, disp: 0 };
        let instr12 = Instruction::Mov(Operand::Reg(RAX), Operand::Mem(mem12));
        assert_eq!(encode_instruction(instr12).unwrap(), vec![0x49, 0x8B, 0x04, 0x24]);

        // R13은 RBP와 코드가 같으므로 disp8=0이 필요함
        // mov rax, [r13] -> 49 8B 45 00
        let mem13 = MemoryAddr { base: Some(R13), index: None, scale: 1, disp: 0 };
        let instr13 = Instruction::Mov(Operand::Reg(RAX), Operand::Mem(mem13));
        assert_eq!(encode_instruction(instr13).unwrap(), vec![0x49, 0x8B, 0x45, 0x00]);
    }

    #[test]
    fn test_complex_sib_addressing() {
        // mov [rax + rcx*4 + 0x12345678], rdx
        let mem = MemoryAddr {
            base: Some(RAX),
            index: Some(RCX),
            scale: 4,
            disp: 0x12345678,
        };
        let instr = Instruction::Mov(Operand::Mem(mem), Operand::Reg(RDX));
        let bytes = encode_instruction(instr).unwrap();
        // REX.W(48) + Op(89) + ModRM(84) + SIB(88) + Disp32
        assert_eq!(bytes[0..4], [0x48, 0x89, 0x94, 0x88]);
        assert_eq!(bytes[4..8], 0x12345678i32.to_le_bytes());
    }

    #[test]
    fn test_arithmetic_imm8_optimization() {
        // add rax, 10 -> 48 83 C0 0A (83 opcode used for small immediate)
        let instr = Instruction::Add(Operand::Reg(RAX), Operand::Imm32(10));
        let bytes = encode_instruction(instr).unwrap();
        assert_eq!(bytes, vec![0x48, 0x83, 0xC0, 0x0A]);

        // add rax, 0x1000 -> 48 81 C0 00 10 00 00 (81 opcode used for large immediate)
        let instr2 = Instruction::Add(Operand::Reg(RAX), Operand::Imm32(0x1000));
        let bytes2 = encode_instruction(instr2).unwrap();
        assert_eq!(bytes2, vec![0x48, 0x81, 0xC0, 0x00, 0x10, 0x00, 0x00]);
    }

    #[test]
    fn test_unary_and_shifts() {
        // not qword [rdi] -> 48 F7 17
        let mem = MemoryAddr { base: Some(RDI), index: None, scale: 1, disp: 0 };
        let instr = Instruction::Not(Operand::Mem(mem));
        assert_eq!(encode_instruction(instr).unwrap(), vec![0x48, 0xF7, 0x17]);

        // shl rax, cl -> 48 D3 E0
        let instr_shl = Instruction::Shl(Operand::Reg(RAX), Operand::Reg(RCX));
        assert_eq!(encode_instruction(instr_shl).unwrap(), vec![0x48, 0xD3, 0xE0]);
    }
}
