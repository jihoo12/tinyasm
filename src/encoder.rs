use crate::registers::Register;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryAddr {
    pub base: Option<Register>,
    pub index: Option<Register>,
    pub scale: u8, // 1, 2, 4, 8
    pub disp: i32,
}

#[derive(Debug, Clone, Copy)]
pub enum Operand {
    Reg(Register),
    Imm64(u64),
    Imm32(i32),
    Mem(MemoryAddr),
}

#[derive(Debug, Clone, Copy)]
pub enum Instruction {
    Mov(Operand, Operand), // Destination, Source
    Add(Operand, Operand),
    Sub(Operand, Operand),
    Mul(Operand), // Operand is r/m64
    Div(Operand), // Operand is r/m64
}

pub fn encode_instruction(instr: Instruction) -> Vec<u8> {
    let mut bytes = Vec::new();
    match instr {
        Instruction::Mov(dst, src) => encode_mov(dst, src, &mut bytes),
        Instruction::Add(dst, src) => encode_arithmetic(0x01, 0x03, 0, dst, src, &mut bytes),
        Instruction::Sub(dst, src) => encode_arithmetic(0x29, 0x2B, 5, dst, src, &mut bytes),
        Instruction::Mul(op) => encode_unary(0xF7, 4, op, &mut bytes),
        Instruction::Div(op) => encode_unary(0xF7, 6, op, &mut bytes),
    }
    bytes
}

fn encode_unary(opcode: u8, ext_idx: u8, op: Operand, bytes: &mut Vec<u8>) {
    match op {
        Operand::Reg(reg) => {
            let mut rex = 0x48;
            if reg.is_extended() {
                rex |= 0x01;
            }
            bytes.push(rex);
            bytes.push(opcode);
            let modrm = 0xC0 | (ext_idx << 3) | reg.code();
            bytes.push(modrm);
        }
        Operand::Mem(mem) => {
            let (modrm, sib, disp_size) = encode_mem_parts(ext_idx, false, mem, bytes);
            bytes.push(opcode);
            bytes.push(modrm);
            if let Some(s) = sib {
                bytes.push(s);
            }
            push_displacement(mem.disp, disp_size, bytes);
        }
        _ => panic!("Unsupported operand for unary instruction"),
    }
}

fn encode_mov(dst: Operand, src: Operand, bytes: &mut Vec<u8>) {
    match (dst, src) {
        // MOV r64, imm64
        (Operand::Reg(dst_reg), Operand::Imm64(imm)) => {
            let mut rex = 0x48;
            if dst_reg.is_extended() {
                rex |= 0x01;
            }
            bytes.push(rex);
            bytes.push(0xB8 + dst_reg.code());
            bytes.extend_from_slice(&imm.to_le_bytes());
        }

        // MOV r64, r64
        (Operand::Reg(dst_reg), Operand::Reg(src_reg)) => {
            let mut rex = 0x48;
            if src_reg.is_extended() {
                rex |= 0x04;
            }
            if dst_reg.is_extended() {
                rex |= 0x01;
            }
            bytes.push(rex);
            bytes.push(0x89);
            let modrm = 0xC0 | (src_reg.code() << 3) | dst_reg.code();
            bytes.push(modrm);
        }

        // MOV r64, m64 (Load)
        (Operand::Reg(dst_reg), Operand::Mem(mem)) => {
            let (modrm, sib, disp_size) =
                encode_mem_parts(dst_reg.code(), dst_reg.is_extended(), mem, bytes);
            bytes.push(0x8B); // Opcode for MOV r64, r/m64
            bytes.push(modrm);
            if let Some(s) = sib {
                bytes.push(s);
            }
            push_displacement(mem.disp, disp_size, bytes);
        }

        // MOV m64, r64 (Store)
        (Operand::Mem(mem), Operand::Reg(src_reg)) => {
            let (modrm, sib, disp_size) =
                encode_mem_parts(src_reg.code(), src_reg.is_extended(), mem, bytes);
            bytes.push(0x89); // Opcode for MOV r/m64, r64
            bytes.push(modrm);
            if let Some(s) = sib {
                bytes.push(s);
            }
            push_displacement(mem.disp, disp_size, bytes);
        }
        _ => panic!("Unsupported MOV combination"),
    }
}

fn encode_arithmetic(
    op_mr: u8,   // r/m64, r64 (e.g., 0x01 for ADD)
    op_rm: u8,   // r64, r/m64 (e.g., 0x03 for ADD)
    ext_idx: u8, // extension for imm (e.g., 0 for ADD, 5 for SUB)
    dst: Operand,
    src: Operand,
    bytes: &mut Vec<u8>,
) {
    match (dst, src) {
        // OP r64, r64
        (Operand::Reg(dst_reg), Operand::Reg(src_reg)) => {
            let mut rex = 0x48;
            if src_reg.is_extended() {
                rex |= 0x04;
            }
            if dst_reg.is_extended() {
                rex |= 0x01;
            }
            bytes.push(rex);
            bytes.push(op_mr);
            let modrm = 0xC0 | (src_reg.code() << 3) | dst_reg.code();
            bytes.push(modrm);
        }

        // OP r64, m64
        (Operand::Reg(dst_reg), Operand::Mem(mem)) => {
            let (modrm, sib, disp_size) =
                encode_mem_parts(dst_reg.code(), dst_reg.is_extended(), mem, bytes);
            bytes.push(op_rm);
            bytes.push(modrm);
            if let Some(s) = sib {
                bytes.push(s);
            }
            push_displacement(mem.disp, disp_size, bytes);
        }

        // OP m64, r64
        (Operand::Mem(mem), Operand::Reg(src_reg)) => {
            let (modrm, sib, disp_size) =
                encode_mem_parts(src_reg.code(), src_reg.is_extended(), mem, bytes);
            bytes.push(op_mr);
            bytes.push(modrm);
            if let Some(s) = sib {
                bytes.push(s);
            }
            push_displacement(mem.disp, disp_size, bytes);
        }

        // OP r/m64, imm32
        (dst, Operand::Imm32(imm)) => {
            let (dst_reg_code, is_ext, mem_info) = match dst {
                Operand::Reg(r) => (r.code(), r.is_extended(), None),
                Operand::Mem(m) => (0, false, Some(m)), // Default is_ext false, will be set in encode_mem_parts if mem.base is ext
                _ => panic!("Invalid destination for arithmetic immediate"),
            };

            let (opcode, is_8bit) = if imm >= -128 && imm <= 127 {
                (0x83, true)
            } else {
                (0x81, false)
            };

            if let Some(mem) = mem_info {
                let (modrm, sib, disp_size) = encode_mem_parts(ext_idx, false, mem, bytes);
                bytes.push(opcode);
                bytes.push(modrm);
                if let Some(s) = sib {
                    bytes.push(s);
                }
                push_displacement(mem.disp, disp_size, bytes);
            } else {
                let mut rex = 0x48;
                if is_ext {
                    rex |= 0x01;
                }
                bytes.push(rex);
                bytes.push(opcode);
                let modrm = 0xC0 | (ext_idx << 3) | dst_reg_code;
                bytes.push(modrm);
            }

            if is_8bit {
                bytes.push(imm as u8);
            } else {
                bytes.extend_from_slice(&imm.to_le_bytes());
            }
        }
        _ => panic!("Unsupported arithmetic combination"),
    }
}

fn push_displacement(disp: i32, size: usize, bytes: &mut Vec<u8>) {
    if size == 1 {
        bytes.push(disp as u8);
    } else if size == 4 {
        bytes.extend_from_slice(&disp.to_le_bytes());
    }
}

fn encode_mem_parts(
    reg_val: u8,
    reg_ext: bool,
    mem: MemoryAddr,
    bytes: &mut Vec<u8>,
) -> (u8, Option<u8>, usize) {
    let mut rex = 0x48;
    if reg_ext {
        rex |= 0x04;
    }
    if let Some(b) = mem.base {
        if b.is_extended() {
            rex |= 0x01;
        }
    }
    if let Some(i) = mem.index {
        if i.is_extended() {
            rex |= 0x02;
        }
    }
    bytes.push(rex);

    let (mod_bits, disp_size) = if mem.disp == 0
        && mem.base.is_some()
        && mem.base.unwrap() != Register::RBP
        && mem.base.unwrap() != Register::R13
    {
        (0x00, 0)
    } else if mem.disp >= -128 && mem.disp <= 127 {
        (0x01, 1)
    } else {
        (0x10, 4)
    };

    let use_sib =
        mem.index.is_some() || mem.base == Some(Register::RSP) || mem.base == Some(Register::R12);
    let rm_bits = if use_sib {
        0x04
    } else {
        mem.base.unwrap().code()
    };
    let modrm = (mod_bits << 6) | (reg_val << 3) | rm_bits;

    if use_sib {
        let scale_bits = match mem.scale {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => panic!("Invalid scale"),
        };
        let index_bits = mem.index.map(|r| r.code()).unwrap_or(0x04);
        let base_bits = mem.base.map(|r| r.code()).unwrap_or(0x05);
        let sib = (scale_bits << 6) | (index_bits << 3) | base_bits;
        (modrm, Some(sib), disp_size)
    } else {
        (modrm, None, disp_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registers::Register::*;

    #[test]
    fn test_mov_reg_imm64() {
        // mov rax, 0x123456789ABCDEF0 -> 48 B8 F0 DE BC 9A 78 56 34 12
        let instr = Instruction::Mov(Operand::Reg(RAX), Operand::Imm64(0x123456789ABCDEF0));
        let bytes = encode_instruction(instr);
        assert_eq!(
            bytes,
            vec![0x48, 0xB8, 0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]
        );

        // mov r8, 0x123456789ABCDEF0 -> 49 B8 F0 DE BC 9A 78 56 34 12 (REX.B set)
        let instr = Instruction::Mov(Operand::Reg(R8), Operand::Imm64(0x123456789ABCDEF0));
        let bytes = encode_instruction(instr);
        assert_eq!(
            bytes,
            vec![0x49, 0xB8, 0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]
        );
    }

    #[test]
    fn test_mov_reg_reg() {
        // mov rbx, rax -> 48 89 C3
        let instr = Instruction::Mov(Operand::Reg(RBX), Operand::Reg(RAX));
        let bytes = encode_instruction(instr);
        assert_eq!(bytes, vec![0x48, 0x89, 0xC3]);

        // mov r12, r9 -> 4D 89 CC (REX.R and REX.B set)
        // R9 code=1, R12 code=4. ModR/M = 0xC0 | (1 << 3) | 4 = 0xC0 | 8 | 4 = 0xCC
        let instr = Instruction::Mov(Operand::Reg(R12), Operand::Reg(R9));
        let bytes = encode_instruction(instr);
        assert_eq!(bytes, vec![0x4D, 0x89, 0xCC]);
    }

    #[test]
    fn test_add_sub() {
        // add rax, rbx -> 48 01 D8
        let instr = Instruction::Add(Operand::Reg(RAX), Operand::Reg(RBX));
        let bytes = encode_instruction(instr);
        assert_eq!(bytes, vec![0x48, 0x01, 0xD8]);

        // sub rdi, 10 -> 48 83 EF 0A
        let instr = Instruction::Sub(Operand::Reg(RDI), Operand::Imm32(10));
        let bytes = encode_instruction(instr);
        assert_eq!(bytes, vec![0x48, 0x83, 0xEF, 0x0A]);

        // add [rcx], rax -> 48 01 01
        let mem = MemoryAddr {
            base: Some(RCX),
            index: None,
            scale: 1,
            disp: 0,
        };
        let instr = Instruction::Add(Operand::Mem(mem), Operand::Reg(RAX));
        let bytes = encode_instruction(instr);
        assert_eq!(bytes, vec![0x48, 0x01, 0x01]);
    }

    #[test]
    fn test_mul_div() {
        // mul rbx -> 48 F7 E3
        let instr = Instruction::Mul(Operand::Reg(RBX));
        let bytes = encode_instruction(instr);
        assert_eq!(bytes, vec![0x48, 0xF7, 0xE3]);

        // div rcx -> 48 F7 F1
        let instr = Instruction::Div(Operand::Reg(RCX));
        let bytes = encode_instruction(instr);
        assert_eq!(bytes, vec![0x48, 0xF7, 0xF1]);

        // mul qword ptr[rax + 8] -> 48 F7 60 08
        let mem = MemoryAddr {
            base: Some(RAX),
            index: None,
            scale: 1,
            disp: 8,
        };
        let instr = Instruction::Mul(Operand::Mem(mem));
        let bytes = encode_instruction(instr);
        assert_eq!(bytes, vec![0x48, 0xF7, 0x60, 0x08]);
    }
}
