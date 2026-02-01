mod encoder;
mod registers;

use crate::encoder::{Instruction, MemoryAddr, Operand, encode_instruction};
use crate::registers::Register::*;

fn main() {
    let instructions = vec![
        Instruction::Mov(Operand::Reg(RAX), Operand::Imm64(0x123456789ABCDEF0)),
        Instruction::Add(Operand::Reg(RAX), Operand::Reg(RBX)),
        // sub rdi, 10
        Instruction::Sub(Operand::Reg(RDI), Operand::Imm32(10)),
        // add [rbx + rcx * 4 + 8], rax
        Instruction::Add(
            Operand::Mem(MemoryAddr {
                base: Some(RBX),
                index: Some(RCX),
                scale: 4,
                disp: 8,
            }),
            Operand::Reg(RAX),
        ),
        // mul rbx
        Instruction::Mul(Operand::Reg(RBX)),
        // div qword [rax + 8]
        Instruction::Div(Operand::Mem(MemoryAddr {
            base: Some(RAX),
            index: None,
            scale: 1,
            disp: 8,
        })),
        // and rax, rbx
        Instruction::And(Operand::Reg(RAX), Operand::Reg(RBX)),
        // or rcx, 0x12
        Instruction::Or(Operand::Reg(RCX), Operand::Imm32(0x12)),
        // xor rax, rax
        Instruction::Xor(Operand::Reg(RAX), Operand::Reg(RAX)),
        // not rbx
        Instruction::Not(Operand::Reg(RBX)),
        // shl rax, 4
        Instruction::Shl(Operand::Reg(RAX), Operand::Imm32(4)),
        // shr rbx, cl
        Instruction::Shr(Operand::Reg(RBX), Operand::Reg(RCX)),
        // syscall
        Instruction::Syscall,
    ];

    for instr in instructions {
        let bytes = encode_instruction(instr);
        println!("{:?} -> {:02X?}", instr, bytes);
    }
}
