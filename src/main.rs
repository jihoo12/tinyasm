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
    ];

    for instr in instructions {
        let bytes = encode_instruction(instr);
        println!("{:?} -> {:02X?}", instr, bytes);
    }
}
