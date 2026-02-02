mod encoder;
mod jit;
mod registers;

use crate::encoder::{Instruction, MemoryAddr, Operand, encode_instruction};
use crate::jit::JitMemory;
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
        Instruction::Ret,
    ];

    println!("--- Encoding Check ---");
    for instr in &instructions {
        match encode_instruction(*instr) {
            Ok(bytes) => println!("{} -> {:02X?}", instr, bytes),
            Err(e) => println!("{} -> Error: {}", instr, e),
        }
    }

    println!("\n--- JIT Execution ---");
    let jit_instrs = vec![
        // mov rax, 42
        Instruction::Mov(Operand::Reg(RAX), Operand::Imm64(42)),
        Instruction::Ret,
    ];

    let mut code_buf = Vec::new();
    for instr in jit_instrs {
        match encode_instruction(instr) {
            Ok(bytes) => code_buf.extend_from_slice(&bytes),
            Err(e) => {
                println!("Encoding error: {}", e);
                return;
            }
        }
    }

    match JitMemory::new(4096) {
        Ok(mut memory) => {
            if let Err(e) = memory.write(&code_buf) {
                println!("JIT write error: {}", e);
                return;
            }
            if let Err(e) = memory.make_executable() {
                println!("JIT protect error: {}", e);
                return;
            }

            println!("Executing JIT code...");
            let func = unsafe { memory.as_fn_u64() };
            let result = func();
            println!("JIT result: {}", result);
        }
        Err(e) => println!("JIT allocation error: {}", e),
    }
}
