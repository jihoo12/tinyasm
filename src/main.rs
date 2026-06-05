mod registers;
mod encoder;
mod assembler;
mod jit;

use crate::registers::Register::*;
use crate::encoder::{Instruction, Operand};
use crate::assembler::Assembler;
use crate::jit::JitMemory;

fn main() {
    // -----------------------------------------------------------------------
    // Example: count from 0 to 5 using a loop, return the final value in RAX.
    // -----------------------------------------------------------------------
    //
    //   mov rax, 0
    // loop_start:
    //   add rax, 1
    //   cmp rax, 5
    //   jne loop_start
    //   ret

    let mut asm = Assembler::new().with_debug(true);

    asm.add_instruction(Instruction::Mov(Operand::Reg(RAX), Operand::Imm32(0)));
    asm.add_instruction(Instruction::Label("loop_start".into()));
    asm.add_instruction(Instruction::Add(Operand::Reg(RAX), Operand::Imm32(1)));
    asm.add_instruction(Instruction::Cmp(Operand::Reg(RAX), Operand::Imm32(5)));
    asm.add_instruction(Instruction::JneLabel("loop_start".into()));
    asm.add_instruction(Instruction::Ret);

    let code = match asm.assemble() {
        Ok(c) => {
            println!("\n✅ Machine code ({} bytes): {:02X?}", c.len(), c);
            c
        }
        Err(e) => {
            eprintln!("❌ Assembly error: {}", e);
            std::process::exit(1);
        }
    };

    // Allocate RW memory, write the code, then flip to RX.
    let mut jit = JitMemory::new(code.len())
        .unwrap_or_else(|e| panic!("JIT allocation failed: {}", e));

    jit.write(&code).unwrap();
    jit.make_executable().unwrap();

    // Call the JIT-compiled function.
    let result = unsafe { jit.as_fn_u64()() };

    println!("\n--- JIT Result ---");
    println!("RAX = {} (expected 5)", result);
    assert_eq!(result, 5, "loop should leave RAX == 5");
}