## x86-64 JIT Assembler in Rust
A lightweight, educational x86-64 assembler and JIT execution engine written in Rust. This project demonstrates how to translate assembly-like instructions into raw machine code (binary) and execute them directly in memory at runtime using mmap and mprotect.

## Key Features
- 2-Pass Assembler: Supports symbol resolution for labels, allowing for forward and backward jumps.

- Instruction Encoding: Implements a custom encoder for common x86-64 instructions including MOV, ADD, SUB, CMP, and conditional jumps (JE, JNE).

- Complex Addressing: Supports ModR/M and SIB byte encoding for memory operands, including base registers, index registers, scales, and displacements.

- JIT Execution: Allocates executable memory pages using libc to run generated machine code as native functions.

- Debug Mode: Optional verbose output to visualize the assembly process and the resulting bytecodes.

## Project Structure

| File | Description
|---|---|
registers.rs | Defines x86-64 registers and their corresponding 3-bit codes and REX-bit flags.
encoder.rs | The core logic for translating Instruction enums into machine code bytes.
assembler.rs | Manages the instruction list and resolves label addresses during the 2-pass process.
jit.rs | Handles low-level memory management (allocation, protection, and execution).
main.rs | Entry point demonstrating a loop example (incrementing RAX to 5).

## Technical Implementation Details

### The 2-Pass Process

- Pass 1 (Symbol Resolution): The assembler iterates through the instructions to calculate the byte offset of every label and stores them in a symbol table.

- Pass 2 (Code Generation): The assembler generates the final machine code, calculating relative offsets for jump instructions using the symbol table created in Pass 1.

### Encoding Logic
- REX Prefix: Automatically added for 64-bit operations or when using extended registers (R8-R15).

- Immediate Optimization: The encoder chooses between 8-bit and 32-bit immediate opcodes (e.g., 0x83 vs 0x81) based on the value size to minimize code size.

- Memory Addressing: Specialized handling for registers like RSP/R12 (requiring SIB) and RBP/R13 (requiring mandatory displacement).

## Requirements

- Rust: Stable toolchain.

- Dependencies: libc (for memory mapping on Unix-like systems).

- OS: Primarily targeted for Linux/macOS due to mmap usage.