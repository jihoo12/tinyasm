## x86-64 JIT Assembler in Rust
A lightweight, educational x86-64 assembler and JIT execution engine written in Rust. This project demonstrates how to translate assembly-like instructions into raw machine code (binary) and execute them directly in memory at runtime using mmap and mprotect.

## Key Features
- 2-Pass Assembler: Supports symbol resolution for labels, allowing for forward and backward jumps.

- Instruction Encoding: Implements a custom encoder for common x86-64 integer instructions including MOV, ADD, SUB, CMP, arithmetic/logical operations, and conditional jumps.

- SSE2 Floating-Point Support: Supports XMM0-XMM15, MOVSD, scalar double-precision arithmetic (ADDSD, SUBSD, MULSD, DIVSD), and UCOMISD comparisons.

- Label Branching: Supports JMP, JE, JNE, JL, JLE, JGE, JG, JA, and JP label-based branches. JA and JP can be used with UCOMISD for ordered and unordered (NaN) floating-point control flow.

- Complex Addressing: Supports ModR/M and SIB byte encoding for memory operands, including base registers, index registers, scales, and displacements.

- JIT Execution: Allocates writable memory with mmap, writes generated machine code, then switches the region to executable memory with mprotect (RW -> RX).

- Typed JIT Functions: JitMemory::as_typed_fn exposes generated code as typed extern "C" function pointers through JitFunction, with 0 through 4 arguments.

- Debug Mode: Optional verbose output to visualize the assembly process and the resulting bytecodes.

## Project Structure

| File | Description
|---|---|
registers.rs | Defines x86-64 general-purpose registers and XMM0-XMM15, including encoding and REX-extension information.
encoding.rs | Provides low-level helpers for REX, ModR/M, and SIB byte encoding.
encoder.rs | The core logic for translating Instruction enums into machine code bytes, including integer and scalar SSE2 instructions.
assembler.rs | Manages the instruction list and resolves label addresses during the 2-pass process.
jit.rs | Handles executable memory, RW -> RX protection changes, and typed JIT function pointers.
main.rs | Entry point demonstrating a loop example (incrementing RAX to 5).

## Technical Implementation Details

### The 2-Pass Process

- Pass 1 (Symbol Resolution): The assembler iterates through the instructions to calculate the byte offset of every label and stores them in a symbol table.

- Pass 2 (Code Generation): The assembler generates the final machine code, calculating relative offsets for label-based jump instructions using the symbol table created in Pass 1.

### Encoding Logic
- REX Prefix: Automatically added for 64-bit operations or when using extended general-purpose or XMM registers.

- Immediate Optimization: The encoder chooses between 8-bit and 32-bit immediate opcodes (e.g., 0x83 vs 0x81) based on the value size to minimize code size.

- Memory Addressing: Specialized handling for registers like RSP/R12 (requiring SIB) and RBP/R13 (requiring mandatory displacement).

- Scalar SSE2: MOVSD moves double-precision values between XMM registers and memory. ADDSD, SUBSD, MULSD, and DIVSD perform scalar arithmetic, while UCOMISD sets flags for floating-point comparisons.

### JIT Execution

JitMemory follows a write-xor-execute (W^X) flow: allocate an RW region, write the assembled bytes, then call make_executable() to switch it to RX before execution.

The original no-argument API returns an `extern "C" fn() -> u64`:

```rust
let func = unsafe { jit.as_fn() }.unwrap();
let result = func();
```

For generated code with arguments or other return types, `as_typed_fn` can return a typed C-ABI function pointer:

```rust
let func: extern "C" fn(f64, f64) -> f64 =
    unsafe { jit.as_typed_fn() }.unwrap();

let result = func(1.5, 2.25);
```

The selected function type must exactly match the ABI expected by the generated machine code.

## Supported Instruction Examples

Integer instructions include MOV, ADD, SUB, CMP, AND, OR, XOR, TEST, IMUL, MUL, DIV, SHL, SHR, PUSH, POP, CALL, and RET.

Scalar SSE2 instructions include MOVSD, ADDSD, SUBSD, MULSD, DIVSD, and UCOMISD.

Label-based control flow includes JMP, JE, JNE, JL, JLE, JGE, JG, JA, and JP. For example, UCOMISD can be followed by JA for an ordered "above" comparison or JP to detect an unordered comparison such as NaN.

## Requirements

- Rust: Stable toolchain.

- Dependencies: libc (for memory mapping on Unix-like systems).

- OS / Architecture: Primarily targeted for x86-64 Linux/macOS due to the current mmap/mprotect JIT implementation.
