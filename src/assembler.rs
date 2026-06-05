use std::collections::HashMap;
use crate::encoder::{Instruction, encode_instruction, EncodeError};

pub struct Assembler {
    instructions: Vec<Instruction>,
    /// Label name → byte offset in the final output.
    labels: HashMap<String, usize>,
    debug: bool,
}

impl Assembler {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            labels: HashMap::new(),
            debug: false,
        }
    }

    /// Enable/disable verbose per-instruction debug output.
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    pub fn add_instruction(&mut self, instr: Instruction) {
        self.instructions.push(instr);
    }

    // -----------------------------------------------------------------------
    // Two-pass assembly
    // -----------------------------------------------------------------------

    /// Assemble all instructions into a flat byte buffer.
    ///
    /// **Pass 1** walks the instruction list and records the byte offset of
    /// every label in `self.labels`.  Jump instructions use fixed-width
    /// encodings (5 bytes for `jmp`, 6 bytes for conditional jumps) so that
    /// label offsets computed in Pass 1 remain accurate in Pass 2.
    ///
    /// **Pass 2** emits the actual machine bytes, resolving label targets to
    /// relative 32-bit displacements.
    pub fn assemble(&mut self) -> Result<Vec<u8>, EncodeError> {
        self.run_pass1()?;
        self.run_pass2()
    }

    // --- Pass 1: build the symbol table ---------------------------------

    fn run_pass1(&mut self) -> Result<(), EncodeError> {
        if self.debug { eprintln!("=== [Pass 1] Symbol Resolution ==="); }

        let mut offset = 0usize;
        self.labels.clear();

        for instr in &self.instructions {
            match instr {
                Instruction::Label(name) => {
                    if self.labels.contains_key(name) {
                        return Err(EncodeError::Other(
                            format!("Duplicate label: '{}'", name)
                        ));
                    }
                    self.labels.insert(name.clone(), offset);
                    if self.debug {
                        eprintln!("  label '{}' → 0x{:04X}", name, offset);
                    }
                }
                other => {
                    offset += self.fixed_size(other)?;
                }
            }
        }
        Ok(())
    }

    // --- Pass 2: emit bytes ----------------------------------------------

    fn run_pass2(&self) -> Result<Vec<u8>, EncodeError> {
        if self.debug { eprintln!("=== [Pass 2] Code Generation ==="); }

        let mut out = Vec::new();

        for instr in &self.instructions {
            let offset = out.len();

            if self.debug {
                eprint!("  [0x{:04X}] {:<35} → ", offset, format!("{}", instr));
            }

            match instr {
                Instruction::Label(_) => {
                    if self.debug { eprintln!("(label — no bytes)"); }
                    continue;
                }

                Instruction::JmpLabel(target) => {
                    // E9 rel32  (5 bytes total)
                    let bytes = self.encode_rel32_jump(&[0xE9], target, offset, 5)?;
                    self.debug_bytes(&bytes);
                    out.extend(bytes);
                }

                Instruction::JeLabel(target) => {
                    // 0F 84 rel32  (6 bytes total)
                    let bytes = self.encode_rel32_jump(&[0x0F, 0x84], target, offset, 6)?;
                    self.debug_bytes(&bytes);
                    out.extend(bytes);
                }

                Instruction::JneLabel(target) => {
                    // 0F 85 rel32  (6 bytes total)
                    let bytes = self.encode_rel32_jump(&[0x0F, 0x85], target, offset, 6)?;
                    self.debug_bytes(&bytes);
                    out.extend(bytes);
                }

                Instruction::JlLabel(target) => {
                    // 0F 8C rel32  (6 bytes total)
                    let bytes = self.encode_rel32_jump(&[0x0F, 0x8C], target, offset, 6)?;
                    self.debug_bytes(&bytes);
                    out.extend(bytes);
                }

                Instruction::JgeLabel(target) => {
                    // 0F 8D rel32  (6 bytes total)
                    let bytes = self.encode_rel32_jump(&[0x0F, 0x8D], target, offset, 6)?;
                    self.debug_bytes(&bytes);
                    out.extend(bytes);
                }

                other => {
                    let bytes = encode_instruction(other.clone())?;
                    self.debug_bytes(&bytes);
                    out.extend(bytes);
                }
            }
        }

        Ok(out)
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Encode a near jump with a rel32 displacement.
    ///
    /// `prefix`      — opcode byte(s) before the displacement (e.g. `&[0xE9]`).
    /// `target`      — label name to jump to.
    /// `instr_offset`— byte offset of this instruction in the output buffer.
    /// `instr_len`   — total byte length of this instruction (prefix + 4).
    fn encode_rel32_jump(
        &self,
        prefix: &[u8],
        target: &str,
        instr_offset: usize,
        instr_len: usize,
    ) -> Result<Vec<u8>, EncodeError> {
        let target_offset = *self.labels.get(target).ok_or_else(|| {
            EncodeError::Other(format!("Undefined label: '{}'", target))
        })?;

        // The CPU adds the displacement to the instruction pointer *after*
        // the jump instruction, so next_ip = instr_offset + instr_len.
        let next_ip = instr_offset + instr_len;
        let rel: i32 = (target_offset as i64 - next_ip as i64)
            .try_into()
            .map_err(|_| EncodeError::Other(
                format!("Jump to '{}' is out of rel32 range", target)
            ))?;

        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(&rel.to_le_bytes());
        Ok(bytes)
    }

    /// Returns the fixed encoded size of an instruction.
    ///
    /// For labels (zero bytes) and jump instructions (fixed-width encoding)
    /// this avoids calling `encode_instruction`, which would reject them.
    fn fixed_size(&self, instr: &Instruction) -> Result<usize, EncodeError> {
        match instr {
            Instruction::Label(_)    => Ok(0),
            Instruction::JmpLabel(_) => Ok(5),
            Instruction::JeLabel(_)
            | Instruction::JneLabel(_)
            | Instruction::JlLabel(_)
            | Instruction::JgeLabel(_) => Ok(6),
            other => {
                encode_instruction(other.clone()).map(|b| b.len())
            }
        }
    }

    fn debug_bytes(&self, bytes: &[u8]) {
        if self.debug {
            let hex: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
            eprintln!("[{}]", hex.join(" "));
        }
    }
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::{Instruction, Operand};
    use crate::registers::Register::*;

    fn simple_loop() -> Vec<u8> {
        let mut asm = Assembler::new();
        asm.add_instruction(Instruction::Mov(Operand::Reg(RAX), Operand::Imm32(0)));
        asm.add_instruction(Instruction::Label("loop_start".into()));
        asm.add_instruction(Instruction::Add(Operand::Reg(RAX), Operand::Imm32(1)));
        asm.add_instruction(Instruction::Cmp(Operand::Reg(RAX), Operand::Imm32(5)));
        asm.add_instruction(Instruction::JneLabel("loop_start".into()));
        asm.add_instruction(Instruction::Ret);
        asm.assemble().expect("assembly failed")
    }

    #[test]
    fn test_loop_assembles_without_error() {
        let code = simple_loop();
        assert!(!code.is_empty());
    }

    #[test]
    fn test_ret_is_last_byte() {
        let code = simple_loop();
        assert_eq!(*code.last().unwrap(), 0xC3, "last byte must be RET (0xC3)");
    }

    #[test]
    fn test_forward_jump() {
        // jmp past_ret / ret / Label("past_ret") / ret
        let mut asm = Assembler::new();
        asm.add_instruction(Instruction::JmpLabel("done".into()));
        asm.add_instruction(Instruction::Ret); // unreachable
        asm.add_instruction(Instruction::Label("done".into()));
        asm.add_instruction(Instruction::Ret);
        let code = asm.assemble().expect("forward jump failed");
        // First instruction: E9 xx xx xx xx  (jmp rel32)
        assert_eq!(code[0], 0xE9);
    }

    #[test]
    fn test_duplicate_label_is_error() {
        let mut asm = Assembler::new();
        asm.add_instruction(Instruction::Label("dup".into()));
        asm.add_instruction(Instruction::Label("dup".into()));
        assert!(asm.assemble().is_err());
    }

    #[test]
    fn test_undefined_label_is_error() {
        let mut asm = Assembler::new();
        asm.add_instruction(Instruction::JmpLabel("nowhere".into()));
        assert!(asm.assemble().is_err());
    }
}