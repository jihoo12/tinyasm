#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    RAX,
    RCX,
    RDX,
    RBX,
    RSP,
    RBP,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl Register {
    /// Returns the 3-bit code for the register used in ModR/M, Opcode, etc.
    pub fn code(&self) -> u8 {
        match self {
            Register::RAX | Register::R8 => 0,
            Register::RCX | Register::R9 => 1,
            Register::RDX | Register::R10 => 2,
            Register::RBX | Register::R11 => 3,
            Register::RSP | Register::R12 => 4,
            Register::RBP | Register::R13 => 5,
            Register::RSI | Register::R14 => 6,
            Register::RDI | Register::R15 => 7,
        }
    }

    /// Returns true if the register is one of the extended registers (R8-R15).
    pub fn is_extended(&self) -> bool {
        match self {
            Register::R8
            | Register::R9
            | Register::R10
            | Register::R11
            | Register::R12
            | Register::R13
            | Register::R14
            | Register::R15 => true,
            _ => false,
        }
    }
}
