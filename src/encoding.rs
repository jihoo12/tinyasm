//! Low-level x86-64 instruction encoding primitives.
//!
//! This module owns byte-layout details shared by instruction families.
//! Higher-level encoders should describe operands/opcodes and delegate bit
//! packing here instead of open-coding REX, ModR/M, or SIB bytes.

/// Build a REX.W prefix (0100 WRXB) for a 64-bit operand.
#[inline]
pub(crate) const fn rex_w(r: bool, x: bool, b: bool) -> u8 {
    0x48 | ((r as u8) << 2) | ((x as u8) << 1) | (b as u8)
}

/// Build a ModR/M byte from its three logical fields.
#[inline]
pub(crate) const fn modrm(mod_bits: u8, reg: u8, rm: u8) -> u8 {
    ((mod_bits & 0b11) << 6) | ((reg & 0b111) << 3) | (rm & 0b111)
}

/// Build a SIB byte from scale, index, and base fields.
#[inline]
pub(crate) const fn sib(scale_bits: u8, index: u8, base: u8) -> u8 {
    ((scale_bits & 0b11) << 6) | ((index & 0b111) << 3) | (base & 0b111)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rex_w_packs_extension_bits() {
        assert_eq!(rex_w(false, false, false), 0x48);
        assert_eq!(rex_w(true, true, true), 0x4f);
    }

    #[test]
    fn modrm_packs_fields() {
        assert_eq!(modrm(0b11, 0, 1), 0xc1);
        assert_eq!(modrm(0b01, 3, 4), 0x5c);
    }

    #[test]
    fn sib_packs_fields() {
        assert_eq!(sib(0b10, 1, 4), 0x8c);
    }
}
