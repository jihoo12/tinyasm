// 외부에서 이 모듈들에 접근할 수 있도록 pub 선언
pub mod registers;
pub mod encoder;
pub mod assembler;
pub mod jit;

// 자주 사용하는 구조체를 리익스포트(Re-export)하면 사용자가 편리합니다.
pub use assembler::Assembler;
pub use encoder::{Instruction, Operand, MemoryAddr};
pub use jit::JitMemory;
