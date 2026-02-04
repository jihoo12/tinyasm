// 1. 프로젝트 내의 다른 파일(모듈)들을 불러옵니다.
mod registers;
mod encoder;
mod assembler;
mod jit;

// 2. 필요한 타입들을 현재 범위로 가져옵니다.
use crate::registers::Register::*; // RAX, RCX 등을 바로 쓰기 위함
use crate::encoder::{Instruction, Operand}; // Instruction, Operand 사용
use crate::assembler::Assembler;
use crate::jit::JitMemory;

fn main() {
    let mut asm = Assembler::new();

    // === 루프(Loop) 예제: RAX를 0부터 5까지 증가시키기 ===

    // 1. 초기화: mov rax, 0
    asm.add_instruction(Instruction::Mov(Operand::Reg(RAX), Operand::Imm32(0)));
    
    // 2. 라벨 정의: loop_start (여기로 다시 돌아올 예정)
    asm.add_instruction(Instruction::Label("loop_start".to_string()));

    // 3. 값 증가: add rax, 1
    asm.add_instruction(Instruction::Add(Operand::Reg(RAX), Operand::Imm32(1)));

    // 4. 비교: cmp rax, 5
    // rax와 5를 비교하여 CPU의 EFLAGS 레지스터를 업데이트합니다.
    asm.add_instruction(Instruction::Cmp(Operand::Reg(RAX), Operand::Imm32(5)));

    // 5. 조건부 점프: jne loop_start
    // Jump if Not Equal: rax가 5가 아니면 "loop_start"로 점프합니다.
    asm.add_instruction(Instruction::JneLabel("loop_start".to_string()));

    // 6. 종료: ret (함수를 끝내고 rax 값을 반환)
    asm.add_instruction(Instruction::Ret);

    // --- 실행 과정 ---
    match asm.assemble() {
        Ok(code) => {
            println!("✅ 생성된 기계어: {:02X?}", code);
            
            // JIT 메모리 할당 및 쓰기
            let mut jit = JitMemory::new(code.len()).unwrap_or_else(|e| {
                panic!("JIT 메모리 할당 실패: {}", e);
            });
            
            jit.write(&code).unwrap();
            jit.make_executable().unwrap();
            
            // 기계어를 함수로 캐스팅하여 실행
            let func = unsafe { jit.as_fn_u64() };
            let result = func();
            
            println!("--- JIT 실행 결과 ---");
            println!("RAX 최종 값: {}", result); // 5가 나오면 성공!
        },
        Err(e) => println!("❌ 어셈블리 오류: {}", e),
    }
}
