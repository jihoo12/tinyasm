use std::collections::HashMap;
use crate::encoder::{Instruction, encode_instruction, EncodeError};

pub struct Assembler {
    // 코드 전체를 저장
    instructions: Vec<Instruction>,
    // 라벨 이름 -> 바이트 오프셋 (주소) 매핑
    labels: HashMap<String, usize>,
    // 🔥 추가: 디버그 모드 플래그
    debug: bool,
}

impl Assembler {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            labels: HashMap::new(),
            debug: false, // 기본값은 '출력 안 함'
        }
    }

    // 🔥 추가: 체이닝 방식으로 디버그 모드를 설정할 수 있는 메서드
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    pub fn add_instruction(&mut self, instr: Instruction) {
        self.instructions.push(instr);
    }

    // 🔥 핵심 로직: 2-Pass 어셈블리 수행
    pub fn assemble(&mut self) -> Result<Vec<u8>, EncodeError> {
        // --- [Pass 1] 주소 계산 및 심볼 테이블 작성 ---
        if self.debug { println!("--- [Pass 1] Symbol Resolution ---"); }
        
        let mut current_offset = 0;
        self.labels.clear();

        for instr in &self.instructions {
            match instr {
                Instruction::Label(name) => {
                    // 현재 위치(offset)를 라벨 이름과 함께 기록
                    self.labels.insert(name.clone(), current_offset);
                    if self.debug { println!("  Label defined: {} at offset 0x{:X}", name, current_offset); }
                }
                _ => {
                    // 명령어의 크기를 더함
                    let size = self.estimate_size(instr)?;
                    current_offset += size;
                }
            }
        }

        // --- [Pass 2] 실제 기계어 생성 ---
        if self.debug { println!("--- [Pass 2] Code Generation ---"); }

        let mut output_bytes = Vec::new();
        let mut current_offset = 0; // 다시 0부터 시작

        for instr in &self.instructions {
            // 디버그 모드일 때 현재 처리 중인 명령어 출력
            if self.debug { 
                print!("  [0x{:04X}] {:<30} => ", current_offset, format!("{}", instr)); 
            }

            let instr_bytes = match instr {
                Instruction::Label(_) => {
                    if self.debug { println!("(Label)"); }
                    // 라벨은 실제 코드로 변환되지 않음
                    continue;
                }
                Instruction::JmpLabel(target) => {
                    let target_addr = *self.labels.get(target)
                        .ok_or(EncodeError::Other(format!("Label not found: {}", target)))?;
                    
                    let instr_len = 5;
                    let next_ip = current_offset + instr_len;
                    let relative_offset = (target_addr as i32) - (next_ip as i32);

                    let mut bytes = vec![0xE9];
                    bytes.extend_from_slice(&relative_offset.to_le_bytes());
                    
                    current_offset += instr_len;
                    bytes
                }
                Instruction::JeLabel(target) => {
                    let target_addr = *self.labels.get(target)
                        .ok_or(EncodeError::Other(format!("Label not found: {}", target)))?;
                    
                    let instr_len = 6;
                    let next_ip = current_offset + instr_len;
                    let relative_offset = (target_addr as i32) - (next_ip as i32);

                    let mut bytes = vec![0x0F, 0x84];
                    bytes.extend_from_slice(&relative_offset.to_le_bytes());
                    
                    current_offset += instr_len;
                    bytes
                }
                Instruction::JneLabel(target) => {
                    let target_addr = *self.labels.get(target)
                        .ok_or(EncodeError::Other(format!("Label not found: {}", target)))?;
                    
                    let instr_len = 6;
                    let next_ip = current_offset + instr_len;
                    let relative_offset = (target_addr as i32) - (next_ip as i32);

                    let mut bytes = vec![0x0F, 0x85];
                    bytes.extend_from_slice(&relative_offset.to_le_bytes());
                    current_offset += instr_len;
                    bytes
                }
                _ => {
                    let bytes = encode_instruction(instr.clone())?;
                    current_offset += bytes.len();
                    bytes
                }
            };

            // 디버그 모드일 때 생성된 바이트 출력
            if self.debug {
                print!("[");
                for b in &instr_bytes { print!("{:02X} ", b); }
                println!("]");
            }

            output_bytes.extend(instr_bytes);
        }

        Ok(output_bytes)
    }

    // 📏 명령어 크기 예측 함수
    fn estimate_size(&self, instr: &Instruction) -> Result<usize, EncodeError> {
        match instr {
            Instruction::Label(_) => Ok(0),
            Instruction::JmpLabel(_) => Ok(5), 
            Instruction::JeLabel(_) => Ok(6), 
            Instruction::JneLabel(_) => Ok(6), 
            _ => {
                let bytes = encode_instruction(instr.clone())?;
                Ok(bytes.len())
            }
        }
    }
}
