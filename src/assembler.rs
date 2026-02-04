use std::collections::HashMap;
use crate::encoder::{Instruction, encode_instruction, EncodeError};

pub struct Assembler {
    // 코드 전체를 저장
    instructions: Vec<Instruction>,
    // 라벨 이름 -> 바이트 오프셋 (주소) 매핑
    labels: HashMap<String, usize>, 
}

impl Assembler {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            labels: HashMap::new(),
        }
    }

    pub fn add_instruction(&mut self, instr: Instruction) {
        self.instructions.push(instr);
    }

    // 🔥 핵심 로직: 2-Pass 어셈블리 수행
    pub fn assemble(&mut self) -> Result<Vec<u8>, EncodeError> {
        // --- [Pass 1] 주소 계산 및 심볼 테이블 작성 ---
        let mut current_offset = 0;
        self.labels.clear();

        for instr in &self.instructions {
            match instr {
                Instruction::Label(name) => {
                    // 현재 위치(offset)를 라벨 이름과 함께 기록
                    self.labels.insert(name.clone(), current_offset);
                }
                _ => {
                    // 명령어의 크기를 더함
                    current_offset += self.estimate_size(instr)?;
                }
            }
        }

        // --- [Pass 2] 실제 기계어 생성 ---
        let mut output_bytes = Vec::new();
        let mut current_offset = 0; // 다시 0부터 시작

        for instr in &self.instructions {
            match instr {
                Instruction::Label(_) => {
                    // 라벨은 실제 코드로 변환되지 않음 (위치만 표시할 뿐)
                    continue;
                }
                Instruction::JmpLabel(target) => {
                    // 1. 타겟 라벨의 주소를 가져옴
                    let target_addr = *self.labels.get(target)
                        .ok_or(EncodeError::Other(format!("Label not found: {}", target)))?;
                    
                    // 2. 상대 주소 계산 (Target - (Current + 5))
                    // JMP(E9)는 5바이트 명령어이므로, 명령어 끝나는 지점 기준 차이를 구함
                    let instr_len = 5;
                    let next_ip = current_offset + instr_len;
                    let relative_offset = (target_addr as i32) - (next_ip as i32);

                    // 3. 바이트 생성 (0xE9 + disp32)
                    output_bytes.push(0xE9);
                    output_bytes.extend_from_slice(&relative_offset.to_le_bytes());
                    
                    current_offset += instr_len;
                }
                Instruction::JeLabel(target) => {
                    // JE (0F 84) + disp32 (총 6바이트)
                    let target_addr = *self.labels.get(target)
                        .ok_or(EncodeError::Other(format!("Label not found: {}", target)))?;
                    
                    let instr_len = 6;
                    let next_ip = current_offset + instr_len;
                    let relative_offset = (target_addr as i32) - (next_ip as i32);

                    output_bytes.push(0x0F);
                    output_bytes.push(0x84);
                    output_bytes.extend_from_slice(&relative_offset.to_le_bytes());
                    
                    current_offset += instr_len;
                }
                // 🔥 추가된 부분: JNE 처리
                Instruction::JneLabel(target) => {
                    let target_addr = *self.labels.get(target)
                        .ok_or(EncodeError::Other(format!("Label not found: {}", target)))?;
                    
                    let instr_len = 6;
                    let next_ip = current_offset + instr_len;
                    let relative_offset = (target_addr as i32) - (next_ip as i32);

                    output_bytes.push(0x0F);
                    output_bytes.push(0x85); // JNE opcode
                    output_bytes.extend_from_slice(&relative_offset.to_le_bytes());
                    current_offset += instr_len;
                }
                _ => {
                    // 일반 명령어: 기존 인코더 사용
                    let bytes = encode_instruction(instr.clone())?;
                    current_offset += bytes.len();
                    output_bytes.extend(bytes);
                }
            }
        }

        Ok(output_bytes)
    }

    // 📏 명령어 크기 예측 함수
    // 점프 명령어는 5바이트(JMP) 혹은 6바이트(Jcc)로 고정한다고 가정 (단순화를 위해 Long Jump 사용)
    fn estimate_size(&self, instr: &Instruction) -> Result<usize, EncodeError> {
        match instr {
            Instruction::Label(_) => Ok(0),
            Instruction::JmpLabel(_) => Ok(5), // E9 xx xx xx xx
            Instruction::JeLabel(_) => Ok(6),  // 0F 84 xx xx xx xx
            Instruction::JneLabel(_) => Ok(6), // 0F 85 xx xx xx xx
            _ => {
                // 일반 명령어는 실제로 인코딩해봐서 길이를 잰다 (가장 확실한 방법)
                let bytes = encode_instruction(instr.clone())?;
                Ok(bytes.len())
            }
        }
    }
}
