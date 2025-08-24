// relayer/src/zk/circuit.rs - Refactored ZK Circuit for UIBCP
use winter_air::{Air, AirContext, Assertion, EvaluationFrame, TraceInfo, Matrix};
use winter_math::{fields::f252::BaseElement, FieldElement, StarkField};
use winter_crypto::hashers::poseidon::Poseidon;
use winterfell::{Prover, ProofOptions, StarkProof, TraceTable};
use anyhow::{Result, anyhow};
use crate::uibc::v1::{UniversalMessage, ZkProof};
use crate::adapters::chain_adapter::InclusionProof;
use crate::adapters::evm::EVMAdapter;
use ethabi::{encode, Token};

// Corrected and public constants
pub const POSEIDON_WIDTH: usize = 3;
pub const POSEIDON_FULL_ROUNDS: usize = 8;
pub const POSEIDON_PARTIAL_ROUNDS: usize = 56;
pub const MERKLE_LEVELS: usize = 32;
pub const TRACE_WIDTH: usize = POSEIDON_WIDTH + 3 * MERKLE_LEVELS + 1; // 100
pub const POSEIDON_STEPS: usize = POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS; // 64
pub const TOTAL_STEPS: usize = POSEIDON_STEPS * (MERKLE_LEVELS + 1) + 1; // 2113
pub const BN254_MODULUS_LIMBS: [u64; 4] = [
    1161245052955562761,
    18446744073709551615,
    18446744073709551615,
    16584218841459030617,
];

// --- DATA STRUCTURES ---

#[derive(Debug, Clone)]
pub struct Ics23ProofData {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub siblings: Vec<BaseElement>,
    pub path: Vec<bool>,
}

#[derive(Debug, Clone)]
pub struct PublicInputs {
    pub state_root: [BaseElement; 4],
    pub message_hash: BaseElement,
    pub chain_id: BaseElement,
}

// --- AIR CIRCUIT ---

pub struct Ics23Air {
    context: AirContext<BaseElement>,
    pub_inputs: PublicInputs,
    mds_matrix: Matrix<BaseElement>,
    poseidon_round_constants: Vec<BaseElement>,
}

impl Air for Ics23Air {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let hasher = Poseidon::new(POSEIDON_WIDTH, POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS);
        let mds_matrix = hasher.mds_matrix();
        let round_constants = hasher.get_round_constants().to_vec();
        let degrees = vec![2; TRACE_WIDTH];
        let num_assertions = 3;

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            pub_inputs,
            mds_matrix,
            poseidon_round_constants: round_constants,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        let step = frame.position();
        let mut constraint_idx = 0;

        // Trace layout:
        // - Columns 0..2: Poseidon state for leaf and message hash
        // - Columns 3..98: Merkle path (left, right, bit per level)
        // - Column 99: Chain ID

        // Poseidon hashing constraints (leaf/message hash, steps 0..63)
        if step < POSEIDON_STEPS {
            let is_full_round = step < 4 || step >= POSEIDON_STEPS - 4;
            let state = &current[0..POSEIDON_WIDTH];
            let next_state = &next[0..POSEIDON_WIDTH];

            // Add round constants
            for i in 0..POSEIDON_WIDTH {
                result[constraint_idx] = next_state[i] - (state[i] + E::from(self.poseidon_round_constants[step * POSEIDON_WIDTH + i]));
                constraint_idx += 1;
            }

            // S-box layer (x^5)
            if is_full_round {
                for i in 0..POSEIDON_WIDTH {
                    let x = E::from(state[i]);
                    let x2 = x * x;
                    let x4 = x2 * x2;
                    result[constraint_idx] = next_state[i] - x4 * x;
                    constraint_idx += 1;
                }
            } else {
                let x = E::from(state[0]);
                let x2 = x * x;
                let x4 = x2 * x2;
                result[constraint_idx] = next_state[0] - x4 * x;
                constraint_idx += 1;
                for i in 1..POSEIDON_WIDTH {
                    result[constraint_idx] = next_state[i] - E::from(state[i]);
                    constraint_idx += 1;
                }
            }

            // MDS matrix multiplication
            for i in 0..POSEIDON_WIDTH {
                let mut sum = E::ZERO;
                for j in 0..POSEIDON_WIDTH {
                    sum += E::from(self.mds_matrix.get(i, j)) * E::from(state[j]);
                }
                result[constraint_idx] = next_state[i] - sum;
                constraint_idx += 1;
            }
        }

        // Merkle path constraints (steps 64..2112)
        if step >= POSEIDON_STEPS && step < TOTAL_STEPS - 1 {
            let level = (step - POSEIDON_STEPS) / POSEIDON_STEPS;
            let round = (step - POSEIDON_STEPS) % POSEIDON_STEPS;
            let merkle_start = POSEIDON_WIDTH + level * 3;

            if round == 0 {
                let left = current[merkle_start];
                let right = current[merkle_start + 1];
                let bit = current[merkle_start + 2];
                let current_hash = if level == 0 {
                    current[POSEIDON_WIDTH - 1] // Leaf hash
                } else {
                    current[merkle_start - 3 + 2] // Previous level parent
                };

                // Bit constraint: bit * (1 - bit) = 0
                result[constraint_idx] = E::from(bit) * (E::ONE - E::from(bit));
                constraint_idx += 1;

                // Left input selection
                result[constraint_idx] = next[0] - ((E::ONE - E::from(bit)) * E::from(left) + E::from(bit) * E::from(current_hash));
                constraint_idx += 1;

                // Right input selection
                result[constraint_idx] = next[1] - (E::from(bit) * E::from(right) + (E::ONE - E::from(bit)) * E::from(current_hash));
                constraint_idx += 1;

                // Zero padding
                result[constraint_idx] = next[2] - E::ZERO;
                constraint_idx += 1;
            } else {
                let state = &current[merkle_start..merkle_start + POSEIDON_WIDTH];
                let next_state = &next[merkle_start..merkle_start + POSEIDON_WIDTH];
                let is_full_round = round < 4 || round >= POSEIDON_STEPS - 4;

                // Add round constants
                for i in 0..POSEIDON_WIDTH {
                    result[constraint_idx] = next_state[i] - (state[i] + E::from(self.poseidon_round_constants[round * POSEIDON_WIDTH + i]));
                    constraint_idx += 1;
                }

                // S-box layer
                if is_full_round {
                    for i in 0..POSEIDON_WIDTH {
                        let x = E::from(state[i]);
                        let x2 = x * x;
                        let x4 = x2 * x2;
                        result[constraint_idx] = next_state[i] - x4 * x;
                        constraint_idx += 1;
                    }
                } else {
                    let x = E::from(state[0]);
                    let x2 = x * x;
                    let x4 = x2 * x2;
                    result[constraint_idx] = next_state[0] - x4 * x;
                    constraint_idx += 1;
                    for i in 1..POSEIDON_WIDTH {
                        result[constraint_idx] = next_state[i] - E::from(state[i]);
                        constraint_idx += 1;
                    }
                }

                // MDS matrix multiplication
                for i in 0..POSEIDON_WIDTH {
                    let mut sum = E::ZERO;
                    for j in 0..POSEIDON_WIDTH {
                        sum += E::from(self.mds_matrix.get(i, j)) * E::from(state[j]);
                    }
                    result[constraint_idx] = next_state[i] - sum;
                    constraint_idx += 1;
                }
            }
        }

        // Chain ID constraint
        result[constraint_idx] = next[TRACE_WIDTH - 1] - current[TRACE_WIDTH - 1];
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();
        let final_step = TOTAL_STEPS - 1;

        // Assert final root matches public input
        let final_hash_idx = TRACE_WIDTH - POSEIDON_WIDTH;
        let expected_root = self.compute_root_from_limbs();
        assertions.push(Assertion::single(final_hash_idx, final_step, expected_root));

        // Assert message hash constraint
        assertions.push(Assertion::single(POSEIDON_WIDTH - 1, POSEIDON_STEPS - 1, self.pub_inputs.message_hash));

        // Assert chain ID constraint
        assertions.push(Assertion::single(TRACE_WIDTH - 1, 0, self.pub_inputs.chain_id));

        assertions
    }

    fn compute_root_from_limbs(&self) -> Self::BaseField {
        let root_limbs = self.pub_inputs.state_root;
        let base = BaseElement::new(2_u64.pow(64));
        root_limbs[0] +
            root_limbs[1] * base +
            root_limbs[2] * base.square() +
            root_limbs[3] * base.square().square()
    }
}

// --- PROVER ---

pub struct Ics23StarkProver {
    options: ProofOptions,
}

impl Ics23StarkProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    pub fn generate_proof(
        &self,
        message: &UniversalMessage,
        ics23_proof: &InclusionProof,
    ) -> Result<ZkProof> {
        let proof_data = self.convert_to_circuit_proof(ics23_proof)?;
        let pub_inputs = self.extract_public_inputs(message, &proof_data)?;
        let trace = self.build_trace(&proof_data, &pub_inputs)?;

        let prover = Ics23StarkProver::new(self.options.clone());
        let zk_proof = prover.generate_proof(message, ics23_proof)?;
        let trace_info = TraceInfo::new(TRACE_WIDTH, TOTAL_STEPS);
        let air = Ics23Air::new(trace_info, pub_inputs.clone(), self.options.clone());
        let stark_proof = prover
            .prove_with_air::<Ics23Air, Poseidon>(trace, &air)
            .map_err(|e| anyhow!("STARK proof generation failed: {}", e))?;

        let proof_data = stark_proof.to_bytes();
        let public_inputs = self.serialize_public_inputs(&pub_inputs)?;

        Ok(ZkProof {
            proof_data,
            public_inputs,
            circuit_id: "ics23_verification".to_string(),
            proof_system: "stark".to_string(),
            proof_generation_cost: 10_000,
            verification_gas_limit: 5_000,
        })
    }

    fn convert_to_circuit_proof(&self, proof: &InclusionProof) -> Result<Ics23ProofData> {
        let siblings = self.parse_siblings(&proof.proof_data)?;
        let path = self.parse_path(&proof.proof_data)?;

        Ok(Ics23ProofData {
            key: proof.path.clone(),
            value: proof.value.clone(),
            siblings,
            path,
        })
    }

    fn parse_siblings(&self, proof_data: &[u8]) -> Result<Vec<BaseElement>> {
        if proof_data.len() < MERKLE_LEVELS * 32 {
            return Err(anyhow!("Insufficient proof data for siblings"));
        }
        let mut siblings = Vec::with_capacity(MERKLE_LEVELS);
        for i in 0..MERKLE_LEVELS {
            let start = i * 32;
            let sibling_bytes = &proof_data[start..start + 32];
            let sibling = BaseElement::from_bytes(sibling_bytes).map_err(|e| anyhow!("Invalid sibling: {}", e))?;
            siblings.push(sibling);
        }
        Ok(siblings)
    }

    fn parse_path(&self, proof_data: &[u8]) -> Result<Vec<bool>> {
        let offset = MERKLE_LEVELS * 32;
        if proof_data.len() < offset + MERKLE_LEVELS / 8 {
            return Err(anyhow!("Insufficient proof data for path"));
        }
        let mut path = Vec::with_capacity(MERKLE_LEVELS);
        for i in 0..MERKLE_LEVELS {
            let byte_idx = offset + i / 8;
            let bit_idx = i % 8;
            let bit = (proof_data[byte_idx] >> bit_idx) & 1;
            path.push(bit == 1);
        }
        Ok(path)
    }

    fn extract_public_inputs(&self, message: &UniversalMessage, proof: &Ics23ProofData) -> Result<PublicInputs> {
        let state_root = if let Some(checkpoint) = &message.state_checkpoint {
            self.bytes_to_field_limbs(&checkpoint.state_root)?
        } else {
            [BaseElement::ZERO; 4]
        };

        let message_hash = self.hash_message(message)?;
        let chain_id = if let Some(dest) = &message.destination {
            self.string_to_field(&dest.chain_id)?
        } else {
            BaseElement::ZERO
        };

        Ok(PublicInputs {
            state_root,
            message_hash,
            chain_id,
        })
    }

    fn build_trace(&self, proof: &Ics23ProofData, pub_inputs: &PublicInputs) -> Result<TraceTable<BaseElement>> {
        let mut trace = TraceTable::new(TRACE_WIDTH, TOTAL_STEPS);
        let hasher = Poseidon::new(POSEIDON_WIDTH, POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS);

        // Initialize chain ID column
        for row in 0..TOTAL_STEPS {
            trace[(row, TRACE_WIDTH - 1)] = pub_inputs.chain_id;
        }

        // Compute leaf hash: H(0x00 || key, value, 0)
        let leaf_input = [
            self.bytes_to_field(&[vec![0x00], proof.key.clone()].concat())?,
            self.bytes_to_field(&proof.value)?,
            BaseElement::ZERO,
        ];
        let mut state = leaf_input;
        for step in 0..POSEIDON_STEPS {
            for i in 0..POSEIDON_WIDTH {
                trace[(step, i)] = state[i];
            }
            hasher.apply_round(&mut state, step);
        }
        let leaf_hash = state[0];

        // Merkle path computation
        let mut current_hash = leaf_hash;
        for level in 0..MERKLE_LEVELS {
            let step_base = POSEIDON_STEPS * (level + 1);
            let merkle_start = POSEIDON_WIDTH + level * 3;

            // Set left, right, and path bit
            let left = if proof.path[level] { proof.siblings[level] } else { current_hash };
            let right = if proof.path[level] { current_hash } else { proof.siblings[level] };
            trace[(step_base, merkle_start)] = left;
            trace[(step_base, merkle_start + 1)] = right;
            trace[(step_base, merkle_start + 2)] = if proof.path[level] { BaseElement::ONE } else { BaseElement::ZERO };

            // Compute parent hash
            state = [left, right, BaseElement::ZERO];
            for round in 0..POSEIDON_STEPS {
                for i in 0..POSEIDON_WIDTH {
                    trace[(step_base + round, merkle_start + i)] = state[i];
                }
                hasher.apply_round(&mut state, round);
            }
            current_hash = state[0];
        }

        // Set final root
        trace[(TOTAL_STEPS - 1, TRACE_WIDTH - POSEIDON_WIDTH)] = pub_inputs.compute_root_from_limbs();

        Ok(trace)
    }

    fn bytes_to_field(&self, bytes: &prost::bytes::Bytes) -> Result<BaseElement> {
        if bytes.is_empty() {
            return Ok(BaseElement::ZERO);
        }
        
        // Logic for long byte arrays (more than 31 bytes)
        if bytes.len() > 31 {
            let hasher = Poseidon::new(POSEIDON_WIDTH, POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS);
            let chunks: Vec<BaseElement> = bytes
                .chunks(31)
                .map(|chunk| {
                    let mut padded = [0u8; 32];
                    chunk.iter().enumerate().for_each(|(i, &b)| padded[i] = b);
                    BaseElement::from_bytes(&padded).unwrap_or(BaseElement::ZERO)
                })
                .collect();
            let digest = hasher.hash_elements(&chunks);
            BaseElement::from_bytes(&digest[0..32]).map_err(|e| anyhow!("Invalid bytes: {}", e))
        } else { // Logic for short byte arrays (31 bytes or less)
            let mut padded = [0u8; 32];
            bytes.iter().enumerate().for_each(|(i, &b)| padded[i] = b);
            BaseElement::from_bytes(&padded).map_err(|e| anyhow!("Invalid bytes: {}", e))
        }
    }

    fn bytes_to_field_limbs(&self, bytes: &[u8]) -> Result<[BaseElement; 4]> {
        if bytes.len() != 32 {
            return Err(anyhow!("Expected 32-byte input for field limbs"));
        }
        let mut limbs = [BaseElement::ZERO; 4];
        for i in 0..4 {
            let chunk = &bytes[i * 8..(i + 1) * 8];
            let value = u64::from_le_bytes(chunk.try_into()?);
            limbs[i] = BaseElement::new(value);
        }
        Ok(limbs)
    }

    fn hash_message(&self, message: &UniversalMessage) -> Result<BaseElement> {
        let hasher = Poseidon::new(POSEIDON_WIDTH, POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS);
        let message_bytes = message.encode_to_vec();
        let digest = hasher.hash_bytes(&message_bytes);
        BaseElement::from_bytes(&digest[0..32]).map_err(|e| anyhow!("Invalid message hash: {}", e))
    }

    fn string_to_field(&self, s: &str) -> Result<BaseElement> {
        self.bytes_to_field(s.as_bytes())
    }

    fn serialize_public_inputs(&self, pub_inputs: &PublicInputs) -> Result<Vec<u8>> {
        let base = BaseElement::new(2_u64.pow(64));
        let state_root_val = pub_inputs.state_root[0] +
            pub_inputs.state_root[1] * base +
            pub_inputs.state_root[2] * base.square() +
            pub_inputs.state_root[3] * base.square().square();

        let tokens = vec![
            Token::Uint(u256_from_base_element(state_root_val)),
            Token::Uint(u256_from_base_element(pub_inputs.message_hash)),
            Token::Uint(u256_from_base_element(pub_inputs.chain_id)),
        ];

        Ok(encode(&tokens))
    }
}

// Helper function to convert BaseElement to U256
fn u256_from_base_element(val: BaseElement) -> ethabi::Uint {
    let mut bytes = [0u8; 32];
    val.to_bytes(&mut bytes);
    ethabi::Uint::from_big_endian(&bytes)
}

// --- TESTS & INTEGRATION ---

#[cfg(test)]
mod tests {
    use super::*;
    use winter_air::ProofOptions;

    #[test]
    fn test_generate_proof() {
        let hasher = winter_crypto::hashers::Poseidon::new(POSEIDON_WIDTH, POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS);
        let options = ProofOptions::new(
            32,
            8,
            0,
            hasher.clone(),
            hasher,
            4,
        );
        let prover = Ics23StarkProver::new(options);

        let message = UniversalMessage {
            state_checkpoint: Some(crate::proto::uibc::v1::StateCheckpoint {
                state_root: vec![0u8; 32],
                ..Default::default()
            }),
            destination: Some(crate::proto::uibc::v1::Destination {
                chain_id: "test-chain".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ics23_proof = InclusionProof {
            path: vec![0u8; 32],
            value: vec![1u8; 32],
            proof_data: vec![0u8; MERKLE_LEVELS * 32 + MERKLE_LEVELS / 8],
        };

        let result = prover.generate_proof(&message, &ics23_proof);
        assert!(result.is_ok(), "Proof generation failed: {:?}", result.err());
    }
}

// Integration with UIBCP fee calculator
impl Ics23StarkProver {
    pub fn estimate_proof_cost(&self, message: &UniversalMessage) -> Result<u64> {
        let base_cost = 10_000u64;
        let complexity_multiplier = match &message.payload {
            Some(crate::uibc::v1::universal_message::Payload::TokenTransfer(_)) => 1.0,
            Some(crate::uibc::v1::universal_message::Payload::ContractCall(_)) => 1.5,
            Some(crate::uibc::v1::universal_message::Payload::BatchTransfer(batch)) => {
                1.0 + (batch.transfers.len() as f64 * 0.1)
            },
            _ => 1.2,
        };
        Ok((base_cost as f64 * complexity_multiplier) as u64)
    }

    pub fn estimate_verification_cost(&self) -> u64 {
        5_000
    }
}

// Integration helper for EVM adapter
impl EVMAdapter {
    pub async fn generate_optimistic_proof(
        &self,
        message: &UniversalMessage,
        ics23_proof: &InclusionProof,
    ) -> Result<Vec<u8>> {
        let hasher = winter_crypto::hashers::Poseidon::new(POSEIDON_WIDTH, POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS);
        let options = ProofOptions::new(
            32,
            8,
            0,
            hasher.clone(),
            hasher,
            4,
        );
        let prover = Ics23StarkProver::new(options);
        let zk_proof = prover.generate_proof(message, ics23_proof)?;
        Ok(zk_proof.proof_data)
    }
}
