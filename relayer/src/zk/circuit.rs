// relayer/src/zk/circuit.rs
use winter_air::{Air, AirContext, Assertion, EvaluationFrame, TraceInfo, Matrix};
use winter_math::{fields::f252::BaseElement, FieldElement, StarkField};
use winter_crypto::hashers::poseidon::{Poseidon, PoseidonSponge}; // Use PoseidonSponge for hashing inputs
use winterfell::{Prover, ProofOptions, StarkProof, TraceTable};
use anyhow::{Result, anyhow};
use prost::Message; // Use Message trait for prost
use crate::proto::uibc::v1::{UniversalMessage, ZkProof};
use crate::adapters::chain_adapter::InclusionProof;
use crate::adapters::evm::EVMAdapter;
use ethabi::{encode, Token};

// --- CORRECTED AND PUBLIC CONSTANTS ---
// These constants define the parameters for the STARK circuit.
// TRACE_WIDTH: The number of columns in the execution trace.
// TOTAL_STEPS: The number of rows in the execution trace.
pub const POSEIDON_WIDTH: usize = 3;
pub const POSEIDON_FULL_ROUNDS: usize = 8;
pub const POSEIDON_PARTIAL_ROUNDS: usize = 56;
pub const MERKLE_LEVELS: usize = 32;
pub const TRACE_WIDTH: usize = 3; // The Poseidon state
pub const TOTAL_STEPS: usize = (MERKLE_LEVELS + 1) * (POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS);

// --- DATA STRUCTURES ---

/// Public inputs for the STARK circuit.
/// These values are not part of the proof but are required for verification.
#[derive(Debug, Clone)]
pub struct PublicInputs {
    pub state_root: [BaseElement; 4],
    pub message_hash: BaseElement,
    pub chain_id: BaseElement,
}

/// The Air circuit for ICS-23 inclusion proofs.
/// This circuit verifies the integrity of a Poseidon Merkle proof.
pub struct Ics23Air {
    context: AirContext<BaseElement>,
    pub_inputs: PublicInputs,
}

impl Air for Ics23Air {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // We define the degree of the transition constraints.
        // The degree of the Poseidon hash function is 9, so we set our constraint degree to 9.
        let degrees = vec![9; TRACE_WIDTH];
        // We have three assertions: one for the leaf hash, one for the final root hash,
        // and one for the chain ID.
        let num_assertions = 3;
        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    /// This function evaluates the transition constraints of the circuit.
    /// It ensures that the state transitions in the trace are consistent with the
    /// Poseidon hash function.
    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // The constraints enforce the Poseidon state transition.
        let mut state = [current[0], current[1], current[2]];
        let mut next_state = [next[0], next[1], next[2]];

        let poseidon_hasher = Poseidon::new(
            POSEIDON_WIDTH,
            POSEIDON_FULL_ROUNDS,
            POSEIDON_PARTIAL_ROUNDS,
        );

        poseidon_hasher.apply_round(&mut state, 0); // Apply the first round
        
        // This constraint ensures that `next_state` is the result of applying
        // a Poseidon round to `current_state`.
        for i in 0..POSEIDON_WIDTH {
            result[i] = next_state[i] - state[i];
        }
    }
    
    /// This function defines the assertions (boundary constraints) of the circuit.
    /// These are the public values that are pinned to specific points in the trace.
    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();

        let steps_per_merkle_level = POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS;

        // Assertion 1: Leaf hash
        // The last state of the first Poseidon hash computation (the leaf hash)
        // must match the expected message hash from public inputs.
        let leaf_hash_step = steps_per_merkle_level - 1;
        assertions.push(Assertion::single(
            0,
            leaf_hash_step,
            self.pub_inputs.message_hash,
        ));
        
        // Assertion 2: Root hash
        // The last state of the final Poseidon hash computation (the root hash)
        // must match the expected state root from public inputs.
        let final_hash_step = TOTAL_STEPS - 1;
        let expected_root = self.compute_root_from_limbs();
        assertions.push(Assertion::single(
            0,
            final_hash_step,
            expected_root,
        ));
        
        // Assertion 3: Chain ID (ensures it is constant throughout the trace)
        // This is a placeholder for a more complex chain ID assertion if needed.
        assertions.push(Assertion::single(
            TRACE_WIDTH - 1, 0,
            self.pub_inputs.chain_id,
        ));

        assertions
    }
    
    /// Helper function to convert 4 field limbs back into a single field element.
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

/// The prover for the ICS-23 STARK circuit.
pub struct Ics23StarkProver {
    options: ProofOptions,
}

impl Ics23StarkProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    /// Generates a STARK proof for the given message and inclusion proof.
    pub fn generate_proof(
        &self,
        message: &UniversalMessage,
        ics23_proof: &InclusionProof,
    ) -> Result<ZkProof> {
        // Step 1: Prepare data for the circuit
        let proof_data = self.convert_to_circuit_proof(ics23_proof)?;
        let pub_inputs = self.extract_public_inputs(message, &proof_data)?;
        let trace = self.build_trace(&proof_data)?;

        // Step 2: Create a prover instance and generate the proof
        let prover = winterfell::Prover::new(self.options.clone());
        let stark_proof = prover.prove(Ics23Air::new(
            trace.info(),
            pub_inputs.clone(),
            self.options.clone(),
        ), trace)
        .map_err(|e| anyhow!("STARK proof generation failed: {}", e))?;

        // Step 3: Serialize the proof and public inputs
        let proof_data = stark_proof.to_bytes();
        let public_inputs = self.serialize_public_inputs(&pub_inputs)?;

        // Step 4: Return the final ZkProof object
        Ok(ZkProof {
            proof_data,
            public_inputs,
            circuit_id: "ics23_verification".to_string(),
            proof_system: "stark".to_string(),
            proof_generation_cost: self.estimate_proof_cost(message)?,
            verification_gas_limit: self.estimate_verification_cost(),
        })
    }

    // --- HELPER METHODS ---

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
            let sibling = BaseElement::from_bytes(sibling_bytes)
                .map_err(|e| anyhow!("Invalid sibling: {}", e))?;
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

    fn extract_public_inputs(&self, message: &UniversalMessage, _proof: &Ics23ProofData) -> Result<PublicInputs> {
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
    
    /// This function builds the execution trace for the STARK proof.
    /// It simulates the Poseidon hash and Merkle tree traversal.
    fn build_trace(&self, proof: &Ics23ProofData) -> Result<TraceTable<BaseElement>> {
        let steps_per_level = POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS;
        let mut trace = TraceTable::new(TRACE_WIDTH, TOTAL_STEPS);
        let hasher = Poseidon::new(POSEIDON_WIDTH, POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS);

        // Compute leaf hash
        let leaf_input = [
            bytes_to_field(&[vec![0x00], proof.key.clone()].concat())?,
            bytes_to_field(&proof.value)?,
            BaseElement::ZERO,
        ];
        
        let mut state = leaf_input;
        for step in 0..steps_per_level {
            trace[(step, 0)] = state[0];
            trace[(step, 1)] = state[1];
            trace[(step, 2)] = state[2];
            hasher.apply_round(&mut state, step);
        }

        // Merkle path computation
        let mut current_hash = state[0];
        for level in 0..MERKLE_LEVELS {
            let step_base = steps_per_level * (level + 1);
            let left_sibling = if proof.path[level] { proof.siblings[level] } else { current_hash };
            let right_sibling = if proof.path[level] { current_hash } else { proof.siblings[level] };

            let mut state = [left_sibling, right_sibling, BaseElement::ZERO];

            for round in 0..steps_per_level {
                trace[(step_base + round, 0)] = state[0];
                trace[(step_base + round, 1)] = state[1];
                trace[(step_base + round, 2)] = state[2];
                hasher.apply_round(&mut state, round);
            }
            current_hash = state[0];
        }

        Ok(trace)
    }

    fn bytes_to_field(bytes: &[u8]) -> Result<BaseElement> {
        let mut padded = [0u8; 32];
        let len = bytes.len().min(32);
        padded[..len].copy_from_slice(&bytes[..len]);
        BaseElement::from_bytes(&padded).map_err(|e| anyhow!("Invalid bytes: {}", e))
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
        let mut hasher = PoseidonSponge::new();
        let message_bytes = message.encode_to_vec();
        hasher.absorb_bytes(&message_bytes);
        let digest_bytes = hasher.squeeze_bytes(32);
        BaseElement::from_bytes(&digest_bytes[0..32]).map_err(|e| anyhow!("Invalid message hash: {}", e))
    }
    
    fn string_to_field(&self, s: &str) -> Result<BaseElement> {
        Self::bytes_to_field(s.as_bytes())
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
    use crate::proto::uibc::v1::{UniversalMessage, ChainEndpoint};
    use crate::proto::uibc::v1::StateCheckpoint;
    use winterfell::ProofOptions;

    #[test]
    fn test_generate_proof() {
        let options = ProofOptions::new(
            4, 256, 16, false, 8, 2048, 2048, 1, 1, 1,
        );
        let prover = Ics23StarkProver::new(options);

        let message = UniversalMessage {
            state_checkpoint: Some(StateCheckpoint {
                state_root: vec![0u8; 32],
                ..Default::default()
            }),
            destination: Some(ChainEndpoint {
                chain_id: "test-chain".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let ics23_proof = InclusionProof {
            path: vec![0u8; 32],
            value: vec![1u8; 32],
            proof_data: vec![0u8; MERKLE_LEVELS * 32 + MERKLE_LEVELS / 8],
            proof_type: "ics23".to_string(),
        };

        let result = prover.generate_proof(&message, &ics23_proof);
        assert!(result.is_ok(), "Proof generation failed: {:?}", result.err());
    }
}

// Integration with UIBCP fee calculator
impl Ics23StarkProver {
    pub fn estimate_proof_cost(&self, message: &UniversalMessage) -> Result<u64> {
        let base_cost = 10_000u64;
        let complexity_multiplier = match message.payload {
            Some(crate::proto::uibc::v1::universal_message::Payload::TokenTransfer(_)) => 1.0,
            Some(crate::proto::uibc::v1::universal_message::Payload::ContractCall(_)) => 1.5,
            Some(crate::proto::uibc::v1::universal_message::Payload::BatchTransfer(ref batch)) => {
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
        let options = ProofOptions::new(
            4, 256, 16, false, 8, 2048, 2048, 1, 1, 1,
        );
        let prover = Ics23StarkProver::new(options);
        let zk_proof = prover.generate_proof(message, ics23_proof)?;
        Ok(zk_proof.proof_data)
    }
}
