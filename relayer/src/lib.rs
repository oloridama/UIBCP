// relayer/src/lib.rs
use winter_air::{Air, AirContext, Assertion, EvaluationFrame, TraceInfo, Matrix, ProofOptions, FieldExtension};
use winter_math::{fields::f252::BaseElement, FieldElement, StarkField};
use winter_crypto::hashers::poseidon::Poseidon;
use winterfell::{Prover, StarkProof, TraceTable};
use anyhow::{Result, anyhow};
use prost::bytes::Bytes;
use crate::uibc::v1::{UniversalMessage, ZkProof, ZkProofRequirement, Ics23Proof, ChainType, proof_requirement::Requirement};
use crate::uibc::ibc::v1::IbcCompatibilityData;
use crate::uibc::ibc::extensions::EVMExtension;
use crate::zk::circuit::{Ics23StarkProver, PublicInputs, Ics23Air};

// Corrected import path for `uibc_gen.rs`
mod uibc {
    include!(concat!(env!("OUT_DIR"), "/uibc_gen.rs"));
}

pub mod adapters;
pub mod zk;

pub const MODULUS: u64 = BaseElement::MODULUS as u64;

// Relayer Logic
pub fn generate_zkp(
    message: UniversalMessage,
    proof: Ics23Proof,
    root: [BaseElement; 4],
    zk_req: Option<ZkProofRequirement>,
    ibc_data: Option<IbcCompatibilityData>,
    evm_ext: Option<EVMExtension>,
) -> Result<Vec<u8>> {
    let trace_info = TraceInfo::new(TRACE_WIDTH, TOTAL_STEPS);
    let degrees = Ics23Air::transition_constraint_degrees();
    let num_assertions = Ics23Air::num_assertions();

    let air = Ics23Air {
        context: AirContext::new(trace_info, degrees, num_assertions, ProofOptions::new(4, 256, 16, false, 8, 2048, 2048, 1, 1, 1)),
        poseidon: Poseidon::new(POSEIDON_WIDTH, POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS),
        pub_inputs: PublicInputs {
            message_hash: bytes_to_field(&message.message_id),
            state_root: root,
            chain_id: bytes_to_field(&message.source.as_ref().map_or_else(|| "".to_string(), |s| s.chain_id.clone()).as_bytes()),
            sequence: ibc_data.as_ref().map_or(BaseElement::ZERO, |d| BaseElement::new(d.sequence % MODULUS)),
            gas_limit: evm_ext.as_ref().map_or(BaseElement::ZERO, |e| BaseElement::new(e.gas_limit % MODULUS)),
            max_fee_per_gas: evm_ext.as_ref().map_or(BaseElement::ZERO, |e| BaseElement::new(e.max_fee_per_gas % MODULUS)),
        },
    };

    let prover = Ics23Prover {
        air,
        options: ProofOptions::default(),
    };

    let trace = prover.build_trace(message, proof, zk_req, ibc_data, evm_ext)?;
    
    prover.prove(trace).map_err(|e| anyhow!("Proving failed: {}", e))
}

// Message Processing
pub fn process_message(message: uibc::v1::UniversalMessage, proof: uibc::v1::Ics23Proof, root: [BaseElement; 4]) -> Result<Vec<u8>> {
    // 1. Validate the message and proof
    if !message.is_valid() {
        return Err(anyhow!("Message validation failed"));
    }
    if message.message_id.is_empty() {
        return Err(anyhow!("Message has no message_id"));
    }

    let proof_len = (proof.proof_data.len() - MERKLE_LEVELS / 8) / 32;
    if proof_len != MERKLE_LEVELS {
        return Err(anyhow!("Invalid proof length"));
    }

    // 2. Check for ZK proof requirement
    let zk_req = match &message.proof_requirement {
        Some(uibc::v1::proof_requirement::Requirement::ZkProof(req)) => Some(req.clone()),
        _ => None,
    };

    if zk_req.is_none() {
        return Err(anyhow!("Unsupported or empty payload for ZK proof"));
    }

    // 3. Instantiate the prover and generate the proof
    let options = ProofOptions::new(4, 256, 16, Some(FieldExtension::Quadratic), 8, 2048);
    let prover = Ics23StarkProver::new(options);
    
    // The prover needs the InclusionProof data structure, not the raw fields.
    let inclusion_proof = InclusionProof {
        path: proof.key,
        value: proof.value,
        proof_data: proof.proof_data,
    };

    // Correctly call generate_proof with all required inputs
    let zk_proof = prover.generate_proof(&message, &inclusion_proof)?;
    
    Ok(zk_proof.proof_data)
    // Extract payload for ZK proof (using TokenTransfer as an example)
    //let (key, value) = match &message.payload {
        //Some(uibc::v1::universal_message::Payload::TokenTransfer(token)) => (
            //token.sender.as_bytes(),
            //token.amount.as_bytes(),
       // ),
       // _ => (vec![], vec![]),
   // };
    //if key.is_empty() || value.is_empty() {
       // return Err("Unsupported or empty payload for ZK proof");
    //}

    // Extract IBC data
    //let ibc_data = message.ibc_data.clone();

    // Extract EVM extension if present
    //let evm_ext = if message.source.as_ref().map_or(false, |s| s.chain_type == uibc::v1::ChainType::ChainTypeEvm as i32) ||
                     //message.destination.as_ref().map_or(false, |d| d.chain_type == uibc::v1::ChainType::ChainTypeEvm as i32) {
        //Some(uibc::ibc::extensions::EVMExtension {
            //domain_separator: vec![], // Placeholder
            //gas_limit: 200000,
            //max_fee_per_gas: 1000000000, // 1 gwei
            //max_priority_fee: 500000000, // 0.5 gwei
            //access_list: vec![uibc::ibc::extensions::AccessTuple {
                //address: vec![0x11; 20], // Example address
                //storage_keys: vec![vec![0x22; 32]], // Example storage key
            //}],
        //})
    //} else {
        //None
    //};

    // Generate STARK proof
    let zkp = generate_zkp(message.clone(), proof.clone(), root, zk_req, ibc_data, evm_ext)?;

    // Log message details
    println!("Processing UIBCP message with ID: {:?}", message.message_id);
    let canonical_bytes = message.canonical_encode();
    println!("Canonical byte representation (length {}): {:?}", canonical_bytes.len(), canonical_bytes);

    // Verify leaf hash consistency
    let mut hasher = Poseidon::<BaseElement>::new(POSEIDON_WIDTH, POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS);
    let leaf_input = [
        bytes_to_field(&[vec![0x00], key].concat()),
        bytes_to_field(&value),
        BaseElement::ZERO,
    ];
    let leaf_hash = hasher.hash_elements(&leaf_input);
    println!("Computed leaf hash: {:?}", leaf_hash);

    // Process fees (example logging)
    if let Some(fees) = &message.fees {
        println!("Total fee: {} {}", fees.total_fee.amount, fees.total_fee.denom);
    }

    // In production:
    // - Submit zkp to IbcPacketHandler contract
    // - Handle fee distribution and relayer assignment
    // - Emit events for blockchain updates

    Ok(zkp)
}

// Unit Tests
#[cfg(test)]
mod tests {
    use super::*;
    use uibc::v1::{UniversalMessage, Ics23Proof, token_transfer::TokenTransfer, proof_requirement::Requirement};
    use uibc::ibc::v1::{IbcCompatibilityData, FungibleTokenPacket, Height};
    use uibc::ibc::extensions::EVMExtension;

    #[test]
    fn test_process_message() {
        let message = UniversalMessage {
            version: 1,
            message_id: vec![0u8; 32],
            created_at: 1698765432,
            source: Some(uibc::v1::ChainEndpoint {
                chain_id: "chain-1".to_string(),
                chain_type: uibc::v1::ChainType::ChainTypeEvm as i32,
                ..Default::default()
            }),
            destination: Some(uibc::v1::ChainEndpoint {
                chain_id: "chain-2".to_string(),
                chain_type: uibc::v1::ChainType::ChainTypeEvm as i32,
                ..Default::default()
            }),
            route_hints: vec![],
            message_type: uibc::v1::MessageType::MessageTypeTokenTransfer as i32,
            payload: Some(uibc::v1::universal_message::Payload::TokenTransfer(TokenTransfer {
                denom: "ETH".to_string(),
                amount: "1000000000000000000".to_string(), // 1 ETH
                sender: "0x1234".to_string(),
                receiver: "0x5678".to_string(),
                memo: "".to_string(),
                metadata: None,
            })),
            timeout: Some(uibc::v1::universal_message::Timeout::TimeoutTimestamp(1698765432)),
            proof_requirement: Some(uibc::v1::ProofRequirement {
                requirement: Some(Requirement::ZkProof(uibc::v1::ZkProofRequirement {
                    circuit_id: "ics23".to_string(),
                    public_inputs: vec![vec![1, 2, 3]],
                    proof_system: "stark".to_string(),
                    verification_gas_limit: 200000,
                })),
            }),
            state_checkpoint: None,
            fees: None,
            relayer_assignment: None,
            economic_parameters: None,
            ibc_data: Some(IbcCompatibilityData {
                sequence: 1,
                source_port: "port-1".to_string(),
                source_channel: "channel-1".to_string(),
                destination_port: "port-2".to_string(),
                destination_channel: "channel-2".to_string(),
                timeout: Some(uibc::ibc::v1::ibc_compatibility_data::Timeout::TimeoutHeight(Height {
                    revision_number: 1,
                    revision_height: 1000,
                })),
                token_data: Some(FungibleTokenPacket {
                    denom: "uatom".to_string(),
                    amount: "1000000".to_string(),
                    sender: "cosmos1abc".to_string(),
                    receiver: "cosmos2def".to_string(),
                    memo: "".to_string(),
                    metadata: None,
                }),
                ics27_data: vec![],
                custom_app_data: vec![],
                connection_info: None,
                client_info: None,
            }),
        };
        let proof = uibc::v1::Ics23Proof {
            key: message.payload.as_ref().unwrap().encode_to_vec(),
            value: vec![1, 2, 3],
            siblings: vec![0; MERKLE_LEVELS],
            path: vec![false; MERKLE_LEVELS],
        };
        let root = [BaseElement::ZERO; 4];
        let result = process_message(message, proof, root);
        assert!(result.is_ok());
    }
}
