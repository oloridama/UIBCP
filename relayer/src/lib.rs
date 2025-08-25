// relayer/src/lib.rs

// Standard library and third-party imports
use anyhow::{Result, anyhow};
use prost::bytes::Bytes;

// winterfell framework imports
use winter_air::{AirContext, TraceInfo, ProofOptions, FieldExtension};
use winter_math::{fields::f252::BaseElement, FieldElement, StarkField};
use winter_crypto::hashers::poseidon::Poseidon;
use winterfell::StarkProof;

// Local crate imports
use crate::uibc::v1::{UniversalMessage, ZkProof, Ics23Proof, proof_requirement::Requirement};
use crate::adapters::chain_adapter::InclusionProof;
use crate::zk::circuit::{Ics23StarkProver, PublicInputs, Ics23Air, 
    TRACE_WIDTH, TOTAL_STEPS, POSEIDON_WIDTH, POSEIDON_FULL_ROUNDS, 
    POSEIDON_PARTIAL_ROUNDS, MERKLE_LEVELS, bytes_to_field};

// Local module declarations
// This includes the generated code from your build.rs script.
mod uibc {
    include!(concat!(env!("OUT_DIR"), "/uibc.rs"));
}
pub mod adapters;
pub mod zk;

// The core function for ZK proof generation.
// This function is dedicated solely to validating the message and creating the STARK proof.
// It returns the proof data or an error.
pub fn process_message(message: UniversalMessage, proof: Ics23Proof, root: [BaseElement; 4]) -> Result<Vec<u8>> {
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
        Some(Requirement::ZkProof(req)) => Some(req.clone()),
        _ => None,
    };

    if zk_req.is_none() {
        return Err(anyhow!("Unsupported or empty payload for ZK proof"));
    }

    // 3. Instantiate the prover and generate the proof
    // Use the correct API for ProofOptions.
    let options = ProofOptions::new(4, 256, 16, FieldExtension::Quadratic, 8, 2048);
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
}

// This is where your main application logic should reside.
// It calls the `process_message` function and then handles everything else,
// such as logging, fees, and on-chain submission.
// You can structure this to match your application's flow.
pub fn handle_message_and_submit(message: UniversalMessage, proof: Ics23Proof, root: [BaseElement; 4]) -> Result<()> {
    // Call the function that generates the STARK proof.
    let zkp = process_message(message.clone(), proof.clone(), root)?;

    // Log message details.
    println!("Processing UIBCP message with ID: {:?}", message.message_id);
    let canonical_bytes = message.canonical_encode();
    println!("Canonical byte representation (length {}): {:?}", canonical_bytes.len(), canonical_bytes);
    
    // Process fees (example logging).
    if let Some(fees) = &message.fees {
        println!("Total fee: {} {}", fees.total_fee.amount, fees.total_fee.denom);
    }
    
    // You would typically use the generated `zkp` here:
    // - Submit zkp to an IbcPacketHandler contract.
    // - Handle fee distribution and relayer assignment.
    // - Emit events for blockchain updates.

    Ok(())
}

// Unit Tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::uibc::v1::{UniversalMessage, Ics23Proof, token_transfer::TokenTransfer, proof_requirement::Requirement};
    use crate::uibc::ibc::v1::{IbcCompatibilityData, FungibleTokenPacket, Height};
    use crate::uibc::ibc::extensions::EVMExtension;
    use crate::zk::circuit::MERKLE_LEVELS;

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
            proof_data: vec![], // Added this field to match the struct definition
        };
        let root = [BaseElement::ZERO; 4];
        let result = process_message(message, proof, root);
        assert!(result.is_ok());
    }
}
