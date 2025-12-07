// relayer/src/lib.rs

// ----------------------------
// Standard + External imports
// ----------------------------
use anyhow::{Result, anyhow};
use prost::bytes::Bytes;

// Winterfell imports
use winter_air::{AirContext, TraceInfo, ProofOptions, FieldExtension};
use winter_math::{FieldElement, StarkField};
use winterfell::StarkProof;

// ----------------------------
// Local modules
// ----------------------------
pub mod adapters;
pub mod zk;

// ----------------------------
// Generated Protobuf modules
// ----------------------------
pub mod proto {
    pub mod uibc {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/uibc.v1.rs"));
        }
        pub mod ibc {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/uibc.ibc.v1.compatibility.rs"));
            }
        }
    }
}

// Optional alias for convenience
pub use proto::uibc as uibc;

// ----------------------------
// Imports for protobuf types
// ----------------------------
use crate::proto::uibc::v1::{
    UniversalMessage,
    Ics23Proof,
    proof_requirement::Requirement,
};

use crate::adapters::chain_adapter::InclusionProof;
use crate::zk::circuit::{
    Ics23StarkProver,
    TRACE_WIDTH,
    TOTAL_STEPS,
    POSEIDON_WIDTH,
    POSEIDON_FULL_ROUNDS,
    POSEIDON_PARTIAL_ROUNDS,
    MERKLE_LEVELS,
    bytes_to_field,
};


// ===========================================================================
// CORE LOGIC
// ===========================================================================

pub fn process_message(
    message: UniversalMessage,
    proof: Ics23Proof,
    root: [winter_math::fields::f256::BaseElement; 4],
) -> Result<Vec<u8>> {

    // 1. Validate the message
    if !message.is_valid() {
        return Err(anyhow!("Message validation failed"));
    }

    if message.message_id.is_empty() {
        return Err(anyhow!("Message has no message_id"));
    }

    // Validate proof length
    let proof_len = (proof.proof_data.len() - MERKLE_LEVELS / 8) / 32;
    if proof_len != MERKLE_LEVELS {
        return Err(anyhow!("Invalid proof length"));
    }

    // Extract zk proof requirement
    let zk_req = match &message.proof_requirement {
        Some(Requirement::ZkProof(req)) => Some(req.clone()),
        _ => None,
    };

    if zk_req.is_none() {
        return Err(anyhow!("Unsupported or empty ZK proof payload"));
    }

    // 2. STARK Proof generation
    let options = ProofOptions::new(
        4,
        256,
        16,
        FieldExtension::Quadratic,
        8,
        2048,
    );

    let prover = Ics23StarkProver::new(options);

    // Convert protobuf -> InclusionProof
    let inclusion = InclusionProof {
        path: proof.key,
        value: proof.value,
        proof_data: proof.proof_data,
    };

    let zk_proof = prover.generate_proof(&message, &inclusion)?;

    Ok(zk_proof.proof_data)
}


// ===========================================================================
// RELAYER LOGIC
// ===========================================================================

pub fn handle_message_and_submit(
    message: UniversalMessage,
    proof: Ics23Proof,
    root: [winter_math::fields::f256::BaseElement; 4],
) -> Result<()> {

    let zkp = process_message(message.clone(), proof.clone(), root)?;

    println!("Processing UIBCP message with ID {:?}", message.message_id);
    println!("Canonical bytes = {:?}", message.canonical_encode());

    if let Some(fees) = &message.fees {
        println!("Total fee: {} {}", fees.total_fee.amount, fees.total_fee.denom);
    }

    // TODO: submit proof to contract
    Ok(())
}


// ===========================================================================
// UNIT TESTS
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use crate::proto::uibc::v1::{
        UniversalMessage,
        Ics23Proof,
        token_transfer::TokenTransfer,
        proof_requirement::Requirement,
    };
    use crate::proto::uibc::ibc::v1::{
        IbcCompatibilityData,
        FungibleTokenPacket,
        Height,
    };

    #[test]
    fn test_process_message() {
        use crate::proto::uibc::v1 as uibcv1;

        let message = UniversalMessage {
            version: 1,
            message_id: vec![0u8; 32],
            created_at: 1698765432,
            source: Some(uibcv1::ChainEndpoint {
                chain_id: "chain-1".into(),
                chain_type: uibcv1::ChainType::ChainTypeEvm as i32,
                ..Default::default()
            }),
            destination: Some(uibcv1::ChainEndpoint {
                chain_id: "chain-2".into(),
                chain_type: uibcv1::ChainType::ChainTypeEvm as i32,
                ..Default::default()
            }),
            route_hints: vec![],
            message_type: uibcv1::MessageType::MessageTypeTokenTransfer as i32,
            payload: Some(uibcv1::universal_message::Payload::TokenTransfer(
                TokenTransfer {
                    denom: "ETH".into(),
                    amount: "1000000000000000000".into(),
                    sender: "0x1234".into(),
                    receiver: "0x5678".into(),
                    memo: "".into(),
                    metadata: None,
                }
            )),
            timeout: Some(uibcv1::universal_message::Timeout::TimeoutTimestamp(1698765432)),
            proof_requirement: Some(uibcv1::ProofRequirement {
                requirement: Some(Requirement::ZkProof(
                    uibcv1::ZkProofRequirement {
                        circuit_id: "ics23".into(),
                        public_inputs: vec![vec![1, 2, 3]],
                        proof_system: "stark".into(),
                        verification_gas_limit: 200000,
                    }
                )),
            }),
            state_checkpoint: None,
            fees: None,
            relayer_assignment: None,
            economic_parameters: None,
            ibc_data: Some(IbcCompatibilityData {
                sequence: 1,
                source_port: "port-1".into(),
                source_channel: "channel-1".into(),
                destination_port: "port-2".into(),
                destination_channel: "channel-2".into(),
                timeout: Some(crate::proto::uibc::ibc::v1::ibc_compatibility_data::Timeout::TimeoutHeight(
                    Height {
                        revision_number: 1,
                        revision_height: 1000,
                    }
                )),
                token_data: Some(FungibleTokenPacket {
                    denom: "uatom".into(),
                    amount: "1000000".into(),
                    sender: "cosmos1abc".into(),
                    receiver: "cosmos2def".into(),
                    memo: "".into(),
                    metadata: None,
                }),
                ics27_data: vec![],
                custom_app_data: vec![],
                connection_info: None,
                client_info: None,
            }),
        };

        let proof = Ics23Proof {
            key: message.payload.as_ref().unwrap().encode_to_vec(),
            value: vec![1, 2, 3],
            siblings: vec![0; MERKLE_LEVELS],
            path: vec![false; MERKLE_LEVELS],
            proof_data: vec![],
        };

        let root = [winter_math::fields::f256::BaseElement::ZERO; 4];

        assert!(process_message(message, proof, root).is_ok());
    }
}
