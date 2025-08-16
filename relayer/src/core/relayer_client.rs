// relayer/src/core/relayer_client.rs
use crate::core::{
    fee_calculator::FeeCalculator,
    message::UibcMessage,
    proof::{generate_zk_proof, verify_proof_locally},
};
use crate::adapters::evm::EVMAdapter;
use crate::proto::uibc::v1::{
    UniversalMessage, MessageType, ProofRequirement, ZkProofRequirement, ChainEndpoint,
    universal_message::Payload, TokenTransfer, IbcCompatibilityData, EconomicParameters, RelayerAssignment, Fee,
};
use crate::adapters::chain_adapter::{NetworkConditions, Route, ChainId};
use anyhow::{Result, anyhow};
use ethers_core::types::{H256, Bytes, TransactionReceipt, U256};
use ethers_core::abi;
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub struct RelayerClient {
    evm_adapter: EVMAdapter,
    fee_calculator: FeeCalculator,
}

impl RelayerClient {
    pub fn new(evm_adapter: EVMAdapter) -> Self {
        RelayerClient {
            evm_adapter,
            fee_calculator: FeeCalculator::new(),
            chain_adapter,
        }
    }

    pub fn assign_relayer(&self, message: &UniversalMessage) -> Result<String> {
        let relayer_assignment = self.chain_adapter.select_relayer(message).await?;
        let relayer_address = relayer_assignment.assigned_relayer;
        Ok(hex::encode(relayer_address)) // return as hex string
    }

    fn generate_message_id(&self, message: &UniversalMessage) -> H256 {
        let mut hasher = Sha256::new();
        hasher.update(message.encode_to_vec());
        H256::from_slice(&hasher.finalize()[..32])
    }

    fn serialize_message(&self, message: &UniversalMessage) -> Result<Bytes> {
        Ok(Bytes::from(message.encode_to_vec()))
    }

    fn generate_zk_proof(&self, message: &UniversalMessage) -> Result<(Bytes, Bytes)> {
        if let Some(ProofRequirement { zk_proof: Some(proof), public_inputs }) = &message.proof_requirement {
            if !proof.is_empty() {
                Ok((Bytes::from(proof.clone()), Bytes::from(public_inputs.clone())))
            } else {
                Err(anyhow!("No ZK proof data"))
            }
        } else {
            Err(anyhow!("No ZK proof requirement"))
        }
    }

    fn generate_zk_public_inputs(&self, message: &UniversalMessage) -> Result<Bytes> {
        if let Some(ProofRequirement { zk_proof: _, public_inputs }) = &message.proof_requirement {
            if !public_inputs.is_empty() {
                Ok(Bytes::from(public_inputs.clone()))
            } else {
                Err(anyhow!("No public inputs available"))
            }
        } else {
            Err(anyhow!("No ZK proof requirement"))
        }
    }

    fn generate_economic_params(&self, fee: Fee) -> EconomicParameters {
        EconomicParameters {
            base_fee: fee.amount.parse().unwrap_or(0),
            verification_fee: 5000, // Placeholder, to be refined
        }
    }

    fn generate_relayer_assignment(&self) -> RelayerAssignment {
        RelayerAssignment {
            assigned_relayer: ethers_core::types::H160::zero().into(), // Placeholder
        }
    }

    pub async fn submit_optimistic_message(&self, mut message: UniversalMessage, use_optimistic: bool, challenge_period: Option<u64>) -> Result<()> {
        // Assiign relayer
        let relayer_address = self.assign_relayer(&message)?;
        message.relayer_assignment = Some(RelayerAssignment {
            assigned_relayer: hex::decode(relayer_address)?,
        });

        // Validate message
        let uibc_msg = UibcMessage::new(message.clone());
        uibc_msg.validate()?;

        // Calculate and set fee
        let route = Route {
            path: vec![
                message.source.as_ref().unwrap().chain_id.clone(),
                message.destination.as_ref().unwrap().chain_id.clone(),
            ],
        };
        let network_conditions = NetworkConditions {
            congestion_multipliers: HashMap::new(), // Placeholder
        };
        let fee = self.fee_calculator
            .calculate_total_fee(&message, &route, &network_conditions)
            .await?;
        message.total_fee = Some(fee.clone());

        // Generate ZK proof and public inputs
        let (zk_proof, _) = self.generate_zk_proof(&message)?;
        let zk_public_inputs = self.generate_zk_public_inputs(&message)?;
        let message_data = self.serialize_message(&message)?;

        // Verify proof locally (optional safety check)
        if !zk_proof.is_empty() {
            if let Some(proof_req) = &message.proof_requirement {
                if !verify_proof_locally(&zk_proof, &zk_public_inputs, &proof_req)? {
                    return Err(anyhow!("Local proof verification failed"));
                }
            }
        }

        // Set economic parameters and relayer assignment
        message.economic_parameters = Some(self.generate_economic_params(fee.clone()));
        message.relayer_assignment = Some(self.generate_relayer_assignment());

        // Set timeout
        let timeout_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() + 7 * 24 * 3600; // 7 days
        message.timeout_timestamp = timeout_timestamp as u64;

        let call_data = if use_optimistic {
            // Prepare data for receivePacketOptimistic
            let source_channel = message.ibc_data.as_ref().map(|d| d.source_channel.clone()).unwrap_or("channel-0".to_string());
            let sequence = message.ibc_data.as_ref().map(|d| d.sequence).unwrap_or(1);
            abi::encode(&[
                abi::Token::String(source_channel),
                abi::Token::Uint(sequence.into()),
                abi::Token::Bytes(message_data.to_vec()),
                abi::Token::Uint(timeout_timestamp.into()),
                abi::Token::Bytes(zk_proof.to_vec()),
                abi::Token::Bytes(zk_public_inputs.to_vec()),
            ]).into()
        } else {
            // Prepare data for receiveUIBCPacket
            let proof_data = abi::encode(&[
                abi::Token::Bytes(zk_proof.to_vec()),
                abi::Token::Bytes(zk_public_inputs.to_vec()),
            ]).into();
            let challenge_period = challenge_period.unwrap_or(0);
            abi::encode(&[
                abi::Token::Bytes(message_data.to_vec()),
                abi::Token::Bytes(proof_data),
                abi::Token::Uint(challenge_period.into()),
            ]).into()
        };

        let tx_receipt = self.evm_adapter
            .provider
            .send_transaction(
                ethers_core::types::TransactionRequest::new()
                    .to(self.evm_adapter.contract_address)
                    .data(call_data)
                    .value(U256::from(0))
                    .from(ethers_core::types::H160::zero()) // Placeholder sender
                    .chain_id(self.evm_adapter.evm_chain_id)
                    .gas(U256::from(50_000)) // Adjusted for ZK cost
                    .gas_price(self.evm_adapter.provider.get_gas_price().await?)
                    .into(),
                None,
            )
            .await?
            .await?
            .ok_or_else(|| anyhow!("Transaction failed"))?;

        println!("Successfully submitted optimistic message. Transaction Hash: {:?}", tx_receipt.transaction_hash);

        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::uibc::v1::proof::ProofRequirement as ProtoProofRequirement;
    use mockall::predicate::*;
    use mockall::*;

    mock! {
        pub EVMAdapter {}
        impl EVMAdapter for EVMAdapter {
            fn provider(&self) -> Arc<Provider<Http>>;
            fn contract_address(&self) -> ethers_core::types::Address;
            fn evm_chain_id(&self) -> u64;
        }
    }

    #[tokio::test]
    async fn test_submit_optimistic_message_uibc() {
        let mut mock_adapter = MockEVMAdapter::new();
        let client = RelayerClient::new(mock_adapter);

        let mut message = UniversalMessage {
            version: 1,
            message_id: vec![0; 32],
            created_at: 0,
            source: Some(ChainEndpoint { chain_id: "ethereum-1".to_string(), ..Default::default() }),
            destination: Some(ChainEndpoint { chain_id: "cosmoshub-4".to_string(), ..Default::default() }),
            route_hints: vec![],
            message_type: MessageType::MessageTypeTokenTransfer as i32,
            payload: Some(Payload::TokenTransfer(TokenTransfer {
                amount: "1000".to_string(),
                denom: "uatom".to_string(),
                sender: vec![],
                receiver: vec![],
            })),
            timeout_timestamp: 0,
            proof_requirement: Some(ProtoProofRequirement {
                zk_proof: vec![1, 2, 3], // Mock ZK proof
                public_inputs: vec![4, 5, 6], // Mock public inputs
                ..Default::default()
            }),
            ibc_data: Some(IbcCompatibilityData {
                sequence: 1,
                source_channel: "channel-0".to_string(),
                ..Default::default()
            }),
            economic_parameters: None,
            relayer_assignment: None,
            total_fee: None,
            ..Default::default()
        };

        mock_adapter.expect_provider()
            .times(1)
            .returning(|| Arc::new(Provider::<Http>::try_from("http://localhost:8545").unwrap()));
        mock_adapter.expect_contract_address()
            .times(1)
            .returning(|| ethers_core::types::H160::zero());
        mock_adapter.expect_evm_chain_id()
            .times(1)
            .returning(|| 1);

        let result = client.submit_optimistic_message(message.clone(), false, Some(7 * 24 * 3600)).await; // 7 days challenge
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_submit_optimistic_message_optimistic() {
        let mut mock_adapter = MockEVMAdapter::new();
        let client = RelayerClient::new(mock_adapter);

        let mut message = UniversalMessage {
            version: 1,
            message_id: vec![0; 32],
            created_at: 0,
            source: Some(ChainEndpoint { chain_id: "ethereum-1".to_string(), ..Default::default() }),
            destination: Some(ChainEndpoint { chain_id: "cosmoshub-4".to_string(), ..Default::default() }),
            route_hints: vec![],
            message_type: MessageType::MessageTypeTokenTransfer as i32,
            payload: Some(Payload::TokenTransfer(TokenTransfer {
                amount: "1000".to_string(),
                denom: "uatom".to_string(),
                sender: vec![],
                receiver: vec![],
            })),
            timeout_timestamp: 0,
            proof_requirement: Some(ProtoProofRequirement {
                zk_proof: vec![1, 2, 3], // Mock ZK proof
                public_inputs: vec![4, 5, 6], // Mock public inputs
                ..Default::default()
            }),
            ibc_data: Some(IbcCompatibilityData {
                sequence: 1,
                source_channel: "channel-0".to_string(),
                ..Default::default()
            }),
            economic_parameters: None,
            relayer_assignment: None,
            total_fee: None,
            ..Default::default()
        };

        mock_adapter.expect_provider()
            .times(1)
            .returning(|| Arc::new(Provider::<Http>::try_from("http://localhost:8545").unwrap()));
        mock_adapter.expect_contract_address()
            .times(1)
            .returning(|| ethers_core::types::H160::zero());
        mock_adapter.expect_evm_chain_id()
            .times(1)
            .returning(|| 1);

        let result = client.submit_optimistic_message(message, true, None).await; // Use receivePacketOptimistic
        assert!(result.is_ok());
    }
}