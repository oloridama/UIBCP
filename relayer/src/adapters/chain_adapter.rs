+
// relayer/src/adapters/chain_adapter.rs
use crate::proto::uibc::v1::{UniversalMessage, Fee, ProofRequirement, ChainType};
use anyhow::Result;
use std::time::Duration;
use async_trait::async_trait; // NEW: For async trait methods

// Enhanced type definitions with better structure
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainId(String);

impl ChainId {
    pub fn new(id: String) -> Self {
        ChainId(id)
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for ChainId {
    fn from(id: String) -> Self {
        ChainId(id)
    }
}

// NEW: Consensus type enum for better type safety
#[derive(Debug, Clone, PartialEq)]
pub enum ConsensusType {
    Tendermint,
    PoS,        // Ethereum 2.0 style
    PoW,        // Bitcoin/Ethereum 1.0 style
    PoA,        // Proof of Authority
    DPoS,       // Delegated Proof of Stake
    Unknown,
}

// NEW: Enhanced proof structures
#[derive(Debug, Clone)]
pub struct InclusionProof {
    pub proof_data: Vec<u8>,
    pub path: Vec<u8>,
    pub value: Vec<u8>,
    pub proof_type: String, // "merkle", "verkle", "ics23"
}

#[derive(Debug, Clone)]
pub struct StateRoot {
    pub hash: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
}

// NEW: Enhanced block structure with chain-specific data
#[derive(Debug, Clone)]
pub struct Block {
    pub height: u64,
    pub hash: [u8; 32],
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub logs: Vec<Log>, // For EVM chains
    pub events: Vec<Event>, // For Cosmos chains
    pub state_root: StateRoot,
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub hash: [u8; 32],
    pub from: Vec<u8>,
    pub to: Option<Vec<u8>>,
    pub data: Vec<u8>,
    pub events: Vec<Event>,
}

#[derive(Debug, Clone)]
pub struct Log {
    pub address: [u8; 20], // EVM address
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub event_type: String,
    pub attributes: Vec<EventAttribute>,
}

#[derive(Debug, Clone)]
pub struct EventAttribute {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct Header {
    pub height: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub timestamp: u64,
    pub state_root: [u8; 32],
    pub validator_set_hash: Option<[u8; 32]>, // For Tendermint chains
}

#[derive(Debug, Clone)]
pub struct ValidatorSet {
    pub validators: Vec<Validator>,
    pub total_voting_power: u64,
}

#[derive(Debug, Clone)]
pub struct Validator {
    pub address: Vec<u8>,
    pub public_key: Vec<u8>,
    pub voting_power: u64,
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub validator_address: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TransactionReceipt {
    pub tx_hash: [u8; 32],
    pub block_hash: [u8; 32],
    pub block_height: u64,
    pub gas_used: u64,
    pub status: TransactionStatus,
    pub logs: Vec<Log>,
    pub events: Vec<Event>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransactionStatus {
    Success,
    Failed,
    Pending,
}

#[derive(Debug, Clone)]
pub struct Route {
    pub path: Vec<ChainId>,
    pub estimated_cost: Fee,
    pub estimated_time: Duration,
    pub reliability_score: f64, // 0.0 to 1.0
}

// NEW: Network conditions for dynamic fee calculation
#[derive(Debug, Clone)]
pub struct NetworkConditions {
    pub congestion_multiplier: f64,
    pub average_block_time: Duration,
    pub gas_price: Fee,
    pub finality_time: Duration,
}

// NEW: Chain capabilities for feature detection
#[derive(Debug, Clone)]
pub struct ChainCapabilities {
    pub supports_smart_contracts: bool,
    pub supports_zk_proofs: bool,
    pub supports_optimistic_proofs: bool,
    pub max_message_size: usize,
    pub supported_proof_types: Vec<String>,
}

/// The ChainAdapter trait defines a standard interface for the relayer to interact with
/// different blockchain ecosystems (e.g., IBC, EVM, etc.).
/// 
/// This trait abstracts away chain-specific details and provides a uniform interface
/// for message processing, proof generation, and fee calculation.
#[async_trait]
pub trait ChainAdapter: Send + Sync {
    // Chain Information
    fn chain_id(&self) -> ChainId;
    fn consensus_type(&self) -> ConsensusType;
    fn chain_type(&self) -> ChainType; // NEW: For routing optimization
    
    // NEW: Chain capabilities for feature detection
    fn capabilities(&self) -> ChainCapabilities;
    
    // NEW: Network status for dynamic optimization
    async fn get_network_conditions(&self) -> Result<NetworkConditions>;
    
    // State Verification
    fn verify_inclusion_proof(&self, 
        proof: &InclusionProof, 
        root: &StateRoot,
        key: &[u8], 
        value: &[u8]
    ) -> Result<bool>;
    
    // NEW: Non-inclusion proof verification for timeouts
    fn verify_exclusion_proof(&self,
        proof: &InclusionProof,
        root: &StateRoot,
        key: &[u8],
    ) -> Result<bool>;
    
    // Header Verification
    fn verify_header(&self, 
        header: &Header, 
        validator_set: &ValidatorSet
    ) -> Result<bool>;
    
    // NEW: Verify header chain for light client updates
    fn verify_header_chain(&self,
        headers: &[Header],
        initial_validator_set: &ValidatorSet,
    ) -> Result<ValidatorSet>; // Returns final validator set
    
    // Message Processing
    fn extract_messages(&self, block: &Block) -> Vec<UniversalMessage>;
    
    fn create_inclusion_proof(&self, 
        block: &Block, 
        message: &UniversalMessage
    ) -> Result<InclusionProof>;
    
    // NEW: Create exclusion proof for timeouts
    fn create_exclusion_proof(&self,
        block: &Block,
        key: &[u8],
    ) -> Result<InclusionProof>;
    
    // Economic
    fn estimate_fee(&self, message: &UniversalMessage) -> Result<Fee>;
    
    // NEW: Dynamic fee estimation based on network conditions
    async fn estimate_dynamic_fee(&self, 
        message: &UniversalMessage,
        priority: u32,
    ) -> Result<Fee>;
    
    fn minimum_timeout(&self) -> Duration;
    
    // NEW: Calculate optimal timeout based on network conditions
    async fn calculate_optimal_timeout(&self) -> Result<Duration>;
    
    // Message Submission
    async fn submit_message(&self, message: &UniversalMessage) -> Result<TransactionReceipt>;
    
    // NEW: Batch message submission for efficiency
    async fn submit_batch_messages(&self, messages: Vec<UniversalMessage>) -> Result<Vec<TransactionReceipt>>;
    
    // NEW: Light Client Management
    async fn get_latest_header(&self) -> Result<Header>;
    
    async fn get_header_at_height(&self, height: u64) -> Result<Header>;
    
    async fn get_validator_set_at_height(&self, height: u64) -> Result<ValidatorSet>;
    
    // NEW: Proof Requirements
    fn get_proof_requirement(&self, message_type: &str) -> ProofRequirement;
    
    // NEW: Health Check
    async fn health_check(&self) -> Result<HealthStatus>;

    // NEW: Get available relayers based on chain conditions
    async fn get_available_relayers(&self) -> Result<Vec<RelayerInfo>>;

    // NEW Select a relayer for a message based on criteria
    async fn select_relayer(&self, message: &UniversalMessage) -> Result<RelayerAssignment>;
}

// NEW: Relayer info structure
#[derive(Debug, Clone)]
pub struct RelayerInfo {
    pub address: Vec<u8>, // Relayer's address
    pub bond_amount: u64, // Bond in wei or equivalent
    pub reliability_score: f64, // 0.0 to 1.0
    pub latency: Duration, // Average response time
}

// NEW: Health status for monitoring
#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub is_healthy: bool,
    pub latest_block_height: u64,
    pub blocks_behind: u64,
    pub peer_count: u32,
    pub sync_status: SyncStatus,
    pub last_checked: u64, // Unix timestamp
}

#[derive(Debug, Clone, PartialEq)]
pub enum SyncStatus {
    Synced,
    Syncing,
    Stalled,
    Disconnected,
}

// NEW: Adapter factory for creating chain adapters
pub trait ChainAdapterFactory {
    fn create_adapter(&self, chain_id: ChainId, config: AdapterConfig) -> Result<Box<dyn ChainAdapter>>;
    fn supported_chains(&self) -> Vec<ChainId>;
}

// NEW: Configuration for adapter creation
#[derive(Debug, Clone)]
pub struct AdapterConfig {
    pub rpc_endpoints: Vec<String>,
    pub ws_endpoints: Vec<String>,
    pub contract_addresses: std::collections::HashMap<String, Vec<u8>>,
    pub private_key: Option<Vec<u8>>, // For transaction signing
    pub gas_config: GasConfig,
    pub retry_config: RetryConfig,
}

#[derive(Debug, Clone)]
pub struct GasConfig {
    pub max_gas_price: Fee,
    pub gas_multiplier: f64, // For gas estimation buffer
    pub priority_fee: Fee,
}

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_factor: f64,
}