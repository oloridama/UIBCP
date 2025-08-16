// build.rs
use std::io::{Result, Write};
use std::path::{Path, PathBuf};
use std::fs;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=proto/");
    println!("cargo:rerun-if-changed=build.rs");
    
    let mut config = prost_build::Config::new();
    
    // Enable bytes for performance
    config.bytes(&["."]);
    
    // Add serde derives
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".", "#[serde(rename_all = \"camelCase\")]");
    
    // Add custom derives for key messages from message.proto
    config.message_attribute("uibc.v1.UniversalMessage", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.MessageFees", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.Fee", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.FeeDistribution", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.PerformanceBonus", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.ChainEndpoint", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.TokenTransfer", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.BatchTransfer", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.ContractCall", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.StateQuery", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.Acknowledgment", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.Error", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.RelayerAssignment", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.EconomicParameters", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.StateCheckpoint", "#[derive(Clone, PartialEq, prost::Message)]");
    
    // Add custom derives for key messages from proof.proto
    config.message_attribute("uibc.v1.ProofRequirement", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.LightClientProof", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.ZkProofRequirement", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.OptimisticProof", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.CommitteeProof", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.NoProofRequired", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.UniversalProof", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.ProofMetadata", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.MerkleProof", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.ZkProof", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.OptimisticProofData", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.CommitteeSignatures", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.v1.Signature", "#[derive(Clone, PartialEq, prost::Message)]");
    
    // Add custom derives for key messages from compatibility.proto
    config.message_attribute("uibc.ibc.v1.Height", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.ibc.v1.IbcCompatibilityData", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.ibc.v1.FungibleTokenPacket", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.ibc.v1.TokenMetadata", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.ibc.v1.ConnectionInfo", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.ibc.v1.ClientInfo", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.ibc.v1.ChannelInfo", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.ibc.v1.IbcAcknowledgement", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.ibc.v1.PacketCommitment", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.ibc.v1.PacketReceipt", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.ibc.v1.NextSequenceReceive", "#[derive(Clone, PartialEq, prost::Message)]");
    
    // Add custom derives for key messages from evm.proto
    config.message_attribute("uibc.ibc.extensions.EVMExtension", "#[derive(Clone, PartialEq, prost::Message)]");
    config.message_attribute("uibc.ibc.extensions.AccessTuple", "#[derive(Clone, PartialEq, prost::Message)]");
    
    // Assume Ics23Proof from proof.proto (using ibc.core.commitment.merkle.proto)
    config.message_attribute("uibc.v1.Ics23Proof", "#[derive(Clone, PartialEq, prost::Message)]");
    
    // Add validation attributes
    config.field_attribute("uibc.v1.UniversalMessage.message_id", "#[validate(length(equal = 32))]");
    config.field_attribute("uibc.v1.Fee.amount", "#[validate(regex = \"^[0-9]+$\")]");
    config.field_attribute("uibc.v1.TokenTransfer.amount", "#[validate(regex = \"^[0-9]+$\")]");
    
    // Enable optional support
    //config.enable_type_names();
    
    // Set output directory
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    config.out_dir(&out_dir);
    
    // Compile protobuf files (including dependency on ibc proto)
    let proto_files = vec![
        "proto/uibc/v1/message.proto",
        "proto/uibc/v1/proof.proto",
        "proto/uibc/ibc/v1/compatibility.proto",
        "proto/uibc/ibc/extensions/evm.proto",
    ];
    
    let include_dirs = vec!["proto/", "proto/ibc/core/commitment/"]; // Add ibc proto path
    
    config.compile_protos(&proto_files, &include_dirs)?;
    
    // Generate helper code
    generate_helper_code(&out_dir, &proto_files)?;
    
    println!("Protobuf compilation completed successfully!");
    
    Ok(())
}

fn generate_helper_code(out_dir: &Path, proto_files: &[&str]) -> Result<()> {
    let helpers_path = out_dir.join("uibc_gen.rs");
    let mut file = fs::File::create(&helpers_path)?;

    // Add necessary imports
    writeln!(file, "use prost::Message;")?;
    writeln!(file, "use prost::bytes::Bytes;")?;
    writeln!(file, "use serde;")?;
    writeln!(file, "use serde_bytes;")?;
    writeln!(file, "use validator::Validate;")?;
    
    // Define IbcMessage trait
    writeln!(file, r#"
pub trait IbcMessage {{
    fn canonical_encode(&self) -> Vec<u8>;
}}
"#)?;
    
    // Implement IbcMessage for relevant messages
    writeln!(file, "impl IbcMessage for super::uibc::v1::UniversalMessage {{")?;
    writeln!(file, "    fn canonical_encode(&self) -> Vec<u8> {{")?;
    writeln!(file, "        self.encode_to_vec()")?;
    writeln!(file, "    }}")?;
    writeln!(file, "}}")?;
    
    writeln!(file, "impl IbcMessage for super::uibc::v1::Ics23Proof {{")?;
    writeln!(file, "    fn canonical_encode(&self) -> Vec<u8> {{")?;
    writeln!(file, "        self.encode_to_vec()")?;
    writeln!(file, "    }}")?;
    writeln!(file, "}}")?;
    
    // Re-export generated modules
    writeln!(file, r#"
pub mod uibc {{
    pub mod v1 {{
        include!(concat!(env!("OUT_DIR"), "/uibc.v1.rs"));
    }}
    pub mod ibc {{
        pub mod v1 {{
            include!(concat!(env!("OUT_DIR"), "/uibc.ibc.v1.rs"));
        }}
        pub mod extensions {{
            include!(concat!(env!("OUT_DIR"), "/uibc.ibc.extensions.rs"));
        }}
    }}
}}
"#)?;

    Ok(())
}
