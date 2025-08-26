// File: build.rs
// This script will compile the .proto files and generate the Rust code.
use std::io::Result;
use prost_build::Config;

fn main() -> Result<()> {
    // This tells Cargo to re-run the build script if any of the proto files change
    println!("cargo:rerun-if-changed=proto/");

    let mut config = Config::new();

    // Add serde derives to enable serialization and deserialization
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".", "#[serde(rename_all = \"camelCase\")]");
    
    // Configure serialization for specific `bytes` fields
    config.field_attribute("uibc.v1.StateCheckpoint.state_root", "#[serde(with = \"prost_serde_bytes\")]");
    config.field_attribute("uibc.v1.UniversalMessage.message_hash", "#[serde(with = \"prost_serde_bytes\")]");
    config.field_attribute("uibc.v1.ChainEndpoint.chain_id", "#[serde(with = \"prost_serde_bytes\")]");
    config.field_attribute("*.bytes", "#[serde(with = \"prost_serde_bytes\")]");

    // Add necessary derives to specific messages
    config.message_attribute("uibc.v1.UniversalMessage", "#[derive(Clone, validator::Validate)]");
    config.message_attribute("uibc.v1.Ics23Proof", "#[derive(Clone)]");
    
    // Add validation attributes using the validator crate
    config.field_attribute("uibc.v1.UniversalMessage.message_id", "#[validate(length(equal = 32))]");
    config.field_attribute("uibc.v1.Fee.amount", "#[validate(regex = \"^[0-9]+$\")]");
    config.field_attribute("uibc.v1.TokenTransfer.amount", "#[validate(regex = \"^[0-9]+$\")]");

    // We compile all the proto files by pointing to a single top-level file
    // that imports the others. This ensures a single output file.
    let proto_files = &[
        "uibc/v1/uibc.proto",
    ];
    let include_dirs = &[
        "proto", // Include the root of your proto files
        "proto/uibc/ibc", // Explicitly include this path
    ];

    // This is the core function that generates the code
    config.compile_protos(proto_files, include_dirs)?;

    Ok(())
}
