// build.rs
use std::io::Result;
use prost_build::Config;

fn main() -> Result<()> {
    // Tell Cargo to re-run this build script if any proto file changes
    println!("cargo:rerun-if-changed=proto/");

    let mut config = Config::new();

    // Add serde derives for all messages
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.type_attribute(".", "#[serde(rename_all = \"camelCase\")]");
    
    // Configure serialization for `bytes` fields using the `serde_bytes` module.
    config.field_attribute("uibc.v1.StateCheckpoint.state_root", "#[serde(with = \"serde_bytes\")]");
    config.field_attribute("uibc.v1.UniversalMessage.message_hash", "#[serde(with = \"serde_bytes\")]");
    config.field_attribute("uibc.v1.ChainEndpoint.chain_id", "#[serde(with = \"serde_bytes\")]");
    config.field_attribute("*.bytes", "#[serde(with = \"serde_bytes\")]");

    // Add necessary derives to key messages
    config.message_attribute("uibc.v1.UniversalMessage", "#[derive(Clone, validator::Validate)]");
    config.message_attribute("uibc.v1.Ics23Proof", "#[derive(Clone)]");
    
    // Add validation attributes
    config.field_attribute("uibc.v1.UniversalMessage.message_id", "#[validate(length(equal = 32))]");
    config.field_attribute("uibc.v1.Fee.amount", "#[validate(regex = \"^[0-9]+$\")]");
    config.field_attribute("uibc.v1.TokenTransfer.amount", "#[validate(regex = \"^[0-9]+$\")]");

    // We will now explicitly compile every proto file in a dependency-aware order.
    // This is the most reliable way to handle complex nested imports.
    let proto_files = &[
        "uibc/v1/common.proto",
        "uibc/ibc/v1/ics20.proto",
        "uibc/ibc/extensions/evm.proto",
        "uibc/v1/proof.proto",
        "uibc/ibc/v1/compatibility.proto",
        "uibc/v1/message.proto",
        "uibc/v1/uibc.proto",
    ];
    let include_dirs = &["proto"];

    config.emit_cargo_warnings(true);

    // This is the key debugging step. It will print the exact command to the console.
    eprintln!("DEBUG: Compiling with the following proto files and include directories:");
    eprintln!("Files: {:?}", proto_files);
    eprintln!("Includes: {:?}", include_dirs);
    
    config.compile_protos(proto_files, include_dirs)?;

    Ok(())
}
