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
    
    // Configure serialization for `bytes` fields
    config.field_attribute("uibc.v1.StateCheckpoint.state_root", "#[serde(with = \"prost_serde_bytes\")]");
    config.field_attribute("uibc.v1.UniversalMessage.message_hash", "#[serde(with = \"prost_serde_bytes\")]");
    config.field_attribute("uibc.v1.ChainEndpoint.chain_id", "#[serde(with = \"prost_serde_bytes\")]");
    config.field_attribute("*.bytes", "#[serde(with = \"prost_serde_bytes\")]");

    // Add necessary derives to key messages
    config.message_attribute("uibc.v1.UniversalMessage", "#[derive(Clone, validator::Validate)]");
    config.message_attribute("uibc.v1.Ics23Proof", "#[derive(Clone)]");
    
    // Add validation attributes
    config.field_attribute("uibc.v1.UniversalMessage.message_id", "#[validate(length(equal = 32))]");
    config.field_attribute("uibc.v1.Fee.amount", "#[validate(regex = \"^[0-9]+$\")]");
    config.field_attribute("uibc.v1.TokenTransfer.amount", "#[validate(regex = \"^[0-9]+$\")]");

    // Compile the specified proto files from the proto/ directory
    let proto_files = &[
        "uibc/v1/common.proto",
        "uibc/v1/proof.proto",
        "uibc/v1/message.proto",
        "uibc/ibc/v1/compatibility.proto",
        "uibc/ibc/v1/ics20.proto",
        "uibc/ibc/extensions/evm.proto",
    ];
    let include_dirs = &["proto"];

    // The key change: We use `compile_protos` to generate all the code.
    // The output file will be a single file named `uibc.rs` (or similar)
    // in the `OUT_DIR`.
    config.compile_protos(proto_files, include_dirs)?;

    Ok(())
}
