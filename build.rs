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

    // This is the crucial change. We are now explicitly listing every single proto file
    // so the compiler processes them all directly, bypassing any import resolution issues.
    let proto_files = &[
        "uibc/v1/common.proto",
        "uibc/v1/message.proto",
        "uibc/v1/proof.proto",
        "uibc/v1/uibc.proto",
        "uibc/ibc/extensions/evm.proto",
        "uibc/ibc/v1/compatibility.proto",
        "uibc/ibc/v1/ics20.proto",
    ];
    let include_dirs = &["proto"];

    config.compile_protos(proto_files, include_dirs)?;

    Ok(())
}
