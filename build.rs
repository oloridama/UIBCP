// build.rs
use std::io::{self, Write};
use prost_build::Config;
use std::env;
use std::path::{Path, PathBuf};

fn main() -> io::Result<()> {
    // Tell Cargo to re-run this build script if any proto file changes
    writeln!(io::stderr(), "cargo:rerun-if-changed=proto/")?;

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

    // We compile all the proto files by explicitly listing them to avoid
    // any issues with the import chain.
    let proto_files = &[
        Path::new("uibc/v1/uibc.proto"),
        Path::new("uibc/v1/common.proto"),
        Path::new("uibc/v1/proof.proto"),
        Path::new("uibc/v1/message.proto"),
        Path::new("uibc/ibc/v1/compatibility.proto"),
        Path::new("uibc/ibc/v1/ics20.proto"),
        Path::new("uibc/ibc/extensions/evm.proto"),
    ];
    let include_dirs = &[Path::new("proto")];

    config.compile_protos(proto_files, include_dirs)?;

    Ok(())
}
