// build.rs
use std::io::Result;
use prost_build::Config;

fn main() -> Result<()> {
    // Tell Cargo to rerun if any proto changes
    println!("cargo:rerun-if-changed=proto/");

    let mut config = Config::new();

    // Add serde derives for all messages
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize, Clone)]");
    config.type_attribute(".", "#[serde(rename_all = \"camelCase\")]");

    // Remove serde_bytes on String fields; only apply to actual bytes fields
    config.field_attribute("uibc.v1.UniversalMessage.message_id", "#[serde(with = \"serde_bytes\")]");
    config.field_attribute("uibc.v1.StateCheckpoint.state_root", "#[serde(with = \"serde_bytes\")]");
    config.field_attribute("*.bytes", "#[serde(with = \"serde_bytes\")]");

    // Do NOT apply validator here if you don't have the crate
    // config.message_attribute("uibc.v1.UniversalMessage", "#[derive(validator::Validate)]");

    // Explicitly compile proto files in dependency order
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

    // Debug info
    eprintln!("DEBUG: Compiling proto files: {:?}", proto_files);
    eprintln!("DEBUG: Using include dirs: {:?}", include_dirs);

    config.compile_protos(proto_files, include_dirs)?;

    // Generate a top-level mod.rs combining all modules
    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(
        format!("{}/uibc.rs", out_dir),
        r#"
        pub mod v1 {
            include!(concat!(env!(\"OUT_DIR\"), \"/uibc.v1.rs\"));
        }
        pub mod ibc {
            pub mod v1 {
                include!(concat!(env!(\"OUT_DIR\"), \"/uibc.ibc.v1.compatibility.rs\"));
            }
            pub mod extensions {
                include!(concat!(env!(\"OUT_DIR\"), \"/uibc.ibc.extensions.rs\"));
            }
        }
        "#,
    )?;

    println!("cargo:warning=Proto files compiled. OUT_DIR = {:?}", out_dir);

    Ok(())
}
