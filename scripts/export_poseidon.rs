// scripts/export_poseidon.rs
use winter_crypto::hashers::poseidon::Poseidon;
use winter_math::fields::f252::BaseElement;
use winter_math::{FieldElement, StarkField};

// These constants are defined in your circuit.rs, but we replicate them here
// to ensure this binary has the correct configuration for the Poseidon hash function.
pub const POSEIDON_WIDTH: usize = 3;
pub const POSEIDON_FULL_ROUNDS: usize = 8;
pub const POSEIDON_PARTIAL_ROUNDS: usize = 56;

// The main function of the binary. When run, it will compute and print
// the Poseidon round constants to stdout.
fn main() {
    println!("Generating Poseidon constants...");
    
    // Create a new Poseidon hasher instance
    let poseidon = Poseidon::new(POSEIDON_WIDTH, POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS);

    // The Poseidon `Poseidon::new()` function initializes the constants internally.
    // We can access them directly from the hasher object for printing.
    
    // Print the Poseidon round constants
    println!("--- Round Constants ---");
    for (i, constant) in poseidon.constants().iter().enumerate() {
        // Convert the BaseElement constant to a byte array and then to a hexadecimal string
        let mut bytes = [0u8; 32];
        constant.to_bytes(&mut bytes);
        println!("Round {}: 0x{}", i, hex::encode(bytes));
    }
    
    // Also print the S-box constant, which is a key part of the Poseidon hash function
    println!("\n--- S-box Constant ---");
    println!("{}", poseidon.sbox_constant());

    println!("\nPoseidon constants export complete.");
}
