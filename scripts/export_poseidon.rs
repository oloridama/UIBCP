// scripts/export_poseidon.rs
use neptune::poseidon::parameters::generate_parameters;
use winter_math::fields::f252::BaseElement;

fn main() {
    let params = generate_parameters::<BaseElement>(3, 8, 56);
    println!("// Round constants");
    println!("uint256[192] constant RC = [");
    for (i, rc) in params.round_constants.iter().enumerate() {
        print!("    0x{:x}", rc);
        if i < params.round_constants.len() - 1 {
            print!(",");
        }
        if i % 3 == 2 {
            println!();
        }
    }
    println!("];");
    println!("// MDS matrix");
    println!("uint256[9] constant MDS = [");
    for i in 0..3 {
        for j in 0..3 {
            print!("    0x{:x}", params.mds_matrix.get(i, j));
            if i * 3 + j < 8 {
                print!(",");
            }
        }
        println!();
    }
    println!("];");
}