// contracts/lib/PoseidonBN254.sol
pragma solidity ^0.8.20;

import ".interfaces/IPoseidonBN254.sol";

library PoseidonBN254 is IPoseidonBN254{
    uint256 constant MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Run export_poseidon_constants from Rust and paste the output here
    uint256[192] constant RC = [
        // ... (replace with actual constants)
    ];
    uint256[9] constant MDS = [
        // ... (replace with actual constants)
    ];

    function poseidon(uint256[3] memory input) internal pure returns (uint256) {
        uint256 t0 = input[0];
        uint256 t1 = input[1];
        uint256 t2 = input[2];
        for (uint r = 0; r < 8 + 56; r++) {
            t0 = addmod(t0, RC[r * 3], MODULUS);
            t1 = addmod(t1, RC[r * 3 + 1], MODULUS);
            t2 = addmod(t2, RC[r * 3 + 2], MODULUS);
            if (r < 8 || r >= 8 + 56 - 4) {
                t0 = mulmod(mulmod(t0, t0, MODULUS), mulmod(t0, t0, MODULUS), MODULUS);
                t1 = mulmod(mulmod(t1, t1, MODULUS), mulmod(t1, t1, MODULUS), MODULUS);
                t2 = mulmod(mulmod(t2, t2, MODULUS), mulmod(t2, t2, MODULUS), MODULUS);
            } else {
                t0 = mulmod(mulmod(t0, t0, MODULUS), mulmod(t0, t0, MODULUS), MODULUS);
            }
            uint256 new_t0 = addmod(
                mulmod(MDS[0], t0, MODULUS),
                addmod(mulmod(MDS[1], t1, MODULUS), mulmod(MDS[2], t2, MODULUS), MODULUS),
                MODULUS
            );
            uint256 new_t1 = addmod(
                mulmod(MDS[3], t0, MODULUS),
                addmod(mulmod(MDS[4], t1, MODULUS), mulmod(MDS[5], t2, MODULUS), MODULUS),
                MODULUS
            );
            uint256 new_t2 = addmod(
                mulmod(MDS[6], t0, MODULUS),
                addmod(mulmod(MDS[7], t1, MODULUS), mulmod(MDS[8], t2, MODULUS), MODULUS),
                MODULUS
            );
            t0 = new_t0;
            t1 = new_t1;
            t2 = new_t2;
        }
        return t0;
    }
}