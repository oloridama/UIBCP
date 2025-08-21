// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IPoseidonBN254.sol";

// @title StarkVerifier
// @dev Verifies a STARK-to-Groth16 proof for ICS-23 inclusion, targeting <5k gas
// @notice Uses off-chain STARK-to-Groth16 transcoder (e.g., snarkjs, Polygon Miden)
// @notice VK is immutable, set in constructor from snarkjs/gnark setup
// @notice MODULUS, BN254_MODULUS_LIMBS, and Poseidon constants must match circuit.rs
contract StarkVerifier {
    // BN254 field modulus (MUST match circuit.rs and PoseidonBN254.sol)
    uint256 constant MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // BN254 modulus limbs for state root (MUST match circuit.rs)
    uint64[4] constant BN254_MODULUS_LIMBS = [
        1161245052955562761,
        18446744073709551615,
        18446744073709551615,
        16584218841459030617
    ];

    IPoseidonBN254 immutable poseidon;
    VerificationKey immutable VK;

    // Groth16 Verification Key (set in constructor from snarkjs/gnark setup)
    struct VerificationKey {
        uint[2] alfa1; // G1 point
        uint[2][2] beta2; // G2 point
        uint[2][2] gamma2; // G2 point
        uint[2][2] delta2; // G2 point
        uint[2][4] ic; // Coefficients for constant + 3 public inputs
    }

    constructor(address _poseidonAddress, VerificationKey memory _vk) {
        require(_poseidonAddress != address(0), "Invalid Poseidon address");
        poseidon = IPoseidonBN254(_poseidonAddress);
        VK = _vk;
    }

    // @dev Verifies a transcoded STARK-to-Groth16 proof
    function verify(uint[8] memory proof, bytes memory publicInputs, bytes32 trustedRoot) external view returns (bool) {
        // Step 1: Deserialize public inputs (96 bytes: state_root, message_hash, chain_id)
        require(publicInputs.length == 96, "Invalid public inputs length");
        (uint256 stateRoot, uint256 messageHash, uint256 chainId) = abi.decode(publicInputs, (uint256, uint256, uint256));

        // Step 2: Verify state root
        if (uint256(trustedRoot) != stateRoot) {
            return false;
        }

        // Step 3: Parse Groth16 proof (uint[8]: A[2], B[4], C[2])
        uint[2] memory a = [proof[0], proof[1]];
        uint[2][2] memory b = [[proof[2], proof[3]], [proof[4], proof[5]]];
        uint[2] memory c = [proof[6], proof[7]];

        // Step 4: Zero-check proof elements
        require(a[0] != 0 && a[1] != 0, "Invalid proof: A is zero");
        require(b[0][0] != 0 && b[0][1] != 0 && b[1][0] != 0 && b[1][1] != 0, "Invalid proof: B is zero");
        require(c[0] != 0 && c[1] != 0, "Invalid proof: C is zero");

        // Step 5: Prepare public inputs for Groth16
        uint[3] memory inputs = [stateRoot, messageHash, chainId];

        // Step 6: Verify Groth16 proof
        return verifyGroth16(a, b, c, inputs);
    }

    // @dev Standard Groth16 verification (based on snarkjs/OpenZeppelin)
    function verifyGroth16(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[3] memory input
    ) internal view returns (bool) {
        // Compute vk_x = ic[0] + sum(input[i] * ic[i+1])
        uint[2] memory vk_x = VK.ic[0];
        for (uint i = 0; i < 3; i++) {
            vk_x[0] = addmod(vk_x[0], mulmod(input[i], VK.ic[i + 1][0], MODULUS), MODULUS);
            vk_x[1] = addmod(vk_x[1], mulmod(input[i], VK.ic[i + 1][1], MODULUS), MODULUS);
        }

        // Prepare inputs for four-pairing check: e(-A, B) * e(alfa1, beta2) * e(vk_x, gamma2) * e(C, delta2)
        uint[24] memory pairingInput;
        pairingInput[0] = a[0];
        pairingInput[1] = MODULUS - a[1]; // -A.y
        pairingInput[2] = b[0][0]; // B.x0
        pairingInput[3] = b[0][1]; // B.x1
        pairingInput[4] = b[1][0]; // B.y0
        pairingInput[5] = b[1][1]; // B.y1
        pairingInput[6] = VK.alfa1[0];
        pairingInput[7] = VK.alfa1[1];
        pairingInput[8] = VK.beta2[0][0];
        pairingInput[9] = VK.beta2[0][1];
        pairingInput[10] = VK.beta2[1][0];
        pairingInput[11] = VK.beta2[1][1];
        pairingInput[12] = vk_x[0];
        pairingInput[13] = vk_x[1];
        pairingInput[14] = VK.gamma2[0][0];
        pairingInput[15] = VK.gamma2[0][1];
        pairingInput[16] = VK.gamma2[1][0];
        pairingInput[17] = VK.gamma2[1][1];
        pairingInput[18] = c[0];
        pairingInput[19] = c[1];
        pairingInput[20] = VK.delta2[0][0];
        pairingInput[21] = VK.delta2[0][1];
        pairingInput[22] = VK.delta2[1][0];
        pairingInput[23] = VK.delta2[1][1];

        // Call precompiled pairing contract (0x08)
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(gas(), 8, pairingInput, 768, out, 32)
        }
        require(success, "Pairing check failed");
        return out[0] == 1;
    }

    // @dev Computes state root from limbs (matches circuit.rs)
    function computeStateRootFromLimbs(uint64[4] memory limbs) internal pure returns (uint256) {
        uint256 base = 2 ** 64;
        uint256 result = limbs[0];
        result = addmod(result, mulmod(limbs[1], base, MODULUS), MODULUS);
        result = addmod(result, mulmod(limbs[2], base * base % MODULUS, MODULUS), MODULUS);
        result = addmod(result, mulmod(limbs[3], (base * base * base) % MODULUS, MODULUS), MODULUS);
        return result;
    }

    // @dev Getter for VK (optional, for transparency)
    function getVerificationKey() external view returns (VerificationKey memory) {
        return VK;
    }
}
