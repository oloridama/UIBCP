// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPoseidonBN254 {
    /// @notice Computes a Poseidon hash for a 3-element input array.
    /// @param input The input array of 3 uint256 values.
    /// @return The resulting hash value.
    function poseidon(uint256[3] memory input) external pure returns (uint256);

    /// @notice Computes a Poseidon hash for a variable-length input array (batched hashing).
    /// @param input The input array of uint256 values (length must be a multiple of 3 for full state).
    /// @return The resulting hash value.
    function poseidonBatch(uint256[] memory input) external pure returns (uint256);

    /// @notice Retrieves the modulus used in Poseidon computations (BN254 scalar field).
    /// @return The modulus value.
    function getModulus() external pure returns (uint256);
}