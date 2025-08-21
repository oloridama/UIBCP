// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IPoseidonBN254
/// @notice Interface for the Poseidon hash function library over the BN254 curve.
///         This interface allows other contracts to interact with the Poseidon
///         hashing logic.
interface IPoseidonBN254 {
    /// @dev Computes the Poseidon hash of a single state (width-3) input.
    /// @param input The array of three uint256 elements to be hashed.
    /// @return The resulting 256-bit hash.
    function hash(uint256[3] calldata input) external pure returns (uint256);
}
