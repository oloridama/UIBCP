// contracts/PoseidonBN254Contract.sol
pragma solidity ^0.8.20;

import "./lib/PoseidonBN254.sol";
import "./interfaces/IPoseidonBN254.sol";

contract PoseidonBN254Contract is IPoseidonBN254 {
    using PoseidonBN254 for *;

    function poseidon(uint256[3] memory input) external pure override returns (uint256) {
        return PoseidonBN254.poseidon(input);
    }
}