// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IIbcPacketHandler {
    function getNextSequence(bytes32 channelHash) external view returns (uint64);
    function depositBond() external payable;
    function receivePacket(
        string memory _sourceChannelId,
        uint64 _sequence,
        bytes memory _data,
        uint64 _timeoutTimestamp,
        uint64 _timeoutHeight,
        bytes memory _starkProof,
        bytes memory _zkpPublicInputs,
        bytes memory _packetCommitmentProof,
        uint64 _trustedHeight,
        bytes32 _trustedRoot
    ) external returns (bytes memory acknowledgement);
    function timeoutPacket(
        string memory _sourceChannelId,
        uint64 _sequence,
        bytes memory _timeoutProof,
        bytes32 _trustedRoot,
        uint64 _trustedHeight
    ) external;
    function setNextExpectedSequence(string memory _channelId, uint64 _sequence) external;
}