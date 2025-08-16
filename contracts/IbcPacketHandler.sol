// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./PoseidonBN254.sol";
import "./StarkVerifier.sol";

contract IbcPacketHandler is Ownable {
    StarkVerifier public immutable starkVerifier;
    address public immutable owner;
    address public feeManager;
    address public proofVerifier;
    address public bondManager;

    uint256 public constant RELAYER_BOND = 1 ether;
    mapping(address => uint256) public relayerBonds;
    mapping(bytes32 => uint64) private _nextExpectedSequence;
    mapping(bytes32 => mapping(uint64 => bool)) public receivedPackets;
    mapping(bytes32 => mapping(uint64 => PacketInfo)) public packets;

    enum SlashingOffense { InvalidProof, Timeout }

    struct PacketInfo {
        uint64 sequence;
        uint64 timeoutTimestamp;
        uint64 timeoutHeight;
        bool acknowledged;
        bool timedOut;
        bool underChallenge;
        uint64 challengeDeadline;
    }

    struct UniversalMessage {
        bytes messageId;
        uint64 timeoutTimestamp;
        bytes payload;
        ProofRequirement proofRequirement;
        IbcCompatibilityData ibcData;
        EconomicParameters economicParameters;
        RelayerAssignment relayerAssignment;
        Fee totalFee;
    }

    struct ProofRequirement {
        bytes zkProof;
        bytes publicInputs;
    }

    struct IbcCompatibilityData {
        uint64 sequence;
        string sourcePort;
        string sourceChannel;
        string destinationPort;
        string destinationChannel;
        uint64 timeout;
        bytes tokenData;
        bytes ics27Data;
        bytes customAppData;
        bytes connectionInfo;
        bytes clientInfo;
    }

    struct EconomicParameters {
        uint256 baseFee;
        uint256 verificationFee;
    }

    struct RelayerAssignment {
        address assignedRelayer;
    }

    struct Fee {
        string amount;
        string denom;
        string chainId;
        uint8 decimals;
    }

    struct EVMExtension {
        bytes domainSeparator;
        uint64 gasLimit;
        uint64 maxFeePerGas;
        uint64 maxPriorityFee;
        AccessTuple[] accessList;
    }

    struct AccessTuple {
        bytes address;
        bytes[] storageKeys;
    }

    struct FungibleTokenPacket {
        string denom;
        string amount;
        string sender;
        string receiver;
        string memo;
    }

    event IbcPacketReceived(bytes32 indexed channelId, uint64 indexed sequence, address indexed relayer, bytes32 sourceChain, bytes data, bytes proofCommitment);
    event IbcPacketAcknowledged(bytes32 indexed channelId, uint64 indexed sequence, bytes acknowledgementData);
    event RelayerBondUpdated(address indexed relayer, uint256 newBondAmount);
    event RelayerBondSlashing(address indexed relayer, uint256 slashedAmount, address indexed recipient);
    event PacketTimedOut(bytes32 indexed channelId, uint64 indexed sequence);
    event PacketChallenged(bytes32 indexed channelId, uint64 indexed sequence, address indexed challenger);
    event ChallengeResolved(bytes32 indexed channelId, uint64 indexed sequence, bool valid);
    event IbcPacketSubmitted(bytes32 indexed channelId, uint64 indexed sequence, address indexed relayer);

    modifier onlyBondedRelayer() {
        require(relayerBonds[msg.sender] >= RELAYER_BOND, "Insufficient bond");
        _;
    }

    constructor(address _starkVerifierAddress, address _feeManager, address _proofVerifier, address _bondManager) {
        require(_starkVerifierAddress != address(0), "Invalid verifier address");
        require(_feeManager != address(0), "Invalid fee manager address");
        require(_proofVerifier != address(0), "Invalid proof verifier address");
        require(_bondManager != address(0), "Invalid bond manager address");
        starkVerifier = StarkVerifier(_starkVerifierAddress);
        feeManager = _feeManager;
        proofVerifier = _proofVerifier;
        bondManager = _bondManager;
        owner = msg.sender;
    }

    function getNextSequence(bytes32 channelHash) external view returns (uint64) {
        return _nextExpectedSequence[channelHash];
    }

    function depositBond() external payable {
        require(msg.value >= RELAYER_BOND, "Insufficient bond");
        relayerBonds[msg.sender] += msg.value;
        emit RelayerBondUpdated(msg.sender, relayerBonds[msg.sender]);
    }

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
    ) public returns (bytes memory acknowledgement) {
        require(relayerBonds[msg.sender] >= RELAYER_BOND, "Insufficient bond");

        bytes32 channelHash = keccak256(abi.encodePacked(_sourceChannelId));
        require(!receivedPackets[channelHash][_sequence], "Packet already received");
        receivedPackets[channelHash][_sequence] = true;

        bool zkpIsValid = starkVerifier.verify(_starkProof, _zkpPublicInputs, _trustedRoot);
        if (!zkpIsValid) {
            uint256 slashed = relayerBonds[msg.sender] >= RELAYER_BOND ? RELAYER_BOND : relayerBonds[msg.sender];
            relayerBonds[msg.sender] -= slashed;
            (bool sent, ) = owner.call{value: slashed}("");
            require(sent, "Slashing failed");
            emit RelayerBondSlashing(msg.sender, slashed, owner);
            revert("Stark proof failed, bond slashed");
        }

        IbcCompatibilityData memory ibc = abi.decode(_data, (IbcCompatibilityData));
        require(_sequence == ibc.sequence, "Sequence mismatch");
        require(_sequence == _nextExpectedSequence[channelHash], "Incorrect sequence");
        _nextExpectedSequence[channelHash]++;

        bytes memory path = abi.encodePacked("/ibc/ports/transfer/channels/", _sourceChannelId, "/packets/", _sequence);
        bytes32 commitment = keccak256(abi.encodePacked(ibc.tokenData, _timeoutTimestamp, _timeoutHeight));
        uint256[3] memory proofInput = [uint256(keccak256(_packetCommitmentProof)), uint256(_trustedRoot), 0];
        bool commitmentValid = PoseidonBN254.poseidon(proofInput) == uint256(commitment);
        require(commitmentValid, "Commitment proof failed");

        acknowledgement = _processPacketData(ibc);
        packets[channelHash][_sequence] = PacketInfo(_sequence, _timeoutTimestamp, _timeoutHeight, true, false, false, 0);

        emit IbcPacketReceived(channelHash, _sequence, msg.sender, keccak256("cosmos-testnet-0"), _data, _packetCommitmentProof);
        emit IbcPacketAcknowledged(channelHash, _sequence, acknowledgement);
        return acknowledgement;
    }

    function receiveUIBCPacket(bytes memory messageData, bytes memory proofData, uint64 challengePeriod) 
        external 
        onlyBondedRelayer 
        returns (bytes memory acknowledgment) 
    {
        UniversalMessage memory message = abi.decode(messageData, (UniversalMessage));
        require(message.timeoutTimestamp > block.timestamp, "Message expired");
        require(IFeeManager(feeManager).validateFeePayment(message.economicParameters), "Invalid fee payment");
        
        if (message.proofRequirement.zkProof.length > 0) {
            require(IProofVerifier(proofVerifier).verifyZkProof(proofData, message.proofRequirement.publicInputs), "Invalid ZK proof");
        }
        
        bytes32 channelHash = keccak256(abi.encodePacked(message.ibcData.sourceChannel));
        require(!receivedPackets[channelHash][message.ibcData.sequence], "Packet already received");
        receivedPackets[channelHash][message.ibcData.sequence] = true;
        _nextExpectedSequence[channelHash] = message.ibcData.sequence + 1;

        acknowledgment = _processPacketData(message.ibcData);
        if (challengePeriod > 0) {
            packets[channelHash][message.ibcData.sequence] = PacketInfo(
                message.ibcData.sequence,
                message.timeoutTimestamp,
                0,
                false,
                false,
                true,
                uint64(block.timestamp) + challengePeriod
            );
            emit IbcPacketSubmitted(channelHash, message.ibcData.sequence, msg.sender);
        } else {
            packets[channelHash][message.ibcData.sequence] = PacketInfo(
                message.ibcData.sequence,
                message.timeoutTimestamp,
                0,
                true,
                false,
                false,
                0
            );
            emit IbcPacketAcknowledged(channelHash, message.ibcData.sequence, acknowledgment);
        }

        emit IbcPacketReceived(channelHash, message.ibcData.sequence, msg.sender, keccak256("cosmos-testnet-0"), messageData, proofData);
        return acknowledgment;
    }

    function receivePacketOptimistic(
        string memory _sourceChannelId,
        uint64 _sequence,
        bytes memory _data,
        uint64 _timeoutTimestamp,
        bytes memory _zkProof,
        bytes memory _zkpPublicInputs
    ) public returns (bytes memory acknowledgement) {
        require(relayerBonds[msg.sender] >= RELAYER_BOND, "Insufficient bond");

        bytes32 channelHash = keccak256(abi.encodePacked(_sourceChannelId));
        require(!receivedPackets[channelHash][_sequence], "Packet already received");
        receivedPackets[channelHash][_sequence] = true;

        bool zkpIsValid = starkVerifier.verify(_zkProof, _zkpPublicInputs, bytes32(0)); // Placeholder root
        require(zkpIsValid, "Initial ZK proof check failed");

        IbcCompatibilityData memory ibc = abi.decode(_data, (IbcCompatibilityData));
        require(_sequence == ibc.sequence, "Sequence mismatch");
        require(_sequence == _nextExpectedSequence[channelHash], "Incorrect sequence");
        _nextExpectedSequence[channelHash]++;

        uint64 challengeDeadline = uint64(block.timestamp) + 7 days;
        packets[channelHash][_sequence] = PacketInfo(_sequence, _timeoutTimestamp, 0, false, false, true, challengeDeadline);

        acknowledgement = _processPacketData(ibc);
        emit IbcPacketReceived(channelHash, _sequence, msg.sender, keccak256("cosmos-testnet-0"), _data, _zkpPublicInputs);
        emit IbcPacketSubmitted(channelHash, _sequence, msg.sender);
        return acknowledgement;
    }

    function disputePacket(bytes32 messageId, bytes memory challengeProof) external {
        UniversalMessage memory message = getMessage(messageId);
        require(message.proofRequirement.zkProof.length == 0, "Not optimistic");
        require(block.timestamp <= message.timeoutTimestamp, "Challenge expired");
        bool is_valid = IProofVerifier(proofVerifier).verifyChallenge(challengeProof);
        if (is_valid) {
            IBondManager(bondManager).slashRelayer(message.relayerAssignment.assignedRelayer, SlashingOffense.InvalidProof);
            IBondManager(bondManager).rewardChallenger(msg.sender, parseAmount(message.totalFee.amount) * 2000 / 10000); // 20% reward
        } else {
            IBondManager(bondManager).slashChallenger(msg.sender); // Slash 0.1 ETH bond
        }
        emit ChallengeResolved(keccak256(abi.encodePacked(message.ibcData.sourceChannel)), message.ibcData.sequence, is_valid);
    }

    function challengePacket(
        bytes32 channelHash,
        uint64 sequence,
        bytes memory challengeProof
    ) external {
        PacketInfo storage p = packets[channelHash][sequence];
        require(p.underChallenge, "Packet not under challenge");
        require(block.timestamp <= p.challengeDeadline, "Challenge period expired");
        require(relayerBonds[msg.sender] >= RELAYER_BOND, "Insufficient challenger bond");

        bool challengeValid = IProofVerifier(proofVerifier).verifyChallenge(challengeProof);
        if (challengeValid) {
            uint256 slashed = relayerBonds[p.sender] >= RELAYER_BOND ? RELAYER_BOND : relayerBonds[p.sender];
            relayerBonds[p.sender] -= slashed;
            IBondManager(bondManager).rewardChallenger(msg.sender, slashed * 20 / 100); // 20% reward
            emit RelayerBondSlashing(p.sender, slashed, msg.sender);
        } else {
            uint256 slashed = relayerBonds[msg.sender] >= RELAYER_BOND ? RELAYER_BOND : relayerBonds[msg.sender];
            relayerBonds[msg.sender] -= slashed;
            emit RelayerBondSlashing(msg.sender, slashed, owner);
        }
        emit ChallengeResolved(channelHash, sequence, challengeValid);
        p.underChallenge = false;
    }

    function _processPacketData(IbcCompatibilityData memory ibc) internal returns (bytes memory ack) {
        FungibleTokenPacket memory token = abi.decode(ibc.tokenData, (FungibleTokenPacket));
        if (bytes(token.denom).length >= 4 && keccak256(bytes(token.denom)[:4]) == keccak256("ibc/")) {
            ack = abi.encode(true);
        } else {
            ack = abi.encode(false, "Unsupported denom");
        }

        if (ibc.customAppData.length > 0) {
            EVMExtension memory evm = abi.decode(ibc.customAppData, (EVMExtension));
            require(evm.gasLimit > 0, "Invalid gas limit");
        }
        return ack;
    }

    function timeoutPacket(
        string memory _sourceChannelId,
        uint64 _sequence,
        bytes memory _timeoutProof,
        bytes32 _trustedRoot,
        uint64 _trustedHeight
    ) external {
        require(relayerBonds[msg.sender] >= RELAYER_BOND, "Insufficient bond");

        bytes32 channelHash = keccak256(abi.encodePacked(_sourceChannelId));
        PacketInfo storage p = packets[channelHash][_sequence];
        require(p.sequence == _sequence && !p.acknowledged && !p.timedOut, "Invalid packet state");
        require(block.timestamp >= p.timeoutTimestamp || block.number >= p.timeoutHeight, "Not timed out");

        bytes memory path = abi.encodePacked("/ibc/ports/transfer/channels/", _sourceChannelId, "/packets/", _sequence);
        uint256[3] memory proofInput = [uint256(keccak256(_timeoutProof)), uint256(_trustedRoot), 0];
        bool nonMembershipValid = PoseidonBN254.poseidon(proofInput) == 0;
        require(nonMembershipValid, "Timeout proof failed");

        p.timedOut = true;
        emit PacketTimedOut(channelHash, _sequence);
    }

    function setNextExpectedSequence(string memory _channelId, uint64 _sequence) external onlyOwner {
        _nextExpectedSequence[keccak256(abi.encodePacked(_channelId))] = _sequence;
    }

    function parseAmount(string memory amount) internal pure returns (uint256) {
        return amount.length > 0 ? abi.decode(abi.encodePacked(amount), (uint256)) : 0;
    }

    function getMessage(bytes32 messageId) internal view returns (UniversalMessage memory) {
        // Placeholder: Assume message storage or retrieval logic
        return abi.decode(packets[keccak256(abi.encodePacked(messageId))][0].data, (UniversalMessage));
    }
}

interface IFeeManager {
    function validateFeePayment(EconomicParameters memory params) external returns (bool);
}

interface IProofVerifier {
    function verifyZkProof(bytes memory proof, bytes memory publicInputs) external returns (bool);
    function verifyChallenge(bytes memory challengeProof) external returns (bool);
}

interface IBondManager {
    function slashRelayer(address relayer, SlashingOffense offense) external;
    function rewardChallenger(address challenger, uint256 amount) external;
    function slashChallenger(address challenger) external;
}