// contracts/libraries/UIBCTypes.sol
library UIBCTypes {
function decodeUniversalMessage(
bytes calldata data
) internal pure returns (UniversalMessage memory) {
(uint8 version, bytes32 messageId, /* ... */ ) =
abi.decode(data, (uint8, bytes32, /* ... */ ));
return UniversalMessage({
version: version,
message_id: messageId,
// ... other fields
});
}
}