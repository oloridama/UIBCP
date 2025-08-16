// relayer/src/adapters/ibc.rs
impl IbcAdapter {
fn to_uibc_message(&self, packet: IbcPacket) -> UniversalMessage {
UniversalMessage {
version: 1,
message_id: Self::generate_message_id(&packet),
source: ChainEndpoint {
chain_id: packet.source_chain,
endpoint_specifics: Some(IbcEndpoint {
connection_id: packet.connection_id,
channel_id: packet.channel_id,
port_id: packet.port_id,
}),
},
ibc_data: Some(IbcCompatibilityData {
sequence: packet.sequence,
..Default::default()
}),
..Default::default()
}
}
}