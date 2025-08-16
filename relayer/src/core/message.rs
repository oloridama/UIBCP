// relayer/src/core/message.rs
use crate::proto::uibc::v1::{UniversalMessage, MessageType, ProofRequirement};
use anyhow::{Result, anyhow};
use std::time::{SystemTime, UNIX_EPOCH};
use ibc::core::ics04_channel::packet::Packet;

pub struct UibcMessage {
    inner: UniversalMessage,
}

impl UibcMessage {
    pub fn new(message: UniversalMessage) -> Self {
        UibcMessage { inner: message }
    }

    pub fn validate(&self) -> Result<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        if let Some(timeout) = self.inner.timeout_timestamp {
            if timeout < current_time {
                return Err(anyhow!("Message has timed out"));
            }
        }
        if self.inner.message_type == MessageType::MessageTypeUnspecified as i32 {
            return Err(anyhow!("Invalid message type"));
        }
        Ok(())
    }

    pub fn to_ibc_packet(&self) -> Result<Packet> {
        if self.inner.ibc_data.is_none() {
            return Err(anyhow!("No IBC compatibility data"));
        }
        Ok(Packet {
            data: self.inner.encode_to_vec(),
            timeout_height: self.inner.timeout_height,
            timeout_timestamp: self.inner.timeout_timestamp.map(|t| ibc::timestamp::Timestamp::from_nanoseconds(t * 1_000_000_000)?),
            // Add other IBC fields as needed
            ..Default::default()
        })
    }

    pub fn proof_requirement(&self) -> Option<&ProofRequirement> {
        self.inner.proof_requirement.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_timeout() {
        let mut msg = UniversalMessage::default();
        msg.timeout_timestamp = Some(0); // Expired
        let uibc_msg = UibcMessage::new(msg);
        assert!(uibc_msg.validate().is_err());
    }
}