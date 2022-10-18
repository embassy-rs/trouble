use crate::{bytes::*, Error};
use bitflags::bitflags;

bitflags! {
    /// A set of optional Link Layer features.
    pub struct FeatureSet: u64 {
        /// Low-Energy data encryption.
        ///
        /// Setting this bit means that the implementation must support the following:
        /// * The following types of LL Control PDUs: `LL_ENC_REQ`, `LL_ENC_RSP`,
        ///   `LL_START_ENC_REQ`, `LL_START_END_RSP`, `LL_PAUSE_ENC_REQ`, `LL_PAUSE_ENC_RSP`.
        /// * *Encryption Start* and *Encryption Pause* procedures.
        ///
        /// Note that the Security Manager Protocol also needs to be implemented for this to be
        /// useful.
        const LE_ENCRYPTION = 1 << 0;

        /// Connection parameters request procedure.
        ///
        /// Setting this bit means that the implementation must support the following:
        /// * The following types of LL Control PDUs: `LL_REJECT_IND_EXT`,
        ///   `LL_CONNECTION_PARAM_REQ`, `LL_CONNECTION_PARAM_RSP`.
        /// * *Connection Parameters Request Procedure*
        ///
        /// This is a superset of `EXTENDED_REJECT_INDICATION`, which may also be set when this bit
        /// is set.
        const CONN_PARAM_REQ = 1 << 1;

        /// Support for the LL Control PDU `LL_REJECT_IND_EXT`.
        const EXTENDED_REJECT_INDICATION = 1 << 2;

        /// Slave-initiated feature exchange.
        ///
        /// Setting this bit means that the implementation must support the following:
        /// * The following types of LL Control PDUs: `LL_SLAVE_FEATURE_REQ`, `LL_FEATURE_RSP`.
        ///
        /// TODO: What's the use of this?
        const SLAVE_FEATURE_EXCHANGE = 1 << 3;

        /// Low-Energy Link-Layer ping exchange.
        ///
        /// Setting this bit means that the implementation must support the following:
        /// * The following types of LL Control PDUs: `LL_PING_REQ`, `LL_PING_RSP`.
        /// * The *LE Ping Procedure*
        /// * *LE Authenticated Payload Timeout*
        ///
        /// If a Link-Layer is in idle state, it will transmit empty PDUs, which are never
        /// authenticated with a MIC. Supporting this feature allows configuring a timeout between
        /// authenticated packets, since dummy data can then be sent via `LL_PING_REQ`.
        const LE_PING = 1 << 4;

        /// Link-Layer PDU length update (support for data channel PDUs with more than 31 Bytes).
        ///
        /// Setting this bit means that the implementation must support the following:
        /// * The following types of LL Control PDUs: `LL_LENGTH_REQ`, `LL_LENGTH_RSP`
        /// * The *Data Length Update Procedure*
        const LE_PACKET_LENGTH_EXTENSION = 1 << 5;

        /// Support for untrackable randomized device addresses (LL Privacy).
        const LL_PRIVACY = 1 << 6;

        /// Extended scan filter policies.
        const EXT_SCANNER_FILTER_POLICIES = 1 << 7;
    }
}

impl FeatureSet {
    /// Returns the feature set supported by Rubble.
    pub fn supported() -> Self {
        FeatureSet::empty()
    }
}

impl ToBytes for FeatureSet {
    fn to_bytes(&self, writer: &mut ByteWriter<'_>) -> Result<(), Error> {
        writer.write_u64_le(self.bits())
    }
}

impl<'a> FromBytes<'a> for FeatureSet {
    fn from_bytes(bytes: &mut ByteReader<'a>) -> Result<Self, Error> {
        let raw = bytes.read_u64_le()?;
        Ok(Self::from_bits_truncate(raw))
    }
}

impl RawRepr<u64> for FeatureSet {
    fn from_raw(raw: u64) -> Self {
        Self::from_bits_truncate(raw)
    }

    fn as_raw(&self) -> u64 {
        self.bits()
    }
}
