//! Defines packet structures used by the Link Layer Control Protocol.

use crate::link::{channel_map::ChannelMap, comp_id::CompanyId, features::FeatureSet};
use crate::{bytes::*, time::Duration, utils::Hex, Error};
use core::{cmp, convert::TryInto};

/// A connection parameter update request or response (`LL_CONNECTION_PARAM_REQ`/
/// `LL_CONNECTION_PARAM_RSP`).
#[derive(Debug, Copy, Clone)]
pub struct ConnectionParamRequest {
    interval_min: u16,
    interval_max: u16,
    slave_latency: u16,
    supervision_timeout: u16,
    /// `connInterval` is preferred to be a multiple of this value (in 1.25 ms steps).
    preferred_periodicity: u8,
    reference_conn_event_count: u16,
    offsets: [u16; 6],
}

impl ConnectionParamRequest {
    /// Creates a new connection update request structure filled with default values.
    ///
    /// The returned structure will use conservative (maximally permissive) default values that will
    /// not usually result in a change in connection parameters, so users of this function likely
    /// want to call a setter afterwards.
    pub fn new() -> Self {
        Self {
            interval_min: 6,    // 7.5ms
            interval_max: 3200, // 4s
            slave_latency: 0,
            supervision_timeout: 100,      // FIXME (unsure; 1s)
            preferred_periodicity: 0,      // not valid
            reference_conn_event_count: 0, // irrelevant
            offsets: [0xFFFF; 6],          // none valid
        }
    }

    /// Sets the minimum and maximum requested connection interval.
    ///
    /// # Parameters
    ///
    /// * `min`: Minimum connection interval to request.
    /// * `max`: Maximum connection interval to request.
    ///
    /// Both `min` and `max` must be in range 7.5ms to 4s, or they will be constrained to lie in
    /// that range.
    ///
    /// Both `min` and `max` will be rounded down to units of 1.25 ms.
    ///
    /// # Panics
    ///
    /// This will panic if `min > max`.
    pub fn set_conn_interval(&mut self, min: Duration, max: Duration) {
        assert!(min <= max);

        // Convert and round to units of 1.25 ms.
        let max = max.as_micros() / 1_250;
        let min = min.as_micros() / 1_250;

        // Clamp to valid range of 6..=3200
        let min = cmp::min(cmp::max(min, 6), 3200);
        let max = cmp::min(cmp::max(max, 6), 3200);
        debug_assert!(min <= max);
        self.interval_min = min as u16;
        self.interval_max = max as u16;
    }

    /// Returns the minimum requested connection interval.
    pub fn min_conn_interval(&self) -> Duration {
        Duration::from_micros(u32::from(self.interval_min) * 1_250)
    }

    /// Returns the maximum requested connection interval.
    pub fn max_conn_interval(&self) -> Duration {
        Duration::from_micros(u32::from(self.interval_max) * 1_250)
    }

    /// Returns the slave latency in number of connection events.
    pub fn slave_latency(&self) -> u16 {
        self.slave_latency
    }

    /// Returns the supervision timeout.
    pub fn supervision_timeout(&self) -> Duration {
        Duration::from_millis(self.supervision_timeout * 10)
    }
}

impl<'a> FromBytes<'a> for ConnectionParamRequest {
    fn from_bytes(bytes: &mut ByteReader<'a>) -> Result<Self, Error> {
        Ok(Self {
            interval_min: bytes.read_u16_le()?,
            interval_max: bytes.read_u16_le()?,
            slave_latency: bytes.read_u16_le()?,
            supervision_timeout: bytes.read_u16_le()?,
            preferred_periodicity: bytes.read_u8()?,
            reference_conn_event_count: bytes.read_u16_le()?,
            offsets: [
                bytes.read_u16_le()?,
                bytes.read_u16_le()?,
                bytes.read_u16_le()?,
                bytes.read_u16_le()?,
                bytes.read_u16_le()?,
                bytes.read_u16_le()?,
            ],
        })
    }
}

impl ToBytes for ConnectionParamRequest {
    fn to_bytes(&self, writer: &mut ByteWriter<'_>) -> Result<(), Error> {
        writer.write_u16_le(self.interval_min)?;
        writer.write_u16_le(self.interval_max)?;
        writer.write_u16_le(self.slave_latency)?;
        writer.write_u16_le(self.supervision_timeout)?;
        writer.write_u8(self.preferred_periodicity)?;
        writer.write_u16_le(self.reference_conn_event_count)?;
        for offset in &self.offsets {
            writer.write_u16_le(*offset)?;
        }
        Ok(())
    }
}

/// Data transmitted with an `LL_CONNECTION_UPDATE_REQ` Control PDU, containing a new set of
/// connection parameters.
#[derive(Debug, Copy, Clone, zerocopy::FromBytes, zerocopy::Unaligned)]
#[repr(packed)]
pub struct ConnectionUpdateData {
    win_size: u8,
    win_offset: u16,
    interval: u16,
    latency: u16,
    timeout: u16,
    instant: u16,
}

impl ConnectionUpdateData {
    /// Returns the size of the transmit window for the first PDU of the connection.
    pub fn win_size(&self) -> Duration {
        Duration::from_micros(u32::from(self.win_size) * 1_250)
    }

    /// Returns the offset of the transmit window, as a duration since the `instant`.
    pub fn win_offset(&self) -> Duration {
        Duration::from_micros(u32::from(self.win_offset) * 1_250)
    }

    /// Returns the duration between connection events.
    pub fn interval(&self) -> Duration {
        Duration::from_micros(u32::from(self.interval) * 1_250)
    }

    /// Returns the slave latency.
    pub fn latency(&self) -> u16 {
        self.latency
    }

    /// Returns the connection supervision timeout (`connSupervisionTimeout`).
    pub fn timeout(&self) -> Duration {
        Duration::from_micros(u32::from(self.timeout) * 10_000)
    }

    /// Returns the instant at which these changes should take effect.
    pub fn instant(&self) -> u16 {
        self.instant
    }
}

#[derive(Debug, Copy, Clone, zerocopy::FromBytes, zerocopy::Unaligned)]
#[repr(packed)]
pub struct ChannelMapReq {
    pub map: Field<[u8; 5], ChannelMap>,
    pub instant: u16,
}

/// A structured representation of an LL Control PDU used by the Link Layer Control Protocol (LLCP).
#[derive(Debug, Copy, Clone)]
pub enum ControlPdu<'a> {
    /// `0x00`/`LL_CONNECTION_UPDATE_REQ` - Update connection parameters.
    ///
    /// Sent by the master. The slave does not send a response back.
    ConnectionUpdateReq(&'a ConnectionUpdateData),

    /// `0x01`/`LL_CHANNEL_MAP_REQ` - Update the channel map.
    ///
    /// Sent by the master. The slave does not send a response back.
    ChannelMapReq(&'a ChannelMapReq),

    /// `0x02`/`LL_TERMINATE_IND` - Close the connection.
    ///
    /// Can be sent by master or slave.
    TerminateInd {
        error_code: Hex<u8>,
    },

    /// `0x07`/`LL_UNKNOWN_RSP` - Response to unknown/unsupported LL Control PDUs.
    ///
    /// This is returned as a response to an incoming LL Control PDU when the opcode is
    /// unimplemented or unknown, or when the `CtrData` is invalid for the opcode.
    UnknownRsp {
        /// Opcode of the unknown PDU.
        unknown_type: ControlOpcode,
    },

    /// `0x08`/`LL_FEATURE_REQ` - Master requests slave's features.
    FeatureReq {
        /// Supported feature set of the master.
        features_master: FeatureSet,
    },

    /// `0x09`/`LL_FEATURE_RSP` - Slave answers `LL_FEATURE_REQ` with the used feature set.
    FeatureRsp {
        /// Features that will be used for the connection. Logical `AND` of master and slave
        /// features.
        features_used: FeatureSet,
    },

    /// `0x0C`/`LL_VERSION_IND` - Bluetooth version indication (sent by both master and slave).
    ///
    /// When either master or slave receive this PDU, they should respond with their version if they
    /// have not already sent this PDU during this data connection (FIXME do this).
    VersionInd {
        vers_nr: VersionNumber,
        comp_id: CompanyId,
        sub_vers_nr: Hex<u16>,
    },

    ConnectionParamReq(ConnectionParamRequest),
    ConnectionParamRsp(ConnectionParamRequest),

    /// Catch-all variant for unsupported opcodes.
    Unknown {
        /// The opcode we don't support. This can also be the `Unknown` variant.
        opcode: ControlOpcode,

        /// Additional data depending on the opcode.
        ctr_data: &'a [u8],
    },
}

impl ControlPdu<'_> {
    /// Returns the opcode of this LL Control PDU.
    pub fn opcode(&self) -> ControlOpcode {
        match self {
            ControlPdu::ConnectionUpdateReq { .. } => ControlOpcode::ConnectionUpdateReq,
            ControlPdu::ChannelMapReq { .. } => ControlOpcode::ChannelMapReq,
            ControlPdu::TerminateInd { .. } => ControlOpcode::TerminateInd,
            ControlPdu::UnknownRsp { .. } => ControlOpcode::UnknownRsp,
            ControlPdu::FeatureReq { .. } => ControlOpcode::FeatureReq,
            ControlPdu::FeatureRsp { .. } => ControlOpcode::FeatureRsp,
            ControlPdu::VersionInd { .. } => ControlOpcode::VersionInd,
            ControlPdu::ConnectionParamReq(_) => ControlOpcode::ConnectionParamReq,
            ControlPdu::ConnectionParamRsp(_) => ControlOpcode::ConnectionParamRsp,
            ControlPdu::Unknown { opcode, .. } => *opcode,
        }
    }

    /// Returns the encoded size of this LLCPDU, including the opcode byte.
    pub fn encoded_size(&self) -> u8 {
        use self::ControlOpcode::*;

        1 + match self.opcode() {
            ConnectionUpdateReq => 1 + 2 + 2 + 2 + 2 + 2,
            ChannelMapReq => 5 + 2,
            TerminateInd => 1,
            EncReq => 8 + 2 + 8 + 4,
            EncRsp => 8 + 4,
            StartEncReq => 0,
            StartEncRsp => 0,
            UnknownRsp => 1,
            FeatureReq => 8,
            FeatureRsp => 8,
            PauseEncReq => 0,
            PauseEncRsp => 0,
            VersionInd => 1 + 2 + 2,
            RejectInd => 1,
            SlaveFeatureReq => 8,
            ConnectionParamReq | ConnectionParamRsp => {
                2 + 2 + 2 + 2 + 1 + 2 + 2 + 2 + 2 + 2 + 2 + 2
            }
            RejectIndExt => 1 + 1,
            PingReq => 0,
            PingRsp => 0,
            LengthReq | LengthRsp => 2 + 2 + 2 + 2,
            Unknown(_) => {
                if let ControlPdu::Unknown {
                    ctr_data,
                    opcode: _,
                } = self
                {
                    ctr_data.len().try_into().unwrap()
                } else {
                    unreachable!()
                }
            }
        }
    }
}

impl<'a> FromBytes<'a> for ControlPdu<'a> {
    fn from_bytes(bytes: &mut ByteReader<'a>) -> Result<Self, Error> {
        let opcode = ControlOpcode::from(bytes.read_u8()?);
        Ok(match opcode {
            ControlOpcode::ConnectionUpdateReq => {
                ControlPdu::ConnectionUpdateReq(bytes.read_obj()?)
            }
            ControlOpcode::ChannelMapReq => ControlPdu::ChannelMapReq(bytes.read_obj()?),
            ControlOpcode::TerminateInd => ControlPdu::TerminateInd {
                error_code: Hex(bytes.read_u8()?),
            },
            ControlOpcode::UnknownRsp => ControlPdu::UnknownRsp {
                unknown_type: ControlOpcode::from(bytes.read_u8()?),
            },
            ControlOpcode::FeatureReq => ControlPdu::FeatureReq {
                features_master: FeatureSet::from_bytes(bytes)?,
            },
            ControlOpcode::FeatureRsp => ControlPdu::FeatureRsp {
                features_used: FeatureSet::from_bytes(bytes)?,
            },
            ControlOpcode::VersionInd => ControlPdu::VersionInd {
                vers_nr: VersionNumber::from(bytes.read_u8()?),
                comp_id: CompanyId::from_raw(bytes.read_u16_le()?),
                sub_vers_nr: Hex(bytes.read_u16_le()?),
            },
            _ => ControlPdu::Unknown {
                opcode,
                ctr_data: bytes.read_rest(),
            },
        })
    }
}

impl<'a> ToBytes for ControlPdu<'a> {
    fn to_bytes(&self, buffer: &mut ByteWriter<'_>) -> Result<(), Error> {
        buffer.write_u8(self.opcode().into())?;
        match self {
            ControlPdu::ConnectionUpdateReq(data) => {
                buffer.write_u8(data.win_size)?;
                buffer.write_u16_le(data.win_offset)?;
                buffer.write_u16_le(data.interval)?;
                buffer.write_u16_le(data.latency)?;
                buffer.write_u16_le(data.timeout)?;
                buffer.write_u16_le(data.instant)?;
                Ok(())
            }
            ControlPdu::ChannelMapReq(req) => {
                buffer.write_slice(req.map.raw())?;
                buffer.write_u16_le(req.instant)?;
                Ok(())
            }
            ControlPdu::TerminateInd { error_code } => {
                buffer.write_u8(error_code.0)?;
                Ok(())
            }
            ControlPdu::UnknownRsp { unknown_type } => {
                buffer.write_u8(u8::from(*unknown_type))?;
                Ok(())
            }
            ControlPdu::FeatureReq { features_master } => features_master.to_bytes(buffer),
            ControlPdu::FeatureRsp { features_used } => features_used.to_bytes(buffer),
            ControlPdu::VersionInd {
                vers_nr,
                comp_id,
                sub_vers_nr,
            } => {
                buffer.write_u8(u8::from(*vers_nr))?;
                buffer.write_u16_le(comp_id.as_u16())?;
                buffer.write_u16_le(sub_vers_nr.0)?;
                Ok(())
            }
            ControlPdu::ConnectionParamReq(data) | ControlPdu::ConnectionParamRsp(data) => {
                data.to_bytes(buffer)
            }
            ControlPdu::Unknown { ctr_data, .. } => {
                buffer.write_slice(ctr_data)?;
                Ok(())
            }
        }
    }
}

enum_with_unknown! {
    /// Enumeration of all known LL Control PDU opcodes (not all of which might be supported).
    #[derive(Debug, Copy, Clone, PartialEq, Eq, defmt::Format)]
    pub enum ControlOpcode(u8) {
        ConnectionUpdateReq = 0x00,
        ChannelMapReq = 0x01,
        TerminateInd = 0x02,
        EncReq = 0x03,
        EncRsp = 0x04,
        StartEncReq = 0x05,
        StartEncRsp = 0x06,
        UnknownRsp = 0x07,
        FeatureReq = 0x08,
        FeatureRsp = 0x09,
        PauseEncReq = 0x0A,
        PauseEncRsp = 0x0B,
        VersionInd = 0x0C,
        RejectInd = 0x0D,
        SlaveFeatureReq = 0x0E,
        ConnectionParamReq = 0x0F,
        ConnectionParamRsp = 0x10,
        RejectIndExt = 0x11,
        PingReq = 0x12,
        PingRsp = 0x13,
        LengthReq = 0x14,
        LengthRsp = 0x15,
    }
}

enum_with_unknown! {
    /// Enumeration of all possible `VersNr` for `LL_VERSION_IND` PDUs.
    ///
    /// According to <https://www.bluetooth.com/specifications/assigned-numbers/link-layer>.
    #[derive(Debug, Copy, Clone, PartialEq, Eq, defmt::Format)]
    pub enum VersionNumber(u8) {
        V4_0 = 6,
        V4_1 = 7,
        V4_2 = 8,
        V5_0 = 9,
        V5_1 = 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_req_set_conn_interval() {
        fn set(min: Duration, max: Duration) -> (Duration, Duration) {
            let mut req = ConnectionParamRequest::new();
            req.set_conn_interval(min, max);

            (req.min_conn_interval(), req.max_conn_interval())
        }

        fn same(min: Duration, max: Duration) {
            let (min2, max2) = set(min, max);
            assert_eq!(min2, min);
            assert_eq!(max2, max);
        }

        same(Duration::from_secs(1), Duration::from_secs(1));
        same(Duration::from_micros(7_500), Duration::from_micros(7_500));
        same(Duration::from_micros(7_500), Duration::from_secs(4));
        same(Duration::from_secs(4), Duration::from_secs(4));

        let (min, max) = set(Duration::from_secs(8), Duration::from_secs(8));
        assert_eq!(min, Duration::from_secs(4));
        assert_eq!(max, Duration::from_secs(4));

        let (min, max) = set(Duration::from_secs(0), Duration::from_secs(8));
        assert_eq!(min, Duration::from_micros(7_500));
        assert_eq!(max, Duration::from_secs(4));

        let (min, max) = set(Duration::from_micros(7_501), Duration::from_micros(7_502));
        assert_eq!(min, Duration::from_micros(7_500));
        assert_eq!(max, Duration::from_micros(7_500));
    }

    #[test]
    #[should_panic(expected = "min <= max")]
    fn update_req_set_conn_interval_minmax() {
        let mut req = ConnectionParamRequest::new();
        req.set_conn_interval(Duration::from_secs(8), Duration::from_secs(7));
    }
}
