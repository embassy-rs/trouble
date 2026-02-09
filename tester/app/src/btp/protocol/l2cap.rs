//! L2CAP service (ID 3) protocol definitions.
#![allow(dead_code)]

use embedded_io_async::Write;

use super::Cursor;
use super::header::BtpHeader;
use crate::btp::error::Error;
use crate::btp::types::{Address, Opcode, ServiceId};

/// L2CAP service opcodes.
pub mod opcodes {
    use crate::btp::types::Opcode;

    // Commands
    pub const READ_SUPPORTED_COMMANDS: Opcode = Opcode(0x01);
    pub const CONNECT: Opcode = Opcode(0x02);
    pub const DISCONNECT: Opcode = Opcode(0x03);
    pub const SEND_DATA: Opcode = Opcode(0x04);
    pub const LISTEN: Opcode = Opcode(0x05);
    pub const ACCEPT_CONNECTION: Opcode = Opcode(0x06);
    pub const RECONFIGURE: Opcode = Opcode(0x07);
    pub const CREDITS: Opcode = Opcode(0x08);
    pub const DISCONNECT_EATT_CHANS: Opcode = Opcode(0x09);

    // Events
    pub const EVENT_CONNECTION_REQUEST: Opcode = Opcode(0x80);
    pub const EVENT_CONNECTED: Opcode = Opcode(0x81);
    pub const EVENT_DISCONNECTED: Opcode = Opcode(0x82);
    pub const EVENT_DATA_RECEIVED: Opcode = Opcode(0x83);
    pub const EVENT_RECONFIGURED: Opcode = Opcode(0x84);
}

/// Supported commands bitmask for L2CAP service.
pub const SUPPORTED_COMMANDS: [u8; 2] = super::supported_commands_bitmask(&[
    opcodes::READ_SUPPORTED_COMMANDS,
    opcodes::CONNECT,
    opcodes::DISCONNECT,
    opcodes::SEND_DATA,
    opcodes::LISTEN,
    opcodes::ACCEPT_CONNECTION,
    opcodes::RECONFIGURE,
    opcodes::CREDITS,
    opcodes::DISCONNECT_EATT_CHANS,
]);

/// L2CAP transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum Transport {
    /// BR/EDR transport.
    BrEdr = 0x00,
    /// LE transport.
    #[default]
    Le = 0x01,
}

impl TryFrom<u8> for Transport {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::BrEdr),
            0x01 => Ok(Self::Le),
            _ => Err(Error::InvalidPacket),
        }
    }
}

/// L2CAP connection options (v1).
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnectOptions(u8);

bitflags::bitflags! {
    impl ConnectOptions: u8 {
        /// Use Enhanced Credit-Based Flow Control (ECFC).
        const ECFC = 1 << 0;
        /// Hold at least 1 credit until Credits command is received.
        const HOLD_CREDIT = 1 << 1;
    }
}

/// L2CAP connection options (v2) - 4 bytes.
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnectOptionsV2(u32);

bitflags::bitflags! {
    impl ConnectOptionsV2: u32 {
        /// Use Enhanced Credit-Based Flow Control (ECFC).
        const ECFC = 1 << 0;
        /// Hold at least 1 credit until Credits command is received.
        const HOLD_CREDIT = 1 << 1;
        /// Mode is optional (BR/EDR only).
        const MODE_OPTIONAL = 1 << 2;
        /// Extended window size (BR/EDR only).
        const EXTENDED_WINDOW_SIZE = 1 << 3;
        /// No FCS (BR/EDR only).
        const NO_FCS = 1 << 4;
    }
}

/// L2CAP channel mode (for v2 commands).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum ChannelMode {
    /// Basic mode or None.
    #[default]
    Basic = 0x00,
    /// Retransmission mode (BR/EDR only).
    Retransmission = 0x01,
    /// Flow-control mode (BR/EDR only).
    FlowControl = 0x02,
    /// Enhanced retransmission mode (BR/EDR only).
    EnhancedRetransmission = 0x03,
    /// Stream mode (BR/EDR only).
    Stream = 0x04,
}

impl TryFrom<u8> for ChannelMode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Basic),
            0x01 => Ok(Self::Retransmission),
            0x02 => Ok(Self::FlowControl),
            0x03 => Ok(Self::EnhancedRetransmission),
            0x04 => Ok(Self::Stream),
            _ => Err(Error::InvalidPacket),
        }
    }
}

/// L2CAP listen security response values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u16)]
pub enum ListenResponse {
    /// Success - accept connection.
    #[default]
    Success = 0x0000,
    /// Insufficient authentication.
    InsufficientAuthentication = 0x0001,
    /// Insufficient authorization.
    InsufficientAuthorization = 0x0002,
    /// Insufficient encryption key size.
    InsufficientEncryptionKeySize = 0x0003,
    /// Insufficient encryption.
    InsufficientEncryption = 0x0004,
    /// Insufficient secure authentication.
    InsufficientSecureAuthentication = 0x0005,
}

impl TryFrom<u16> for ListenResponse {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(Self::Success),
            0x0001 => Ok(Self::InsufficientAuthentication),
            0x0002 => Ok(Self::InsufficientAuthorization),
            0x0003 => Ok(Self::InsufficientEncryptionKeySize),
            0x0004 => Ok(Self::InsufficientEncryption),
            0x0005 => Ok(Self::InsufficientSecureAuthentication),
            _ => Err(Error::InvalidPacket),
        }
    }
}

/// Maximum number of L2CAP channels that can be created at once.
pub const MAX_CHANNELS: usize = 5;

/// Maximum data size for L2CAP data transfers.
pub const MAX_DATA_SIZE: usize = 512;

// --- L2capCommand structs ---

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnectCommand {
    pub address: Address,
    pub psm: u16,
    pub mtu: u16,
    pub num: u8,
    pub options: ConnectOptions,
}

#[derive(Debug, Clone)]
pub struct SendDataCommand<'a> {
    pub chan_id: u8,
    pub data: &'a [u8],
}

#[cfg(feature = "defmt")]
impl defmt::Format for SendDataCommand<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "SendDataCommand {{ chan_id: {=u8}, data_len: {=usize} }}",
            self.chan_id,
            self.data.len()
        )
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ListenCommand {
    pub psm: u16,
    pub transport: Transport,
    pub mtu: u16,
    pub security_type: u8,
    pub key_size: u8,
    pub response: ListenResponse,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AcceptConnectionCommand {
    pub chan_id: u8,
    pub result: u16,
}

#[derive(Debug, Clone)]
pub struct ReconfigureCommand<'a> {
    pub address: Address,
    pub mtu: u16,
    pub channels: &'a [u8],
}

#[cfg(feature = "defmt")]
impl defmt::Format for ReconfigureCommand<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "ReconfigureCommand {{ address: {}, mtu: {=u16}, channels_len: {=usize} }}",
            self.address,
            self.mtu,
            self.channels.len()
        )
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DisconnectEattChansCommand {
    pub address: Address,
    pub count: u8,
}

/// Parsed L2CAP command.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum L2capCommand<'a> {
    /// Read supported commands (0x01).
    ReadSupportedCommands,

    /// Connect command (0x02).
    Connect(ConnectCommand),

    /// Disconnect command (0x03).
    Disconnect(u8),

    /// Send data command (0x04).
    SendData(SendDataCommand<'a>),

    /// Listen command (0x05).
    Listen(ListenCommand),

    /// Accept connection request (0x06).
    AcceptConnection(AcceptConnectionCommand),

    /// Reconfigure command (0x07).
    Reconfigure(ReconfigureCommand<'a>),

    /// Credits command (0x08).
    Credits(u8),

    /// Disconnect EATT channels (0x09).
    DisconnectEattChans(DisconnectEattChansCommand),
}

impl<'a> L2capCommand<'a> {
    /// Parse an L2CAP command from header and cursor.
    pub fn parse(header: &BtpHeader, cursor: &mut Cursor<'a>) -> Result<Self, Error> {
        // ReadSupportedCommands doesn't require controller index
        if header.opcode == opcodes::READ_SUPPORTED_COMMANDS {
            return Ok(L2capCommand::ReadSupportedCommands);
        }

        // All other commands require controller index 0
        match header.controller_index {
            Some(0) => {}
            Some(_) => return Err(Error::InvalidIndex),
            None => return Err(Error::InvalidIndex),
        }

        match header.opcode {
            opcodes::CONNECT => {
                let address = cursor.read_address()?;
                let psm = cursor.read_u16_le()?;
                let mtu = cursor.read_u16_le()?;
                let num = cursor.read_u8()?;
                let options = ConnectOptions::from_bits_truncate(cursor.read_u8()?);
                Ok(L2capCommand::Connect(ConnectCommand {
                    address,
                    psm,
                    mtu,
                    num,
                    options,
                }))
            }
            opcodes::DISCONNECT => {
                let chan_id = cursor.read_u8()?;
                Ok(L2capCommand::Disconnect(chan_id))
            }
            opcodes::SEND_DATA => {
                let chan_id = cursor.read_u8()?;
                let data_len = cursor.read_u16_le()? as usize;
                let data = cursor.read_exact(data_len)?;
                Ok(L2capCommand::SendData(SendDataCommand { chan_id, data }))
            }
            opcodes::LISTEN => {
                let psm = cursor.read_u16_le()?;
                let transport = Transport::try_from(cursor.read_u8()?)?;
                let mtu = cursor.read_u16_le()?;
                let security_type = cursor.read_u8()?;
                let key_size = cursor.read_u8()?;
                let response = ListenResponse::try_from(cursor.read_u16_le()?)?;
                Ok(L2capCommand::Listen(ListenCommand {
                    psm,
                    transport,
                    mtu,
                    security_type,
                    key_size,
                    response,
                }))
            }
            opcodes::ACCEPT_CONNECTION => {
                let chan_id = cursor.read_u8()?;
                let result = cursor.read_u16_le()?;
                Ok(L2capCommand::AcceptConnection(AcceptConnectionCommand {
                    chan_id,
                    result,
                }))
            }
            opcodes::RECONFIGURE => {
                let address = cursor.read_address()?;
                let mtu = cursor.read_u16_le()?;
                let num = cursor.read_u8()? as usize;
                let channels = cursor.read_exact(num)?;
                Ok(L2capCommand::Reconfigure(ReconfigureCommand { address, mtu, channels }))
            }
            opcodes::CREDITS => {
                let chan_id = cursor.read_u8()?;
                Ok(L2capCommand::Credits(chan_id))
            }
            opcodes::DISCONNECT_EATT_CHANS => {
                let address = cursor.read_address()?;
                let count = cursor.read_u8()?;
                Ok(L2capCommand::DisconnectEattChans(DisconnectEattChansCommand {
                    address,
                    count,
                }))
            }
            _ => Err(Error::UnknownCommand {
                service: ServiceId::L2CAP,
                opcode: header.opcode,
            }),
        }
    }

    /// Get the opcode for this command.
    pub fn opcode(&self) -> Opcode {
        match self {
            L2capCommand::ReadSupportedCommands => opcodes::READ_SUPPORTED_COMMANDS,
            L2capCommand::Connect(..) => opcodes::CONNECT,
            L2capCommand::Disconnect(..) => opcodes::DISCONNECT,
            L2capCommand::SendData(..) => opcodes::SEND_DATA,
            L2capCommand::Listen(..) => opcodes::LISTEN,
            L2capCommand::AcceptConnection(..) => opcodes::ACCEPT_CONNECTION,
            L2capCommand::Reconfigure(..) => opcodes::RECONFIGURE,
            L2capCommand::Credits(..) => opcodes::CREDITS,
            L2capCommand::DisconnectEattChans(..) => opcodes::DISCONNECT_EATT_CHANS,
        }
    }
}

// --- L2capResponse structs ---

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnectedResponse {
    pub num: u8,
    pub chan_ids: heapless::Vec<u8, MAX_CHANNELS>,
}

/// L2CAP service response.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum L2capResponse {
    /// Supported commands bitmask (response to 0x01).
    SupportedCommands([u8; 2]),

    /// Connect response (response to 0x02, 0x0b).
    Connected(ConnectedResponse),

    /// Empty response for commands that only indicate success.
    Empty,
}

impl L2capResponse {
    /// Get the data length for this response.
    pub fn data_len(&self) -> u16 {
        match self {
            L2capResponse::SupportedCommands(bitmask) => bitmask.len() as u16,
            L2capResponse::Connected(rsp) => 1 + rsp.chan_ids.len() as u16,
            L2capResponse::Empty => 0,
        }
    }

    /// Write the response data.
    pub async fn write<W: Write>(&self, mut writer: W) -> Result<(), W::Error> {
        match self {
            L2capResponse::SupportedCommands(bitmask) => writer.write_all(bitmask).await,
            L2capResponse::Connected(rsp) => {
                writer.write_all(&[rsp.num]).await?;
                writer.write_all(&rsp.chan_ids).await
            }
            L2capResponse::Empty => Ok(()),
        }
    }
}

// --- L2capEvent structs ---

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnectionRequestEvent {
    pub chan_id: u8,
    pub psm: u16,
    pub address: Address,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnectedEvent {
    pub chan_id: u8,
    pub psm: u16,
    pub peer_mtu: u16,
    pub peer_mps: u16,
    pub our_mtu: u16,
    pub our_mps: u16,
    pub address: Address,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DisconnectedEvent {
    pub result: u16,
    pub chan_id: u8,
    pub psm: u16,
    pub address: Address,
}

#[derive(Debug, Clone)]
pub struct DataReceivedEvent<'a> {
    pub chan_id: u8,
    pub data: &'a [u8],
}

#[cfg(feature = "defmt")]
impl defmt::Format for DataReceivedEvent<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "DataReceivedEvent {{ chan_id: {=u8}, data_len: {=usize} }}",
            self.chan_id,
            self.data.len()
        )
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReconfiguredEvent {
    pub chan_id: u8,
    pub peer_mtu: u16,
    pub peer_mps: u16,
    pub our_mtu: u16,
    pub our_mps: u16,
}

/// L2CAP service event.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum L2capEvent<'a> {
    /// Connection request event (0x80).
    ConnectionRequest(ConnectionRequestEvent),

    /// Connected event (0x81).
    Connected(ConnectedEvent),

    /// Disconnected event (0x82).
    Disconnected(DisconnectedEvent),

    /// Data received event (0x83).
    DataReceived(DataReceivedEvent<'a>),

    /// Reconfigured event (0x84).
    Reconfigured(ReconfiguredEvent),
}

impl L2capEvent<'_> {
    /// Get the header for this event.
    pub fn header(&self) -> BtpHeader {
        let (opcode, data_len) = match self {
            L2capEvent::ConnectionRequest(..) => (opcodes::EVENT_CONNECTION_REQUEST, 10),
            L2capEvent::Connected(..) => (opcodes::EVENT_CONNECTED, 18),
            L2capEvent::Disconnected(..) => (opcodes::EVENT_DISCONNECTED, 12),
            L2capEvent::DataReceived(evt) => (opcodes::EVENT_DATA_RECEIVED, 3 + evt.data.len() as u16),
            L2capEvent::Reconfigured(..) => (opcodes::EVENT_RECONFIGURED, 9),
        };
        BtpHeader::event(ServiceId::L2CAP, opcode, Some(0), data_len)
    }

    /// Write the event data.
    pub async fn write<W: Write>(&self, mut writer: W) -> Result<(), W::Error> {
        match self {
            L2capEvent::ConnectionRequest(evt) => {
                writer.write_all(&[evt.chan_id]).await?;
                writer.write_all(&evt.psm.to_le_bytes()).await?;
                writer.write_all(&[evt.address.kind.as_raw()]).await?;
                writer.write_all(evt.address.addr.raw()).await
            }
            L2capEvent::Connected(evt) => {
                writer.write_all(&[evt.chan_id]).await?;
                writer.write_all(&evt.psm.to_le_bytes()).await?;
                writer.write_all(&evt.peer_mtu.to_le_bytes()).await?;
                writer.write_all(&evt.peer_mps.to_le_bytes()).await?;
                writer.write_all(&evt.our_mtu.to_le_bytes()).await?;
                writer.write_all(&evt.our_mps.to_le_bytes()).await?;
                writer.write_all(&[evt.address.kind.as_raw()]).await?;
                writer.write_all(evt.address.addr.raw()).await
            }
            L2capEvent::Disconnected(evt) => {
                writer.write_all(&evt.result.to_le_bytes()).await?;
                writer.write_all(&[evt.chan_id]).await?;
                writer.write_all(&evt.psm.to_le_bytes()).await?;
                writer.write_all(&[evt.address.kind.as_raw()]).await?;
                writer.write_all(evt.address.addr.raw()).await
            }
            L2capEvent::DataReceived(evt) => {
                writer.write_all(&[evt.chan_id]).await?;
                writer.write_all(&(evt.data.len() as u16).to_le_bytes()).await?;
                writer.write_all(evt.data).await
            }
            L2capEvent::Reconfigured(evt) => {
                writer.write_all(&[evt.chan_id]).await?;
                writer.write_all(&evt.peer_mtu.to_le_bytes()).await?;
                writer.write_all(&evt.peer_mps.to_le_bytes()).await?;
                writer.write_all(&evt.our_mtu.to_le_bytes()).await?;
                writer.write_all(&evt.our_mps.to_le_bytes()).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btp::types::{AddrKind, BdAddr};

    fn make_header(opcode: Opcode, controller_index: Option<u8>) -> BtpHeader {
        BtpHeader::new(ServiceId::L2CAP, opcode, controller_index, 0)
    }

    #[test]
    fn test_transport_try_from() {
        assert_eq!(Transport::try_from(0x00).unwrap(), Transport::BrEdr);
        assert_eq!(Transport::try_from(0x01).unwrap(), Transport::Le);
        assert!(Transport::try_from(0x02).is_err());
    }

    #[test]
    fn test_channel_mode_try_from() {
        assert_eq!(ChannelMode::try_from(0x00).unwrap(), ChannelMode::Basic);
        assert_eq!(ChannelMode::try_from(0x01).unwrap(), ChannelMode::Retransmission);
        assert_eq!(ChannelMode::try_from(0x02).unwrap(), ChannelMode::FlowControl);
        assert_eq!(
            ChannelMode::try_from(0x03).unwrap(),
            ChannelMode::EnhancedRetransmission
        );
        assert_eq!(ChannelMode::try_from(0x04).unwrap(), ChannelMode::Stream);
        assert!(ChannelMode::try_from(0x05).is_err());
    }

    #[test]
    fn test_listen_response_try_from() {
        assert_eq!(ListenResponse::try_from(0x0000).unwrap(), ListenResponse::Success);
        assert_eq!(
            ListenResponse::try_from(0x0001).unwrap(),
            ListenResponse::InsufficientAuthentication
        );
        assert_eq!(
            ListenResponse::try_from(0x0005).unwrap(),
            ListenResponse::InsufficientSecureAuthentication
        );
        assert!(ListenResponse::try_from(0x0006).is_err());
    }

    #[test]
    fn test_connect_options() {
        let opts = ConnectOptions::ECFC | ConnectOptions::HOLD_CREDIT;
        assert!(opts.contains(ConnectOptions::ECFC));
        assert!(opts.contains(ConnectOptions::HOLD_CREDIT));
    }

    #[test]
    fn test_connect_options_v2() {
        let opts = ConnectOptionsV2::ECFC | ConnectOptionsV2::MODE_OPTIONAL | ConnectOptionsV2::NO_FCS;
        assert!(opts.contains(ConnectOptionsV2::ECFC));
        assert!(!opts.contains(ConnectOptionsV2::HOLD_CREDIT));
        assert!(opts.contains(ConnectOptionsV2::MODE_OPTIONAL));
        assert!(!opts.contains(ConnectOptionsV2::EXTENDED_WINDOW_SIZE));
        assert!(opts.contains(ConnectOptionsV2::NO_FCS));
    }

    #[test]
    fn test_read_supported_commands() {
        let data: &[u8] = &[];
        let header = make_header(opcodes::READ_SUPPORTED_COMMANDS, None);
        let mut cursor = Cursor::new(data);
        let cmd = L2capCommand::parse(&header, &mut cursor).unwrap();
        assert!(matches!(cmd, L2capCommand::ReadSupportedCommands));
    }

    #[test]
    fn test_read_connect() {
        // addr_type=1, addr=[1,2,3,4,5,6], psm=0x0025, mtu=256, num=1, options=0x01
        let data: &[u8] = &[
            0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x25, 0x00, 0x00, 0x01, 0x01, 0x01,
        ];
        let header = make_header(opcodes::CONNECT, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = L2capCommand::parse(&header, &mut cursor).unwrap();
        if let L2capCommand::Connect(ConnectCommand {
            address,
            psm,
            mtu,
            num,
            options,
        }) = cmd
        {
            assert_eq!(address.kind, AddrKind::RANDOM);
            assert_eq!(address.addr.raw(), &[1, 2, 3, 4, 5, 6]);
            assert_eq!(psm, 0x0025);
            assert_eq!(mtu, 256);
            assert_eq!(num, 1);
            assert!(options.contains(ConnectOptions::ECFC));
        } else {
            panic!("Expected Connect");
        }
    }

    #[test]
    fn test_read_disconnect() {
        let data: &[u8] = &[0x01];
        let header = make_header(opcodes::DISCONNECT, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = L2capCommand::parse(&header, &mut cursor).unwrap();
        if let L2capCommand::Disconnect(chan_id) = cmd {
            assert_eq!(chan_id, 1);
        } else {
            panic!("Expected Disconnect");
        }
    }

    #[test]
    fn test_read_send_data() {
        // chan_id=1, data_len=3, data=[0xAA,0xBB,0xCC]
        let data: &[u8] = &[0x01, 0x03, 0x00, 0xAA, 0xBB, 0xCC];
        let header = make_header(opcodes::SEND_DATA, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = L2capCommand::parse(&header, &mut cursor).unwrap();
        if let L2capCommand::SendData(cmd) = cmd {
            assert_eq!(cmd.chan_id, 1);
            assert_eq!(cmd.data, &[0xAA, 0xBB, 0xCC]);
        } else {
            panic!("Expected SendData");
        }
    }

    #[test]
    fn test_read_listen() {
        // psm=0x0025, transport=1 (LE), mtu=256, security_type=0, key_size=16, response=0
        let data: &[u8] = &[0x25, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00];
        let header = make_header(opcodes::LISTEN, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = L2capCommand::parse(&header, &mut cursor).unwrap();
        if let L2capCommand::Listen(ListenCommand {
            psm,
            transport,
            mtu,
            security_type,
            key_size,
            response,
        }) = cmd
        {
            assert_eq!(psm, 0x0025);
            assert_eq!(transport, Transport::Le);
            assert_eq!(mtu, 256);
            assert_eq!(security_type, 0);
            assert_eq!(key_size, 16);
            assert_eq!(response, ListenResponse::Success);
        } else {
            panic!("Expected Listen");
        }
    }

    #[test]
    fn test_read_accept_connection() {
        // chan_id=1, result=0
        let data: &[u8] = &[0x01, 0x00, 0x00];
        let header = make_header(opcodes::ACCEPT_CONNECTION, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = L2capCommand::parse(&header, &mut cursor).unwrap();
        if let L2capCommand::AcceptConnection(cmd) = cmd {
            assert_eq!(cmd.chan_id, 1);
            assert_eq!(cmd.result, 0);
        } else {
            panic!("Expected AcceptConnection");
        }
    }

    #[test]
    fn test_read_reconfigure() {
        // addr_type=0, addr=[1,2,3,4,5,6], mtu=512, num=2, channels=[1,2]
        let data: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x02, 0x02, 0x01, 0x02];
        let header = make_header(opcodes::RECONFIGURE, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = L2capCommand::parse(&header, &mut cursor).unwrap();
        if let L2capCommand::Reconfigure(ReconfigureCommand { address, mtu, channels }) = cmd {
            assert_eq!(address.kind, AddrKind::PUBLIC);
            assert_eq!(address.addr.raw(), &[1, 2, 3, 4, 5, 6]);
            assert_eq!(mtu, 512);
            assert_eq!(channels, &[1, 2]);
        } else {
            panic!("Expected Reconfigure");
        }
    }

    #[test]
    fn test_read_credits() {
        let data: &[u8] = &[0x03];
        let header = make_header(opcodes::CREDITS, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = L2capCommand::parse(&header, &mut cursor).unwrap();
        if let L2capCommand::Credits(chan_id) = cmd {
            assert_eq!(chan_id, 3);
        } else {
            panic!("Expected Credits");
        }
    }

    #[test]
    fn test_read_disconnect_eatt_chans() {
        // addr_type=0, addr=[1,2,3,4,5,6], count=2
        let data: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x02];
        let header = make_header(opcodes::DISCONNECT_EATT_CHANS, Some(0));
        let mut cursor = Cursor::new(data);
        let cmd = L2capCommand::parse(&header, &mut cursor).unwrap();
        if let L2capCommand::DisconnectEattChans(cmd) = cmd {
            assert_eq!(cmd.address.kind, AddrKind::PUBLIC);
            assert_eq!(cmd.address.addr.raw(), &[1, 2, 3, 4, 5, 6]);
            assert_eq!(cmd.count, 2);
        } else {
            panic!("Expected DisconnectEattChans");
        }
    }

    #[test]
    fn test_command_opcode() {
        assert_eq!(
            L2capCommand::ReadSupportedCommands.opcode(),
            opcodes::READ_SUPPORTED_COMMANDS
        );
        assert_eq!(L2capCommand::Disconnect(1).opcode(), opcodes::DISCONNECT);
        assert_eq!(L2capCommand::Credits(1).opcode(), opcodes::CREDITS);
    }

    #[test]
    fn test_write_supported_commands_response() {
        use futures_executor::block_on;
        let resp = L2capResponse::SupportedCommands([0xFE, 0x01]);
        assert_eq!(resp.data_len(), 2);
        let mut buf = [0u8; 16];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(&buf[..2], &[0xFE, 0x01]);
    }

    #[test]
    fn test_write_connected_response() {
        use futures_executor::block_on;
        let mut chan_ids = heapless::Vec::new();
        chan_ids.push(1).unwrap();
        chan_ids.push(2).unwrap();
        let resp = L2capResponse::Connected(ConnectedResponse { num: 2, chan_ids });
        assert_eq!(resp.data_len(), 3);
        let mut buf = [0u8; 16];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(&buf[..3], &[0x02, 0x01, 0x02]);
    }

    #[test]
    fn test_connection_request_event_header() {
        let evt = L2capEvent::ConnectionRequest(ConnectionRequestEvent {
            chan_id: 1,
            psm: 0x0025,
            address: Address {
                kind: AddrKind::PUBLIC,
                addr: BdAddr::default(),
            },
        });
        let header = evt.header();
        assert_eq!(header.service_id, ServiceId::L2CAP);
        assert_eq!(header.opcode, opcodes::EVENT_CONNECTION_REQUEST);
        assert_eq!(header.data_len, 10);
    }

    #[test]
    fn test_connected_event_header() {
        let evt = L2capEvent::Connected(ConnectedEvent {
            chan_id: 1,
            psm: 0x0025,
            peer_mtu: 256,
            peer_mps: 64,
            our_mtu: 256,
            our_mps: 64,
            address: Address {
                kind: AddrKind::PUBLIC,
                addr: BdAddr::default(),
            },
        });
        let header = evt.header();
        assert_eq!(header.data_len, 18);
    }

    #[test]
    fn test_write_connection_request_event() {
        use futures_executor::block_on;
        let evt = L2capEvent::ConnectionRequest(ConnectionRequestEvent {
            chan_id: 1,
            psm: 0x0025,
            address: Address {
                kind: AddrKind::RANDOM,
                addr: BdAddr::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            },
        });
        let mut buf = [0u8; 16];
        block_on(evt.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[0], 1); // chan_id
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 0x0025); // psm
        assert_eq!(buf[3], 0x01); // addr_type (RANDOM)
        assert_eq!(&buf[4..10], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // address
    }

    #[test]
    fn test_write_data_received_event() {
        use futures_executor::block_on;
        let evt = L2capEvent::DataReceived(DataReceivedEvent {
            chan_id: 5,
            data: &[0x01, 0x02, 0x03],
        });
        let header = evt.header();
        assert_eq!(header.data_len, 6); // 1 + 2 + 3
        let mut buf = [0u8; 16];
        block_on(evt.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[0], 5); // chan_id
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 3); // data_len
        assert_eq!(&buf[3..6], &[0x01, 0x02, 0x03]); // data
    }

    #[test]
    fn test_write_reconfigured_event() {
        use futures_executor::block_on;
        let evt = L2capEvent::Reconfigured(ReconfiguredEvent {
            chan_id: 1,
            peer_mtu: 512,
            peer_mps: 128,
            our_mtu: 256,
            our_mps: 64,
        });
        let header = evt.header();
        assert_eq!(header.data_len, 9);
        let mut buf = [0u8; 16];
        block_on(evt.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[0], 1); // chan_id
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 512); // peer_mtu
        assert_eq!(u16::from_le_bytes([buf[3], buf[4]]), 128); // peer_mps
        assert_eq!(u16::from_le_bytes([buf[5], buf[6]]), 256); // our_mtu
        assert_eq!(u16::from_le_bytes([buf[7], buf[8]]), 64); // our_mps
    }

    #[test]
    fn test_invalid_controller_index() {
        let data: &[u8] = &[0x01];
        let header = make_header(opcodes::DISCONNECT, Some(1));
        let mut cursor = Cursor::new(data);
        let result = L2capCommand::parse(&header, &mut cursor);
        assert!(matches!(result, Err(Error::InvalidIndex)));

        let header = make_header(opcodes::DISCONNECT, None);
        let mut cursor = Cursor::new(data);
        let result = L2capCommand::parse(&header, &mut cursor);
        assert!(matches!(result, Err(Error::InvalidIndex)));
    }

    #[test]
    fn test_unknown_command() {
        let data: &[u8] = &[];
        let header = make_header(Opcode(0x0a), Some(0));
        let mut cursor = Cursor::new(data);
        let result = L2capCommand::parse(&header, &mut cursor);
        assert!(matches!(
            result,
            Err(Error::UnknownCommand {
                service: ServiceId::L2CAP,
                opcode: Opcode(0x0a)
            })
        ));
    }
}
