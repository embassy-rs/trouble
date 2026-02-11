//! Core service (ID 0) protocol definitions.

use embedded_io_async::Write;

use super::Cursor;
use super::header::BtpHeader;
use crate::btp::error::Error;
use crate::btp::types::ServiceId;

/// Core service opcodes.
pub mod opcodes {
    use crate::btp::types::Opcode;

    pub const READ_SUPPORTED_COMMANDS: Opcode = Opcode(0x01);
    pub const READ_SUPPORTED_SERVICES: Opcode = Opcode(0x02);
    pub const REGISTER_SERVICE: Opcode = Opcode(0x03);
    pub const UNREGISTER_SERVICE: Opcode = Opcode(0x04);

    pub const EVENT_IUT_READY: Opcode = Opcode(0x80);
}

/// Supported commands bitmask for Core service.
pub const SUPPORTED_COMMANDS: [u8; 1] = super::supported_commands_bitmask(&[
    opcodes::READ_SUPPORTED_COMMANDS,
    opcodes::READ_SUPPORTED_SERVICES,
    opcodes::REGISTER_SERVICE,
    opcodes::UNREGISTER_SERVICE,
]);

/// Supported services bitmask.
/// Services: Core(0), GAP(1), GATT(2)
pub const SUPPORTED_SERVICES: [u8; 1] = [0x07];

/// Parsed Core service command.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CoreCommand {
    /// Read supported commands (0x01).
    ReadSupportedCommands,
    /// Read supported services (0x02).
    ReadSupportedServices,
    /// Register a service (0x03).
    RegisterService(#[allow(unused)] ServiceId),
    /// Unregister a service (0x04).
    UnregisterService(#[allow(unused)] ServiceId),
}

impl CoreCommand {
    /// Parse a Core command from header and cursor.
    pub fn parse(header: &BtpHeader, cursor: &mut Cursor<'_>) -> Result<Self, Error> {
        match header.opcode {
            opcodes::READ_SUPPORTED_COMMANDS => Ok(CoreCommand::ReadSupportedCommands),
            opcodes::READ_SUPPORTED_SERVICES => Ok(CoreCommand::ReadSupportedServices),
            opcodes::REGISTER_SERVICE => {
                let id = cursor.read_u8()?;
                Ok(CoreCommand::RegisterService(ServiceId(id)))
            }
            opcodes::UNREGISTER_SERVICE => {
                let id = cursor.read_u8()?;
                Ok(CoreCommand::UnregisterService(ServiceId(id)))
            }
            _ => Err(Error::UnknownCommand {
                service: ServiceId::CORE,
                opcode: header.opcode,
            }),
        }
    }
}

/// Core service response.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CoreResponse {
    /// Supported commands bitmask.
    SupportedCommands([u8; 1]),
    /// Supported services bitmask.
    SupportedServices([u8; 1]),
    /// Service registered (empty response).
    ServiceRegistered,
    /// Service unregistered (empty response).
    ServiceUnregistered,
}

impl CoreResponse {
    /// Get the data length for this response.
    pub fn data_len(&self) -> u16 {
        match self {
            CoreResponse::SupportedCommands(bitmask) => bitmask.len() as u16,
            CoreResponse::SupportedServices(bitmask) => bitmask.len() as u16,
            CoreResponse::ServiceRegistered => 0,
            CoreResponse::ServiceUnregistered => 0,
        }
    }

    /// Write the response data.
    pub async fn write<W: Write>(&self, mut writer: W) -> Result<(), W::Error> {
        match self {
            CoreResponse::SupportedCommands(bitmask) => writer.write_all(bitmask).await,
            CoreResponse::SupportedServices(bitmask) => writer.write_all(bitmask).await,
            CoreResponse::ServiceRegistered => Ok(()),
            CoreResponse::ServiceUnregistered => Ok(()),
        }
    }
}

/// Core service event.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CoreEvent {
    /// IUT Ready event (0x80).
    IutReady,
}

impl CoreEvent {
    /// Get the header for this event.
    pub fn header(&self) -> BtpHeader {
        match self {
            CoreEvent::IutReady => BtpHeader::event(ServiceId::CORE, opcodes::EVENT_IUT_READY, None, 0),
        }
    }

    /// Write the event data.
    pub async fn write<W: Write>(&self, _writer: W) -> Result<(), W::Error> {
        match self {
            CoreEvent::IutReady => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btp::types::Opcode;

    fn make_header(opcode: Opcode, data_len: u16) -> BtpHeader {
        BtpHeader::new(ServiceId::CORE, opcode, None, data_len)
    }

    #[test]
    fn test_read_supported_commands() {
        let data: &[u8] = &[];
        let header = make_header(opcodes::READ_SUPPORTED_COMMANDS, 0);
        let mut cursor = Cursor::new(data);
        let cmd = CoreCommand::parse(&header, &mut cursor).unwrap();
        assert!(matches!(cmd, CoreCommand::ReadSupportedCommands));
    }

    #[test]
    fn test_read_register_service() {
        let data: &[u8] = &[0x01];
        let header = make_header(opcodes::REGISTER_SERVICE, 1);
        let mut cursor = Cursor::new(data);
        let cmd = CoreCommand::parse(&header, &mut cursor).unwrap();
        if let CoreCommand::RegisterService(service_id) = cmd {
            assert_eq!(service_id, ServiceId::GAP);
        } else {
            panic!("Expected RegisterService");
        }
    }

    #[test]
    fn test_read_register_service_missing_data() {
        let data: &[u8] = &[];
        let header = make_header(opcodes::REGISTER_SERVICE, 1);
        let mut cursor = Cursor::new(data);
        let result = CoreCommand::parse(&header, &mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_iut_ready_header() {
        let evt = CoreEvent::IutReady;
        let header = evt.header();
        assert_eq!(header.service_id, ServiceId::CORE);
        assert_eq!(header.opcode, opcodes::EVENT_IUT_READY);
        assert_eq!(header.controller_index, None);
        assert_eq!(header.data_len, 0);
    }

    #[test]
    fn test_read_supported_services() {
        let data: &[u8] = &[];
        let header = make_header(opcodes::READ_SUPPORTED_SERVICES, 0);
        let mut cursor = Cursor::new(data);
        let cmd = CoreCommand::parse(&header, &mut cursor).unwrap();
        assert!(matches!(cmd, CoreCommand::ReadSupportedServices));
    }

    #[test]
    fn test_read_unregister_service() {
        let data: &[u8] = &[0x02];
        let header = make_header(opcodes::UNREGISTER_SERVICE, 1);
        let mut cursor = Cursor::new(data);
        let cmd = CoreCommand::parse(&header, &mut cursor).unwrap();
        if let CoreCommand::UnregisterService(service_id) = cmd {
            assert_eq!(service_id, ServiceId::GATT);
        } else {
            panic!("Expected UnregisterService");
        }
    }

    #[test]
    fn test_unregister_service_missing_data() {
        let data: &[u8] = &[];
        let header = make_header(opcodes::UNREGISTER_SERVICE, 1);
        let mut cursor = Cursor::new(data);
        let result = CoreCommand::parse(&header, &mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_opcode() {
        let data: &[u8] = &[];
        let header = make_header(Opcode(0x7F), 0);
        let mut cursor = Cursor::new(data);
        let result = CoreCommand::parse(&header, &mut cursor);
        assert!(matches!(
            result,
            Err(crate::btp::error::Error::UnknownCommand {
                service: ServiceId::CORE,
                ..
            })
        ));
    }

    #[test]
    fn test_supported_commands_response_roundtrip() {
        use futures_executor::block_on;
        let resp = CoreResponse::SupportedCommands(SUPPORTED_COMMANDS);
        assert_eq!(resp.data_len(), 1);
        let mut buf = [0u8; 4];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[0], SUPPORTED_COMMANDS[0]);
    }

    #[test]
    fn test_supported_services_response_roundtrip() {
        use futures_executor::block_on;
        let resp = CoreResponse::SupportedServices(SUPPORTED_SERVICES);
        assert_eq!(resp.data_len(), 1);
        let mut buf = [0u8; 4];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
        assert_eq!(buf[0], SUPPORTED_SERVICES[0]);
    }

    #[test]
    fn test_service_registered_response() {
        use futures_executor::block_on;
        let resp = CoreResponse::ServiceRegistered;
        assert_eq!(resp.data_len(), 0);
        let mut buf = [0u8; 4];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
    }

    #[test]
    fn test_service_unregistered_response() {
        use futures_executor::block_on;
        let resp = CoreResponse::ServiceUnregistered;
        assert_eq!(resp.data_len(), 0);
        let mut buf = [0u8; 4];
        block_on(resp.write(&mut buf.as_mut_slice())).unwrap();
    }

    #[test]
    fn test_iut_ready_event_write() {
        use futures_executor::block_on;
        let evt = CoreEvent::IutReady;
        let mut buf = [0u8; 4];
        block_on(evt.write(&mut buf.as_mut_slice())).unwrap();
        // IutReady has no data, so buf should be unchanged
    }
}
