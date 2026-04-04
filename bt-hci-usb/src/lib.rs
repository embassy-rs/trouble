use std::io;
use std::pin::pin;
use std::time::Duration;

use bt_hci::data::AclPacket;
use bt_hci::event::EventPacket;
use bt_hci::{ControllerToHostPacket, FromHciBytes, HostToControllerPacket, PacketKind};
use futures::future::Either;
use nusb::io::{EndpointRead, EndpointWrite};
use nusb::transfer::{Bulk, BulkOrInterrupt, ControlOut, ControlType, Interrupt, Recipient};
use nusb::{Device, DeviceInfo, Interface};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

const USB_CLASS_WIRELESS: u8 = 0xE0;
const USB_SUBCLASS_BLUETOOTH: u8 = 0x01;
const USB_PROTOCOL_BLUETOOTH_HCI: u8 = 0x01;

const ENDPOINT_EVENT_IN: u8 = 0x81;
const ENDPOINT_ACL_IN: u8 = 0x82;
const ENDPOINT_ACL_OUT: u8 = 0x02;

#[derive(Debug)]
pub enum Error {
    FromHciBytesError(bt_hci::FromHciBytesError),
    UsbTransfer(nusb::transfer::TransferError),
    Io(io::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FromHciBytesError(_) => write!(f, "failed to parse HCI bytes"),
            Self::UsbTransfer(e) => write!(f, "USB transfer: {e}"),
            Self::Io(e) => write!(f, "I/O: {e}"),
        }
    }
}

impl core::error::Error for Error {}

impl embedded_io::Error for Error {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

impl From<bt_hci::FromHciBytesError> for Error {
    fn from(e: bt_hci::FromHciBytesError) -> Self {
        Self::FromHciBytesError(e)
    }
}

pub struct Transport {
    interface: Interface,
    in_endpoints: Mutex<InEndpoints>,
    acl_writer: Mutex<EndpointWrite<Bulk>>,
}

struct InEndpoints {
    event_reader: EndpointRead<Interrupt>,
    acl_reader: EndpointRead<Bulk>,
}

async fn read_packet<R>(reader: &mut EndpointRead<R>, rx: &mut [u8]) -> Result<(), Error>
where
    R: BulkOrInterrupt,
{
    let mut reader = reader.until_short_packet();
    match reader.read_exact(rx).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            // Short packet, so we have the full data.
        }
        Err(_) => {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small",
            )));
        }
    }
    reader.consume_end().unwrap();
    Ok(())
}

impl Transport {
    pub async fn new(dev: Device) -> Result<Self, nusb::Error> {
        dev.set_configuration(1).await?;
        let interface = dev.detach_and_claim_interface(0).await?;
        let event_in = interface.endpoint(ENDPOINT_EVENT_IN)?;
        let acl_in = interface.endpoint(ENDPOINT_ACL_IN)?;
        let acl_out = interface.endpoint(ENDPOINT_ACL_OUT)?;

        // Suggested max packet size is 16 for interrupt in and 512 bytes for high speed bulk.
        let event_reader = event_in.reader(16);
        let acl_reader = acl_in.reader(512);
        let acl_writer = acl_out.writer(512);

        Ok(Self {
            interface,
            in_endpoints: Mutex::new(InEndpoints {
                event_reader,
                acl_reader,
            }),
            acl_writer: Mutex::new(acl_writer),
        })
    }
}

impl bt_hci::transport::Transport for Transport {
    async fn read<'a>(&self, rx: &'a mut [u8]) -> Result<ControllerToHostPacket<'a>, Self::Error> {
        let mut in_endpoints = self.in_endpoints.lock().await;
        let InEndpoints {
            event_reader,
            acl_reader,
        } = &mut *in_endpoints;

        let event_ready = pin!(event_reader.fill_buf());
        let acl_ready = pin!(acl_reader.fill_buf());

        let packet = match futures::future::select(event_ready, acl_ready).await {
            Either::Left(_) => {
                read_packet(event_reader, rx).await?;
                let (packet, _) = EventPacket::from_hci_bytes(rx).map_err(Error::FromHciBytesError)?;
                ControllerToHostPacket::Event(packet)
            }
            Either::Right(_) => {
                read_packet(acl_reader, rx).await?;
                let (packet, _) = AclPacket::from_hci_bytes(rx).map_err(Error::FromHciBytesError)?;
                ControllerToHostPacket::Acl(packet)
            }
        };

        Ok(packet)
    }

    async fn write<T: HostToControllerPacket>(&self, val: &T) -> Result<(), Self::Error> {
        let mut buf = Vec::<u8>::new();
        val.write_hci(&mut buf).unwrap();
        match T::KIND {
            PacketKind::Cmd => {
                let data = ControlOut {
                    control_type: ControlType::Class,
                    recipient: Recipient::Device,
                    request: 0x00,
                    value: 0x00,
                    index: 0x00,
                    data: &buf,
                };
                self.interface
                    .control_out(data, Duration::from_secs(5))
                    .await
                    .map_err(Error::UsbTransfer)?;
            }
            PacketKind::AclData => {
                let mut acl_writer = self.acl_writer.lock().await;
                acl_writer.write_all(&buf).await.map_err(Error::Io)?;
                acl_writer.submit_end();
            }
            _ => {
                todo!();
            }
        }

        Ok(())
    }
}

impl embedded_io::ErrorType for Transport {
    type Error = Error;
}

pub async fn list_devices() -> Result<impl Iterator<Item = DeviceInfo>, nusb::Error> {
    Ok(nusb::list_devices().await?.filter(|d| {
        d.class() == USB_CLASS_WIRELESS
            && d.subclass() == USB_SUBCLASS_BLUETOOTH
            && d.protocol() == USB_PROTOCOL_BLUETOOTH_HCI
    }))
}
