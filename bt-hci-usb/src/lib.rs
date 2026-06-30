use std::convert::Infallible;
use std::io;
use std::pin::pin;
use std::time::Duration;

use bt_hci_driver::{self, PacketKind, PacketToController, PacketToHost, ReadHciError};
use embedded_io::ReadExactError;
use futures::future::Either;
use nusb::io::{EndpointRead, EndpointReadUntilShortPacket, EndpointWrite};
use nusb::transfer::{Bulk, BulkOrInterrupt, ControlOut, ControlType, Interrupt, Recipient};
use nusb::{Device, DeviceInfo, Interface};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

const USB_CLASS_WIRELESS: u8 = 0xE0;
const USB_SUBCLASS_BLUETOOTH: u8 = 0x01;
const USB_PROTOCOL_BLUETOOTH_HCI: u8 = 0x01;

const ENDPOINT_EVENT_IN: u8 = 0x81;
const ENDPOINT_ACL_IN: u8 = 0x82;
const ENDPOINT_ACL_OUT: u8 = 0x02;

#[derive(Debug)]
pub enum Error {
    FromHciBytesError(ReadHciError<Infallible>),
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

impl From<ReadHciError<io::Error>> for Error {
    fn from(e: ReadHciError<io::Error>) -> Self {
        match e {
            ReadHciError::BufferTooSmall => Error::FromHciBytesError(ReadHciError::BufferTooSmall),
            ReadHciError::InvalidValue => Error::FromHciBytesError(ReadHciError::InvalidValue),
            ReadHciError::Read(ReadExactError::UnexpectedEof) => {
                Error::FromHciBytesError(ReadHciError::Read(ReadExactError::UnexpectedEof))
            }
            ReadHciError::Read(ReadExactError::Other(io)) => Error::Io(io),
        }
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

struct UsbReader<'a, R>
where
    R: BulkOrInterrupt,
{
    reader: EndpointReadUntilShortPacket<'a, R>,
}

impl<R> embedded_io::ErrorType for UsbReader<'_, R>
where
    R: BulkOrInterrupt,
{
    type Error = io::Error;
}

impl<R> embedded_io_async::Read for UsbReader<'_, R>
where
    R: BulkOrInterrupt,
{
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        tokio::io::AsyncReadExt::read(&mut self.reader, buf).await
    }
}

impl<R> Drop for UsbReader<'_, R>
where
    R: BulkOrInterrupt,
{
    fn drop(&mut self) {
        self.reader.consume_end().unwrap();
    }
}

async fn read_packet<'a, P: PacketToHost<'a>, R>(
    kind: PacketKind,
    reader: &mut EndpointRead<R>,
    rx: &'a mut [u8],
) -> Result<P, Error>
where
    R: BulkOrInterrupt,
{
    let mut reader = UsbReader {
        reader: reader.until_short_packet(),
    };
    let packet = P::read_hci_async(kind, &mut reader, rx).await?;
    Ok(packet)
}

impl Transport {
    pub async fn new(dev: Device) -> Result<Self, nusb::Error> {
        // Ignore errors because this method fails on windows where the WinUSB driver does not
        // have permission to set the configuration for the device.
        // Setting the configuration appears to be required on MacOS though, so we still attempt it.
        let _ = dev.set_configuration(1).await;
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

impl bt_hci_driver::Transport for Transport {
    async fn read<'a, P: PacketToHost<'a>>(&self, rx: &'a mut [u8]) -> Result<P, Self::Error> {
        let mut in_endpoints = self.in_endpoints.lock().await;
        let InEndpoints {
            event_reader,
            acl_reader,
        } = &mut *in_endpoints;

        let event_ready = pin!(event_reader.fill_buf());
        let acl_ready = pin!(acl_reader.fill_buf());

        match futures::future::select(event_ready, acl_ready).await {
            Either::Left(_) => read_packet::<P, _>(PacketKind::Event, event_reader, rx).await,
            Either::Right(_) => read_packet::<P, _>(PacketKind::AclData, event_reader, rx).await,
        }
    }

    async fn write<P: PacketToController>(&self, val: &P) -> Result<(), Self::Error> {
        let mut buf = Vec::<u8>::new();
        val.write_hci(&mut buf).unwrap();
        match P::KIND {
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
