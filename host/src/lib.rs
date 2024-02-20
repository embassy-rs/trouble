#![no_std]
#![allow(async_fn_in_trait)]

use core::cell::RefCell;
use core::task::{Context, Poll};

use acl::AclPacket;
use ad_structure::AdvertisementDataError;
use adapter::{AdapterEvent, BleAdapter, BleConnection, HciMessage};
use command::{
    opcode, Command, INFORMATIONAL_OGF, LONG_TERM_KEY_REQUEST_REPLY_OCF, READ_BD_ADDR_OCF, SET_ADVERTISE_ENABLE_OCF,
    SET_ADVERTISING_DATA_OCF, SET_EVENT_MASK_OCF,
};
use command::{LE_OGF, SET_ADVERTISING_PARAMETERS_OCF};
use driver::HciDriver;
use driver::HciMessageType;
use event::EventType;

mod fmt;

pub mod acl;
pub mod adapter;
pub mod att;
pub mod driver;
pub mod l2cap;
mod portal;

pub mod command;
pub mod event;

pub mod ad_structure;

pub mod attribute;
pub mod attribute_server;

#[cfg(feature = "crypto")]
pub mod crypto;
#[cfg(feature = "crypto")]
pub mod sm;

use command::CONTROLLER_OGF;
use command::RESET_OCF;

const TIMEOUT_MILLIS: u64 = 1000;

#[derive(Debug)]
pub enum Error<E> {
    Timeout,
    Advertisement(AdvertisementDataError),
    Failed(u8),
    Driver(E),
    Encode,
    Decode,
}

#[cfg(feature = "defmt")]
impl<E> defmt::Format for Error<E>
where
    E: defmt::Format,
{
    fn format(&self, fmt: defmt::Formatter) {
        match self {
            Error::Encode => {
                defmt::write!(fmt, "Encode")
            }
            Error::Decode => {
                defmt::write!(fmt, "Decode")
            }
            Error::Timeout => {
                defmt::write!(fmt, "Timeout")
            }
            Error::Failed(value) => {
                defmt::write!(fmt, "Failed({})", value)
            }
            Error::Driver(value) => {
                defmt::write!(fmt, "Driver({})", value)
            }
        }
    }
}

/// 56-bit device address in big-endian byte order used by [`DHKey::f5`] and
/// [`MacKey::f6`] functions ([Vol 3] Part H, Section 2.2.7 and 2.2.8).
#[derive(Clone, Copy, Debug)]
#[must_use]
#[repr(transparent)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Addr(pub [u8; 7]);

impl Addr {
    /// Creates a device address from a little-endian byte array.
    #[inline]
    pub fn from_le_bytes(is_random: bool, mut v: [u8; 6]) -> Self {
        v.reverse();
        let mut a = [0; 7];
        a[0] = u8::from(is_random);
        a[1..].copy_from_slice(&v);
        Self(a)
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PollResult {
    Event(EventType),
    AsyncData(AclPacket),
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy)]
pub struct Data {
    pub data: [u8; 256],
    pub len: usize,
}

impl Data {
    pub fn new(bytes: &[u8]) -> Data {
        let mut data = [0u8; 256];
        data[..bytes.len()].copy_from_slice(bytes);
        Data { data, len: bytes.len() }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[0..self.len]
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.len..]
    }

    pub fn set_len(&mut self, new_len: usize) {
        self.len = if new_len > self.data.len() {
            self.data.len()
        } else {
            new_len
        };
    }

    pub fn append_len(&mut self, extra_len: usize) {
        self.set_len(self.len + extra_len);
    }

    pub fn limit_len(&mut self, max_len: usize) {
        if self.len > max_len {
            self.len = max_len;
        }
    }

    pub fn subdata_from(&self, from: usize) -> Data {
        let mut data = [0u8; 256];
        let new_len = self.len - from;
        data[..new_len].copy_from_slice(&self.data[from..(from + new_len)]);
        Data { data, len: new_len }
    }

    pub fn append(&mut self, bytes: &[u8]) {
        self.data[self.len..(self.len + bytes.len())].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    pub fn append_value<T: Sized + 'static>(&mut self, value: T) {
        let slice = unsafe { core::slice::from_raw_parts(&value as *const _ as *const _, core::mem::size_of::<T>()) };

        #[cfg(target_endian = "little")]
        self.append(slice);

        #[cfg(target_endian = "big")]
        {
            let top = slice.len() - 1;
            for (index, byte) in slice.iter().enumerate() {
                self.set(top - index, *byte);
            }
            self.append_len(slice.len());
        }
    }

    pub fn set(&mut self, index: usize, byte: u8) {
        self.data[index] = byte;
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl Default for Data {
    fn default() -> Self {
        Data::new(&[])
    }
}

impl core::fmt::Debug for Data {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x?}", &self.data[..self.len]).expect("Failed to format Data");
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AdvertisingType {
    AdvInd = 0x00,
    AdvDirectInd = 0x01,
    AdvScanInd = 0x02,
    AdvNonConnInd = 0x03,
    AdvDirectIndLowDuty = 0x04,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OwnAddressType {
    Public = 0x00,
    Random = 0x01,
    ResolvablePrivateAddress = 0x02,
    ResolvablePrivateAddressFromIRK = 0x03,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PeerAddressType {
    Public = 0x00,
    Random = 0x01,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AdvertisingChannelMapBits {
    Channel37 = 0b001,
    Channel38 = 0b010,
    Channel39 = 0b100,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AdvertisingFilterPolicy {
    All = 0x00,
    FilteredScanAllConnect = 0x01,
    AllScanFilteredConnect = 0x02,
    Filtered = 0x03,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AdvertisingParameters {
    pub advertising_interval_min: u16,
    pub advertising_interval_max: u16,
    pub advertising_type: AdvertisingType,
    pub own_address_type: OwnAddressType,
    pub peer_address_type: PeerAddressType,
    pub peer_address: [u8; 6],
    pub advertising_channel_map: u8,
    pub filter_policy: AdvertisingFilterPolicy,
}

pub struct AdvertiseConfig<'static> {
    pub params: Option<AdvertisingParameters>,
    pub data: &'static [AdStructure<'static>],
}

pub struct BleConfig {
    pub advertise_config: Option<AdvertiseConfig<'static>>,
}

impl Default for BleConfig {
    fn default() -> Self {
        Self { advertise: None }
    }
}

pub struct Ble<'d, T: HciDriver> {
    adapter: BleAdapter<'d, T>,
    config: BleConfig,
}

impl<'d, T: HciDriver> Ble<'d, T> {
    pub fn new<const CONN: usize>(
        driver: T,
        config: BleConfig,
        mut resources: adapter::AdapterResources<'d, CONN>,
    ) -> Self {
        Self {
            adapter: BleAdapter::new(driver, &mut resources),
            config,
        }
    }

    async fn init(&mut self) -> Result<(), Error<T::Error>> {
        self.adapter.request(Command::Reset).await?;
        self.adapter
            .request(Command::SetEventMask {
                events: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            })
            .await?;
        Ok(())
    }

    async fn start_advertise(&mut self) -> Result<(), Error<T::Error>> {
        if let Some(ad_config) = &self.config.advertise_config {
            let data = ad_structure::create_advertising_data(ad_config.data).map_err(Error::Advertisement)?;
            if let Some(params) = ad_config.params {
                self.adapter
                    .request(Command::LeSetAdvertisingParametersCustom(&params))
                    .await?;
            } else {
                self.adapter.request(Command::LeSetAdvertisingParameters).await?;
            }
            self.adapter.request(Command::LeSetAdvertisingData { data }).await?;
            self.adapter.request(Command::LeSetAdvertiseEnable(true)).await?;
        }
        Ok(())
    }

    pub async fn run<F: Fn(AdapterEvent) -> Result<Option<HciMessage<'_>>, Error<T::Error>>>(
        &self,
        processor: Option<F>,
    ) -> Result<(), Error<T::Error>> {
        self.init().await?;
        self.start_advertise().await?;
        loop {
            let event = self.adapter.recv().await?;
            if let Some(processor) = processor {
                if let Ok(Some(outbound)) = processor(event) {

                self.adapter.send(outbound).await?;
            }
        }
    }
}

pub struct Connection<'d, T: HciDriver> {
    ble: &'d BleAdapter<'d, T>,
    handle: BleConnection,
}

impl<'d, T: HciDriver> Connection<'d, T> {
    pub async fn accept(ble: &'d Ble<'d, T>) -> Result<Self, Error<T::Error>> {
        let handle = ble.adapter.accept_connection().await?;
        Ok(Self {
            ble: &ble.adapter,
            handle,
        })
    }
}
/*
    adapter: BleAdapter<'d, T>,
    millis: fn() -> u64,
}

impl<'d, T> Ble<'d, T>
where
    T: HciDriver,
{
    pub fn new(adapter: BleAdapter<'d, T>, millis: fn() -> u64) -> Ble<'d, T> {
        Ble { adapter, millis }
    }

        match self.adapter.process(HciMessage::Command(command)) {
            Ok(None) => {
                self.register_write_waker(cx.wake());
                Poll::Pending
            }
            Ok(Some(_)) => Poll::Ready(Ok()),
            Err(e) => Poll::Ready(Err(e)),
        })
        .await?;
        self.wait_for_command_complete(CONTROLLER_OGF, RESET_OCF).await
    }

    async fn wait_for_command_complete(&mut self, ogf: u8, ocf: u16) -> Result<(), Error<T::Error>> {
        poll_fn(|cx| match self.adapter.try_read() {
            Ok(Some(HciMEssage::Event(EventType::CommandComplete { opcode: code, .. })))
                if code == opcode(ogf, ocf) =>
            {
                Poll::Ready(Ok())
            }
            Ok(_) => {
                self.register_read_waker(cx.wake());
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        })
        .await
    }

    pub async fn init(&mut self) -> Result<(), Error<T::Error>> {
        self.request(Command::Reset, CONTROLLER_OGF, RESET_OCF).await?;
        self.request(
            Command::SetEventMask {
                events: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            },
            CONTROLLER_OGF,
            SET_EVENT_MASK_OCF,
        )
        .await?;
        Ok(())
    }

    pub async fn cmd_set_le_advertising_parameters(&mut self) -> Result<EventType, Error<T::Error>>
    where
        Self: Sized,
    {
        self.write_command(Command::LeSetAdvertisingParameters.encode().as_slice())
            .await?;
        self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF)
            .await?
            .check_command_completed()
    }

    pub async fn cmd_set_le_advertising_parameters_custom(
        &mut self,
        params: &AdvertisingParameters,
    ) -> Result<EventType, Error<T::Error>>
    where
        Self: Sized,
    {
        self.write_command(Command::LeSetAdvertisingParametersCustom(params).encode().as_slice())
            .await?;
        self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF)
            .await?
            .check_command_completed()
    }

    pub async fn cmd_set_le_advertising_data(&mut self, data: Data) -> Result<EventType, Error<T::Error>>
    where
        Self: Sized,
    {
        self.write_command(Command::LeSetAdvertisingData { data }.encode().as_slice())
            .await?;
        self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_DATA_OCF)
            .await?
            .check_command_completed()
    }

    pub async fn cmd_set_le_advertise_enable(&mut self, enable: bool) -> Result<EventType, Error<T::Error>>
    where
        Self: Sized,
    {
        self.write_command(Command::LeSetAdvertiseEnable(enable).encode().as_slice())
            .await?;
        self.wait_for_command_complete(LE_OGF, SET_ADVERTISE_ENABLE_OCF)
            .await?
            .check_command_completed()
    }

    pub async fn cmd_long_term_key_request_reply(
        &mut self,
        handle: u16,
        ltk: u128,
    ) -> Result<EventType, Error<T::Error>>
    where
        Self: Sized,
    {
        self.write_command(Command::LeLongTermKeyRequestReply { handle, ltk }.encode().as_slice())
            .await?;
        let res = self
            .wait_for_command_complete(LE_OGF, LONG_TERM_KEY_REQUEST_REPLY_OCF)
            .await?
            .check_command_completed();

        res
    }

    pub async fn cmd_read_br_addr(&mut self) -> Result<[u8; 6], Error<T::Error>>
    where
        Self: Sized,
    {
        self.write_command(Command::ReadBrAddr.encode().as_slice()).await?;
        let res = self
            .wait_for_command_complete(INFORMATIONAL_OGF, READ_BD_ADDR_OCF)
            .await?
            .check_command_completed()?;
        match res {
            EventType::CommandComplete {
                num_packets: _,
                opcode: _,
                data,
            } => Ok(data.as_slice()[1..][..6].try_into().unwrap()),
            _ => Err(Error::Failed(0)),
        }
    }

    pub(crate) async fn wait_for_command_complete(&mut self, ogf: u8, ocf: u16) -> Result<EventType, Error<T::Error>>
    where
        Self: Sized,
    {
        let timeout_at = (self.millis)() + TIMEOUT_MILLIS;
        loop {
            let res = self.poll().await?;

            match res {
                Some(PollResult::Event(event)) => match event {
                    EventType::CommandComplete { opcode: code, .. } if code == opcode(ogf, ocf) => {
                        return Ok(event);
                    }
                    _ => (),
                },
                _ => (),
            }

            if (self.millis)() > timeout_at {
                return Err(Error::Timeout);
            }
        }
    }

    pub async fn poll(&mut self) -> Result<Option<PollResult>, Error<T::Error>>
    where
        Self: Sized,
    {
        let mut hci_packet = [0u8; 259];
        // poll & process input
        let packet_type = self.hci.read(&mut hci_packet).await.map_err(Error::Driver)?;

        match packet_type {
            HciMessageType::Command => Ok(None),
            HciMessageType::Data => {
                let mut acl_packet = AclPacket::read(&hci_packet[..]);

                let wanted = u16::from_le_bytes(acl_packet.data.as_slice()[..2].try_into().unwrap()) as usize;

                // somewhat dirty way to handle re-assembling fragmented packets
                loop {
                    // debug!("Wanted = {}, actual = {}", wanted, acl_packet.data.len());

                    if wanted == acl_packet.data.len() - 4 {
                        break;
                    }

                    // Read next packet
                    if let HciMessageType::Data = self.hci.read(&mut hci_packet).await.map_err(Error::Driver)? {
                        let next_acl_packet = AclPacket::read(&hci_packet);
                        acl_packet.data.append(next_acl_packet.data.as_slice());
                    } else {
                        return Err(Error::Failed(0));
                    }
                }

                return Ok(Some(PollResult::AsyncData(acl_packet)));
            }
            HciMessageType::Event => {
                let event = EventType::read(&hci_packet[..]);
                trace!("received event {:?}", event);
                return Ok(Some(PollResult::Event(event)));
            }
        }
    }
}
*/

#[cfg(not(feature = "crypto"))]
pub mod no_rng {
    pub struct NoRng;

    impl rand_core::CryptoRng for NoRng {}

    impl rand_core::RngCore for NoRng {
        fn next_u32(&mut self) -> u32 {
            unimplemented!()
        }

        fn next_u64(&mut self) -> u64 {
            unimplemented!()
        }

        fn fill_bytes(&mut self, _dest: &mut [u8]) {
            unimplemented!()
        }

        fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
            unimplemented!()
        }
    }
}
