//! BLE beacon support, without dealing with Link-Layer stuff.

use crate::link::advertising::{Header, Pdu, PduBuf};
use crate::link::filter::{self, AddressFilter, ScanFilter};
use crate::link::{
    ad_structure::AdStructure, Cmd, DeviceAddress, NextUpdate, RadioCmd, Transmitter,
};
use crate::phy::AdvertisingChannel;
use crate::time::{Duration, Instant};
use crate::{bytes::*, Error};

/// A BLE beacon.
///
/// FIXME: This has to randomly offset the broadcast interval
pub struct Beacon {
    pdu: PduBuf,
}

impl Beacon {
    /// Creates a new beacon that will broadcast a packet on all advertisement
    /// channels.
    ///
    /// # Parameters
    ///
    /// * **`addr`**: Address of the beacon device.
    /// * **`data`**: Data to broadcast. This must fit within a single PDU.
    ///
    /// # Errors
    ///
    /// If `data` doesn't fit in a single PDU, an error will be returned.
    pub fn new(addr: DeviceAddress, data: &[AdStructure<'_>]) -> Result<Self, Error> {
        let pdu = PduBuf::beacon(addr, data)?;
        Ok(Self { pdu })
    }

    /// Broadcasts the beacon data using `tx`.
    ///
    /// This will broadcast once on every advertising channel.
    pub fn broadcast<T: Transmitter>(&self, tx: &mut T) {
        // The spec says that we have to broadcast on all 3 channels in sequence, so that the total
        // time of this broadcast ("advertising event") is <10ms.

        // The transmitter retains the old transmit buffer, but it might be used for other purposes
        // (like sending multiple beacon payloads), so we always copy our payload into the tx
        // buffer here.
        let payload = self.pdu.payload();
        let buf = tx.tx_payload_buf();
        buf[..payload.len()].copy_from_slice(payload);

        for channel in AdvertisingChannel::iter_all() {
            tx.transmit_advertising(self.pdu.header(), channel);
        }
    }
}

/// Callback for the [`BeaconScanner`].
pub trait ScanCallback {
    /// Called when a beacon is received and has passed the configured device address filter.
    ///
    /// # Parameters
    ///
    /// * **`adv_addr`**: Address of the device sending the beacon.
    /// * **`adv_data`**: Advertising data structures attached to the beacon.
    fn beacon<'a, I>(&mut self, adv_addr: DeviceAddress, adv_data: I)
    where
        I: Iterator<Item = AdStructure<'a>>;
}

/// A passive scanner for non-connectable beacon advertisements.
pub struct BeaconScanner<C: ScanCallback, F: AddressFilter> {
    cb: C,
    filter: ScanFilter<F>,
    interval: Duration,
    channel: AdvertisingChannel,
}

impl<C: ScanCallback> BeaconScanner<C, filter::AllowAll> {
    /// Creates a `BeaconScanner` that will report beacons from any device.
    pub fn new(callback: C) -> Self {
        Self::with_filter(callback, filter::AllowAll)
    }
}

impl<C: ScanCallback, F: AddressFilter> BeaconScanner<C, F> {
    /// Creates a `BeaconScanner` with a custom device filter.
    pub fn with_filter(callback: C, scan_filter: F) -> Self {
        Self {
            cb: callback,
            filter: ScanFilter::new(scan_filter),
            interval: Duration::from_micros(0),
            channel: AdvertisingChannel::first(),
        }
    }

    /// Configures the `BeaconScanner` and returns a `Cmd` to apply to the radio.
    ///
    /// The `next_update` field of the returned `Cmd` specifies when to call `timer_update` the next
    /// time. The timer used for this does not have to be very accurate, it is only used to switch
    /// to the next advertising channel after `interval` elapses.
    pub fn configure(&mut self, now: Instant, interval: Duration) -> Cmd {
        self.interval = interval;
        self.channel = AdvertisingChannel::first();

        Cmd {
            // Switch channels
            next_update: NextUpdate::At(now + self.interval),

            radio: RadioCmd::ListenAdvertising {
                channel: self.channel,
            },

            queued_work: false,
        }
    }

    /// Updates the `BeaconScanner` after the configured timer has fired.
    ///
    /// This switches to the next advertising channel and will listen there.
    pub fn timer_update(&mut self, now: Instant) -> Cmd {
        self.channel = self.channel.cycle();

        Cmd {
            // Switch channels
            next_update: NextUpdate::At(now + self.interval),

            radio: RadioCmd::ListenAdvertising {
                channel: self.channel,
            },

            queued_work: false,
        }
    }

    /// Processes a received advertising channel packet.
    ///
    /// This should be called whenever the radio receives a packet on the configured advertising
    /// channel.
    pub fn process_adv_packet(&mut self, header: Header, payload: &[u8], crc_ok: bool) -> Cmd {
        if crc_ok && header.type_().is_beacon() {
            // Partially decode to get the device ID and run it through the filter
            if let Ok(pdu) = Pdu::from_header_and_payload(header, &mut ByteReader::new(payload)) {
                if self.filter.should_scan(*pdu.sender()) {
                    let ad = pdu.advertising_data().unwrap();
                    self.cb.beacon(*pdu.sender(), ad);
                }
            }
        }

        Cmd {
            next_update: NextUpdate::Keep,
            radio: RadioCmd::ListenAdvertising {
                channel: self.channel,
            },
            queued_work: false,
        }
    }
}
