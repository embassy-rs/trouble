#![no_std]
#![no_main]

use defmt::{info, unwrap};
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_nrf::{bind_interrupts, config, cracen, mode::Blocking};
use embassy_time::{Duration, Timer};
use nrf_sdc::mpsl::MultiprotocolServiceLayer;
use nrf_sdc::{self as sdc, mpsl};
use static_cell::StaticCell;
use trouble_host::prelude::*;
use trouble_host::gatt::{AttributeKind, AttributeTable, Attribute, PeerState};

use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    SWI00 => nrf_sdc::mpsl::LowPrioInterruptHandler;
    CLOCK_POWER => nrf_sdc::mpsl::ClockInterruptHandler;
    RADIO_0 => nrf_sdc::mpsl::HighPrioInterruptHandler;
    TIMER10 => nrf_sdc::mpsl::HighPrioInterruptHandler;
    GRTC_3 => nrf_sdc::mpsl::HighPrioInterruptHandler;
});

#[embassy_executor::task]
async fn mpsl_task(mpsl: &'static MultiprotocolServiceLayer<'static>) -> ! {
    mpsl.run().await
}

/// How many outgoing L2CAP buffers per link
const L2CAP_TXQ: u8 = 3;

/// How many incoming L2CAP buffers per link
const L2CAP_RXQ: u8 = 3;

fn build_sdc<'d, const N: usize>(
    p: nrf_sdc::Peripherals<'d>,
    rng: &'d mut cracen::Cracen<'static, Blocking>,
    mpsl: &'d MultiprotocolServiceLayer,
    mem: &'d mut sdc::Mem<N>,
) -> Result<nrf_sdc::SoftdeviceController<'d>, nrf_sdc::Error> {
    sdc::Builder::new()?
        .support_adv()?
        .support_peripheral()?
        .peripheral_count(1)?
        .buffer_cfg(
            DefaultPacketPool::MTU as u16,
            DefaultPacketPool::MTU as u16,
            L2CAP_TXQ,
            L2CAP_RXQ,
        )?
        .build(p, rng, mpsl, mem)
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config: config::Config = Default::default();
    config.clock_speed = config::ClockSpeed::CK128;
    config.hfclk_source = config::HfclkSource::ExternalXtal;
    config.lfclk_source = config::LfclkSource::ExternalXtal;
    let p = embassy_nrf::init(config);
    let mpsl_p = mpsl::Peripherals::new(
        p.GRTC_CH7,
        p.GRTC_CH8,
        p.GRTC_CH9,
        p.GRTC_CH10,
        p.GRTC_CH11,
        p.TIMER10,
        p.TIMER20,
        p.TEMP,
        p.PPI10_CH0,
        p.PPI20_CH1,
        p.PPIB11_CH0,
        p.PPIB21_CH0,
    );
    let lfclk_cfg = mpsl::raw::mpsl_clock_lfclk_cfg_t {
        source: mpsl::raw::MPSL_CLOCK_LF_SRC_XTAL as u8,
        rc_ctiv: 0,
        rc_temp_ctiv: 0,
        accuracy_ppm: 50,
        skip_wait_lfclk_started: false,
    };
    static MPSL: StaticCell<MultiprotocolServiceLayer> = StaticCell::new();
    let mpsl = MPSL.init(unwrap!(mpsl::MultiprotocolServiceLayer::new(mpsl_p, Irqs, lfclk_cfg)));
    spawner.spawn(unwrap!(mpsl_task(&*mpsl)));

    let sdc_p = sdc::Peripherals::new(
        p.PPI00_CH1,
        p.PPI00_CH3,
        p.PPI10_CH1,
        p.PPI10_CH2,
        p.PPI10_CH3,
        p.PPI10_CH4,
        p.PPI10_CH5,
        p.PPI10_CH6,
        p.PPI10_CH7,
        p.PPI10_CH8,
        p.PPI10_CH9,
        p.PPI10_CH10,
        p.PPI10_CH11,
        p.PPIB00_CH1,
        p.PPIB00_CH2,
        p.PPIB00_CH3,
        p.PPIB10_CH1,
        p.PPIB10_CH2,
        p.PPIB10_CH3,
    );

    let mut rng = cracen::Cracen::new_blocking(p.CRACEN);

    let mut sdc_mem = sdc::Mem::<4720>::new();
    let sdc = unwrap!(build_sdc(sdc_p, &mut rng, mpsl, &mut sdc_mem));

    let address: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
    const CONNECTIONS_MAX: usize = 2;
    const L2CAP_CHANNELS_MAX: usize = 2;
    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();
    let stack = trouble_host::new(sdc, &mut resources).set_random_address(address);
    let Host {
        mut peripheral,
        mut runner,
        ..
    } = stack.build();

    let mut adv_data = [0; 31];
    let adv_data_len = unwrap!(AdStructure::encode_slice(
        &[AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED)],
        &mut adv_data[..],
    ));

    let mut scan_data = [0; 31];
    let scan_data_len = unwrap!(AdStructure::encode_slice(
        &[AdStructure::CompleteLocalName(b"Trouble")],
        &mut scan_data[..]
    ));

    let table = BasTable::new();
    let server = AttributeServer::new(&table);
    let state = ClientState::new();

    let _ = join(runner.run(), async {
        loop {
            let advertiser = unwrap!(
                peripheral
                    .advertise(
                        &Default::default(),
                        Advertisement::ConnectableScannableUndirected {
                            adv_data: &adv_data[..adv_data_len],
                            scan_data: &scan_data[..scan_data_len],
                        },
                    )
                    .await
            );
            let conn = unwrap!(advertiser.accept().await);
            let conn = unwrap!(conn.with_attribute_server(&server, &state));

            while let Ok(event) = conn.next().await {
                info!("Event: {:?}", event);
            }

            Timer::after(Duration::from_secs(2)).await;
            break;
        }
    })
    .await;
}

struct BasTable {
    battery_level: u8,
    cccd_notifications: bool,
}

impl BasTable {
    pub fn new() -> Self {
        Self {
            battery_level: 10,
            cccd_notifications: false,
        }
    }
}

impl<'a> AttributeTable for &'a BasTable {
    type Attribute = MyAttribute<'a>;
    type Iterator = MyIter<'a>;

    fn iter(&self) -> Self::Iterator {
        MyIter {
            table: self,
            index: 0,
        }
    }
}

enum MyAttribute<'a> {
    ServiceDeclaration,
    CharacteristicDeclaration,
    CharacteristicValue(&'a BasTable),
    ValidRangeDescriptor,
    MeasurementDescriptor,
    Cccd(&'a BasTable),
}

struct MyIter<'a> {
    table: &'a BasTable,
    index: usize,
}

impl<'a> Iterator for MyIter<'a> {
    type Item = MyAttribute<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let item = match self.index {
            0 => Some(MyAttribute::ServiceDeclaration),
            1 => Some(MyAttribute::CharacteristicDeclaration),
            2 => Some(MyAttribute::CharacteristicValue(self.table)),
            3 => Some(MyAttribute::ValidRangeDescriptor),
            4 => Some(MyAttribute::MeasurementDescriptor),
            5 => Some(MyAttribute::Cccd(self.table)),
            _ => None,
        };
        self.index += 1;
        item
    }
}

impl<'a> Attribute for MyAttribute<'a> {
    type Error = AttErrorCode;

    fn handle(&self) -> u16 {
        match self {
            MyAttribute::ServiceDeclaration => 1,
            MyAttribute::CharacteristicDeclaration => 2,
            MyAttribute::CharacteristicValue(_) => 3,
            MyAttribute::ValidRangeDescriptor => 4,
            MyAttribute::MeasurementDescriptor => 5,
            MyAttribute::Cccd(_) => 6,
        }
    }

    fn uuid(&self) -> Uuid {
        match self {
            MyAttribute::ServiceDeclaration => Uuid::from(declarations::PRIMARY_SERVICE),
            MyAttribute::CharacteristicDeclaration => Uuid::from(declarations::CHARACTERISTIC),
            MyAttribute::CharacteristicValue(_) => Uuid::from(characteristic::BATTERY_LEVEL),
            MyAttribute::ValidRangeDescriptor => Uuid::from(descriptors::VALID_RANGE),
            MyAttribute::MeasurementDescriptor => Uuid::from(descriptors::MEASUREMENT_DESCRIPTION),
            MyAttribute::Cccd(_) => Uuid::from(descriptors::CLIENT_CHARACTERISTIC_CONFIGURATION),
        }
    }

    fn last(&self) -> u16 {
        // All attributes in this service group end at handle 6
        6
    }

    fn kind(&self) -> AttributeKind {
        match self {
            MyAttribute::ServiceDeclaration => AttributeKind::Service,
            MyAttribute::CharacteristicDeclaration => AttributeKind::Declaration,
            MyAttribute::CharacteristicValue(_) => AttributeKind::Data,
            MyAttribute::ValidRangeDescriptor => AttributeKind::Data,
            MyAttribute::MeasurementDescriptor => AttributeKind::Data,
            MyAttribute::Cccd(_) => AttributeKind::Cccd,
        }
    }

    async fn read(&self, offset: u16, output: &mut [u8]) -> Result<usize, Self::Error> {
        let offset = offset as usize;
        match self {
            MyAttribute::ServiceDeclaration => {
                // Service UUID: 0x180F (Battery Service)
                let uuid = service::BATTERY.as_le_bytes();
                if offset >= uuid.len() {
                    return Ok(0);
                }
                let len = (uuid.len() - offset).min(output.len());
                output[..len].copy_from_slice(&uuid[offset..offset + len]);
                Ok(len)
            }
            MyAttribute::CharacteristicDeclaration => {
                // Characteristic declaration: properties (1 byte) + handle (2 bytes) + UUID
                // Properties: Read (0x02) | Notify (0x10) = 0x12
                let properties = 0x12u8;
                let handle = 3u16; // Handle of the characteristic value
                let uuid = characteristic::BATTERY_LEVEL.as_le_bytes();

                let mut data = [0u8; 19]; // 1 + 2 + 16 max
                data[0] = properties;
                data[1..3].copy_from_slice(&handle.to_le_bytes());
                data[3..3 + uuid.len()].copy_from_slice(uuid);
                let total_len = 3 + uuid.len();

                if offset >= total_len {
                    return Ok(0);
                }
                let len = (total_len - offset).min(output.len());
                output[..len].copy_from_slice(&data[offset..offset + len]);
                Ok(len)
            }
            MyAttribute::CharacteristicValue(table) => {
                if offset > 0 {
                    return Ok(0);
                }
                if output.is_empty() {
                    return Ok(0);
                }
                output[0] = table.battery_level;
                Ok(1)
            }
            MyAttribute::ValidRangeDescriptor => {
                // Valid range: [0, 100]
                let range = [0u8, 100u8];
                if offset >= range.len() {
                    return Ok(0);
                }
                let len = (range.len() - offset).min(output.len());
                output[..len].copy_from_slice(&range[offset..offset + len]);
                Ok(len)
            }
            MyAttribute::MeasurementDescriptor => {
                // Measurement description: "Battery Level"
                let description = b"Battery Level";
                if offset >= description.len() {
                    return Ok(0);
                }
                let len = (description.len() - offset).min(output.len());
                output[..len].copy_from_slice(&description[offset..offset + len]);
                Ok(len)
            }
            MyAttribute::Cccd(table) => {
                if offset > 0 {
                    return Ok(0);
                }
                if output.len() < 2 {
                    return Ok(0);
                }
                // CCCD value: bit 0 = notifications, bit 1 = indications
                let value = if table.cccd_notifications { 0x01u16 } else { 0x00u16 };
                output[0..2].copy_from_slice(&value.to_le_bytes());
                Ok(2)
            }
        }
    }

    async fn write(&self, _offset: u16, _input: &[u8]) -> Result<(), Self::Error> {
        match self {
            MyAttribute::CharacteristicValue(_table) => {
                // For now, we'll allow writing but won't update the value
                // In a real implementation, you'd need interior mutability
                Ok(())
            }
            MyAttribute::Cccd(_table) => {
                // Update CCCD - would need interior mutability in real implementation
                // For now, just accept the write
                Ok(())
            }
            _ => {
                // Other attributes are not writable
                Err(AttErrorCode::WRITE_NOT_PERMITTED)
            }
        }
    }
}

struct ClientState {}
impl ClientState {
    pub fn new() -> Self {
        Self {}
    }
}

impl PeerState for ClientState {
    type Error = ();

    fn connect(&self, _peer: &Identity) -> Result<(), Error> {
        Ok(())
    }

    fn disconnect(&self, _peer: &Identity) -> Result<(), Error> {
        Ok(())
    }

    fn set_notify(&self, _peer: &Identity, _handle: u16, _enable: bool) {
        // No-op for now
    }

    fn set_indicate(&self, _peer: &Identity, _handle: u16, _enable: bool) {
        // No-op for now
    }

    fn should_notify(&self, _peer: &Identity, _handle: u16) -> bool {
        false
    }

    fn should_indicate(&self, _peer: &Identity, _handle: u16) -> bool {
        false
    }
}
