#![no_std]
#![no_main]
#![feature(impl_trait_in_assoc_type)]

use defmt::{info, unwrap};
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_nrf::{bind_interrupts, pac};
use embassy_time::{Duration, Instant, Timer};
use nrf_sdc::mpsl::MultiprotocolServiceLayer;
use nrf_sdc::{self as sdc, mpsl};
use sdc::rng_pool::RngPool;
use static_cell::StaticCell;
use trouble_host::advertise::{
    AdStructure, AdvFilterPolicy, Advertisement, AdvertisementParameters, AdvertisementSet, PhyKind, TxPower,
    BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE,
};
use trouble_host::{Address, BleHost, BleHostResources, PacketQos};
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    RNG => nrf_sdc::rng_pool::InterruptHandler;
    SWI0_EGU0 => nrf_sdc::mpsl::LowPrioInterruptHandler;
    POWER_CLOCK => nrf_sdc::mpsl::ClockInterruptHandler;
    RADIO => nrf_sdc::mpsl::HighPrioInterruptHandler;
    TIMER0 => nrf_sdc::mpsl::HighPrioInterruptHandler;
    RTC0 => nrf_sdc::mpsl::HighPrioInterruptHandler;
});

#[embassy_executor::task]
async fn mpsl_task(mpsl: &'static MultiprotocolServiceLayer<'static>) -> ! {
    mpsl.run().await
}

fn my_addr() -> Address {
    unsafe {
        let ficr = &*pac::FICR::ptr();
        let high = u64::from((ficr.deviceaddr[1].read().bits() & 0x0000ffff) | 0x0000c000);
        let addr = high << 32 | u64::from(ficr.deviceaddr[0].read().bits());
        Address::random(unwrap!(addr.to_le_bytes()[..6].try_into()))
    }
}

/// Size of L2CAP packets (ATT MTU is this - 4)
const L2CAP_MTU: usize = 27;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 2; // Signal + att

fn build_sdc<'d, const N: usize>(
    p: nrf_sdc::Peripherals<'d>,
    rng: &'d RngPool,
    mpsl: &'d MultiprotocolServiceLayer,
    mem: &'d mut sdc::Mem<N>,
) -> Result<nrf_sdc::SoftdeviceController<'d>, nrf_sdc::Error> {
    sdc::Builder::new()?
        .support_adv()?
        .support_le_coded_phy()?
        .support_ext_adv()?
        .adv_count(2)?
        .build(p, rng, mpsl, mem)
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_nrf::init(Default::default());
    let pac_p = pac::Peripherals::take().unwrap();

    let mpsl_p = mpsl::Peripherals::new(
        pac_p.CLOCK,
        pac_p.RADIO,
        p.RTC0,
        p.TIMER0,
        p.TEMP,
        p.PPI_CH19,
        p.PPI_CH30,
        p.PPI_CH31,
    );
    let lfclk_cfg = mpsl::raw::mpsl_clock_lfclk_cfg_t {
        source: mpsl::raw::MPSL_CLOCK_LF_SRC_RC as u8,
        rc_ctiv: mpsl::raw::MPSL_RECOMMENDED_RC_CTIV as u8,
        rc_temp_ctiv: mpsl::raw::MPSL_RECOMMENDED_RC_TEMP_CTIV as u8,
        accuracy_ppm: mpsl::raw::MPSL_DEFAULT_CLOCK_ACCURACY_PPM as u16,
        skip_wait_lfclk_started: mpsl::raw::MPSL_DEFAULT_SKIP_WAIT_LFCLK_STARTED != 0,
    };
    static MPSL: StaticCell<MultiprotocolServiceLayer> = StaticCell::new();
    let mpsl = MPSL.init(unwrap!(mpsl::MultiprotocolServiceLayer::new(mpsl_p, Irqs, lfclk_cfg)));
    spawner.must_spawn(mpsl_task(&*mpsl));

    let sdc_p = sdc::Peripherals::new(
        pac_p.ECB, pac_p.AAR, p.PPI_CH17, p.PPI_CH18, p.PPI_CH20, p.PPI_CH21, p.PPI_CH22, p.PPI_CH23, p.PPI_CH24,
        p.PPI_CH25, p.PPI_CH26, p.PPI_CH27, p.PPI_CH28, p.PPI_CH29,
    );

    let mut pool = [0; 256];
    let rng = sdc::rng_pool::RngPool::new(p.RNG, Irqs, &mut pool, 64);

    let mut sdc_mem = sdc::Mem::<8192>::new();
    let sdc = unwrap!(build_sdc(sdc_p, &rng, mpsl, &mut sdc_mem));

    info!("Our address = {:02x}", my_addr());
    Timer::after(Duration::from_millis(200)).await;

    static HOST_RESOURCES: StaticCell<BleHostResources<CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, L2CAP_MTU>> =
        StaticCell::new();
    let host_resources = HOST_RESOURCES.init(BleHostResources::new(PacketQos::None));

    let mut ble: BleHost<'_, _> = BleHost::new(sdc, host_resources);
    ble.set_random_address(my_addr());

    let mut adv_data = [0; 31];
    let len = unwrap!(AdStructure::encode_slice(
        &[
            AdStructure::CompleteLocalName(b"Trouble Multiadv"),
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED)
        ],
        &mut adv_data[..],
    ));

    let sets = [
        AdvertisementSet {
            handle: 0,
            params: AdvertisementParameters {
                tx_power: TxPower::Plus8dBm,
                primary_phy: PhyKind::Le1M,
                secondary_phy: PhyKind::Le1M,
                max_events: Some(1), // Advertise set only once
                timeout: None,
                interval_min: Duration::from_secs(1),
                interval_max: Duration::from_secs(1),
                channel_map: None,
                filter_policy: AdvFilterPolicy::Unfiltered,
            },
            data: Advertisement::ExtNonconnectableScannableUndirected {
                scan_data: &adv_data[..len],
            },
        },
        AdvertisementSet {
            handle: 1,
            params: AdvertisementParameters {
                tx_power: TxPower::Plus8dBm,
                primary_phy: PhyKind::LeCoded,
                secondary_phy: PhyKind::LeCoded,
                max_events: None,
                timeout: Some(Duration::from_secs(4)), // Advertise this set for 4 seconds
                interval_min: Duration::from_secs(1),
                interval_max: Duration::from_secs(1),
                channel_map: None,
                filter_policy: AdvFilterPolicy::Unfiltered,
                ..Default::default()
            },
            data: Advertisement::ExtNonconnectableScannableUndirected {
                scan_data: &adv_data[..len],
            },
        },
    ];

    info!("Starting advertising");
    let _ = join(ble.run(), async {
        loop {
            let start = Instant::now();
            let mut advertiser = unwrap!(ble.advertise_ext(&sets).await);
            match advertiser.accept().await {
                Ok(_) => {}
                Err(trouble_host::Error::Timeout) => {
                    let d: Duration = Instant::now() - start;
                    defmt::info!("timeout/done after {} millis", d.as_millis());
                    Timer::after(Duration::from_secs(2)).await;
                }
                Err(e) => {
                    defmt::warn!("advertising error: {:?}", e);
                    Timer::after(Duration::from_secs(2)).await;
                }
            };
        }
    })
    .await;
}
