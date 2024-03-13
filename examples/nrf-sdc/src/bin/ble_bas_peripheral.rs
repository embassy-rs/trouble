#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use bt_hci::cmd::SyncCmd;
use bt_hci::param::BdAddr;
use defmt::{info, unwrap};
use embassy_executor::Spawner;
use embassy_futures::join::join3;
use embassy_nrf::{bind_interrupts, pac};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::{Duration, Timer};
use nrf_sdc::{self as sdc, mpsl, mpsl::MultiprotocolServiceLayer};
use sdc::rng_pool::RngPool;
use sdc::vendor::ZephyrWriteBdAddr;
use static_cell::StaticCell;
use trouble_host::{
    adapter::{Adapter, HostResources},
    advertise::{AdStructure, AdvertiseConfig, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE},
    attribute::{AttributesBuilder, CharacteristicProp, ServiceBuilder, Uuid},
    gatt::{GattEvent, GattServer},
    PacketQos,
};

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

fn bd_addr() -> BdAddr {
    unsafe {
        let ficr = &*pac::FICR::ptr();
        let high = u64::from((ficr.deviceid[1].read().bits() & 0x0000ffff) | 0x0000c000);
        let addr = high << 32 | u64::from(ficr.deviceid[0].read().bits());
        BdAddr::new(unwrap!(addr.to_le_bytes()[..6].try_into()))
    }
}

fn build_sdc<'d, const N: usize>(
    p: nrf_sdc::Peripherals<'d>,
    rng: &'d RngPool<'d>,
    mpsl: &'d MultiprotocolServiceLayer<'d>,
    mem: &'d mut sdc::Mem<N>,
) -> Result<nrf_sdc::SoftdeviceController<'d>, nrf_sdc::Error> {
    sdc::Builder::new()?
        .support_adv()?
        .support_peripheral()?
        .peripheral_count(1)?
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
        pac_p.ECB, pac_p.AAR, p.NVMC, p.PPI_CH17, p.PPI_CH18, p.PPI_CH20, p.PPI_CH21, p.PPI_CH22, p.PPI_CH23,
        p.PPI_CH24, p.PPI_CH25, p.PPI_CH26, p.PPI_CH27, p.PPI_CH28, p.PPI_CH29,
    );

    let mut pool = [0; 256];
    let rng = sdc::rng_pool::RngPool::new(p.RNG, Irqs, &mut pool, 64);

    let mut sdc_mem = sdc::Mem::<1672>::new();
    let sdc = unwrap!(build_sdc(sdc_p, &rng, mpsl, &mut sdc_mem));

    info!("Advertising as {:02x}", bd_addr());
    unwrap!(ZephyrWriteBdAddr::new(bd_addr()).exec(&sdc).await);
    Timer::after(Duration::from_millis(200)).await;

    static HOST_RESOURCES: StaticCell<HostResources<NoopRawMutex, 4, 32, 27>> = StaticCell::new();
    let host_resources = HOST_RESOURCES.init(HostResources::new(PacketQos::None));

    let adapter: Adapter<'_, NoopRawMutex, _, 2, 4, 1, 1> = Adapter::new(sdc, host_resources);
    let mut advertiser = adapter.advertiser(AdvertiseConfig {
        params: None,
        data: &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::ServiceUuids16(&[Uuid::Uuid16([0x0f, 0x18])]),
            AdStructure::CompleteLocalName("Trouble"),
        ],
    });

    let mut attributes: AttributesBuilder<'_, 10> = AttributesBuilder::new();
    static DATA: StaticCell<[u8; 1]> = StaticCell::new();
    let data = DATA.init([32; 1]);
    ServiceBuilder::new(&mut attributes, 0x180f_u16.into())
        .add_characteristic(0x2a19.into(), &[CharacteristicProp::Read], data)
        .done();
    let mut attributes = attributes.build();

    let mut server = GattServer::new(&adapter, &mut attributes[..]);

    info!("Starting advertising and GATT service");
    let _ = join3(
        adapter.run(),
        async {
            loop {
                match server.next().await {
                    GattEvent::Write(_conn, attribute) => {
                        info!("Attribute was written: {:?}", attribute);
                    }
                }
            }
        },
        async {
            let _conn = unwrap!(advertiser.advertise(&adapter).await);
            // Keep connection alive
            loop {
                Timer::after(Duration::from_secs(60)).await
            }
        },
    )
    .await;
}
