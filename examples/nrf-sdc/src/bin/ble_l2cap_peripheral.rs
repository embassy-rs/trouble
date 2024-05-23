#![no_std]
#![no_main]
#![feature(impl_trait_in_assoc_type)]

use defmt::{info, unwrap};
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_nrf::{bind_interrupts, pac};
use embassy_time::{Duration, Timer};
use nrf_sdc::mpsl::MultiprotocolServiceLayer;
use nrf_sdc::{self as sdc, mpsl};
use sdc::rng_pool::RngPool;
use static_cell::StaticCell;
use trouble_host::advertise::{AdStructure, Advertisement, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE};
use trouble_host::l2cap::L2capChannel;
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

/// How many outgoing L2CAP buffers per link
const L2CAP_TXQ: u8 = 20;

/// How many incoming L2CAP buffers per link
const L2CAP_RXQ: u8 = 20;

/// Size of L2CAP packets
const L2CAP_MTU: usize = 27;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 3; // Signal + att + CoC

fn build_sdc<'d, const N: usize>(
    p: nrf_sdc::Peripherals<'d>,
    rng: &'d RngPool,
    mpsl: &'d MultiprotocolServiceLayer,
    mem: &'d mut sdc::Mem<N>,
) -> Result<nrf_sdc::SoftdeviceController<'d>, nrf_sdc::Error> {
    sdc::Builder::new()?
        .support_adv()?
        .support_peripheral()?
        .peripheral_count(1)?
        .buffer_cfg(L2CAP_MTU as u8, L2CAP_MTU as u8, L2CAP_TXQ, L2CAP_RXQ)?
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

    let mut sdc_mem = sdc::Mem::<6224>::new();
    let sdc = unwrap!(build_sdc(sdc_p, &rng, mpsl, &mut sdc_mem));

    info!("Our address = {:02x}", my_addr());
    Timer::after(Duration::from_millis(200)).await;

    static HOST_RESOURCES: StaticCell<BleHostResources<CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, L2CAP_MTU>> =
        StaticCell::new();
    let host_resources = HOST_RESOURCES.init(BleHostResources::new(PacketQos::None));

    let mut ble: BleHost<'_, _> = BleHost::new(sdc, host_resources);
    ble.set_random_address(my_addr());
    let mut adv_data = [0; 31];
    unwrap!(AdStructure::encode_slice(
        &[AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),],
        &mut adv_data[..],
    ));

    let mut scan_data = [0; 31];
    unwrap!(AdStructure::encode_slice(
        &[AdStructure::CompleteLocalName(b"Trouble"),],
        &mut scan_data[..],
    ));

    let _ = join(ble.run(), async {
        loop {
            info!("Advertising, waiting for connection...");
            let conn = unwrap!(
                ble.advertise(
                    &Default::default(),
                    Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..],
                        scan_data: &scan_data[..],
                    }
                )
                .await
            );

            info!("Connection established");

            let mut ch1 =
                unwrap!(L2capChannel::<PAYLOAD_LEN>::accept(&ble, &conn, &[0x2349], &Default::default(),).await);

            info!("L2CAP channel accepted");

            // Size of payload we're expecting
            const PAYLOAD_LEN: usize = 27;
            let mut rx = [0; PAYLOAD_LEN];
            for i in 0..10 {
                let len = unwrap!(ch1.receive(&ble, &mut rx).await);
                assert_eq!(len, rx.len());
                assert_eq!(rx, [i; PAYLOAD_LEN]);
            }

            info!("L2CAP data received, echoing");
            Timer::after(Duration::from_secs(1)).await;
            for i in 0..10 {
                let tx = [i; PAYLOAD_LEN];
                unwrap!(ch1.send(&ble, &tx).await);
            }
            info!("L2CAP data echoed");

            Timer::after(Duration::from_secs(60)).await;
        }
    })
    .await;
}
