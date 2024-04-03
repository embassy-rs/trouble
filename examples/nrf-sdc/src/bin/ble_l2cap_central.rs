#![no_std]
#![no_main]
#![feature(impl_trait_in_assoc_type)]

use bt_hci::cmd::le::LeSetRandomAddr;
use bt_hci::cmd::SyncCmd;
use bt_hci::param::BdAddr;
use defmt::{info, unwrap};
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_nrf::{bind_interrupts, pac};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::{Duration, Timer};
use nrf_sdc::{self as sdc, mpsl, mpsl::MultiprotocolServiceLayer};
use sdc::rng_pool::RngPool;
use static_cell::StaticCell;
use trouble_host::{
    adapter::{Adapter, HostResources},
    connection::Connection,
    l2cap::L2capChannel,
    scan::ScanConfig,
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
        let high = u64::from((ficr.deviceaddr[1].read().bits() & 0x0000ffff) | 0x0000c000);
        let addr = high << 32 | u64::from(ficr.deviceaddr[0].read().bits());
        BdAddr::new(unwrap!(addr.to_le_bytes()[..6].try_into()))
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

/// Number of packets available in the pool
const PACKET_POOL_SIZE: usize = (L2CAP_TXQ + L2CAP_RXQ) as usize;

fn build_sdc<'d, const N: usize>(
    p: nrf_sdc::Peripherals<'d>,
    rng: &'d RngPool<'d>,
    mpsl: &'d MultiprotocolServiceLayer<'d>,
    mem: &'d mut sdc::Mem<N>,
) -> Result<nrf_sdc::SoftdeviceController<'d>, nrf_sdc::Error> {
    sdc::Builder::new()?
        .support_scan()?
        .support_central()?
        .central_count(1)?
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
        pac_p.ECB, pac_p.AAR, p.NVMC, p.PPI_CH17, p.PPI_CH18, p.PPI_CH20, p.PPI_CH21, p.PPI_CH22, p.PPI_CH23,
        p.PPI_CH24, p.PPI_CH25, p.PPI_CH26, p.PPI_CH27, p.PPI_CH28, p.PPI_CH29,
    );

    let mut pool = [0; 256];
    let rng = sdc::rng_pool::RngPool::new(p.RNG, Irqs, &mut pool, 64);

    let mut sdc_mem = sdc::Mem::<6544>::new();
    let sdc = unwrap!(build_sdc(sdc_p, &rng, mpsl, &mut sdc_mem));

    info!("Our address = {:02x}", bd_addr());
    unwrap!(LeSetRandomAddr::new(bd_addr()).exec(&sdc).await);
    Timer::after(Duration::from_millis(200)).await;

    static HOST_RESOURCES: StaticCell<HostResources<NoopRawMutex, L2CAP_CHANNELS_MAX, PACKET_POOL_SIZE, L2CAP_MTU>> =
        StaticCell::new();
    let host_resources = HOST_RESOURCES.init(HostResources::new(PacketQos::Guaranteed(4)));

    let adapter: Adapter<'_, NoopRawMutex, _, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = Adapter::new(sdc, host_resources);

    let config = ScanConfig {
        params: None,
        filter_accept_list: &[],
    };

    // NOTE: Modify this to match the address of the peripheral you want to connect to
    let target: BdAddr = BdAddr::new([0xf5, 0x9f, 0x1a, 0x05, 0xe4, 0xee]);

    info!("Scanning for peripheral...");
    let _ = join(adapter.run(), async {
        loop {
            let reports = unwrap!(adapter.scan(&config).await);
            for report in reports.iter() {
                let report = report.unwrap();
                if report.addr == target {
                    let conn = Connection::connect(&adapter, report.addr).await;
                    info!("Connected, creating l2cap channel");
                    const PAYLOAD_LEN: usize = 27;
                    let mut ch1: L2capChannel<'_, '_, _, PAYLOAD_LEN> =
                        unwrap!(L2capChannel::create(&adapter, &conn, 0x2349).await);
                    info!("New l2cap channel created, sending some data!");
                    for i in 0..10 {
                        let tx = [i; PAYLOAD_LEN];
                        unwrap!(ch1.send(&tx).await);
                    }
                    info!("Sent data, waiting for them to be sent back");
                    let mut rx = [0; PAYLOAD_LEN];
                    for i in 0..10 {
                        let len = unwrap!(ch1.receive(&mut rx).await);
                        assert_eq!(len, rx.len());
                        assert_eq!(rx, [i; PAYLOAD_LEN]);
                    }

                    info!("Received successfully!");

                    Timer::after(Duration::from_secs(60)).await;
                }
            }
        }
    })
    .await;
}
