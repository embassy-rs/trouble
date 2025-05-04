#![no_std]
#![no_main]

use defmt::{info, unwrap};
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_nrf::peripherals::RNG;
use embassy_nrf::{bind_interrupts, rng};
use embassy_time::{Duration, Instant, Timer};
use nrf_sdc::mpsl::MultiprotocolServiceLayer;
use nrf_sdc::{self as sdc, mpsl};
use static_cell::StaticCell;
use trouble_host::prelude::*;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    RNG => rng::InterruptHandler<RNG>;
    EGU0_SWI0 => nrf_sdc::mpsl::LowPrioInterruptHandler;
    CLOCK_POWER => nrf_sdc::mpsl::ClockInterruptHandler;
    RADIO => nrf_sdc::mpsl::HighPrioInterruptHandler;
    TIMER0 => nrf_sdc::mpsl::HighPrioInterruptHandler;
    RTC0 => nrf_sdc::mpsl::HighPrioInterruptHandler;
});

#[embassy_executor::task]
async fn mpsl_task(mpsl: &'static MultiprotocolServiceLayer<'static>) -> ! {
    mpsl.run().await
}

const L2CAP_TXQ: u8 = 4;
const L2CAP_RXQ: u8 = 4;
const L2CAP_MTU: usize = 251;
const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 1;

fn build_sdc<'d, const N: usize>(
    p: nrf_sdc::Peripherals<'d>,
    rng: &'d mut rng::Rng<RNG>,
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
    let mpsl_p = mpsl::Peripherals::new(p.RTC0, p.TIMER0, p.TEMP, p.PPI_CH19, p.PPI_CH30, p.PPI_CH31);
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
        p.PPI_CH17, p.PPI_CH18, p.PPI_CH20, p.PPI_CH21, p.PPI_CH22, p.PPI_CH23, p.PPI_CH24, p.PPI_CH25, p.PPI_CH26,
        p.PPI_CH27, p.PPI_CH28, p.PPI_CH29,
    );

    let mut rng = rng::Rng::new(p.RNG, Irqs);

    let mut sdc_mem = sdc::Mem::<16384>::new();
    let sdc = unwrap!(build_sdc(sdc_p, &mut rng, mpsl, &mut sdc_mem));

    let address: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
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

            const PAYLOAD_LEN: usize = L2CAP_MTU - 6;
            let config = L2capChannelConfig {
                flow_policy: CreditFlowPolicy::MinThreshold(4),
                initial_credits: Some(8),
                mtu: Some(PAYLOAD_LEN as u16),
                mps: Some(L2CAP_MTU as u16 - 4),
            };
            let mut ch1 = unwrap!(L2capChannel::accept(&stack, &conn, &[0x2349], &config).await);

            let mut rx = [0; PAYLOAD_LEN];
            for i in 0..500 {
                let len = unwrap!(ch1.receive(&stack, &mut rx).await);
                assert_eq!(len, rx.len());
                assert_eq!(rx, [(i % 255) as u8; PAYLOAD_LEN]);
            }

            info!("echoing l2ap data");
            Timer::after(Duration::from_secs(1)).await;
            let mut last = Instant::now();
            let mut bytes: u64 = 0;
            for i in 0..500 {
                let tx = [(i % 255) as u8; PAYLOAD_LEN];
                unwrap!(ch1.send(&stack, &tx).await);
                bytes += PAYLOAD_LEN as u64;
                let duration = Instant::now() - last;
                if duration.as_secs() > 10 {
                    info!("throughput: {} bytes/sec", bytes / duration.as_secs());
                    bytes = 0;
                    last = Instant::now();
                }
            }
            info!("done");
            Timer::after(Duration::from_secs(2)).await;
            break;
        }
    })
    .await;
}
