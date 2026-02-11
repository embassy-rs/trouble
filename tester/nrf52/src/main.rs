#![no_std]
#![no_main]

extern crate alloc;

use defmt::{info, unwrap};
use embassy_executor::Spawner;
use embassy_nrf::buffered_uarte::{self, BufferedUarte};
use embassy_nrf::mode::Async;
use embassy_nrf::peripherals::{self, RNG};
use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
use embassy_nrf::{bind_interrupts, rng, usb};
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embedded_alloc::LlffHeap as Heap;
use nrf_sdc::mpsl::MultiprotocolServiceLayer;
use nrf_sdc::{self as sdc, mpsl};
use panic_probe as _;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use static_cell::StaticCell;
use trouble_host::prelude::*;
use trouble_tester_app::BtpConfig;

mod defmt_usb;

#[global_allocator]
static HEAP: Heap = Heap::empty();

bind_interrupts!(struct Irqs {
    RNG => rng::InterruptHandler<RNG>;
    UARTE0 => embassy_nrf::buffered_uarte::InterruptHandler<embassy_nrf::peripherals::UARTE0>;
    USBD => usb::InterruptHandler<peripherals::USBD>;
    CLOCK_POWER => nrf_sdc::mpsl::ClockInterruptHandler, usb::vbus_detect::InterruptHandler;
    EGU0_SWI0 => nrf_sdc::mpsl::LowPrioInterruptHandler;
    RADIO => nrf_sdc::mpsl::HighPrioInterruptHandler;
    TIMER0 => nrf_sdc::mpsl::HighPrioInterruptHandler;
    RTC0 => nrf_sdc::mpsl::HighPrioInterruptHandler;
});

#[embassy_executor::task]
async fn mpsl_task(mpsl: &'static MultiprotocolServiceLayer<'static>) -> ! {
    mpsl.run().await
}

type UsbDriver = usb::Driver<'static, HardwareVbusDetect>;

#[embassy_executor::task]
async fn usb_task(driver: UsbDriver) -> ! {
    static CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static MSOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
    static STATE: StaticCell<State> = StaticCell::new();

    let mut config = embassy_usb::Config::new(0xc0de, 0xcafe);
    config.manufacturer = Some("Tactile Engineering");
    config.product = Some("TrouBLE-Tester defmt");
    config.serial_number = Some("1");
    config.max_power = 100;
    config.max_packet_size_0 = 64;

    let mut builder = embassy_usb::Builder::new(
        driver,
        config,
        CONFIG_DESCRIPTOR.init([0; 256]),
        BOS_DESCRIPTOR.init([0; 256]),
        MSOS_DESCRIPTOR.init([0; 256]),
        CONTROL_BUF.init([0; 64]),
    );

    let class = CdcAcmClass::new(&mut builder, STATE.init(State::new()), 64);
    let mut usb = builder.build();

    let (mut sender, _receiver, control) = class.split_with_control();

    let usb_fut = usb.run();
    let drain_fut = async {
        let mut buf = [0u8; 64];
        loop {
            // Wait for USB endpoint to be enabled (device configured)
            sender.wait_connection().await;

            // Wait for host to open the port (DTR set)
            while !control.dtr() {
                control.control_changed().await;
            }

            // Race data pipeline against DTR drop
            embassy_futures::select::select(
                async {
                    loop {
                        let n = defmt_usb::read(&mut buf).await;
                        if sender.write_packet(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                },
                async {
                    loop {
                        control.control_changed().await;
                        if !control.dtr() {
                            return;
                        }
                    }
                },
            )
            .await;
        }
    };

    embassy_futures::join::join(usb_fut, drain_fut).await;
    unreachable!()
}

/// How many outgoing L2CAP buffers per link
const L2CAP_TXQ: u8 = 3;

/// How many incoming L2CAP buffers per link
const L2CAP_RXQ: u8 = 3;

fn build_sdc<'d, const N: usize>(
    p: nrf_sdc::Peripherals<'d>,
    rng: &'d mut rng::Rng<Async>,
    mpsl: &'d MultiprotocolServiceLayer,
    mem: &'d mut sdc::Mem<N>,
) -> Result<nrf_sdc::SoftdeviceController<'d>, nrf_sdc::Error> {
    sdc::Builder::new()?
        .support_adv()
        .support_scan()
        .support_peripheral()
        .support_central()
        .peripheral_count(1)?
        .central_count(1)?
        .buffer_cfg(
            DefaultPacketPool::MTU as u16,
            DefaultPacketPool::MTU as u16,
            L2CAP_TXQ,
            L2CAP_RXQ,
        )?
        .build(p, rng, mpsl, mem)
}

#[embassy_executor::main]
async fn main(spawner: Spawner) -> ! {
    unsafe {
        embedded_alloc::init!(HEAP, 8192);
    }

    let mut cfg = embassy_nrf::config::Config::default();
    cfg.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    cfg.lfclk_source = embassy_nrf::config::LfclkSource::ExternalXtal;
    cfg.dcdc = embassy_nrf::config::DcdcConfig {
        reg0: true,
        reg0_voltage: None,
        reg1: true,
    };
    cfg.gpiote_interrupt_priority = embassy_nrf::interrupt::Priority::P2;
    cfg.time_interrupt_priority = embassy_nrf::interrupt::Priority::P2;

    let p = embassy_nrf::init(cfg);

    let usb_driver = usb::Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));
    spawner.spawn(unwrap!(usb_task(usb_driver)));

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
    spawner.spawn(unwrap!(mpsl_task(&*mpsl)));

    let sdc_p = sdc::Peripherals::new(
        p.PPI_CH17, p.PPI_CH18, p.PPI_CH20, p.PPI_CH21, p.PPI_CH22, p.PPI_CH23, p.PPI_CH24, p.PPI_CH25, p.PPI_CH26,
        p.PPI_CH27, p.PPI_CH28, p.PPI_CH29,
    );

    let mut rng = rng::Rng::new(p.RNG, Irqs);
    let chacha_rng = ChaCha12Rng::from_rng(&mut rng).unwrap();

    let mut sdc_mem = sdc::Mem::<5872>::new();
    let sdc = unwrap!(build_sdc(sdc_p, &mut rng, mpsl, &mut sdc_mem));

    let mut uart_config = embassy_nrf::uarte::Config::default();
    uart_config.baudrate = buffered_uarte::Baudrate::BAUD115200;
    uart_config.parity = buffered_uarte::Parity::EXCLUDED;
    static RX_BUF: StaticCell<[u8; 512]> = StaticCell::new();
    static TX_BUF: StaticCell<[u8; 512]> = StaticCell::new();
    let rx_buf = RX_BUF.init([0u8; 512]);
    let tx_buf = TX_BUF.init([0u8; 512]);
    let uart = BufferedUarte::new_with_rtscts(
        p.UARTE0,
        p.TIMER1,
        p.PPI_CH0,
        p.PPI_CH1,
        p.PPI_GROUP0,
        p.P0_08,
        p.P0_06,
        p.P0_05,
        p.P0_07,
        Irqs,
        uart_config,
        rx_buf,
        tx_buf,
    );
    let (rx, tx) = uart.split();

    let ficr = embassy_nrf::pac::FICR;
    let mut addr = [0u8; 6];
    let lo = ficr.deviceaddr(0).read();
    let hi = ficr.deviceaddr(1).read();
    addr[0..4].copy_from_slice(&lo.to_le_bytes());
    addr[4..6].copy_from_slice(&hi.to_le_bytes()[0..2]);
    addr[5] |= 0xC0;
    let address = Address::random(addr);
    info!("Address: {}", address);

    let res = trouble_tester_app::run(
        sdc,
        rx,
        tx,
        BtpConfig {
            address,
            device_name: "TrouBLE-Tester",
            appearance: bt_hci::uuid::appearance::UNKNOWN,
        },
        chacha_rng,
    )
    .await;

    if let Err(err) = res {
        defmt::error!("BTP error: {:?}", err);
        // Give USB time to flush the error message before resetting.
        embassy_time::Timer::after_millis(500).await;
    }

    cortex_m::peripheral::SCB::sys_reset();
}
