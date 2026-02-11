#![no_std]
#![no_main]

use cyw43_pio::PioSpi;
#[cfg(not(feature = "skip-cyw43-firmware"))]
use cyw43::aligned_bytes;
use defmt::*;
use embassy_executor::Spawner;
use embassy_rp::{bind_interrupts, dma};
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::{DMA_CH0, PIO0};
use embassy_rp::pio::{InterruptHandler, Pio};
use static_cell::StaticCell;
use trouble_example_apps::ble_beacon;
use trouble_host::prelude::ExternalController;
use {defmt_rtt as _, embassy_time as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => InterruptHandler<PIO0>;
    DMA_IRQ_0 => dma::InterruptHandler<DMA_CH0>;
});

#[embassy_executor::task]
async fn cyw43_task(runner: cyw43::Runner<'static, cyw43::SpiBus<Output<'static>, PioSpi<'static, PIO0, 0>>>) -> ! {
    runner.run().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    #[cfg(feature = "skip-cyw43-firmware")]
    let (fw, clm, btfw, nvram) = {
        static EMPTY: &cyw43::Aligned<cyw43::A4, [u8]> = &cyw43::Aligned([0u8; 0]);
        (EMPTY, &[] as &[u8], EMPTY, EMPTY)
    };

    #[cfg(not(feature = "skip-cyw43-firmware"))]
    let (fw, clm, btfw, nvram) = {
        // IMPORTANT
        //
        // Download and make sure these files from https://github.com/embassy-rs/embassy/tree/main/cyw43-firmware
        // are available in `./examples/rp-pico-w`. (should be automatic)
        //
        // IMPORTANT
        let fw = aligned_bytes!("../../cyw43-firmware/43439A0.bin");
        let clm = aligned_bytes!("../../cyw43-firmware/43439A0_clm.bin");
        let btfw = aligned_bytes!("../../cyw43-firmware/43439A0_btfw.bin");
        let nvram = aligned_bytes!("../../cyw43-firmware/nvram_rp2040.bin");
        (fw, clm, btfw, nvram)
    };

    let pwr = Output::new(p.PIN_23, Level::Low);
    let cs = Output::new(p.PIN_25, Level::High);
    let mut pio = Pio::new(p.PIO0, Irqs);
    let spi = PioSpi::new(
        &mut pio.common,
        pio.sm0,
        cyw43_pio::DEFAULT_CLOCK_DIVIDER,
        pio.irq0,
        cs,
        p.PIN_24,
        p.PIN_29,
        dma::Channel::new(p.DMA_CH0, Irqs),
    );

    static STATE: StaticCell<cyw43::State> = StaticCell::new();
    let state = STATE.init(cyw43::State::new());
    let (_net_device, bt_device, mut control, runner) = cyw43::new_with_bluetooth(state, pwr, spi, fw, btfw, nvram).await;
    spawner.spawn(unwrap!(cyw43_task(runner)));
    control.init(clm).await;

    let controller: ExternalController<_, 10> = ExternalController::new(bt_device);

    ble_beacon::run(controller).await;
}
