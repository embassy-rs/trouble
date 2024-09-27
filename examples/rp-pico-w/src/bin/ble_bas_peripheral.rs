#![no_std]
#![no_main]

use bt_hci::controller::ExternalController;
use cyw43_pio::PioSpi;
use defmt::*;
use embassy_executor::Spawner;
use embassy_rp::bind_interrupts;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::{DMA_CH0, PIO0};
use embassy_rp::pio::{InterruptHandler, Pio};
use static_cell::StaticCell;
use trouble_example_apps::ble_bas_peripheral;
use {defmt_rtt as _, embassy_time as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => InterruptHandler<PIO0>;
});

#[embassy_executor::task]
async fn cyw43_task(runner: cyw43::Runner<'static, Output<'static>, PioSpi<'static, PIO0, 0, DMA_CH0>>) -> ! {
    runner.run().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    //
    // IMPORTANT
    //
    // Download and make sure these files from https://github.com/embassy-rs/embassy/tree/main/cyw43-firmware
    // are available in the below path.
    //
    // IMPORTANT
    //

    #[cfg(feature = "skip-cyw43-firmware")]
    let fw = &[];
    let clm = &[];
    let btfw = &[];

    #[cfg(not(feature = "skip-cyw43-firmware"))]
    let fw = include_bytes!("../../cyw43-firmware/43439A0.bin");
    #[cfg(not(feature = "skip-cyw43-firmware"))]
    let clm = include_bytes!("../../cyw43-firmware/43439A0_clm.bin");
    #[cfg(not(feature = "skip-cyw43-firmware"))]
    let btfw = include_bytes!("../../cyw43-firmware/43439A0_btfw.bin");

    let pwr = Output::new(p.PIN_23, Level::Low);
    let cs = Output::new(p.PIN_25, Level::High);
    let mut pio = Pio::new(p.PIO0, Irqs);
    let spi = PioSpi::new(&mut pio.common, pio.sm0, pio.irq0, cs, p.PIN_24, p.PIN_29, p.DMA_CH0);

    static STATE: StaticCell<cyw43::State> = StaticCell::new();
    let state = STATE.init(cyw43::State::new());
    let (_net_device, bt_device, mut control, runner) = cyw43::new_with_bluetooth(state, pwr, spi, fw, btfw).await;
    unwrap!(spawner.spawn(cyw43_task(runner)));
    control.init(clm).await;

    let controller: ExternalController<_, 10> = ExternalController::new(bt_device);

    ble_bas_peripheral::run(controller).await;
}
