#![no_std]
#![no_main]

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::rcc;
use embassy_stm32::{Config, bind_interrupts};
use embassy_stm32_wpan::controller::ControllerAdapter;
use embassy_stm32_wpan::{Controller, HighInterruptHandler, LowInterruptHandler, Platform, new_platform};
use trouble_example_apps::ble_bas_peripheral;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    RADIO => HighInterruptHandler;
    HASH => LowInterruptHandler;
});

/// BLE runner task - drives the BLE stack sequencer
#[embassy_executor::task]
async fn ble_runner_task(platform: &'static Platform) {
    platform.run_ble().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = Config::default();
    config.rcc = rcc::Config::new_wpan();

    let _p = embassy_stm32::init(config);
    info!("Embassy STM32WBA6 BLE Peripheral Connection Example");

    // Initialize hardware peripherals required by BLE stack
    let (platform, runtime) = new_platform!(8);

    info!("BLE platform initialized");

    // Spawn the BLE runner task (required for proper BLE operation)
    spawner.spawn(ble_runner_task(platform).expect("Failed to spawn BLE runner"));

    // Initialize BLE stack
    let ble = Controller::new(platform, runtime, Irqs)
        .await
        .expect("BLE initialization failed");

    info!("BLE stack initialized");

    let controller = ControllerAdapter::new(ble);

    ble_bas_peripheral::run(controller).await;
}
