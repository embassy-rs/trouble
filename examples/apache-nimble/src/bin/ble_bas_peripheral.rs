#![no_main]
#![no_std]

use apache_nimble::controller::NimbleController;
use apache_nimble::controller::NimbleControllerTask;
use embassy_time::{Duration, Ticker, Timer};
use trouble_example_apps::ble_bas_peripheral;
use {defmt_rtt as _, panic_probe as _};

#[::embassy_executor::task]
async fn other_task() {
    let mut ticker = Ticker::every(Duration::from_secs(1));
    loop {
        ticker.next().await;
        defmt::info!("test");
    }
}

#[embassy_executor::main]
async fn main(spawner: embassy_executor::Spawner) {
    let mut conf = embassy_nrf::config::Config::default();
    conf.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    conf.lfclk_source = embassy_nrf::config::LfclkSource::ExternalXtal;
    embassy_nrf::init(conf);

    apache_nimble::initialize_nimble();
    let controller = NimbleController::new();

    spawner.spawn(run_controller(controller.create_task())).unwrap();

    // wait for RNG to calm down
    Timer::after(Duration::from_secs(1)).await;

    ble_bas_peripheral::run(controller).await;
}

#[embassy_executor::task]
async fn run_controller(controller_task: NimbleControllerTask) {
    controller_task.run().await
}
