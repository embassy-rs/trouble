#![no_std]
#![no_main]

use embassy_executor::Spawner;
use esp_hal::clock::CpuClock;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::timer::timg::TimerGroup;
use esp_radio::Controller;
use esp_radio::ble::controller::BleConnector;
use static_cell::StaticCell;
use trouble_example_apps::ble_bas_central_sec;
use trouble_host::prelude::ExternalController;
use {esp_alloc as _, esp_backtrace as _};

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_hal_embassy::main]
async fn main(_s: Spawner) {
    esp_println::logger::init_logger_from_env();
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: 72 * 1024);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_preempt::start(timg0.timer0);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1); // while alive, 'Trng::try_new()' succeeds
    let mut trng = Trng::try_new().unwrap();

    static RADIO: StaticCell<Controller<'static>> = StaticCell::new();
    let radio = RADIO.init(esp_radio::init().unwrap());

    #[cfg(not(feature = "esp32"))]
    {
        let systimer = esp_hal::timer::systimer::SystemTimer::new(peripherals.SYSTIMER);
        esp_hal_embassy::init(systimer.alarm0);
    }
    #[cfg(feature = "esp32")]
    {
        esp_hal_embassy::init(timg0.timer1);
    }

    let bluetooth = peripherals.BT;
    let connector = BleConnector::new(radio, bluetooth);
    let controller: ExternalController<_, 20> = ExternalController::new(connector);

    ble_bas_central_sec::run(controller, &mut trng).await;
}
