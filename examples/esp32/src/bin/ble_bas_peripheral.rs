#![no_std]
#![no_main]

use bt_hci::controller::ExternalController;
use embassy_executor::Spawner;
use esp_backtrace as _;
use esp_hal::clock::ClockControl;
use esp_hal::peripherals::Peripherals;
use esp_hal::system::SystemControl;
use esp_hal::timer::timg::TimerGroup;
use esp_wifi::ble::controller::asynch::BleConnector;
use trouble_example_apps::ble_bas_peripheral;

#[esp_hal_embassy::main]
async fn main(_s: Spawner) {
    esp_println::logger::init_logger_from_env();
    let peripherals = Peripherals::take();
    let system = SystemControl::new(peripherals.SYSTEM);
    let clocks = ClockControl::max(system.clock_control).freeze();

    let timg0 = TimerGroup::new(peripherals.TIMG0, &clocks);

    let init = esp_wifi::initialize(
        esp_wifi::EspWifiInitFor::Ble,
        timg0.timer0,
        esp_hal::rng::Rng::new(peripherals.RNG),
        peripherals.RADIO_CLK,
        &clocks,
    )
    .unwrap();

    let systimer =
        esp_hal::timer::systimer::SystemTimer::new(peripherals.SYSTIMER).split::<esp_hal::timer::systimer::Target>();
    esp_hal_embassy::init(&clocks, systimer.alarm0);

    let mut bluetooth = peripherals.BT;
    let connector = BleConnector::new(&init, &mut bluetooth);
    let controller: ExternalController<_, 20> = ExternalController::new(connector);

    ble_bas_peripheral::run(controller).await;
}
