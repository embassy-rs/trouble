#![no_std]
#![no_main]

use embassy_executor::Spawner;
use esp_hal::clock::CpuClock;
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::timer::timg::TimerGroup;
use trouble_esp32_wokwi::hci_uart;
use trouble_example_apps::ble_bas_peripheral;
use esp_backtrace as _;

esp_bootloader_esp_idf::esp_app_desc!();

/// Battery service peripheral over external HCI UART (Wokwi → socat → Bumble → BlueZ).
#[esp_rtos::main]
async fn main(_s: Spawner) {
    esp_println::logger::init_logger_from_env();
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: 72 * 1024);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    let controller = hci_uart::init_hci_uart(peripherals.UART0, peripherals.GPIO21, peripherals.GPIO20);

    ble_bas_peripheral::run(controller).await;
}
