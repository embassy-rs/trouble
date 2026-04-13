#![no_std]
#![no_main]

use embassy_executor::Spawner;
use esp_hal::clock::CpuClock;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::timer::timg::TimerGroup;
use esp_radio::ble::controller::BleConnector;
use esp_storage::FlashStorage;
use trouble_example_apps::ble_bas_peripheral_bonding;
use trouble_host::prelude::ExternalController;
use {esp_alloc as _, esp_backtrace as _};

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_rtos::main]
async fn main(_s: Spawner) {
    esp_println::logger::init_logger_from_env();
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: 72 * 1024);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    #[cfg(target_arch = "riscv32")]
    let software_interrupt = esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);

    esp_rtos::start(
        timg0.timer0,
        #[cfg(target_arch = "riscv32")]
        software_interrupt.software_interrupt0,
    );

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let mut trng = Trng::try_new().unwrap();

    let bluetooth = peripherals.BT;
    let connector = BleConnector::new(bluetooth, Default::default()).unwrap();
    let controller: ExternalController<_, 20> = ExternalController::new(connector);

    let flash_storage = FlashStorage::new(peripherals.FLASH);
    use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};
    let erase_size = <FlashStorage as NorFlash>::ERASE_SIZE as u32;
    let capacity = flash_storage.capacity() as u32;
    let storage_range = (capacity - erase_size * 2)..capacity;
    let mut flash = embassy_embedded_hal::adapter::BlockingAsync::new(flash_storage);

    ble_bas_peripheral_bonding::run(controller, &mut trng, &mut flash, storage_range).await;
}
