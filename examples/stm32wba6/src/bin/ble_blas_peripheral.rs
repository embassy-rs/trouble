#![no_std]
#![no_main]

use core::cell::RefCell;

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::aes::{self, Aes};
use embassy_stm32::mode::Blocking;
use embassy_stm32::peripherals::{AES, PKA, RNG};
use embassy_stm32::pka::{self, Pka};
use embassy_stm32::rcc::{
    AHB5Prescaler, AHBPrescaler, APBPrescaler, Hse, HsePrescaler, LsConfig, LseConfig, LseDrive, LseMode, PllDiv,
    PllMul, PllPreDiv, PllSource, RtcClockSource, Sysclk, VoltageScale, mux,
};
use embassy_stm32::rng::{self, Rng};
use embassy_stm32::time::Hertz;
use embassy_stm32::{Config, bind_interrupts};
use embassy_stm32_wpan::controller::ControllerAdapter;
use embassy_stm32_wpan::{Controller, HighInterruptHandler, LowInterruptHandler, ble_runner, new_controller_state};
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use static_cell::StaticCell;
use trouble_example_apps::ble_bas_peripheral;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    RNG => rng::InterruptHandler<RNG>;
    AES => aes::InterruptHandler<AES>;
    PKA => pka::InterruptHandler<PKA>;
    RADIO => HighInterruptHandler;
    HASH => LowInterruptHandler;
});

/// BLE runner task - drives the BLE stack sequencer
#[embassy_executor::task]
async fn ble_runner_task() {
    ble_runner().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = Config::default();

    // Enable HSE (32 MHz external crystal) - REQUIRED for BLE radio
    config.rcc.hse = Some(Hse {
        prescaler: HsePrescaler::Div1,
    });

    // Enable LSE (32.768 kHz external crystal) - REQUIRED for BLE radio sleep timer
    config.rcc.ls = LsConfig {
        rtc: RtcClockSource::Lse,
        lsi: false,
        lse: Some(LseConfig {
            frequency: Hertz(32_768),
            mode: LseMode::Oscillator(LseDrive::MediumLow),
            peripherals_clocked: true,
        }),
    };

    // Configure PLL1 from HSE for system clock
    // HSE = 32MHz (fixed for WBA), using prescaler DIV1 gives 32MHz to PLL
    config.rcc.pll1 = Some(embassy_stm32::rcc::Pll {
        source: PllSource::Hse,   // Use HSE as PLL source
        prediv: PllPreDiv::Div2,  // 32MHz / 2 = 16MHz to PLL input (must be 4-16MHz)
        mul: PllMul::Mul12,       // 16MHz * 12 = 192MHz VCO
        divr: Some(PllDiv::Div2), // 192MHz / 2 = 96MHz system clock
        divq: None,
        divp: Some(PllDiv::Div12), // 192MHz / 12 = 16MHz for peripherals
        frac: Some(0),
    });

    config.rcc.ahb_pre = AHBPrescaler::Div1;
    config.rcc.apb1_pre = APBPrescaler::Div1;
    config.rcc.apb2_pre = APBPrescaler::Div1;
    config.rcc.apb7_pre = APBPrescaler::Div1;
    config.rcc.ahb5_pre = AHB5Prescaler::Div4;
    config.rcc.voltage_scale = VoltageScale::Range1;
    config.rcc.sys = Sysclk::Pll1R;
    config.rcc.mux.rngsel = mux::Rngsel::Hsi; // RNG can still use HSI

    let p = embassy_stm32::init(config);
    info!("Embassy STM32WBA6 BLE Peripheral Connection Example");

    // Apply HSE trimming for accurate radio frequency (matching ST's Config_HSE)
    // and configure radio sleep timer to use LSE
    {
        use embassy_stm32::pac::RCC;
        use embassy_stm32::pac::rcc::vals::Radiostsel;
        RCC.ecscr1().modify(|w| w.set_hsetrim(0x0C));
        RCC.bdcr().modify(|w| w.set_radiostsel(Radiostsel::Lse));
    }

    // Initialize hardware peripherals required by BLE stack
    static RNG_INST: StaticCell<Mutex<CriticalSectionRawMutex, RefCell<Rng<'static, RNG>>>> = StaticCell::new();
    let rng = RNG_INST.init(Mutex::new(RefCell::new(Rng::new(p.RNG, Irqs))));

    static AES_INST: StaticCell<Mutex<CriticalSectionRawMutex, RefCell<Aes<'static, AES, Blocking>>>> =
        StaticCell::new();
    let aes = AES_INST.init(Mutex::new(RefCell::new(Aes::new_blocking(p.AES, Irqs))));

    static PKA_INST: StaticCell<Mutex<CriticalSectionRawMutex, RefCell<Pka<'static, PKA>>>> = StaticCell::new();
    let pka = PKA_INST.init(Mutex::new(RefCell::new(Pka::new_blocking(p.PKA, Irqs))));

    info!("Hardware peripherals initialized (RNG, AES, PKA)");

    // Spawn the BLE runner task (required for proper BLE operation)
    spawner.spawn(ble_runner_task().expect("Failed to spawn BLE runner"));

    // Initialize BLE stack
    let ble = Controller::new(new_controller_state!(8), rng, Some(aes), Some(pka), Irqs)
        .await
        .expect("BLE initialization failed");

    info!("create controller");

    let controller = ControllerAdapter::new(ble);

    ble_bas_peripheral::run(controller).await;
}
