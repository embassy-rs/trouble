#![no_std]
#![no_main]
use bt_hci::driver::{HciController, HciDriver};
use bt_hci::{
    data, param, Controller, ControllerCmdAsync, ControllerCmdSync, ControllerToHostPacket, FromHciBytes, PacketKind,
    ReadHci, WithIndicator, WriteHci,
};
use core::cell::RefCell;
use core::future::{pending, Future};
use core::ops::DerefMut;
use cyw43_pio::PioSpi;
use defmt::{assert_eq, todo, *};
use embassy_executor::{Executor, Spawner};
use embassy_futures::join::join3;
use embassy_futures::yield_now;
use embassy_rp::bind_interrupts;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::{DMA_CH0, PIO0};
use embassy_rp::pio::{InterruptHandler, Pio};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, Timer};
use embedded_io_async::Read;
use static_cell::StaticCell;
use trouble_host::adapter::{Adapter, HostResources};
use trouble_host::advertise::{AdStructure, AdvertiseConfig, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE};
use trouble_host::attribute::{AttributeTable, CharacteristicProp, Service, Uuid};
use trouble_host::PacketQos;
use {defmt_rtt as _, embassy_time as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => InterruptHandler<PIO0>;
});

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());
    let fw = include_bytes!("../../../../embassy/cyw43-firmware/43439A0.bin");
    let clm = include_bytes!("../../../../embassy/cyw43-firmware/43439A0_clm.bin");
    let btfw = include_bytes!("../../../../embassy/cyw43-firmware/43439A0_btfw.bin");

    // To make flashing faster for development, you may want to flash the firmwares independently
    // at hardcoded addresses, instead of baking them into the program with `include_bytes!`:
    //     probe-rs download 43439A0.bin --format bin --chip RP2040 --base-address 0x10100000
    //     probe-rs download 43439A0_clm.bin --format bin --chip RP2040 --base-address 0x10140000
    //let fw = unsafe { core::slice::from_raw_parts(0x10100000 as *const u8, 224190) };
    //let clm = unsafe { core::slice::from_raw_parts(0x10140000 as *const u8, 4752) };

    let pwr = Output::new(p.PIN_23, Level::Low);
    let cs = Output::new(p.PIN_25, Level::High);
    let mut pio = Pio::new(p.PIO0, Irqs);
    let spi = PioSpi::new(&mut pio.common, pio.sm0, pio.irq0, cs, p.PIN_24, p.PIN_29, p.DMA_CH0);

    static STATE: StaticCell<cyw43::State> = StaticCell::new();
    let state = STATE.init(cyw43::State::new());
    let (_net_device, mut control, runner) = cyw43::new_with_bluetooth(state, pwr, spi, fw, btfw).await;

    let driver = PicoWController::new(runner);
    let controller: HciController<_, 10> = HciController::new(driver);
    static HOST_RESOURCES: StaticCell<HostResources<NoopRawMutex, 4, 32, 27>> = StaticCell::new();
    let host_resources = HOST_RESOURCES.init(HostResources::new(PacketQos::None));

    let adapter: Adapter<'_, NoopRawMutex, _, 2, 4, 1, 1> = Adapter::new(controller, host_resources);
    let config = AdvertiseConfig {
        params: None,
        data: &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::ServiceUuids16(&[Uuid::Uuid16([0x0f, 0x18])]),
            AdStructure::CompleteLocalName("Trouble PicoW"),
        ],
    };

    let mut table: AttributeTable<'_, NoopRawMutex, 10> = AttributeTable::new();

    // Generic Access Service (mandatory)
    let id = b"Trouble PicoW";
    let appearance = [0x80, 0x07];
    let mut bat_level = [0; 1];
    let handle = {
        let mut svc = table.add_service(Service::new(0x1800));
        let _ = svc.add_characteristic_ro(0x2a00, id);
        let _ = svc.add_characteristic_ro(0x2a01, &appearance[..]);
        drop(svc);

        // Generic attribute service (mandatory)
        table.add_service(Service::new(0x1801));

        // Battery service
        let mut svc = table.add_service(Service::new(0x180f));

        svc.add_characteristic(
            0x2a19,
            &[CharacteristicProp::Read, CharacteristicProp::Notify],
            &mut bat_level,
        )
    };

    let server = adapter.gatt_server(&table);

    info!("Starting advertising and GATT service");
    let _ = join3(
        adapter.run(),
        async {
            loop {
                match server.next().await {
                    Ok(event) => {
                        info!("Gatt event: {:?}", event);
                    }
                    Err(e) => {
                        error!("Error processing GATT events: {:?}", e);
                    }
                }
            }
        },
        async {
            let conn = adapter.advertise(&config).await.unwrap();
            // Keep connection alive
            let mut tick: u8 = 0;
            loop {
                Timer::after(Duration::from_secs(10)).await;
                tick += 1;
                server.notify(handle, &conn, &[tick]).await.unwrap();
            }
        },
    )
    .await;
}

struct PicoWController {
    runner: Mutex<NoopRawMutex, cyw43::Runner<'static, Output<'static>, PioSpi<'static, PIO0, 0, DMA_CH0>>>,
}

impl PicoWController {
    pub fn new(runner: cyw43::Runner<'static, Output<'static>, PioSpi<'static, PIO0, 0, DMA_CH0>>) -> Self {
        Self {
            runner: Mutex::new(runner),
        }
    }
}

#[derive(Debug, defmt::Format)]
pub struct Error;

impl embedded_io::Error for Error {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

impl HciDriver for PicoWController {
    type Error = Error;
    fn read(&self, rx: &mut [u8]) -> impl Future<Output = Result<usize, Self::Error>> {
        async {
            let mut runner = self.runner.lock().await;
            let n = runner.hci_read(rx).await as usize;
            Ok(n)
        }
    }

    fn write(&self, tx: &[u8]) -> impl Future<Output = Result<(), Self::Error>> {
        async {
            let mut runner = self.runner.lock().await;
            runner.hci_write(tx).await;
            Ok(())
        }
    }
}
