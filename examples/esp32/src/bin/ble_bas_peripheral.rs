#![no_std]
#![no_main]

use bt_hci::controller::ExternalController;
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::{Duration, Timer};
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::prelude::*;
use esp_hal::timer::timg::TimerGroup;
use esp_wifi::ble::controller::asynch::BleConnector;
use esp_wifi::EspWifiInitialization;
use log::{error, info};
use static_cell::StaticCell;
use trouble_host::prelude::*;

/// Size of L2CAP packets (ATT MTU is this - 4)
const L2CAP_MTU: usize = 251;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 2; // Signal + att

const MAX_ATTRIBUTES: usize = 10;

type Hci = ExternalController<BleConnector<'static>, 20>;
type Resources = HostResources<Hci, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, L2CAP_MTU>;

#[esp_hal_embassy::main]
async fn main(s: Spawner) {
    esp_println::logger::init_logger_from_env();
    let peripherals = esp_hal::init({
        let mut config = esp_hal::Config::default();
        config.cpu_clock = CpuClock::max();
        config
    });
    esp_alloc::heap_allocator!(72 * 1024);
    let timg0 = TimerGroup::new(peripherals.TIMG0);

    let init = esp_wifi::initialize(
        esp_wifi::EspWifiInitFor::Ble,
        timg0.timer0,
        esp_hal::rng::Rng::new(peripherals.RNG),
        peripherals.RADIO_CLK,
    )
    .unwrap();

    let systimer =
        esp_hal::timer::systimer::SystemTimer::new(peripherals.SYSTIMER).split::<esp_hal::timer::systimer::Target>();
    esp_hal_embassy::init(systimer.alarm0);

    let bluetooth = peripherals.BT;
    static INIT: StaticCell<EspWifiInitialization> = StaticCell::new();
    static BLE: StaticCell<esp_hal::peripherals::BT> = StaticCell::new();
    let init = INIT.init(init);
    let bluetooth = BLE.init(bluetooth);
    let connector = BleConnector::new(init, bluetooth);
    let controller: ExternalController<_, 20> = ExternalController::new(connector);

    let address = Address::random([0x41, 0x5A, 0xE3, 0x1E, 0x83, 0xE7]);
    info!("Our address = {:?}", address);

    static RESOURCES: StaticCell<Resources> = StaticCell::new();
    let resources = RESOURCES.init(Resources::new(PacketQos::None));
    let (stack, peripheral, _, runner) = trouble_host::new(controller, resources)
        .set_random_address(address)
        .build();

    let mut table: AttributeTable<'_, NoopRawMutex, MAX_ATTRIBUTES> = AttributeTable::new();

    // Generic Access Service (mandatory)
    let id = b"Trouble";
    let appearance = &[0x80, 0x07];
    let mut svc = table.add_service(Service::new(0x1800));
    let _ = svc.add_characteristic_ro(0x2a00, id);
    let _ = svc.add_characteristic_ro(0x2a01, appearance);
    svc.build();

    // Generic attribute service (mandatory)
    table.add_service(Service::new(0x1801));

    // Battery service
    static BAT: StaticCell<[u8; 1]> = StaticCell::new();
    let bat_level = [23; 1];
    let bat_level = BAT.init(bat_level);
    let level_handle = table
        .add_service(Service::new(0x180f))
        .add_characteristic(
            0x2a19,
            &[CharacteristicProp::Read, CharacteristicProp::Notify],
            bat_level,
        )
        .build();

    static TABLE: StaticCell<AttributeTable<'static, NoopRawMutex, MAX_ATTRIBUTES>> = StaticCell::new();
    let table = TABLE.init(table);
    let server = GattServer::<Hci, NoopRawMutex, MAX_ATTRIBUTES, L2CAP_MTU>::new(stack, table);

    info!("Starting advertising and GATT service");
    let (ble_rx, ble_ctrl, ble_tx) = runner.split();
    s.spawn(ble_rx_task(ble_rx)).unwrap();
    s.spawn(ble_tx_task(ble_tx)).unwrap();
    s.spawn(ble_ctrl_task(ble_ctrl)).unwrap();
    let _ = join(
        gatt_task(&server, &table),
        advertise_task(peripheral, &server, level_handle),
    )
    .await;
}

#[embassy_executor::task]
async fn ble_rx_task(mut runner: RxRunner<'static, Hci>) {
    runner.run().await.unwrap();
}

#[embassy_executor::task]
async fn ble_tx_task(mut runner: TxRunner<'static, Hci>) {
    runner.run().await.unwrap();
}

#[embassy_executor::task]
async fn ble_ctrl_task(mut runner: ControlRunner<'static, Hci>) {
    runner.run().await.unwrap();
}

async fn gatt_task<C: Controller>(
    server: &GattServer<'_, '_, C, NoopRawMutex, MAX_ATTRIBUTES, L2CAP_MTU>,
    table: &AttributeTable<'_, NoopRawMutex, MAX_ATTRIBUTES>,
) {
    loop {
        match server.next().await {
            Ok(GattEvent::Write { handle, connection: _ }) => {
                let _ = table.get(handle, |value| {
                    info!("[gatt] Write event on {:?}. Value written: {:?}", handle, value);
                });
            }
            Ok(GattEvent::Read { handle, connection: _ }) => {
                info!("[gatt] Read event on {:?}", handle);
            }
            Err(e) => {
                error!("[gatt] Error processing GATT events: {:?}", e);
            }
        }
    }
}

async fn advertise_task<C: Controller>(
    mut peripheral: Peripheral<'_, C>,
    server: &GattServer<'_, '_, C, NoopRawMutex, MAX_ATTRIBUTES, L2CAP_MTU>,
    handle: Characteristic,
) -> Result<(), BleHostError<C::Error>> {
    let mut adv_data = [0; 31];
    AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::ServiceUuids16(&[Uuid::Uuid16([0x0f, 0x18])]),
            AdStructure::CompleteLocalName(b"Trouble"),
        ],
        &mut adv_data[..],
    )?;
    loop {
        info!("[adv] advertising");
        let mut advertiser = peripheral
            .advertise(
                &Default::default(),
                Advertisement::ConnectableScannableUndirected {
                    adv_data: &adv_data[..],
                    scan_data: &[],
                },
            )
            .await?;
        let conn = advertiser.accept().await?;
        info!("[adv] connection established");
        // Keep connection alive
        let mut tick: u8 = 0;
        while conn.is_connected() {
            Timer::after(Duration::from_secs(2)).await;
            tick = tick.wrapping_add(1);
            info!("[adv] notifying connection of tick {}", tick);
            let _ = server.notify(handle, &conn, &[tick]).await;
        }
    }
}
