use embassy_futures::join::join3;
use embassy_time::{Duration, Timer};
use trouble_host::prelude::*;

/// Size of L2CAP packets (ATT MTU is this - 4)
const L2CAP_MTU: usize = 251;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 2; // Signal + att

const MAX_ATTRIBUTES: usize = 10;

type Resources<C> = HostResources<C, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, L2CAP_MTU>;

// GATT Server definition
#[gatt_server(attribute_data_size = 10)]
struct Server {
    battery_service: BatteryService,
}

// Battery service
#[gatt_service(uuid = "180f")]
struct BatteryService {
    #[characteristic(uuid = "2a19", read, write, notify, on_read = battery_level_on_read, on_write = battery_level_on_write)]
    level: u8,
}

fn battery_level_on_read(_connection: &Connection) {
    info!("[gatt] Read event on battery level characteristic");
}

fn battery_level_on_write(_connection: &Connection, data: &[u8]) -> Result<(), ()> {
    info!("[gatt] Write event on battery level characteristic: {:?}", data);
    Ok(())
}

pub async fn run<C>(controller: C)
where
    C: Controller,
{
    let address = Address::random([0x41, 0x5A, 0xE3, 0x1E, 0x83, 0xE7]);
    info!("Our address = {:?}", address);

    let mut resources = Resources::new(PacketQos::None);
    let (stack, peripheral, _, runner) = trouble_host::new(controller, &mut resources)
        .set_random_address(address)
        .build();

    let server = Server::new_with_config(
        stack,
        GapConfig::Peripheral(PeripheralConfig {
            name: "TrouBLE",
            appearance: &appearance::GENERIC_POWER,
        }),
    )
    .unwrap();

    info!("Starting advertising and GATT service");
    let _ = join3(
        ble_task(runner),
        gatt_task(&server),
        advertise_task(peripheral, &server),
    )
    .await;
}

async fn ble_task<C: Controller>(mut runner: Runner<'_, C>) -> Result<(), BleHostError<C::Error>> {
    runner.run().await
}

async fn gatt_task<C: Controller>(server: &Server<'_, '_, C>) {
    loop {
        match server.next().await {
            Ok(GattEvent::Write {
                value_handle,
                connection: _,
            }) => {
                info!("[gatt] Write event on {:?}", value_handle);
            }
            Ok(GattEvent::Read {
                value_handle,
                connection: _,
            }) => {
                info!("[gatt] Read event on {:?}", value_handle);
            }
            Err(e) => {
                error!("[gatt] Error processing GATT events: {:?}", e);
            }
        }
    }
}

async fn advertise_task<C: Controller>(
    mut peripheral: Peripheral<'_, C>,
    server: &Server<'_, '_, C>,
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
            let _ = server.notify(&server.battery_service.level, &conn, &tick).await;
        }
    }
}
