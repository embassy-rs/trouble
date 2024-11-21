use embassy_futures::select::{select, Either};
use embassy_time::Timer;
use trouble_host::prelude::*;

/// Size of L2CAP packets (ATT MTU is this - 4)
const L2CAP_MTU: usize = 251;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 2; // Signal + att

const MAX_ATTRIBUTES: usize = 10;

type Resources<C> = HostResources<C, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, L2CAP_MTU>;

const ATTRIBUTE_DATA_SIZE: usize = 10;

// GATT Server definition
#[gatt_server(attribute_data_size = ATTRIBUTE_DATA_SIZE)]
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

/// Run the BLE stack.
pub async fn run<C>(controller: C)
where
    C: Controller,
{
    let address = Address::random([0x41, 0x5A, 0xE3, 0x1E, 0x83, 0xE7]);
    info!("Our address = {:?}", address);

    let mut resources = Resources::new(PacketQos::None);
    let (stack, mut peripheral, _, mut runner) = trouble_host::new(controller, &mut resources)
        .set_random_address(address)
        .build();

    info!("Starting advertising and GATT service");
    let server = Server::new_with_config(
        stack,
        GapConfig::Peripheral(PeripheralConfig {
            name: "TrouBLE",
            appearance: &appearance::GENERIC_POWER,
        }),
    )
    .unwrap();
    let ble_runner_task = ble_task(&mut runner);
    let app_task = async {
        loop {
            match advertise("Trouble Example", &mut peripheral).await {
                Ok(conn) => {
                    // set up tasks when the connection is established to a central, so they don't run when no one is connected.
                    let gatt = gatt_task(&server, &conn);
                    let counter_task = example_application_task(&server, &conn);
                    // run until any task ends (usually because the connection has been closed),
                    // then return to advertising state.
                    select(gatt, counter_task).await;
                }
                Err(err) => info!("[adv] error: {:?}", err),
            }
        }
    };
    select(ble_runner_task, app_task).await; // runner must run in the background forever whilst any other ble service runs.
}

async fn ble_task<C: Controller>(runner: &mut Runner<'_, C>) -> Result<(), BleHostError<C::Error>> {
    runner.run().await?;
    info!("BLE task finished");
    Ok(())
}

/// Stream Events until the connection closes.
async fn gatt_task<C: Controller>(
    server: &Server<'_, '_, C>,
    conn: &Connection<'_>,
) -> Result<(), BleHostError<C::Error>> {
    let level = server.battery_service.level;
    loop {
        if let Either::First(event) = select(conn.next(), server.run()).await {
            match event {
                ConnectionEvent::Disconnected { reason } => {
                    info!("[adv] disconnected: {:?}", reason);
                    break;
                }
                ConnectionEvent::Gatt { event, .. } => match event {
                    GattEvent::Read { value_handle } => {
                        if value_handle == level.handle {
                            let value = server.get(&level);
                            info!("[gatt] Read Event to Level Characteristic: {:?}", value);
                        }
                    }
                    GattEvent::Write { value_handle } => {
                        if value_handle == level.handle {
                            let value = server.get(&level);
                            info!("[gatt] Write Event to Level Characteristic: {:?}", value);
                        }
                    }
                },
            }
        }
    }
    info!("[gatt] task finished");
    Ok(())
}

/// Create an advertiser to use to connect to a BLE Central, and wait for it to connect.
async fn advertise<'a, C: Controller>(
    name: &'a str,
    peripheral: &mut Peripheral<'a, C>,
) -> Result<Connection<'a>, BleHostError<C::Error>> {
    let name = if name.len() > 22 {
        let truncated_name = &name[..22];
        info!("Name truncated to {}", truncated_name);
        truncated_name
    } else {
        name
    };
    let mut advertiser_data = [0; 31];
    AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::ServiceUuids16(&[Uuid::Uuid16([0x0f, 0x18])]),
            AdStructure::CompleteLocalName(name.as_bytes()),
        ],
        &mut advertiser_data[..],
    )?;
    let mut advertiser = peripheral
        .advertise(
            &Default::default(),
            Advertisement::ConnectableScannableUndirected {
                adv_data: &advertiser_data[..],
                scan_data: &[],
            },
        )
        .await?;
    info!("[adv] advertising");
    let conn = advertiser.accept().await?;
    info!("[adv] connection established");
    Ok(conn)
}

/// Example task to use the BLE notifier interface.
async fn example_application_task<C: Controller>(server: &Server<'_, '_, C>, conn: &Connection<'_>) {
    let mut tick: u8 = 0;
    let level = server.battery_service.level;
    loop {
        tick = tick.wrapping_add(1);
        info!("[adv] notifying connection of tick {}", tick);
        if let Err(err) = server.notify(&level, &conn, &tick).await {
            info!("[adv] error notifying connection: {:?}", err);
            break;
        };
        Timer::after_secs(2).await;
    }
}
