use bt_hci::{cmd::status::ReadRssi, controller::ControllerCmdSync};
use embassy_futures::select::{select, select3};
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

// GATT Server definition
#[gatt_server]
struct Server {
    battery_service: BatteryService,
}

/// Battery service
#[gatt_service(uuid = service::BATTERY)]
struct BatteryService {
    /// Battery Level
    #[descriptor(uuid = descriptors::VALID_RANGE, read, value = [0, 100])]
    #[descriptor(uuid = descriptors::MEASUREMENT_DESCRIPTION, read, value = "Battery Level")]
    #[characteristic(uuid = characteristic::BATTERY_LEVEL, read, notify, value = 10)]
    level: u8,
    #[characteristic(uuid = "408813df-5dd4-1f87-ec11-cdb001100000", write, read, notify)]
    status: bool,
}

/// Run the BLE stack.
pub async fn run<C>(controller: C)
where
    C: Controller + ControllerCmdSync<ReadRssi>, // Additional trait required for the RSSI task
{
    // Using a fixed seed means the "random" address will be the same every time the program runs,
    // which can be useful for testing. If truly random addresses are required, a different,
    // dynamically generated seed should be used.
    let address = Address::random([0x41, 0x5A, 0xE3, 0x1E, 0x83, 0xE7]);
    info!("Our address = {:?}", address);

    let mut resources = Resources::new(PacketQos::None);
    let (stack, mut peripheral, _, runner) = trouble_host::new(controller, &mut resources)
        .set_random_address(address)
        .build();

    info!("Starting advertising and GATT service");
    let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: "TrouBLE",
        appearance: &appearance::power_device::GENERIC_POWER_DEVICE,
    }))
    .unwrap();
    let app_task = async {
        loop {
            match advertise("Trouble Example", &mut peripheral).await {
                Ok(conn) => {
                    // set up tasks when the connection is established to a central, so they don't run when no one is connected.
                    let connection_task = conn_task(&server, &conn);
                    let counter_task = counter_task(&server, &conn);
                    let rssi_task = report_rssi(&conn, stack);
                    // run until any task ends (usually because the connection has been closed),
                    // then return to advertising state.
                    select3(connection_task, counter_task, rssi_task).await;
                }
                Err(e) => {
                    #[cfg(feature = "defmt")]
                    let e = defmt::Debug2Format(&e);
                    panic!("[adv] error: {:?}", e);
                }
            }
        }
    };
    select(ble_task(runner), app_task).await;
}

/// This is a background task that is required to run forever alongside any other BLE tasks.
///
/// ## Alternative
///
/// If you didn't require this to be generic for your application, you could statically spawn this with i.e.
///
/// ```rust [ignore]
///
/// #[embassy_executor::task]
/// async fn ble_task(mut runner: Runner<'static, SoftdeviceController<'static>>) {
///     runner.run().await;
/// }
///
/// spawner.must_spawn(ble_task(runner));
/// ```
async fn ble_task<C: Controller>(mut runner: Runner<'_, C>) {
    loop {
        if let Err(e) = runner.run().await {
            #[cfg(feature = "defmt")]
            let e = defmt::Debug2Format(&e);
            panic!("[ble_task] error: {:?}", e);
        }
    }
}

/// Stream Events until the connection closes.
async fn conn_task(server: &Server<'_>, conn: &Connection<'_>) -> Result<(), Error> {
    let level = server.battery_service.level;
    loop {
        match conn.next().await {
            ConnectionEvent::Disconnected { reason } => {
                info!("[gatt] disconnected: {:?}", reason);
                break;
            }
            ConnectionEvent::Gatt { data } => {
                // We can choose to handle event directly without an attribute table
                // let req = data.request();
                // ..
                // data.reply(conn, Ok(AttRsp::Error { .. }))

                // But to simplify things, process it in the GATT server that handles
                // the protocol details
                match data.process(server).await {
                    // Server processing emits
                    Ok(Some(GattEvent::Read(event))) => {
                        if event.handle() == level.handle {
                            let value = server.get(&level);
                            info!("[gatt] Read Event to Level Characteristic: {:?}", value);
                        }
                    }
                    Ok(Some(GattEvent::Write(event))) => {
                        if event.handle() == level.handle {
                            info!("[gatt] Write Event to Level Characteristic: {:?}", event.data());
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("[gatt] error processing event: {:?}", e);
                    }
                }
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
    let mut advertiser_data = [0; 31];
    AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::ServiceUuids16(&[Uuid::Uuid16([0x0f, 0x18])]),
            AdStructure::CompleteLocalName(name.as_bytes()),
        ],
        &mut advertiser_data[..],
    )?;
    let advertiser = peripheral
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
async fn counter_task(server: &Server<'_>, conn: &Connection<'_>) {
    let mut tick: u8 = 0;
    let level = server.battery_service.level;
    loop {
        tick = tick.wrapping_add(1);
        info!("[adv] notifying connection of tick {}", tick);
        if level.notify(server, conn, &tick).await.is_err() {
            info!("[adv] error notifying connection");
            break;
        };
        Timer::after_secs(2).await;
    }
}

/// Example task to report the RSSI (Received Signal Strength Indicator) of the connection.
async fn report_rssi<C: Controller + ControllerCmdSync<ReadRssi>>(conn: &Connection<'_>, stack: Stack<'_, C>) {
    loop {
        match conn.rssi(stack.clone()).await {
            Ok(rssi) => info!("[gatt] RSSI: {:?}", rssi),
            Err(e) => {
                #[cfg(feature = "defmt")]
                let e = defmt::Debug2Format(&e);
                panic!("[adv] error: {:?}", e);
            }
        };
        Timer::after_secs(2).await;
    }
}
