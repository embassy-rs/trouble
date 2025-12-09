use embassy_futures::join::join;
use embassy_futures::select::select;
use embassy_time::Timer;
use trouble_host::prelude::*;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 2; // Signal + att

// GATT Server definition
#[gatt_server]
struct Server {
    battery_service: BatteryService,
}

/// Battery service with callback-based characteristics
#[gatt_service(uuid = service::BATTERY)]
struct BatteryService {
    /// Battery Level - callback-based (no storage!)
    #[characteristic(uuid = characteristic::BATTERY_LEVEL, read, notify)]
    level: u8,
    /// Battery Status - callback-based
    #[characteristic(uuid = "408813df-5dd4-1f87-ec11-cdb001100000", write, read, notify)]
    status: bool,
}

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// Simulated battery state
struct BatteryState {
    level: AtomicU8,
    charging: AtomicBool,
}

impl BatteryState {
    const fn new() -> Self {
        Self {
            level: AtomicU8::new(100),
            charging: AtomicBool::new(false),
        }
    }

    fn get_level(&self) -> u8 {
        self.level.load(Ordering::Relaxed)
    }

    fn set_charging(&self, charging: bool) {
        self.charging.store(charging, Ordering::Relaxed);
    }

    fn is_charging(&self) -> bool {
        self.charging.load(Ordering::Relaxed)
    }

    async fn read_battery_level(&self) -> u8 {
        // Simulate async ADC read
        Timer::after_millis(10).await;
        self.level.load(Ordering::Relaxed)
    }

    async fn update_battery(&self) {
        let current = self.level.load(Ordering::Relaxed);
        let charging = self.charging.load(Ordering::Relaxed);

        if charging && current < 100 {
            self.level.store(current + 1, Ordering::Relaxed);
        } else if !charging && current > 0 {
            self.level.store(current.saturating_sub(1), Ordering::Relaxed);
        }
    }
}

static BATTERY_STATE: BatteryState = BatteryState::new();

/// Run the BLE stack.
pub async fn run<C>(controller: C)
where
    C: Controller,
{
    let address: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
    info!("Our address = {:?}", address);

    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
        HostResources::new();
    let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
    let Host {
        mut peripheral, runner, ..
    } = stack.build();

    info!("Starting callback-based GATT service");
    let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: "TrouBLE-Callback",
        appearance: &appearance::power_device::GENERIC_POWER_DEVICE,
    }))
    .unwrap();

    let _ = join(ble_task(runner), async {
        loop {
            match advertise("Trouble Callback Example", &mut peripheral, &server).await {
                Ok(conn) => {
                    info!("[adv] connection established");
                    // Run tasks until disconnection
                    let a = gatt_events_task(&server, &conn);
                    let b = notification_task(&server, &conn);
                    let c = battery_simulation_task();
                    select(select(a, b), c).await;
                }
                Err(e) => {
                    #[cfg(feature = "defmt")]
                    let e = defmt::Debug2Format(&e);
                    panic!("[adv] error: {:?}", e);
                }
            }
        }
    })
    .await;
}

async fn ble_task<C: Controller, P: PacketPool>(mut runner: Runner<'_, C, P>) {
    loop {
        if let Err(e) = runner.run().await {
            #[cfg(feature = "defmt")]
            let e = defmt::Debug2Format(&e);
            panic!("[ble_task] error: {:?}", e);
        }
    }
}

/// Handle GATT events with callback-based characteristics.
///
/// This demonstrates the callback-based GATT API where characteristic values
/// are not stored in the attribute table. Instead, values are provided on-demand
/// through async handlers.
async fn gatt_events_task<P: PacketPool>(
    server: &Server<'_>,
    conn: &GattConnection<'_, '_, P>,
) -> Result<(), Error> {
    let level_handle = server.battery_service.level.handle;
    let status_handle = server.battery_service.status.handle;

    let reason = loop {
        match conn.next().await {
            GattConnectionEvent::Disconnected { reason } => break reason,
            GattConnectionEvent::Gatt { event } => {
                match event {
                    // Handle battery level read (callback-based)
                    GattEvent::Read(read) if read.handle() == level_handle => {
                        info!("[gatt] Battery level read request");

                        // Perform async operation to get battery level
                        let level = BATTERY_STATE.read_battery_level().await;
                        info!("[gatt] Responding with battery level: {}%", level);

                        // Respond with current value
                        match read.respond(&[level]) {
                            Ok(reply) => reply.send().await,
                            Err(e) => warn!("[gatt] error responding to read: {:?}", e),
                        }
                    }

                    // Handle battery status read (callback-based)
                    GattEvent::Read(read) if read.handle() == status_handle => {
                        info!("[gatt] Battery status read request");

                        let charging = BATTERY_STATE.is_charging();
                        info!("[gatt] Responding with charging status: {}", charging);

                        // Respond with bool as single byte (0 or 1)
                        let response = if charging { [1u8] } else { [0u8] };
                        match read.respond(&response) {
                            Ok(reply) => reply.send().await,
                            Err(e) => warn!("[gatt] error responding to read: {:?}", e),
                        }
                    }

                    // Handle battery status write (callback-based)
                    GattEvent::Write(write) if write.handle() == status_handle => {
                        info!("[gatt] Battery status write request");

                        let data = write.data();
                        if let Some(&byte) = data.first() {
                            let charging = byte != 0;
                            BATTERY_STATE.set_charging(charging);
                            info!("[gatt] Set charging status to: {}", charging);
                        }

                        match write.accept() {
                            Ok(reply) => reply.send().await,
                            Err(e) => warn!("[gatt] error accepting write: {:?}", e),
                        }
                    }

                    // Handle all other GATT events normally
                    _ => {
                        match event.accept() {
                            Ok(reply) => reply.send().await,
                            Err(e) => warn!("[gatt] error sending response: {:?}", e),
                        }
                    }
                }
            }
            _ => {}
        }
    };
    info!("[gatt] disconnected: {:?}", reason);
    Ok(())
}

/// Periodic notification task.
///
/// Note: For callback-based characteristics, notify() does NOT store the value
/// in the attribute table. It only sends the notification PDU to subscribed clients.
async fn notification_task<P: PacketPool>(server: &Server<'_>, conn: &GattConnection<'_, '_, P>) {
    let level = server.battery_service.level;
    let status = server.battery_service.status;

    loop {
        Timer::after_secs(5).await;

        // Read current values
        let battery_level = BATTERY_STATE.get_level();
        let charging = BATTERY_STATE.is_charging();

        info!(
            "[notify] Battery: {}%, Charging: {}",
            battery_level, charging
        );

        // Send notifications (does not store values!)
        if level.notify(conn, &battery_level).await.is_err() {
            info!("[notify] connection closed");
            break;
        }

        if status.notify(conn, &charging).await.is_err() {
            info!("[notify] connection closed");
            break;
        }
    }
}

/// Simulate battery level changes
async fn battery_simulation_task() {
    loop {
        Timer::after_secs(2).await;
        BATTERY_STATE.update_battery().await;
    }
}

async fn advertise<'values, 'server, C: Controller>(
    name: &'values str,
    peripheral: &mut Peripheral<'values, C, DefaultPacketPool>,
    server: &'server Server<'values>,
) -> Result<GattConnection<'values, 'server, DefaultPacketPool>, BleHostError<C::Error>> {
    let mut advertiser_data = [0; 31];
    let len = AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::ServiceUuids16(&[[0x0f, 0x18]]),
            AdStructure::CompleteLocalName(name.as_bytes()),
        ],
        &mut advertiser_data[..],
    )?;
    let advertiser = peripheral
        .advertise(
            &Default::default(),
            Advertisement::ConnectableScannableUndirected {
                adv_data: &advertiser_data[..len],
                scan_data: &[],
            },
        )
        .await?;
    info!("[adv] advertising");
    let conn = advertiser.accept().await?.with_attribute_server(server)?;
    info!("[adv] connection established");
    Ok(conn)
}
