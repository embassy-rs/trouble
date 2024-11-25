/* Nordic Uart Service (NUS) peripheral example */
use embassy_futures::{
    join::join3,
    select::{select, Either},
};
use embassy_time::{Duration, Timer};
use heapless::Vec;
use trouble_host::prelude::*;

/// Size of L2CAP packets (ATT MTU is this - 4)
const L2CAP_MTU: usize = 251;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 2; // Signal + att

pub const MTU: usize = 120;
// Aligned to 4 bytes + 3 bytes for header
pub const ATT_MTU: usize = MTU + 3;

type Resources<C> = HostResources<C, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, L2CAP_MTU>;

// GATT Server definition
#[gatt_server]
struct Server {
    nrf_uart: NrfUartService,
}

// NRF UART Service
#[gatt_service(uuid = "6E400001-B5A3-F393-E0A9-E50E24DCCA9E")]
struct NrfUartService {
    #[characteristic(uuid = "6E400002-B5A3-F393-E0A9-E50E24DCCA9E", write)]
    rx: Vec<u8, ATT_MTU>,

    #[characteristic(uuid = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E", notify)]
    tx: Vec<u8, ATT_MTU>,
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
            name: "TrouBLE NUS",
            appearance: &appearance::GENERIC_UNKNOWN,
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

async fn gatt_task<C: Controller>(server: &Server<'_, '_, C>) -> Result<(), BleHostError<C::Error>> {
    server.run().await
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
            AdStructure::CompleteLocalName(b"TrouBLE NUS"),
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

        let mut tick: u8 = 0;
        let mut buf = Vec::<u8, ATT_MTU>::from_slice(&[0; ATT_MTU]).unwrap();

        // Keep connection alive
        loop {
            match select(conn.next(), Timer::after(Duration::from_secs(2))).await {
                Either::First(event) => match event {
                    ConnectionEvent::Disconnected { reason } => {
                        info!("[adv] disconnected: {:?}", reason);
                        break;
                    }
                    ConnectionEvent::Gatt { event, .. } => match event {
                        GattEvent::Read { value_handle } => {
                            /*
                            if value_handle == server.nrf_uart.rx_buf.handle {
                                let value = server.get(&rx_buf).unwrap();
                                info!("[gatt] Read Event to rx_buf Characteristic: {:?}", value.len());
                            } else if value_handle == tx_buf.handle {
                                let value = server.get(&tx_buf).unwrap();
                                info!("[gatt] Read Event to tx_buf Characteristic: {:?}", value.len());
                            }
                            */
                            defmt::info!("Read...");
                        }
                        GattEvent::Write { value_handle } => {
                            /*
                            if value_handle == rx_buf.handle {
                                let value = server.get(&rx_buf).unwrap();
                                info!("[gatt] Write Event to rx_buf Characteristic: {:?}", value.len());
                            } else if value_handle == tx_buf.handle {
                                let value = server.get(&tx_buf).unwrap();
                                info!("[gatt] Write Event to tx_buf Characteristic: {:?}", value.len());
                            }
                            */
                            defmt::info!("Write...");
                        }
                    },
                },
                Either::Second(_) => {
                    tick = tick.wrapping_add(1);
                    info!("[adv] notifying connection of tick {}", tick);
                    buf[0] = tick;
                    let _ = server.notify(&server.nrf_uart.tx, &conn, &buf).await;
                }
            }
        }
    }
}
