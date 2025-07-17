use embassy_futures::join::join;
use embassy_futures::select::select;
use trouble_host::prelude::AdStructure;
use trouble_host::prelude::*;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels
const L2CAP_CHANNELS_MAX: usize = 3; // Signal + att + CoC

/// L2CAP PSM to be published to the client
const L2CAP_PSM: u16 = 0x00C0;

/// GATT Server
#[gatt_server]
struct Server {
    psm_service: PsmService,
}

/// PSM Service - publishes the PSM value for L2CAP client connection
/// The PSM Service UUID is specific to the services iOS/macOS App is scanning for
/// Here, we use value from https://github.com/paulw11/L2CapDemo (L2CapDemo/L2CapDemo/Constants.swift)
/// The PSM Characteristic UUID is predefined https://developer.apple.com/documentation/corebluetooth/cbuuidl2cappsmcharacteristicstring
/// iOS/macOS only accepts L2CAP PSM values in range 0x0040 - 0x00FF
#[gatt_service(uuid = "12E61727-B41A-436F-B64D-4777B35F2294")]
struct PsmService {
    #[characteristic(uuid = "ABDD3056-28FA-441D-A470-55A75A52553A", read, indicate, value = L2CAP_PSM)]
    psm: u16,
}

pub async fn run<C, const L2CAP_MTU: usize>(controller: C)
where
    C: Controller,
{
    // Hardcoded peripheral address
    let address: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
    info!("Our address = {:?}", address);

    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
    let Host {
        mut peripheral,
        mut runner,
        ..
    } = stack.build();

    let mut adv_data = [0; 31];
    AdStructure::encode_slice(
        &[AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED)],
        &mut adv_data[..],
    )
    .expect("Failed to encode adv_data");

    // Advertise the PSM service the iOS/macOS client is scanning for
    let mut scan_data = [0; 31];
    AdStructure::encode_slice(
        &[
            AdStructure::CompleteLocalName(b"Trouble"),
            AdStructure::ServiceUuids128(&[0x12E61727_B41A_436F_B64D_4777B35F2294_u128.to_le_bytes()]),
        ],
        &mut scan_data[..],
    )
    .expect("Failed to encode scan_data");

    let server = Server::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: "Trouble L2CAP Server",
        appearance: &appearance::sensor::GENERIC_SENSOR,
    }))
    .expect("Failed to create GATT server");

    let _ = join(runner.run(), async {
        loop {
            info!("Advertising, waiting for connection...");
            let advertiser = peripheral
                .advertise(
                    &Default::default(),
                    Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..],
                        scan_data: &scan_data[..],
                    },
                )
                .await
                .expect("Failed to advertise");

            let conn = advertiser
                .accept()
                .await
                .expect("Advertising accept failed")
                .with_attribute_server(&server)
                .expect("Failed to set GATT server");

            info!("Connection established");

            let gatt_fut = gatt_task(&conn);
            let l2cap_fut = l2cap_task::<_, _, L2CAP_MTU, L2CAP_PSM>(&conn, &stack);
            select(gatt_fut, l2cap_fut).await;
        }
    })
    .await;
}

/// Task to handle Gatt events
async fn gatt_task<P: PacketPool>(conn: &GattConnection<'_, '_, P>) {
    let reason = loop {
        match conn.next().await {
            GattConnectionEvent::Disconnected { reason } => break reason,
            GattConnectionEvent::Gatt { event } => {
                match event.accept() {
                    Ok(reply) => reply.send().await,
                    Err(e) => warn!("[gatt] error sending response: {:?}", e),
                };
            }
            _ => {} // Ignore other GATT events
        }
    };
    info!("[gatt] disconnected: {:?}", reason);
}

/// Task to handle L2CAP data streaming
async fn l2cap_task<'a, C: Controller, P: PacketPool, const MTU: usize, const PSM: u16>(
    conn: &GattConnection<'_, '_, P>,
    stack: &'a Stack<'a, C, P>,
) {
    let mut channel = match L2capChannel::accept(&stack, conn.raw(), &[PSM], &Default::default()).await {
        Ok(chan) => chan,
        Err(e) => {
            warn!("[l2cap] channel accept error: {:?}", e);
            return;
        }
    };
    info!("[l2cap] channel accepted");

    let mut buf = [0; MTU];
    loop {
        match channel.receive(&stack, &mut buf).await {
            Ok(len) => {
                let rx_data = &buf[..len];
                info!("[l2cap] received: {:02x?}", rx_data);
                // Echo received data
                if let Err(e) = channel.send(&stack, rx_data).await {
                    warn!("[l2cap] error sending data: {:?}", e);
                }
            }
            Err(e) => {
                warn!("[l2cap] error receiving data: {:?}", e);
            }
        }
    }
}
