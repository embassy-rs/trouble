use embassy_futures::join::join;
use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};
use trouble_host::prelude::*;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 3; // Signal + att + CoC

pub async fn run<C>(controller: C)
where
    C: Controller,
{
    // Using a fixed "random" address can be useful for testing. In real scenarios, one would
    // use e.g. the MAC 6 byte array as the address (how to get that varies by the platform).
    let address: Address = Address::random([0xff, 0x8f, 0x1b, 0x05, 0xe4, 0xff]);
    info!("Our address = {:?}", address);

    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(address)
        .build();
    let mut runner = stack.runner();
    let mut central = stack.central();

    // NOTE: Modify this to match the address of the peripheral you want to connect to.
    // Currently it matches the address used by the peripheral examples
    let target: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);

    let config = ConnectConfig {
        connect_params: Default::default(),
        scan_config: ScanConfig {
            filter_accept_list: &[target],
            ..Default::default()
        },
    };

    info!("Scanning for peripheral...");
    let _ = join(runner.run(), async {
        info!("Connecting");

        let conn = central.connect(&config).await.unwrap();
        info!("Connected, creating gatt client");

        // Keep one event consumer alive from connection through GATT setup and
        // until disconnection, including while a parameter reply is in flight.
        let events = async {
            loop {
                match conn.next().await {
                    ConnectionEvent::RequestConnectionParams(request) => {
                        info!("Peer requested connection parameter update: {:?}", request.params());
                        if let Err(error) = request.accept(None, &stack).await {
                            error!("Connection parameter update failed: {:?}", error);
                            conn.disconnect();
                        }
                    }
                    ConnectionEvent::Disconnected { reason } => {
                        info!("Disconnected: {:?}", reason);
                        break;
                    }
                    _ => {}
                }
            }
        };
        let gatt = async {
            let result = async {
                let client = GattClient::<C, DefaultPacketPool, 10>::new(&stack, &conn).await?;
                let operations = async {
                    info!("Looking for battery service");
                    let services = client.services_by_uuid(&Uuid::new_short(0x180f)).await?;
                    let Some(service) = services.first() else {
                        error!("Battery service not found");
                        return Ok(());
                    };

                    info!("Looking for value handle");
                    let c: Characteristic<u8> =
                        client.characteristic_by_uuid(service, &Uuid::new_short(0x2a19)).await?;
                    info!("Subscribing notifications");
                    let mut listener = client.subscribe(&c, false).await?;
                    let reads = async {
                        loop {
                            let mut data = [0; 1];
                            client.read_characteristic(&c, &mut data[..]).await?;
                            info!("Read value: {}", data[0]);
                            Timer::after(Duration::from_secs(10)).await;
                        }
                    };
                    let notifications = async {
                        loop {
                            let data = listener.next().await;
                            info!("Got notification: {:?} (val: {})", data.as_ref(), data.as_ref()[0]);
                        }
                    };
                    match select(reads, notifications).await {
                        Either::First(result) => result,
                        Either::Second(()) => Ok(()),
                    }
                };
                match select(client.task(), operations).await {
                    Either::First(result) | Either::Second(result) => result,
                }
            }
            .await;
            if let Err(error) = result {
                error!("GATT client stopped: {:?}", error);
            }
            conn.disconnect();
        };
        let _ = join(events, gatt).await;
    })
    .await;
}
