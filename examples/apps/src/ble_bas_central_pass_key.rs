use embassy_futures::join::join;
use embassy_time::{Duration, Timer};
use rand_core::{CryptoRng, RngCore};
use trouble_host::prelude::*;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 3; // Signal + att + CoC

pub async fn run<C, RNG>(controller: C, random_generator: &mut RNG)
where
    C: Controller,
    RNG: RngCore + CryptoRng,
{
    // Using a fixed "random" address can be useful for testing. In real scenarios, one would
    // use e.g. the MAC 6 byte array as the address (how to get that varies by the platform).
    let address: Address = Address::random([0xff, 0x8f, 0x1b, 0x05, 0xe4, 0xff]);
    info!("Our address = {:?}", address);

    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(address)
        .set_random_generator_seed(random_generator);

    stack.set_io_capabilities(IoCapabilities::KeyboardOnly);

    let Host {
        mut central,
        mut runner,
        ..
    } = stack.build();

    // NOTE: Modify this to match the address of the peripheral you want to connect to.
    // Currently it matches the address used by the peripheral examples
    let target: Address = Address::random([0xff, 0x8f, 0x19, 0x05, 0xe4, 0xff]);

    let config = ConnectConfig {
        connect_params: Default::default(),
        scan_config: ScanConfig {
            filter_accept_list: &[(target.kind, &target.addr)],
            ..Default::default()
        },
    };

    info!("Scanning for peripheral...");
    let _ = join(runner.run(), async {
        info!("Connecting");

        let conn = central.connect(&config).await.unwrap();
        info!("Connected, creating gatt client");

        #[cfg(feature = "security")]
        {
            conn.request_security().unwrap();
            loop {
                match conn.next().await {
                    ConnectionEvent::PairingComplete { security_level, .. } => {
                        info!("Pairing complete: {:?}", security_level);
                        break;
                    }
                    ConnectionEvent::PairingFailed(err) => {
                        error!("Pairing failed: {:?}", err);
                        break;
                    }
                    ConnectionEvent::Disconnected { reason } => {
                        error!("Disconnected: {:?}", reason);
                        break;
                    }
                    ConnectionEvent::PassKeyInput => {
                        info!("Inputting pass key.");
                        // Normally fetched from user
                        conn.pass_key_input(1234).unwrap();
                    }
                    ConnectionEvent::RequestConnectionParams(req) => req.accept(None, &stack).await.unwrap(),
                    _ => {}
                }
            }
        }

        let client = GattClient::<C, DefaultPacketPool, 10>::new(&stack, &conn)
            .await
            .unwrap();

        let _ = join(client.task(), async {
            info!("Looking for battery service");
            let services = client.services_by_uuid(&Uuid::new_short(0x180f)).await.unwrap();
            let service = services.first().unwrap().clone();

            info!("Looking for value handle");
            let c: Characteristic<u8> = client
                .characteristic_by_uuid(&service, &Uuid::new_short(0x2a19))
                .await
                .unwrap();

            info!("Subscribing notifications");
            let mut listener = client.subscribe(&c, false).await.unwrap();

            let _ = join(
                async {
                    loop {
                        let mut data = [0; 1];
                        client.read_characteristic(&c, &mut data[..]).await.unwrap();
                        info!("Read value: {}", data[0]);
                        Timer::after(Duration::from_secs(10)).await;
                    }
                },
                async {
                    loop {
                        let data = listener.next().await;
                        info!("Got notification: {:?} (val: {})", data.as_ref(), data.as_ref()[0]);
                    }
                },
            )
            .await;
        })
        .await;
    })
    .await;
}
