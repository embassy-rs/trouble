use embassy_futures::join::{join, join3};
use embassy_time::{Duration, Timer};
use trouble_host::prelude::*;

/// Max number of connections
const CONNECTIONS_MAX: usize = 2;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 4; // Signal + att + CoC

pub async fn run<C>(controller: C)
where
    C: Controller,
{
    // Using a fixed "random" address can be useful for testing. In real scenarios, one would
    // use e.g. the MAC 6 byte array as the address (how to get that varies by the platform).
    let address: Address = Address::random([0xff, 0x8f, 0x1b, 0x05, 0xe4, 0xff]);
    info!("Our address = {:?}", address);

    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
    let Host { mut runner, .. } = stack.build();

    info!("Scanning for peripheral...");
    // NOTE: Modify this to match the address of the peripheral you want to connect to.
    let fut1 = scan(&stack, [0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
    let fut2 = scan(&stack, [0xff, 0x8f, 0x1a, 0x05, 0xe5, 0xff]);
    let _ = join3(runner.run(), fut1, fut2).await;
}

async fn scan<'a, C: Controller, P: PacketPool>(stack: &'a Stack<'a, C, P>, addr: [u8; 6]) {
    let Host { mut central, .. } = stack.build();
    let target: Address = Address::random(addr);

    let config = ConnectConfig {
        connect_params: Default::default(),
        scan_config: ScanConfig {
            filter_accept_list: &[(target.kind, &target.addr)],
            ..Default::default()
        },
    };

    info!("Connecting to {:?}", addr);
    let conn = central.connect(&config).await.unwrap();
    info!("Connected, creating gatt client");

    let client = GattClient::<C, _, 10>::new(stack, &conn).await.unwrap();

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
}
