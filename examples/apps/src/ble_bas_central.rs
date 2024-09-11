use embassy_futures::join::join;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;
use trouble_host::attribute::Uuid;
use trouble_host::connection::ConnectConfig;
use trouble_host::packet_pool::PacketPool;
use trouble_host::scan::ScanConfig;
use trouble_host::{Address, BleHost, BleHostResources, Controller, PacketQos};

/// Size of L2CAP packets
const L2CAP_MTU: usize = 128;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 3; // Signal + att + CoC

pub async fn run<C>(controller: C)
where
    C: Controller,
{
    static HOST_RESOURCES: StaticCell<BleHostResources<CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, L2CAP_MTU>> =
        StaticCell::new();
    let host_resources = HOST_RESOURCES.init(BleHostResources::new(PacketQos::None));

    let ble: BleHost<'_, _> = BleHost::new(controller, host_resources);

    // NOTE: Modify this to match the address of the peripheral you want to connect to.
    // Currently it matches the address used by the peripheral examples
    let target: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);

    let config = ConnectConfig {
        connect_params: Default::default(),
        scan_config: ScanConfig {
            filter_accept_list: &[(target.kind, &target.addr)],
            ..Default::default()
        },
    };

    info!("Scanning for peripheral...");
    let _ = join(ble.run(), async {
        static PACKET_POOL: StaticCell<PacketPool<NoopRawMutex, 24, 64, 1>> = StaticCell::new();
        let packet_pool = PACKET_POOL.init(PacketPool::new(PacketQos::None));

        info!("Connecting");

        let conn = ble.connect(&config).await.unwrap();
        info!("Connected, creating gatt client");

        let client = ble.gatt_client::<10, 64, 16, 24>(&conn, packet_pool).await.unwrap();

        let _ = join(client.task(), async {
            info!("Looking for battery service");
            let services = client.services_by_uuid(&Uuid::new_short(0x180f)).await.unwrap();
            let service = services.first().unwrap().clone();

            info!("Looking for value handle");
            let c = client
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
                        let (len, data) = listener.next().await;
                        info!(
                            "Got notification: {:?} (val: {})",
                            &data.as_ref()[..len as usize],
                            data.as_ref()[0]
                        );
                    }
                },
            )
            .await;
        })
        .await;
    })
    .await;
}
