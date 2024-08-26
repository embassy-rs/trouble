use embassy_futures::join::join;
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;
use trouble_host::attribute::Uuid;
use trouble_host::connection::ConnectConfig;
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
        let conn = ble.connect(&config).await.unwrap();
        info!("Connected, creating gatt client");

        let mut client = ble.gatt_client::<10, 128>(&conn).await.unwrap();

        info!("Looking for battery service");
        let services = client.services_by_uuid(&Uuid::new_short(0x180f)).await.unwrap();
        let service = services.first().unwrap().clone();

        info!("Looking for value handle");
        let c = client
            .characteristic_by_uuid(&service, &Uuid::new_short(0x2a19))
            .await
            .unwrap();

        loop {
            let mut data = [0; 1];
            client.read_characteristic(&c, &mut data[..]).await.unwrap();
            info!("Read value: {}", data[0]);
            Timer::after(Duration::from_secs(10)).await;
        }
    })
    .await;
}
