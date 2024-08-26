use embassy_futures::join::join;
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;
use trouble_host::connection::ConnectConfig;
use trouble_host::l2cap::L2capChannel;
use trouble_host::scan::ScanConfig;
use trouble_host::{Address, BleHost, BleHostResources, Controller, PacketQos};

/// How many outgoing L2CAP buffers per link
const L2CAP_TXQ: u8 = 20;

/// How many incoming L2CAP buffers per link
const L2CAP_RXQ: u8 = 20;

/// Size of L2CAP packets
const L2CAP_MTU: usize = 27;

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
        loop {
            let conn = ble.connect(&config).await.unwrap();
            info!("Connected, creating l2cap channel");
            const PAYLOAD_LEN: usize = 27;
            let mut ch1 = L2capChannel::create(&ble, &conn, 0x2349, &Default::default())
                .await
                .unwrap();
            info!("New l2cap channel created, sending some data!");
            for i in 0..10 {
                let tx = [i; PAYLOAD_LEN];
                ch1.send::<_, PAYLOAD_LEN>(&ble, &tx).await.unwrap();
            }
            info!("Sent data, waiting for them to be sent back");
            let mut rx = [0; PAYLOAD_LEN];
            for i in 0..10 {
                let len = ch1.receive(&ble, &mut rx).await.unwrap();
                assert_eq!(len, rx.len());
                assert_eq!(rx, [i; PAYLOAD_LEN]);
            }

            info!("Received successfully!");

            Timer::after(Duration::from_secs(60)).await;
        }
    })
    .await;
}
