use static_cell::StaticCell;
use tokio::select;
use tokio::time::Duration;
use trouble_host::advertise::{AdStructure, Advertisement, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE};
use trouble_host::connection::ConnectConfig;
use trouble_host::l2cap::L2capChannel;
use trouble_host::scan::ScanConfig;
use trouble_host::{Address, BleHost, BleHostResources, PacketQos};

mod common;

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 3;
const MTU: usize = 23;

/// Verify l2cap le connection oriented channels using two HCI adapters attached to the test machine.
#[tokio::test]
async fn l2cap_connection_oriented_channels() {
    let _ = env_logger::try_init();
    let peripheral = std::env::var("TEST_ADAPTER_ONE").unwrap();
    let central = std::env::var("TEST_ADAPTER_TWO").unwrap();

    let peripheral_address: Address = Address::random([0xff, 0x9f, 0x1a, 0x05, 0xe4, 0xff]);

    let local = tokio::task::LocalSet::new();

    const PAYLOAD_LEN: usize = 4;

    // Spawn peripheral
    let peripheral = local.spawn_local(async move {
        let controller_peripheral = common::create_controller(&peripheral).await;

        static RESOURCES: StaticCell<BleHostResources<CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, 27>> = StaticCell::new();
        let host_resources = RESOURCES.init(BleHostResources::new(PacketQos::None));
        let mut adapter: BleHost<'_, _> = BleHost::new(controller_peripheral, host_resources);

        adapter.set_random_address(peripheral_address);

        select! {
            r = adapter.run() => {
                r
            }
            r = async {
                let mut adv_data = [0; 31];
                AdStructure::encode_slice(
                    &[AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED)],
                    &mut adv_data[..],
                ).unwrap();

                let mut scan_data = [0; 31];
                AdStructure::encode_slice(
                    &[AdStructure::CompleteLocalName(b"trouble-l2cap-int")],
                    &mut scan_data[..],
                ).unwrap();

                loop {
                    println!("[peripheral] advertising");
                    let mut acceptor = adapter.advertise(&Default::default(), Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..],
                        scan_data: &scan_data[..],
                    }).await?;
                    let conn = acceptor.accept().await?;
                    println!("[peripheral] connected");

                    let mut ch1 = L2capChannel::accept(&adapter, &conn, &[0x2349], &Default::default()).await?;

                    println!("[peripheral] channel created");

                    // Size of payload we're expecting
                    let mut rx = [0; PAYLOAD_LEN];
                    for i in 0..10 {
                        let len = ch1.receive(&adapter, &mut rx).await?;
                        assert_eq!(len, rx.len());
                        assert_eq!(rx, [i; PAYLOAD_LEN]);
                    }
                    println!("[peripheral] data received");

                    for i in 0..10 {
                        let tx = [i; PAYLOAD_LEN];
                        ch1.send::<_, MTU>(&adapter, &tx).await?;
                    }
                    println!("[peripheral] data sent");
                    break;
                }
                Ok(())
            } => {
                r
            }
        }
    });

    // Spawn central
    let central = local.spawn_local(async move {
        let controller_central = common::create_controller(&central).await;
        static RESOURCES: StaticCell<BleHostResources<CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, 27>> = StaticCell::new();
        let host_resources = RESOURCES.init(BleHostResources::new(PacketQos::None));

        let adapter: BleHost<'_, _> = BleHost::new(controller_central, host_resources);

        select! {
            r = adapter.run() => {
                r
            }
            r = async {
                let config = ConnectConfig {
                    connect_params: Default::default(),
                    scan_config: ScanConfig {
                        active: true,
                        filter_accept_list: &[(peripheral_address.kind, &peripheral_address.addr)],
                        ..Default::default()
                    },
                };

                println!("[central] connecting");
                loop {
                    let conn = adapter.connect(&config).await.unwrap();
                    println!("[central] connected");
                    let mut ch1 = L2capChannel::create(&adapter, &conn, 0x2349, &Default::default()).await?;
                    println!("[central] channel created");
                    for i in 0..10 {
                        let tx = [i; PAYLOAD_LEN];
                        ch1.send::<_, MTU>(&adapter, &tx).await?;
                    }
                    println!("[central] data sent");
                    let mut rx = [0; PAYLOAD_LEN];
                    for i in 0..10 {
                        let len = ch1.receive(&adapter, &mut rx).await?;
                        assert_eq!(len, rx.len());
                        assert_eq!(rx, [i; PAYLOAD_LEN]);
                    }
                    println!("[central] data received");
                    break;
                }
                Ok(())
            } => {
                r
            }
        }
    });

    match tokio::time::timeout(Duration::from_secs(30), local).await {
        Ok(_) => match tokio::join!(central, peripheral) {
            (Err(e1), Err(e2)) => {
                println!("Central error: {:?}", e1);
                println!("Peripheral error: {:?}", e2);
                assert!(false);
            }
            (Err(e), _) => {
                println!("Central error: {:?}", e);
                assert!(false)
            }
            (_, Err(e)) => {
                println!("Peripheral error: {:?}", e);
                assert!(false)
            }
            _ => {
                println!("Test completed successfully");
            }
        },
        Err(e) => {
            println!("Test timed out: {:?}", e);
            assert!(false);
        }
    }
}
