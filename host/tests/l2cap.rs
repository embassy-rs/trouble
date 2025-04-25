use tokio::select;
use tokio::time::Duration;
use trouble_host::prelude::*;

mod common;

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 3;

/// Verify l2cap le connection oriented channels using two HCI adapters attached to the test machine.
#[tokio::test]
async fn l2cap_connection_oriented_channels() {
    let _ = env_logger::try_init();
    let adapters = common::find_controllers();
    let peripheral = adapters[0].clone();
    let central = adapters[1].clone();

    let peripheral_address: Address = Address::random([0xff, 0x9f, 0x1a, 0x05, 0xe4, 0xff]);

    let local = tokio::task::LocalSet::new();

    const PAYLOAD_LEN: usize = 4;

    // Spawn peripheral
    let peripheral = local.spawn_local(async move {
        let controller_peripheral = common::create_controller(&peripheral).await;

        let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();
        let stack = trouble_host::new(controller_peripheral, &mut resources)
            .set_random_address(peripheral_address);
        let Host {
            mut peripheral,
            mut runner,
            ..
        } = stack.build();


        select! {
            r = runner.run() => {
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
                    let acceptor = peripheral.advertise(&Default::default(), Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..],
                        scan_data: &scan_data[..],
                    }).await?;
                    let conn = acceptor.accept().await?;
                    println!("[peripheral] connected");

                    let mut ch1 = L2capChannel::accept(&stack, &conn, &[0x2349], &Default::default()).await?;

                    println!("[peripheral] channel created");

                    // Size of payload we're expecting
                    let mut rx = [0; PAYLOAD_LEN];
                    for i in 0..10 {
                        let len = ch1.receive(&stack, &mut rx).await?;
                        assert_eq!(len, rx.len());
                        assert_eq!(rx, [i; PAYLOAD_LEN]);
                    }
                    println!("[peripheral] data received");

                    for i in 0..10 {
                        let tx = [i; PAYLOAD_LEN];
                        ch1.send(&stack, &tx).await?;
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
        let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();

        let stack = trouble_host::new(controller_central, &mut resources);
        let Host {
            mut central,
            mut runner,
            ..
        } = stack.build();

        select! {
            r = runner.run() => {
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
                    let conn = central.connect(&config).await.unwrap();
                    println!("[central] connected");
                    let mut ch1 = L2capChannel::create(&stack, &conn, 0x2349, &Default::default()).await?;
                    println!("[central] channel created");
                    for i in 0..10 {
                        let tx = [i; PAYLOAD_LEN];
                        ch1.send(&stack, &tx).await?;
                    }
                    println!("[central] data sent");
                    let mut rx = [0; PAYLOAD_LEN];
                    for i in 0..10 {
                        let len = ch1.receive(&stack, &mut rx).await?;
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
            (Ok(Err(e1)), Ok(Err(e2))) => {
                println!("Central error: {:?}", e1);
                println!("Peripheral error: {:?}", e2);
                assert!(false);
            }
            (Ok(Err(e)), _) => {
                println!("Central error: {:?}", e);
                assert!(false)
            }
            (_, Ok(Err(e))) => {
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
