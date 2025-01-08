use std::time::Duration;
use tokio::select;
use tokio::sync::oneshot;
use trouble_example_tests::{probe, serial};
use trouble_host::prelude::*;

#[tokio::test(flavor = "multi_thread")]
async fn l2cap_peripheral_nrf52() {
    let _ = pretty_env_logger::try_init();
    let adapters = serial::find_controllers();
    let central = adapters[0].clone();
    let config = std::env::var("PROBE_CONFIG").unwrap();
    let config = serde_json::from_str(&config).unwrap();
    let elf = std::fs::read("bins/nrf-sdc/ble_l2cap_peripheral").unwrap();

    let selector = probe::init(config);
    let target = selector
        .select(&[("target", "nrf52"), ("board", "microbit")])
        .expect("no suitable probe found");

    let (cancel_tx, cancel_rx) = oneshot::channel();

    // Flash the binary to the target
    let runner = target.flash(elf).unwrap();

    // Spawn a runner for the target
    let peripheral = tokio::task::spawn(async move { runner.run(cancel_rx).await });

    // Run the central in the test using the serial adapter to verify
    let peripheral_address: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
    let central_fut = async {
        let controller_central = serial::create_controller(&central).await;
        let mut resources: HostResources<serial::Controller, 2, 4, 27> = HostResources::new(PacketQos::None);
        let (stack, _peripheral, mut central, mut runner) =
            trouble_host::new(controller_central, &mut resources).build();
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

                log::info!("[central] connecting");
                loop {
                    let conn = central.connect(&config).await.unwrap();
                    log::info!("[central] connected");
                    const PAYLOAD_LEN: usize = 27;
                    let mut ch1 = L2capChannel::create(stack, &conn, 0x2349, &Default::default()).await?;
                    log::info!("[central] channel created");
                    for i in 0..10 {
                        let tx = [i; PAYLOAD_LEN];
                        ch1.send::<_, PAYLOAD_LEN>(stack, &tx).await?;
                    }
                    log::info!("[central] data sent");
                    let mut rx = [0; PAYLOAD_LEN];
                    for i in 0..10 {
                        let len = ch1.receive(stack, &mut rx).await?;
                        assert_eq!(len, rx.len());
                        assert_eq!(rx, [i; PAYLOAD_LEN]);
                    }
                    log::info!("[central] data received");
                    cancel_tx.send(()).unwrap();
                    break;
                }
                Ok(())
            } => {
                r
            }
        }
    };

    match tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(central_fut, peripheral) }).await {
        Ok(result) => match result {
            (Err(e1), Err(e2)) => {
                println!("Central error: {:?}", e1);
                println!("Peripheral error: {:?}", e2);
                panic!();
            }
            (Err(e), _) => {
                println!("Central error: {:?}", e);
                panic!();
            }
            (_, Err(e)) => {
                println!("Peripheral error: {:?}", e);
                panic!();
            }
            _ => {
                println!("Test completed successfully");
            }
        },
        Err(e) => {
            println!("Test timed out: {:?}", e);
            panic!();
        }
    }
}
