use futures::future::select;
use std::time::Duration;
use tokio::select;
use trouble_example_tests::{probe, serial, TestContext};
use trouble_host::prelude::*;

#[tokio::test]
async fn ble_l2cap_peripheral_nrf52() {
    let _ = pretty_env_logger::try_init();
    let fw = std::fs::read("bins/nrf-sdc/ble_l2cap_peripheral").unwrap();
    let firmware = probe::Firmware { data: fw };
    let local = tokio::task::LocalSet::new();
    local
        .run_until(run_l2cap_peripheral_test(
            &[("target", "nrf52"), ("board", "microbit")],
            firmware,
        ))
        .await;
}

/*
#[tokio::test(flavor = "multi_thread")]
async fn l2cap_peripheral_esp32() {
    let _ = pretty_env_logger::try_init();
    let fw = std::fs::read("bins/esp32/ble_l2cap_peripheral").unwrap();
    let firmware = probe::Firmware {
        data: fw,
        format: Format::Idf(Default::default()),
    };
    run_l2cap_peripheral_test(&[("target", "esp32"), ("board", "esp-rust-board")], firmware).await;
}
*/

async fn run_l2cap_peripheral_test(labels: &[(&str, &str)], firmware: probe::Firmware) {
    let ctx = TestContext::new();
    let central = ctx.serial_adapters[0].clone();

    let dut = ctx.find_dut(labels).unwrap();

    // Flash the binary to the target
    let token = dut.token();

    // Spawn a runner for the target
    let peripheral = tokio::task::spawn_local(dut.run(firmware));

    // Run the central in the test using the serial adapter to verify
    let peripheral_address: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
    let central = tokio::task::spawn_local(async move {
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
                    token.cancel();
                    break;
                }
                Ok(())
            } => {
                r
            }
        }
    });

    tokio::time::timeout(Duration::from_secs(60), select(peripheral, central))
        .await
        .map_err(|_| {
            println!("Test timed out");
            assert!(false);
        })
        .unwrap();
}
