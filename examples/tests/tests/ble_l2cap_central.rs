use futures::future::join;
use std::time::Duration;
use tokio::select;
use trouble_example_tests::{TestContext, serial};
use trouble_host::prelude::*;

#[tokio::test]
async fn ble_l2cap_central_nrf52() {
    let _ = pretty_env_logger::try_init();
    let firmware = "bins/nrf-sdc/ble_l2cap_central";
    let local = tokio::task::LocalSet::new();
    local
        .run_until(run_l2cap_central_test(
            &[("target", "nrf52"), ("board", "microbit")],
            firmware,
        ))
        .await;
}

/*
#[tokio::test]
async fn ble_l2cap_central_esp32c3() {
    let _ = pretty_env_logger::try_init();
    let firmware = "bins/esp32/ble_l2cap_central";
    let local = tokio::task::LocalSet::new();
    local
        .run_until(run_l2cap_central_test(
            &[("target", "esp32"), ("board", "esp-rust-board")],
            firmware,
        ))
        .await;
}
*/

async fn run_l2cap_central_test(labels: &[(&str, &str)], firmware: &str) {
    let ctx = TestContext::new();
    let peripheral = ctx.serial_adapters[0].clone();

    let dut = ctx.find_dut(labels).unwrap();
    let token = dut.token();
    let token2 = token.clone();

    // Spawn a runner for the target
    let mut dut = tokio::task::spawn_local(dut.run(firmware.to_string()));

    // Run the central in the test using the serial adapter to verify
    let peripheral_address: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
    let peripheral = tokio::task::spawn_local(async move {
        let controller_peripheral = serial::create_controller(&peripheral).await;

        let mut resources: HostResources<DefaultPacketPool, 2, 4> = HostResources::new();
        let stack = trouble_host::new(controller_peripheral, &mut resources).set_random_address(peripheral_address);
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
                    &[AdStructure::CompleteLocalName(b"trouble-l2cap-example")],
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

                    const PAYLOAD_LEN: usize = 27;
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
                        ch1.send::<_, PAYLOAD_LEN>(&stack, &tx).await?;
                    }
                    println!("[peripheral] data sent");
                    token.cancel();
                    break;
                }
                Ok(())
            } => {
                r
            }
        }
    });

    match tokio::time::timeout(Duration::from_secs(30), join(&mut dut, peripheral)).await {
        Err(_) => {
            println!("Test timed out");
            token2.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(1), dut).await;
            assert!(false);
        }
        Ok((c, p)) => {
            p.expect("peripheral failed").unwrap();
            c.expect("central failed").unwrap();
        }
    }
}
