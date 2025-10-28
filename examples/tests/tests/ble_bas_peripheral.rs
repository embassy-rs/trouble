use futures::future::join;
use std::time::Duration;
use tokio::select;
use trouble_example_tests::{TestContext, serial};
use trouble_host::prelude::*;

#[tokio::test]
async fn ble_bas_peripheral_nrf52() {
    let _ = pretty_env_logger::try_init();
    let firmware = "bins/nrf52/ble_bas_peripheral";
    let local = tokio::task::LocalSet::new();
    local
        .run_until(run_bas_peripheral_test(
            &[("target", "nrf52"), ("board", "microbit")],
            firmware,
        ))
        .await;
}

async fn run_bas_peripheral_test(labels: &[(&str, &str)], firmware: &str) {
    let ctx = TestContext::new();
    let central = ctx.serial_adapters[0].clone();

    let dut = ctx.find_dut(labels).unwrap();
    let token = dut.token();
    let token2 = token.clone();

    // Spawn a runner for the target
    let mut dut = tokio::task::spawn_local(dut.run(firmware.to_string()));

    // Run the central in the test using the serial adapter to verify
    let peripheral_address: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
    let central = tokio::task::spawn_local(async move {
        let controller_central = serial::create_controller(&central).await;
        let mut resources: HostResources<DefaultPacketPool, 2, 4> = HostResources::new();
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

                log::info!("[central] connecting");
                loop {
                    let conn = central.connect(&config).await.unwrap();
                    log::info!("[central] connected");
                    let client = GattClient::<serial::Controller, DefaultPacketPool, 10>::new(&stack, &conn).await.unwrap();
                    select! {
                        _r = async {
                            client.task().await.unwrap();
                        } => {
                            token.cancel();
                            break;
                        }
                        _r = async {
                            println!("[central] discovering services");
                            const VALUE_UUID: Uuid = Uuid::new_long([
                                0x00, 0x00, 0x10, 0x01, 0xb0, 0xcd, 0x11, 0xec, 0x87, 0x1f, 0xd4, 0x5d, 0xdf, 0x13, 0x88, 0x40,
                            ]);
                            let uuid = service::BATTERY.into();
                            let services = client.services_by_uuid(&uuid).await.unwrap();

                            let service = services.first().unwrap().clone();

                            println!("[central] service discovered successfully");
                            let c: Characteristic<u8> = client.characteristic_by_uuid(&service, &VALUE_UUID).await.unwrap();

                            let mut data = [0; 1];
                            client.read_characteristic(&c, &mut data[..]).await.unwrap();
                            println!("[central] read value: {}", data[0]);
                            data[0] = data[0].wrapping_add(1);
                            println!("[central] write value: {}", data[0]);
                            client.write_characteristic(&c, &data[..]).await.unwrap();
                            data[0] = data[0].wrapping_add(1);
                            println!("[central] write value: {}", data[0]);
                            client.write_characteristic(&c, &data[..]).await.unwrap();
                            println!("[central] write done");
                        } => {
                            token.cancel();
                            break;
                        }
                    }
                }
                Ok(())
            } => {
                r
            }
        }
    });

    match tokio::time::timeout(Duration::from_secs(30), join(&mut dut, central)).await {
        Err(_) => {
            println!("Test timed out");
            token2.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(1), dut).await;
            assert!(false);
        }
        Ok((p, c)) => {
            p.expect("peripheral failed").unwrap();
            c.expect("central failed").unwrap();
        }
    }
}
