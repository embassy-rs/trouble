use std::time::Duration;

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use tokio::select;
use trouble_host::prelude::*;

mod common;

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 3;

const SERVICE_UUID: Uuid = Uuid::new_long([
    0x00, 0x00, 0x10, 0x00, 0xb0, 0xcd, 0x11, 0xec, 0x87, 0x1f, 0xd4, 0x5d, 0xdf, 0x13, 0x88, 0x40,
]);
const VALUE_UUID: Uuid = Uuid::new_long([
    0x00, 0x00, 0x10, 0x01, 0xb0, 0xcd, 0x11, 0xec, 0x87, 0x1f, 0xd4, 0x5d, 0xdf, 0x13, 0x88, 0x40,
]);

#[tokio::test]
async fn gatt_client_server() {
    let _ = env_logger::try_init();
    let peripheral = std::env::var("TEST_ADAPTER_ONE").unwrap();
    let central = std::env::var("TEST_ADAPTER_TWO").unwrap();

    let peripheral_address: Address = Address::random([0xff, 0x9f, 0x1a, 0x05, 0xe4, 0xff]);

    let local = tokio::task::LocalSet::new();

    // Spawn peripheral
    let peripheral = local.spawn_local(async move {
        let controller_peripheral = common::create_controller(&peripheral).await;

        let mut resources: HostResources<common::Controller, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, 27> = HostResources::new(PacketQos::None);
        let (stack, mut peripheral, _central, mut runner) = trouble_host::new(controller_peripheral, &mut resources)
            .set_random_address(peripheral_address)
            .build();
        let mut table: AttributeTable<'_, NoopRawMutex, 10> = AttributeTable::new();

        let id = b"Trouble";
        let appearance = [0x80, 0x07];
        // Random starting value to 'prove' the incremented value is correct
        let mut value: [u8; 1] = [rand::prelude::random(); 1];
        let mut expected = value[0].wrapping_add(1);
        let mut svc = table.add_service(Service::new(0x1800));
        let _ = svc.add_characteristic_ro(0x2a00, id);
        let _ = svc.add_characteristic_ro(0x2a01, &appearance);
        svc.build();

        // Generic attribute service (mandatory)
        table.add_service(Service::new(0x1801));

        // Custom service
        let value_handle = table.add_service(Service::new(SERVICE_UUID.clone()))
            .add_characteristic(
                VALUE_UUID.clone(),
                &[CharacteristicProp::Read, CharacteristicProp::Write, CharacteristicProp::Notify],
                &mut value)
            .build();

        let server = GattServer::<common::Controller, NoopRawMutex, 10, 27>::new(stack, table);
        select! {
            r = runner.run() => {
                r
            }
            r = async {
                let mut writes = 0;
                loop {
                    match server.next().await {
                        Ok(GattEvent::Write {
                            connection: _,
                            value_handle: handle,
                        }) => {
                            let characteristic = server.server().table().find_characteristic_by_value_handle(handle).unwrap();
                            assert_eq!(characteristic, value_handle);
                            let value: u8 = server.server().table().get(&characteristic).unwrap();
                            assert_eq!(expected, value);
                                expected += 1;
                                writes += 1;
                            if writes == 2 {
                                println!("expected value written twice, test pass");
                                // NOTE: Ensure that adapter gets polled again
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            println!("Error processing GATT events: {:?}", e);
                        }
                    }
                }
                Ok(())
            } => {
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
                    &[AdStructure::CompleteLocalName(b"trouble-gatt-int")],
                    &mut scan_data[..],
                ).unwrap();

                loop {
                    println!("[peripheral] advertising");
                    let mut acceptor = peripheral.advertise(&Default::default(), Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..],
                        scan_data: &scan_data[..],
                    }).await?;
                    let _conn = acceptor.accept().await?;
                    println!("[peripheral] connected");
                    // Keep it alive
                    loop {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                }
            } => {
                r
            }
        }
    });

    // Spawn central
    let central = local.spawn_local(async move {
        let controller_central = common::create_controller(&central).await;
        let mut resources: HostResources<common::Controller, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, 27> =
            HostResources::new(PacketQos::None);
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

                println!("[central] connecting");
                let conn = central.connect(&config).await.unwrap();
                println!("[central] connected");
                tokio::time::sleep(Duration::from_secs(5)).await;

                println!("[central] creating gatt client");
                let client = GattClient::<common::Controller, 10, 27>::new(stack, &conn).await.unwrap();

                select! {
                    r = async {
                        client.task().await
                    } => {
                        r
                    }
                    r = async {
                        println!("[central] discovering services");
                        let services = client.services_by_uuid(&SERVICE_UUID).await.unwrap();

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
                        Ok(())
                    } => {
                        r
                    }
                }
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
