#![allow(dead_code)]
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

#[gatt_server(connections_max = CONNECTIONS_MAX, mutex_type = NoopRawMutex, attribute_table_size = 31)]
struct Server {
    service: CustomService,
    bas: BatteryService,
}

const UUID_U128: u128 = 0x408813df_5dd4_1f87_ec11_cdb000100000;

#[gatt_service(uuid = "408813df-5dd4-1f87-ec11-cdb000100000")]
struct CustomService {
    #[descriptor(uuid = "2b20", value = "Read Only Descriptor", read)]
    #[characteristic(uuid = "408813df-5dd4-1f87-ec11-cdb001100000", value = 42, read, write, notify)]
    #[descriptor(uuid = "2b21", value = [0x01,0x02,0x03], read)]
    pub value: u8,
    #[characteristic(uuid = UUID_U128, value = 123.321, read, write, notify)]
    /// Order doesn't matter
    #[descriptor(uuid = "2b20", read, value = 42u16.to_le_bytes())] // empty descriptor
    pub second: f32,
    /// Multi
    ///
    /// Line
    /// Comment
    #[characteristic(uuid = "408815df-5dd4-1f87-ec11-cdb001100000", value = [0,1], read, write, notify)]
    pub third: [u8; 2],
    #[characteristic(uuid = "408816df-5dd4-1f87-ec11-cdb001100000", read, write, notify)]
    pub fourth: heapless::Vec<u8, 3>,
    #[characteristic(uuid = "408817df-5dd4-1f87-ec11-cdb001100000", read, write, notify)]
    pub fifth: heapless::Vec<u8, 33>,
}

#[gatt_service(uuid = service::BATTERY)]
struct BatteryService {
    /// Battery Level
    #[descriptor(uuid = descriptors::VALID_RANGE, read, value = [0, 100])]
    #[descriptor(uuid = descriptors::MEASUREMENT_DESCRIPTION, read, value = "Battery Level")]
    #[characteristic(uuid = characteristic::BATTERY_LEVEL, read, notify, value = 10)]
    level: u8,
}

#[tokio::test]
async fn gatt_client_server() {
    let _ = env_logger::try_init();
    let adapters = common::find_controllers();
    let peripheral = adapters[0].clone();
    let central = adapters[1].clone();

    let name = std::env::var("DEVICE_NAME").unwrap_or("TrouBLE".into());

    let peripheral_address: Address = Address::random([0xff, 0x9f, 0x1a, 0x05, 0xe4, 0xff]);

    let local = tokio::task::LocalSet::new();

    // Spawn peripheral
    let peripheral = local.spawn_local(async move {
        let controller_peripheral = common::create_controller(&peripheral).await;

        let mut resources: HostResources<CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, 27> = HostResources::new();
        let stack = trouble_host::new(controller_peripheral, &mut resources)
            .set_random_address(peripheral_address);
        let Host {
            mut peripheral,
            mut runner,
            ..
        } = stack.build();

        let gap = GapConfig::Peripheral(PeripheralConfig {
            name: &name,
            appearance: &appearance::power_device::GENERIC_POWER_DEVICE,
        });
        let server: Server = Server::new_with_config(
            gap,
        ).unwrap();

        // Random starting value to 'prove' the incremented value is correct
        let value: u8 = rand::prelude::random();
        // The first write will be rejected by the write callback, so value is not expected to change the first time
        let mut expected = value;
        server.set(&server.service.value, &value).unwrap();

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
                    &[AdStructure::CompleteLocalName(b"trouble-gatt-int")],
                    &mut scan_data[..],
                ).unwrap();

                let mut done = false;
                while !done {
                    println!("[peripheral] advertising");
                    let acceptor = peripheral.advertise(&Default::default(), Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..],
                        scan_data: &scan_data[..],
                    }).await?;
                    let conn = acceptor.accept().await?.with_attribute_server(&server)?;
                    println!("[peripheral] connected");
                    let mut writes = 0;
                    while !done {
                        match conn.next().await {
                            GattConnectionEvent::Disconnected { reason } => {
                                println!("Disconnected: {:?}", reason);
                                break;
                            }
                            GattConnectionEvent::Gatt { event } => if let Ok(GattEvent::Write(event)) = event {
                                if writes == 0 {
                                    event.reject(AttErrorCode::VALUE_NOT_ALLOWED).unwrap().send().await;
                                    writes += 1;
                                } else {
                                    let characteristic = server.table().find_characteristic_by_value_handle(event.handle()).unwrap();
                                    let value: u8 = server.table().get(&characteristic).unwrap();
                                    assert_eq!(expected, value);
                                    expected = expected.wrapping_add(2);
                                    writes += 1;
                                    if writes == 2 {
                                        println!("expected value written twice, test pass");

                                        done = true;
                                    }
                                }
                            }
                        }
                    }
                    // NOTE: Ensure that adapter gets polled again
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                println!("[peripheral] done");
                Ok(())
            } => {
                r
            }
        }
    });

    // Spawn central
    let central = local.spawn_local(async move {
        let controller_central = common::create_controller(&central).await;
        let mut resources: HostResources<CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, 27> = HostResources::new();
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
                let conn = central.connect(&config).await.unwrap();
                println!("[central] connected");
                tokio::time::sleep(Duration::from_secs(5)).await;

                println!("[central] creating gatt client");
                let client = GattClient::<common::Controller, 10, 27>::new(&stack, &conn).await.unwrap();

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
                        if let Err(BleHostError::BleHost(Error::Att(AttErrorCode::VALUE_NOT_ALLOWED))) = client.write_characteristic(&c, &data[..]).await {
                            println!("[central] Frist write was rejected by write callback as expected.");
                        } else {
                            println!("[central] First write was expected to be rejected by server write callback!");
                            panic!();
                         }
                        data[0] = data[0].wrapping_add(1);
                        println!("[central] write value: {}", data[0]);
                        if let Ok(()) = client.write_characteristic(&c, &data[..]).await {
                            println!("[central] Second write accepted by server.");
                        } else {
                            println!("[central] Second write was expected to be accepted by the server!");
                            panic!();
                        }
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
