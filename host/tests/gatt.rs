use std::time::Duration;

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use static_cell::StaticCell;
use tokio::select;
use trouble_host::advertise::{AdStructure, Advertisement, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE};
use trouble_host::attribute::{AttributeTable, CharacteristicProp, Service, Uuid};
use trouble_host::connection::ConnectConfig;
use trouble_host::gatt::GattEvent;
use trouble_host::scan::ScanConfig;
use trouble_host::{Address, BleHost, BleHostResources, PacketQos};

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

        static RESOURCES: StaticCell<BleHostResources<CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, 27>> = StaticCell::new();
        let host_resources = RESOURCES.init(BleHostResources::new(PacketQos::None));
        let mut adapter: BleHost<'_, _> = BleHost::new(controller_peripheral, host_resources);

        adapter.set_random_address(peripheral_address);
        let mut table: AttributeTable<'_, NoopRawMutex, 10> = AttributeTable::new();

        let id = b"Trouble";
        let appearance = [0x80, 0x07];
        // Random starting value to 'prove' the incremented value is correct
        let mut value: [u8; 1] = [rand::prelude::random(); 1];
        let mut expected = value[0].wrapping_add(1);
        let mut svc = table.add_service(Service::new(0x1800));
        let _ = svc.add_characteristic_ro(0x2a00, id);
        let _ = svc.add_characteristic_ro(0x2a01, &appearance[..]);
        svc.build();

        // Generic attribute service (mandatory)
        table.add_service(Service::new(0x1801));

        // Custom service
        table.add_service(Service::new(SERVICE_UUID.clone()))
        .add_characteristic(
            VALUE_UUID.clone(),
            &[CharacteristicProp::Read, CharacteristicProp::Write, CharacteristicProp::Notify],
            &mut value,
        )
        .build();

        let server = adapter.gatt_server(&table);

        select! {
            r = adapter.run() => {
                r
            }
            r = async {
                let mut writes = 0;
                loop {
                    match server.next().await {
                        Ok(GattEvent::Write {
                            connection: _,
                            handle,
                        }) => {
                            let _ = table.get(handle, |value| {
                                assert_eq!(expected, value[0]);
                                expected += 1;
                                writes += 1;
                            });
                            if writes == 2 {
                                println!("expected value written twice, test pass");
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
                    let mut acceptor = adapter.advertise(&Default::default(), Advertisement::ConnectableScannableUndirected {
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
                let conn = adapter.connect(&config).await.unwrap();
                println!("[central] connected");
                tokio::time::sleep(Duration::from_secs(5)).await;

                println!("[central] creating gatt client");
                let mut client = adapter.gatt_client::<10, 128>(&conn).await.unwrap();

                println!("[central] discovering services");
                let services = client.services_by_uuid(&SERVICE_UUID).await.unwrap();

                let service = services.first().unwrap().clone();

                println!("[central] service discovered successfully");
                let c = client.characteristic_by_uuid(&service, &VALUE_UUID).await.unwrap();

                let mut data = [0; 1];
                client.read_characteristic(&c, &mut data[..]).await.unwrap();
                println!("[central] read value: {}", data[0]);
                data[0] = data[0].wrapping_add(1);
                client.write_characteristic(&c, &data[..]).await.unwrap();
                data[0] = data[0].wrapping_add(1);
                client.write_characteristic(&c, &data[..]).await.unwrap();
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
