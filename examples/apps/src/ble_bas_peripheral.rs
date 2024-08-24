use embassy_futures::join::join3;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use static_cell::StaticCell;
use trouble_host::advertise::{AdStructure, Advertisement, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE};
use trouble_host::attribute::{AttributeTable, CharacteristicProp, Service, Uuid};
use trouble_host::gatt::GattEvent;
use trouble_host::{Address, BleHost, BleHostResources, Controller, PacketQos};

/// Size of L2CAP packets (ATT MTU is this - 4)
const L2CAP_MTU: usize = 128;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 2; // Signal + att

pub async fn run<C>(controller: C)
where
    C: Controller,
{
    static HOST_RESOURCES: StaticCell<BleHostResources<CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, L2CAP_MTU>> =
        StaticCell::new();
    let resources = HOST_RESOURCES.init(BleHostResources::new(PacketQos::None));

    let mut ble: BleHost<'_, _> = BleHost::new(controller, resources);

    let address: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
    info!("Our address = {:?}", address);
    ble.set_random_address(address);

    let mut table: AttributeTable<'_, NoopRawMutex, 10> = AttributeTable::new();

    // Generic Access Service (mandatory)
    let id = b"Trouble";
    let appearance = [0x80, 0x07];
    let mut bat_level = [23; 1];
    let mut svc = table.add_service(Service::new(0x1800));
    let _ = svc.add_characteristic_ro(0x2a00, id);
    let _ = svc.add_characteristic_ro(0x2a01, &appearance[..]);
    svc.build();

    // Generic attribute service (mandatory)
    table.add_service(Service::new(0x1801));

    // Battery service
    let level_handle = table
        .add_service(Service::new(0x180f))
        .add_characteristic(
            0x2a19,
            &[CharacteristicProp::Read, CharacteristicProp::Notify],
            &mut bat_level,
        )
        .build();

    let server = ble.gatt_server::<NoopRawMutex, 10, L2CAP_MTU>(&table);
    let mut adv_data = [0; 31];
    unwrap!(AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::ServiceUuids16(&[Uuid::Uuid16([0x0f, 0x18])]),
            AdStructure::CompleteLocalName(b"Trouble"),
        ],
        &mut adv_data[..],
    ));

    info!("Starting advertising and GATT service");
    let _ = join3(
        ble.run(),
        async {
            loop {
                match server.next().await {
                    Ok(GattEvent::Write { handle, connection: _ }) => {
                        let _ = table.get(handle, |value| {
                            info!("Write event. Value written: {:?}", value);
                        });
                    }
                    Ok(GattEvent::Read { handle, connection: _ }) => {
                        if handle == level_handle {
                            info!("Battery level read");
                        }
                    }
                    Err(e) => {
                        error!("Error processing GATT events: {:?}", e);
                    }
                }
            }
        },
        async {
            let mut advertiser = ble
                .advertise(
                    &Default::default(),
                    Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..],
                        scan_data: &[],
                    },
                )
                .await
                .unwrap();
            let conn = advertiser.accept().await.unwrap();
            // Keep connection alive
            let mut tick: u8 = 0;
            loop {
                tick += 1;
                server.notify(&ble, level_handle, &conn, &[tick]).await.unwrap();
            }
        },
    )
    .await;
}
