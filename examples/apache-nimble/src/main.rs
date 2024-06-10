#![no_main]
#![no_std]
#![feature(type_alias_impl_trait)]

use defmt::{error, info, Debug2Format};
use embassy_futures::join::join4;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;
use trouble_host::advertise::{AdStructure, Advertisement, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE};
use trouble_host::attribute::{AttributeTable, CharacteristicProp, Service, Uuid};
use trouble_host::gatt::GattEvent;
use trouble_host::{Address, BleHost, BleHostResources, PacketQos};
use {defmt_rtt as _, panic_probe as _};

#[::embassy_executor::task]
async fn other_task() {
    let mut ticker = embassy_time::Ticker::every(Duration::from_secs(1));
    loop {
        ticker.next().await;
        info!("test");
    }
}

#[::embassy_executor::main]
async fn main(spawner: embassy_executor::Spawner) {
    let mut conf = embassy_nrf::config::Config::default();
    conf.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    conf.lfclk_source = embassy_nrf::config::LfclkSource::ExternalXtal;
    embassy_nrf::init(conf);
    apache_nimble::initialize_nimble();

    static HOST_RESOURCE: StaticCell<BleHostResources<2, 2, 27>> = StaticCell::new();
    let host_resources = HOST_RESOURCE.init(BleHostResources::new(PacketQos::None));

    let controller = apache_nimble::controller::NimbleController::new();
    let controller_task = controller.create_task();

    // wait for RNG to calm down
    Timer::after(Duration::from_secs(1)).await;
    let mut adapter = BleHost::new(controller, host_resources);
    adapter.set_random_address(Address::random([0x41, 0x5A, 0xE3, 0x1E, 0x83, 0xE7]));

    let mut table = AttributeTable::<'_, CriticalSectionRawMutex, 10>::new();
    let mut bat_level = [0];

    let handle = {
        let mut svc = table.add_service(Service::new(0x1800));
        svc.add_characteristic_ro(0x2a00, b"Trouble");
        svc.add_characteristic_ro(0x2a01, &[0x80, 0x07]);
        drop(svc);

        table.add_service(Service::new(0x1801));

        let mut svc = table.add_service(Service::new(0x180f));
        svc.add_characteristic(
            0x2a19,
            &[CharacteristicProp::Read, CharacteristicProp::Notify],
            &mut bat_level,
        )
    };

    let server = adapter.gatt_server(&table);

    // Just to check that other tasks are still running
    spawner.spawn(other_task()).unwrap();

    join4(
        adapter.run(),
        controller_task.run(),
        async {
            loop {
                match server.next().await {
                    Ok(event) => match event {
                        GattEvent::Write { value, .. } => {
                            info!("{}", value);
                        }
                    },
                    Err(e) => {
                        error!("{}", Debug2Format(&e));
                    }
                }
            }
        },
        async {
            let mut adv_data = [0; 31];
            AdStructure::encode_slice(
                &[
                    AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                    AdStructure::ServiceUuids16(&[Uuid::Uuid16([0x0f, 0x18])]),
                    AdStructure::CompleteLocalName(b"Trouble"),
                ],
                &mut adv_data,
            )
            .unwrap();

            let conn = adapter
                .advertise(
                    &Default::default(),
                    Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data,
                        scan_data: &[],
                    },
                )
                .await
                .unwrap()
                .accept()
                .await
                .unwrap();

            let mut test = 0;
            loop {
                Timer::after(Duration::from_secs(10)).await;
                test += 1;
                info!("updating value: {}", test);
                server.notify(handle, &conn, &[test]).await.unwrap();
            }
        },
    )
    .await;
}
