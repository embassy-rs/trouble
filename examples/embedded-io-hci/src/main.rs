#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use bt_hci::cmd::SyncCmd;
use bt_hci::param::BdAddr;
use bt_hci::serial::SerialController;
use defmt::{error, info, unwrap};
use embassy_executor::Spawner;
use embassy_futures::join::join3;
use embassy_nrf::peripherals;
use embassy_nrf::{bind_interrupts, pac};
use embassy_nrf::{buffered_uarte, uarte};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;
use trouble_host::{
    adapter::{Adapter, HostResources},
    advertise::{AdStructure, AdvertiseConfig, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE},
    attribute::{AttributeTable, CharacteristicProp, Service, Uuid},
    PacketQos,
};

use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    UARTE0_UART0 => buffered_uarte::InterruptHandler<peripherals::UARTE0>;
});

#[embassy_executor::main]
async fn main(_s: Spawner) {
    let p = embassy_nrf::init(Default::default());

    let uart_tx = p.P0_01;
    let uart_rx = p.P0_17;
    let uart_cts = p.P0_13;
    let uart_rts = p.P1_02;

    let mut config = uarte::Config::default();
    config.parity = uarte::Parity::EXCLUDED;
    config.baudrate = uarte::Baudrate::BAUD115200;

    let mut tx_buffer = [0u8; 4096];
    let mut rx_buffer = [0u8; 4096];

    let mut u = buffered_uarte::BufferedUarte::new_with_rtscts(
        p.UARTE0,
        p.TIMER0,
        p.PPI_CH0,
        p.PPI_CH1,
        p.PPI_GROUP0,
        Irqs,
        uart_rx,
        uart_tx,
        uart_cts,
        uart_rts,
        config,
        &mut rx_buffer,
        &mut tx_buffer,
    );

    let (reader, writer) = u.split();

    let controller: SerialController<NoopRawMutex, _, _, 10> = SerialController::new(reader, writer);
    static HOST_RESOURCES: StaticCell<HostResources<NoopRawMutex, 4, 32, 27>> = StaticCell::new();
    let host_resources = HOST_RESOURCES.init(HostResources::new(PacketQos::None));

    let adapter: Adapter<'_, NoopRawMutex, _, 2, 4, 1, 1> = Adapter::new(controller, host_resources);
    let config = AdvertiseConfig {
        params: None,
        data: &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::ServiceUuids16(&[Uuid::Uuid16([0x0f, 0x18])]),
            AdStructure::CompleteLocalName("Trouble"),
        ],
    };

    let mut table: AttributeTable<'_, NoopRawMutex, 10> = AttributeTable::new();

    // Generic Access Service (mandatory)
    let id = b"Trouble";
    let appearance = [0x80, 0x07];
    let mut bat_level = [0; 1];
    let handle = {
        let mut svc = table.add_service(Service::new(0x1800));
        let _ = svc.add_characteristic_ro(0x2a00, id);
        let _ = svc.add_characteristic_ro(0x2a01, &appearance[..]);
        drop(svc);

        // Generic attribute service (mandatory)
        table.add_service(Service::new(0x1801));

        // Battery service
        let mut svc = table.add_service(Service::new(0x180f));

        svc.add_characteristic(
            0x2a19,
            &[CharacteristicProp::Read, CharacteristicProp::Notify],
            &mut bat_level,
        )
    };

    let server = adapter.gatt_server(&table);

    info!("Starting advertising and GATT service");
    let _ = join3(
        adapter.run(),
        async {
            loop {
                match server.next().await {
                    Ok(event) => {
                        info!("Gatt event: {:?}", event);
                    }
                    Err(e) => {
                        error!("Error processing GATT events: {:?}", e);
                    }
                }
            }
        },
        async {
            let conn = adapter.advertise(&config).await.unwrap();
            // Keep connection alive
            let mut tick: u8 = 0;
            loop {
                Timer::after(Duration::from_secs(10)).await;
                tick += 1;
                server.notify(handle, &conn, &[tick]).await.unwrap();
            }
        },
    )
    .await;
}
