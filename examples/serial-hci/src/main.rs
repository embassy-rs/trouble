// Use with any serial HCI
use bt_hci::driver::HciController;
use bt_hci::serial::SerialHciDriver;
use embassy_futures::join::join3;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use log::*;
use static_cell::StaticCell;
use tokio::time::Duration;
use tokio_serial::SerialStream;
use tokio_serial::{DataBits, Parity, StopBits};
use trouble_host::{
    adapter::{Adapter, HostResources},
    advertise::{AdStructure, AdvertiseConfig, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE},
    attribute::{AttributeTable, CharacteristicProp, Service, Uuid},
    PacketQos,
};

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .format_timestamp_nanos()
        .init();

    let baudrate = 1000000;

    if std::env::args().len() != 2 {
        println!("Provide the serial port as the one and only command line argument.");
        return;
    }

    let args: Vec<String> = std::env::args().collect();

    let mut port = SerialStream::open(
        &tokio_serial::new(args[1].as_str(), baudrate)
            .baud_rate(baudrate)
            .data_bits(DataBits::Eight)
            .parity(Parity::None)
            .stop_bits(StopBits::One),
    )
    .unwrap();

    // Drain input
    tokio::time::sleep(Duration::from_secs(1)).await;
    loop {
        let mut buf = [0; 1];
        match port.try_read(&mut buf[..]) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            _ => {}
        }
    }
    info!("Ready!");

    let (reader, writer) = tokio::io::split(port);

    let reader = embedded_io_adapters::tokio_1::FromTokio::new(reader);
    let writer = embedded_io_adapters::tokio_1::FromTokio::new(writer);

    let driver: SerialHciDriver<NoopRawMutex, _, _> = SerialHciDriver::new(reader, writer);
    let controller: HciController<_, 10> = HciController::new(driver);
    static HOST_RESOURCES: StaticCell<HostResources<NoopRawMutex, 4, 32, 27>> = StaticCell::new();
    let host_resources = HOST_RESOURCES.init(HostResources::new(PacketQos::None));

    let adapter: Adapter<'_, NoopRawMutex, _, 2, 4, 1, 1> = Adapter::new(controller, host_resources);
    let config = AdvertiseConfig {
        params: None,
        data: &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::ServiceUuids16(&[Uuid::Uuid16([0x0f, 0x18])]),
            AdStructure::CompleteLocalName("Trouble HCI"),
        ],
    };

    let mut table: AttributeTable<'_, NoopRawMutex, 10> = AttributeTable::new();

    // Generic Access Service (mandatory)
    let id = b"Trouble HCI";
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
                tokio::time::sleep(Duration::from_secs(10)).await;
                tick += 1;
                server.notify(handle, &conn, &[tick]).await.unwrap();
            }
        },
    )
    .await;
}
