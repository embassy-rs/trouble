// Use with any serial HCI
use bt_hci::controller::ExternalController;
use bt_hci::param::BdAddr;
use bt_hci::transport::SerialTransport;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embedded_io_adapters::tokio_1::FromTokio;
use tokio::io::ReadHalf;
use tokio::io::WriteHalf;
use tokio::join;
use tokio::time::Duration;
use tokio_serial::SerialStream;
use tokio_serial::{DataBits, Parity, StopBits};
use trouble_host::{
    adapter::{Adapter, HostResources},
    advertise::{AdStructure, AdvertiseConfig, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE},
    connection::Connection,
    l2cap::L2capChannel,
    scan::ScanConfig,
    PacketQos,
};

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 2;

async fn create_controller(
    port: &str,
) -> ExternalController<
    SerialTransport<NoopRawMutex, FromTokio<ReadHalf<SerialStream>>, FromTokio<WriteHalf<SerialStream>>>,
    10,
> {
    let baudrate = 1000000;
    let mut port = SerialStream::open(
        &tokio_serial::new(port, baudrate)
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

    let (reader, writer) = tokio::io::split(port);

    let reader = embedded_io_adapters::tokio_1::FromTokio::new(reader);
    let writer = embedded_io_adapters::tokio_1::FromTokio::new(writer);

    let driver: SerialTransport<NoopRawMutex, _, _> = SerialTransport::new(reader, writer);
    ExternalController::new(driver)
}

/// Verify l2cap le connection oriented channels using two HCI adapters attached to the test machine.
#[tokio::test]
async fn test_l2cap_connection_oriented_channels() {
    if std::env::args().len() != 2 {
        println!("Provide the serial port as the one and only command line argument.");
        return;
    }

    let args: Vec<String> = std::env::args().collect();
    let peripheral = args[2].clone();
    let central = args[1].clone();

    let local = tokio::task::LocalSet::new();

    // Spawn peripheral
    local.spawn_local(async move {
        let controller_peripheral = create_controller(&peripheral).await;

        let mut host_resources: HostResources<NoopRawMutex, L2CAP_CHANNELS_MAX, 32, 27> =
            HostResources::new(PacketQos::Guaranteed(4));

        let adapter: Adapter<'_, NoopRawMutex, _, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
            Adapter::new(controller_peripheral, &mut host_resources);

        let config = AdvertiseConfig {
            params: None,
            data: &[
                AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                AdStructure::CompleteLocalName("Trouble"),
            ],
        };

        join!(adapter.run(), async {
            loop {
                let conn = adapter.advertise(&config).await.unwrap();

                let mut ch1: L2capChannel<'_, '_, _, PAYLOAD_LEN> =
                    L2capChannel::accept(&adapter, &conn, 0x2349).await.unwrap();

                // Size of payload we're expecting
                const PAYLOAD_LEN: usize = 27;
                let mut rx = [0; PAYLOAD_LEN];
                for i in 0..10 {
                    let len = ch1.receive(&mut rx).await.unwrap();
                    assert_eq!(len, rx.len());
                    assert_eq!(rx, [i; PAYLOAD_LEN]);
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
                for i in 0..10 {
                    let tx = [i; PAYLOAD_LEN];
                    ch1.send(&tx).await.unwrap();
                }
                return ();
            }
        })
    });

    // Spawn central
    local.spawn_local(async move {
        let controller_central = create_controller(&central).await;
        let mut host_resources: HostResources<NoopRawMutex, L2CAP_CHANNELS_MAX, 32, 27> =
            HostResources::new(PacketQos::Guaranteed(4));

        let adapter: Adapter<'_, NoopRawMutex, _, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> =
            Adapter::new(controller_central, &mut host_resources);

        let config = ScanConfig { params: None };

        // NOTE: Modify this to match the address of the peripheral you want to connect to
        let target: BdAddr = BdAddr::new([0xf5, 0x9f, 0x1a, 0x05, 0xe4, 0xee]);

        join!(adapter.run(), async {
            loop {
                let reports = adapter.scan(&config).await.unwrap();
                for report in reports.iter() {
                    let report = report.unwrap();
                    if report.addr == target {
                        let conn = Connection::connect(&adapter, report.addr).await;
                        const PAYLOAD_LEN: usize = 27;
                        let mut ch1: L2capChannel<'_, '_, _, PAYLOAD_LEN> =
                            L2capChannel::create(&adapter, &conn, 0x2349).await.unwrap();
                        for i in 0..10 {
                            let tx = [i; PAYLOAD_LEN];
                            ch1.send(&tx).await.unwrap();
                        }
                        let mut rx = [0; PAYLOAD_LEN];
                        for i in 0..10 {
                            let len = ch1.receive(&mut rx).await.unwrap();
                            assert_eq!(len, rx.len());
                            assert_eq!(rx, [i; PAYLOAD_LEN]);
                        }

                        return ();
                    }
                }
            }
        })
    });

    match tokio::time::timeout(Duration::from_secs(60), local).await {
        Ok(_) => {
            println!("Test completed successfully");
        }
        Err(e) => {
            println!("Test timed out: {:?}", e);
        }
    }
}
