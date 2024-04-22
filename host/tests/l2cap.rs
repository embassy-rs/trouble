// Use with any serial HCI
use bt_hci::controller::ExternalController;
use bt_hci::transport::SerialTransport;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embedded_io_adapters::tokio_1::FromTokio;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::select;
use tokio::time::Duration;
use tokio_serial::{DataBits, Parity, SerialStream, StopBits};
use trouble_host::adapter::{Adapter, HostResources};
use trouble_host::advertise::{AdStructure, Advertisement, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE};
use trouble_host::connection::ConnectConfig;
use trouble_host::l2cap::{L2capChannel, L2capChannelConfig};
use trouble_host::scan::ScanConfig;
use trouble_host::PacketQos;

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 3;

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
async fn l2cap_connection_oriented_channels() {
    let _ = env_logger::try_init();
    let peripheral = std::env::var("TEST_ADAPTER_ONE").unwrap();
    let central = std::env::var("TEST_ADAPTER_TWO").unwrap();

    let local = tokio::task::LocalSet::new();

    // Spawn peripheral
    let peripheral = local.spawn_local(async move {
        let controller_peripheral = create_controller(&peripheral).await;

        let mut host_resources: HostResources<NoopRawMutex, L2CAP_CHANNELS_MAX, 32, 27> =
            HostResources::new(PacketQos::Guaranteed(4));

        let adapter: Adapter<'_, NoopRawMutex, _, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, 27> =
            Adapter::new(controller_peripheral, &mut host_resources);

        select! {
            r = adapter.run() => {
                r
            }
            r = async {
                let mut adv_data = [0; 31];
                AdStructure::encode_slice(
                    &[AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),],
                    &mut adv_data[..],
                ).unwrap();

                let mut scan_data = [0; 31];
                AdStructure::encode_slice(
                    &[AdStructure::CompleteLocalName(b"trouble-l2cap-int"),],
                    &mut scan_data[..],
                ).unwrap();
                loop {
                    println!("[peripheral] advertising");
                    let conn = adapter.advertise(&Default::default(), Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..],
                        scan_data: &scan_data[..],
                    }).await?;
                    println!("[peripheral] connected");

                    let mut ch1 = L2capChannel::accept(&adapter, &conn, &[0x2349], &L2capChannelConfig {
                        mtu: PAYLOAD_LEN as u16, ..Default::default()
                    }).await?;

                    println!("[peripheral] channel created");

                    // Size of payload we're expecting
                    const PAYLOAD_LEN: usize = 27;
                    let mut rx = [0; PAYLOAD_LEN];
                    for i in 0..10 {
                        let len = ch1.receive(&adapter, &mut rx).await?;
                        assert_eq!(len, rx.len());
                        assert_eq!(rx, [i; PAYLOAD_LEN]);
                    }
                    println!("[peripheral] data received");

                    tokio::time::sleep(Duration::from_secs(1)).await;
                    for i in 0..10 {
                        let tx = [i; PAYLOAD_LEN];
                        ch1.send(&adapter, &tx).await?;
                    }
                    println!("[peripheral] data sent");
                    break;
                }
                Ok(())
            } => {
                r
            }
        }
    });

    // Spawn central
    let central = local.spawn_local(async move {
        let controller_central = create_controller(&central).await;
        let mut host_resources: HostResources<NoopRawMutex, L2CAP_CHANNELS_MAX, 32, 27> =
            HostResources::new(PacketQos::Guaranteed(4));

        let adapter: Adapter<'_, NoopRawMutex, _, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, 27> =
            Adapter::new(controller_central, &mut host_resources);

        select! {
            r = adapter.run() => {
                r
            }
            r = async {
                println!("[central] scanning");
                loop {
                    let reports = adapter.scan(&Default::default()).await?;
                    let mut found = None;
                    for report in reports.iter() {
                        let report = report.unwrap();
                        for adv in AdStructure::decode(report.data) {
                            if let Ok(AdStructure::CompleteLocalName(b"trouble-l2cap-int")) = adv {
                                found.replace((report.addr_kind, report.addr));
                                break;
                            }
                        }
                    }

                    if let Some((kind, addr)) = found {
                        let config = ConnectConfig {
                            connect_params: Default::default(),
                            scan_config: ScanConfig {
                                filter_accept_list: &[(kind, &addr)],
                                ..Default::default()
                            },
                        };
                        println!("[central] connecting");
                        let conn = adapter.connect(&config).await.unwrap();
                        println!("[central] connected");
                        const PAYLOAD_LEN: usize = 27;
                        let mut ch1 = L2capChannel::create(&adapter, &conn, 0x2349, &L2capChannelConfig {
                            mtu: PAYLOAD_LEN as u16,
                            ..Default::default()
                        }).await?;
                        println!("[central] channel created");
                        for i in 0..10 {
                            let tx = [i; PAYLOAD_LEN];
                            ch1.send(&adapter, &tx).await?;
                        }
                        println!("[central] data sent");
                        let mut rx = [0; PAYLOAD_LEN];
                        for i in 0..10 {
                            let len = ch1.receive(&adapter, &mut rx).await?;
                            assert_eq!(len, rx.len());
                            assert_eq!(rx, [i; PAYLOAD_LEN]);
                        }
                        println!("[central] data received");
                        break;
                    }
                }
                Ok(())
            } => {
                r
            }
        }
    });

    match tokio::time::timeout(Duration::from_secs(30), local).await {
        Ok(_) => {
            central.await.unwrap().unwrap();
            peripheral.await.unwrap().unwrap();
            println!("Test completed successfully");
        }
        Err(e) => {
            println!("Test timed out: {:?}", e);
            assert!(false);
        }
    }
}
