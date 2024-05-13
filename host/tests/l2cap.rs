// Use with any serial HCI
use bt_hci::controller::ExternalController;
use bt_hci::transport::SerialTransport;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embedded_io_adapters::tokio_1::FromTokio;
use static_cell::StaticCell;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::select;
use tokio::time::Duration;
use tokio_serial::{DataBits, Parity, SerialStream, StopBits};
use trouble_host::advertise::{AdStructure, Advertisement, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE};
use trouble_host::connection::ConnectConfig;
use trouble_host::l2cap::L2capChannel;
use trouble_host::scan::ScanConfig;
use trouble_host::{Address, BleHost, BleHostResources, PacketQos};

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

    let peripheral_address: Address = Address::random([0xff, 0x9f, 0x1a, 0x05, 0xe4, 0xff]);

    let local = tokio::task::LocalSet::new();

    const PAYLOAD_LEN: usize = 4;

    // Spawn peripheral
    let peripheral = local.spawn_local(async move {
        let controller_peripheral = create_controller(&peripheral).await;

        static RESOURCES: StaticCell<BleHostResources<CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, 32, 27>> = StaticCell::new();
        let host_resources = RESOURCES.init(BleHostResources::new(PacketQos::Guaranteed(4)));
        let mut adapter: BleHost<'_, _> = BleHost::new(controller_peripheral, host_resources);

        adapter.set_random_address(peripheral_address);

        select! {
            r = adapter.run() => {
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
                    &[AdStructure::CompleteLocalName(b"trouble-l2cap-int")],
                    &mut scan_data[..],
                ).unwrap();

                loop {
                    println!("[peripheral] advertising");
                    let conn = adapter.advertise(&Default::default(), Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..],
                        scan_data: &scan_data[..],
                    }).await?;
                    println!("[peripheral] connected");

                    let mut ch1 = L2capChannel::<PAYLOAD_LEN>::accept(&adapter, &conn, &[0x2349], &Default::default()).await?;

                    println!("[peripheral] channel created");

                    // Size of payload we're expecting
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
        static RESOURCES: StaticCell<BleHostResources<CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, 32, 27>> = StaticCell::new();
        let host_resources = RESOURCES.init(BleHostResources::new(PacketQos::Guaranteed(4)));

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
                loop {
                    let conn = adapter.connect(&config).await.unwrap();
                    println!("[central] connected");
                    let mut ch1 = L2capChannel::<PAYLOAD_LEN>::create(&adapter, &conn, 0x2349, &Default::default()).await?;
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
