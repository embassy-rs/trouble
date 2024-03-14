// Use with any serial HCI
use async_io::Async;
use bt_hci::cmd::AsyncCmd;
use bt_hci::cmd::SyncCmd;
use bt_hci::data;
use bt_hci::param;
use bt_hci::Controller;
use bt_hci::ControllerCmdAsync;
use bt_hci::ControllerCmdSync;
use bt_hci::ControllerToHostPacket;
use bt_hci::ReadHci;
use bt_hci::WithIndicator;
use bt_hci::WriteHci;
use core::future::Future;
use core::ops::DerefMut;
use embassy_executor::Executor;
use embassy_futures::join::join3;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time as _;
use embassy_time::{Duration, Timer};
use embedded_io_async::Read;
use log::*;
use nix::sys::termios;
use static_cell::StaticCell;
use trouble_host::{
    adapter::{Adapter, HostResources},
    advertise::{AdStructure, AdvertiseConfig, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE},
    attribute::{AttributeTable, Characteristic, CharacteristicProp, Service, Uuid},
    PacketQos,
};

mod serial_port;
use self::serial_port::SerialPort;

static EXECUTOR: StaticCell<Executor> = StaticCell::new();

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .filter_module("async_io", log::LevelFilter::Info)
        .format_timestamp_nanos()
        .init();

    let executor = EXECUTOR.init(Executor::new());
    executor.run(|spawner| {
        spawner.spawn(run()).unwrap();
    });
}

#[embassy_executor::task]
async fn run() {
    let baudrate = termios::BaudRate::B115200;

    if std::env::args().len() != 2 {
        println!("Provide the serial port as the one and only command line argument.");
        return;
    }

    let args: Vec<String> = std::env::args().collect();

    let port = SerialPort::new(args[1].as_str(), baudrate).unwrap();
    let port = Async::new(port).unwrap();
    let mut port = embedded_io_adapters::futures_03::FromFutures::new(port);

    println!("Reset the target");
    let mut buffer = [0u8; 1];

    loop {
        match port.read(&mut buffer).await {
            Ok(_len) => {
                if buffer[0] == 0xff {
                    break;
                }
            }
            Err(_) => (),
        }
    }

    println!("Connected");
    println!("Q to exit, N to notify, X force disconnect");

    let controller = SerialController::new(port);
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
    let mut id = [b'T', b'r', b'o', b'u', b'b', b'l', b'e'];
    let mut appearance = [0x80, 0x07];
    let mut bat_level = [0; 1];
    let handle = {
        let mut svc = table.add_service(Service::new(0x1800));
        let _ = svc.add_characteristic(Characteristic::new(0x2a00, &[CharacteristicProp::Read], &mut id[..]));
        let _ = svc.add_characteristic(Characteristic::new(
            0x2a01,
            &[CharacteristicProp::Read],
            &mut appearance[..],
        ));
        drop(svc);

        // Generic attribute service (mandatory)
        table.add_service(Service::new(0x1801));

        // Battery service
        let mut svc = table.add_service(Service::new(0x180f));

        svc.add_characteristic(Characteristic::new(
            0x2a19,
            &[CharacteristicProp::Read, CharacteristicProp::Notify],
            &mut bat_level,
        ))
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

pub struct SerialController<T>
where
    T: embedded_io_async::Read + embedded_io_async::Write,
{
    io: Mutex<NoopRawMutex, T>,
}

impl<T> SerialController<T>
where
    T: embedded_io_async::Read + embedded_io_async::Write,
{
    pub fn new(io: T) -> Self {
        Self { io: Mutex::new(io) }
    }
}

impl<T> Controller for SerialController<T>
where
    T: embedded_io_async::Read + embedded_io_async::Write,
{
    type Error = T::Error;
    fn write_acl_data(&self, packet: &data::AclPacket) -> impl Future<Output = Result<(), Self::Error>> {
        async {
            let mut io = self.io.lock().await;
            WithIndicator::new(packet)
                .write_hci_async(io.deref_mut())
                .await
                .unwrap();
            Ok(())
        }
    }

    fn write_sync_data(&self, packet: &data::SyncPacket) -> impl Future<Output = Result<(), Self::Error>> {
        async {
            let mut io = self.io.lock().await;
            WithIndicator::new(packet)
                .write_hci_async(io.deref_mut())
                .await
                .unwrap();
            Ok(())
        }
    }

    fn write_iso_data(&self, packet: &data::IsoPacket) -> impl Future<Output = Result<(), Self::Error>> {
        async {
            let mut io = self.io.lock().await;
            WithIndicator::new(packet)
                .write_hci_async(io.deref_mut())
                .await
                .unwrap();
            Ok(())
        }
    }

    fn read<'a>(&self, buf: &'a mut [u8]) -> impl Future<Output = Result<ControllerToHostPacket<'a>, Self::Error>> {
        async {
            let mut io = self.io.lock().await;
            let value = ControllerToHostPacket::read_hci_async(io.deref_mut(), buf)
                .await
                .unwrap();
            Ok(value)
        }
    }
}

impl<T, C> ControllerCmdSync<C> for SerialController<T>
where
    T: embedded_io_async::Read + embedded_io_async::Write,
    C: SyncCmd,
    C::Return: bt_hci::FixedSizeValue,
{
    fn exec(&self, cmd: &C) -> impl Future<Output = Result<C::Return, param::Error>> {
        async {
            let mut buf = [0; 512];
            let mut io = self.io.lock().await;
            WithIndicator::new(cmd).write_hci_async(io.deref_mut()).await.unwrap();
            let value = C::Return::read_hci_async(io.deref_mut(), &mut buf[..]).await.unwrap();
            Ok(value)
        }
    }
}

impl<T, C> ControllerCmdAsync<C> for SerialController<T>
where
    T: embedded_io_async::Read + embedded_io_async::Write,
    C: AsyncCmd,
{
    fn exec(&self, cmd: &C) -> impl Future<Output = Result<(), param::Error>> {
        async {
            let mut io = self.io.lock().await;
            Ok(WithIndicator::new(cmd).write_hci_async(io.deref_mut()).await.unwrap())
        }
    }
}
