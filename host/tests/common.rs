use bt_hci::controller::ExternalController;
use bt_hci::transport::SerialTransport;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embedded_io_adapters::tokio_1::FromTokio;
use std::path::PathBuf;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::time::Duration;
use tokio_serial::{DataBits, Parity, SerialStream, StopBits};

pub type Controller = ExternalController<
    SerialTransport<NoopRawMutex, FromTokio<ReadHalf<SerialStream>>, FromTokio<WriteHalf<SerialStream>>>,
    10,
>;

pub fn find_controllers() -> Vec<PathBuf> {
    let folder = "/dev/serial/by-id";
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(folder).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        let file_name = path.file_name().unwrap().to_string_lossy();
        if file_name.starts_with("usb-ZEPHYR_Zephyr_HCI_UART_sample") {
            paths.push(path.to_path_buf());
        }
    }
    paths
}

#[allow(unused)]
pub(crate) async fn create_controller(
    port: &PathBuf,
) -> ExternalController<
    SerialTransport<NoopRawMutex, FromTokio<ReadHalf<SerialStream>>, FromTokio<WriteHalf<SerialStream>>>,
    10,
> {
    let port = port.to_string_lossy();
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
