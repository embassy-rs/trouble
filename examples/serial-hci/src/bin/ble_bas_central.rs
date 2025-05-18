// Use with any serial HCI
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use log::*;
use tokio::time::Duration;
use tokio_serial::{DataBits, Parity, SerialStream, StopBits};
use trouble_example_apps::ble_bas_central;
use trouble_host::prelude::{ExternalController, SerialTransport};

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

    let driver: SerialTransport<NoopRawMutex, _, _> = SerialTransport::new(reader, writer);
    let controller: ExternalController<_, 10> = ExternalController::new(driver);

    ble_bas_central::run(controller).await;
}
