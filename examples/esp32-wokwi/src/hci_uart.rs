use bt_hci::transport::SerialTransport;
use embassy_sync_08::blocking_mutex::raw::NoopRawMutex;
use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};
use esp_hal::uart::{Config, IoError, Uart, UartRx, UartTx};
use esp_hal::Async;
use log::info;
use trouble_host::prelude::ExternalController;

pub const HCI_BAUD: u32 = 115_200;

pub struct UartReader(UartRx<'static, Async>);
pub struct UartWriter(UartTx<'static, Async>);

impl ErrorType for UartReader {
    type Error = IoError;
}

impl ErrorType for UartWriter {
    type Error = IoError;
}

impl Read for UartReader {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        Read::read(&mut self.0, buf).await.map_err(IoError::Rx)
    }
}

impl Write for UartWriter {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Write::write(&mut self.0, buf).await.map_err(IoError::Tx)
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Write::flush(&mut self.0).await.map_err(IoError::Tx)
    }
}

pub type UartTransport = SerialTransport<NoopRawMutex, UartReader, UartWriter>;

pub fn init_hci_uart(
    uart: esp_hal::peripherals::UART0<'static>,
    tx: esp_hal::peripherals::GPIO21<'static>,
    rx: esp_hal::peripherals::GPIO20<'static>,
) -> ExternalController<UartTransport, 20> {
    let config = Config::default().with_baudrate(HCI_BAUD);
    let uart = Uart::new(uart, config)
        .expect("failed to init HCI UART")
        .with_tx(tx)
        .with_rx(rx)
        .into_async();

    let (rx, tx) = uart.split();

    info!("hci uart transport ready");
    ExternalController::new(SerialTransport::new(UartReader(rx), UartWriter(tx)))
}
