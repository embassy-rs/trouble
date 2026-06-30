#[cfg(not(target_os = "linux"))]
compile_error!("Only Linux is supported");

use core::future::Future;
use core::mem;
use core::pin::Pin;
use core::task::{ready, Context, Poll};
use std::convert::Infallible;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

use bt_hci_driver::{self, PacketKind, PacketToController, PacketToHost, ReadHciError};
use embedded_io::ReadExactError;
use tokio::io::unix::AsyncFd;
use tokio::io::{split, AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

const BTPROTO_HCI: libc::c_int = 1;
const HCI_CHANNEL_USER: libc::c_ushort = 1;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct sockaddr_hci {
    hci_family: libc::c_ushort,
    hci_dev: libc::c_ushort,
    hci_channel: libc::c_ushort,
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum Error {
    FromHciBytesError(ReadHciError<Infallible>),
    Io(io::Error),
}

impl core::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}

impl embedded_io::Error for Error {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

impl From<ReadHciError<io::Error>> for Error {
    fn from(e: ReadHciError<io::Error>) -> Self {
        match e {
            ReadHciError::BufferTooSmall => Error::FromHciBytesError(ReadHciError::BufferTooSmall),
            ReadHciError::InvalidValue => Error::FromHciBytesError(ReadHciError::InvalidValue),
            ReadHciError::Read(ReadExactError::UnexpectedEof) => {
                Error::FromHciBytesError(ReadHciError::Read(ReadExactError::UnexpectedEof))
            }
            ReadHciError::Read(ReadExactError::Other(io)) => Error::Io(io),
        }
    }
}

impl From<io::Error> for Error {
    fn from(io: io::Error) -> Self {
        Error::Io(io)
    }
}

pub struct Socket {
    fd: AsyncFd<OwnedFd>,
}

// We use `libc` directly because
// * `nix` makes it awkward to bind an arbitrary address
// * `rustix` makes it awkward to set arbitrary sockopts
impl Socket {
    pub fn new(dev: u16) -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_BLUETOOTH,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                BTPROTO_HCI,
            )
        };
        let fd = if fd < 0i32 {
            return Err(io::Error::last_os_error());
        } else {
            unsafe { OwnedFd::from_raw_fd(fd) }
        };

        let mut addr: sockaddr_hci = unsafe { mem::zeroed() };
        addr.hci_family = libc::AF_BLUETOOTH as u16;
        addr.hci_dev = dev;
        addr.hci_channel = HCI_CHANNEL_USER;
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast(),
                mem::size_of::<sockaddr_hci>() as libc::socklen_t,
            )
        } < 0i32
        {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd: AsyncFd::new(fd)? })
    }
}

impl AsyncRead for Socket {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let Self { ref mut fd } = *self.get_mut();
        loop {
            let mut guard = ready!(fd.poll_read_ready_mut(cx))?;

            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| {
                let ret = unsafe { libc::read(inner.as_raw_fd(), unfilled.as_mut_ptr().cast(), unfilled.len()) };
                usize::try_from(ret).map_err(|_try_from_int_error| io::Error::last_os_error())
            }) {
                Ok(result) => {
                    return Poll::Ready(result.map(|len| buf.advance(len)));
                }
                Err(_would_block) => {}
            }
        }
    }
}

impl AsyncWrite for Socket {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let Self { ref mut fd } = *self.get_mut();
        loop {
            let mut guard = ready!(fd.poll_write_ready_mut(cx))?;

            match guard.try_io(|inner| {
                let ret = unsafe { libc::write(inner.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
                usize::try_from(ret).map_err(|_try_from_int_error| io::Error::last_os_error())
            }) {
                Ok(result) => {
                    return Poll::Ready(result);
                }
                Err(_would_block) => {}
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}

struct TokioReader<'a> {
    reader: &'a mut ReadHalf<Socket>,
}
impl embedded_io::ErrorType for TokioReader<'_> {
    type Error = io::Error;
}

impl embedded_io_async::Read for TokioReader<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        tokio::io::AsyncReadExt::read(&mut self.reader, buf).await
    }
}

struct TokioWriter<'a> {
    writer: &'a mut WriteHalf<Socket>,
}

impl embedded_io::ErrorType for TokioWriter<'_> {
    type Error = io::Error;
}

impl embedded_io_async::Write for TokioWriter<'_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        tokio::io::AsyncWriteExt::write(&mut self.writer, buf).await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        tokio::io::AsyncWriteExt::flush(&mut self.writer).await
    }
}

pub struct Transport {
    rx: Mutex<ReadHalf<Socket>>,
    tx: Mutex<WriteHalf<Socket>>,
}

impl Transport {
    pub fn new(dev: u16) -> Result<Self, io::Error> {
        let (rx, tx) = split(Socket::new(dev)?);
        Ok(Self {
            rx: Mutex::new(rx),
            tx: Mutex::new(tx),
        })
    }
}

impl bt_hci_driver::Transport for Transport {
    async fn read<'a, P: PacketToHost<'a>>(&self, rx: &'a mut [u8]) -> Result<P, Self::Error> {
        let mut r = self.rx.lock().await;
        let mut reader = TokioReader { reader: &mut *r };
        let kind = PacketKind::read_async(&mut reader).await?;
        let packet = P::read_hci_async(kind, &mut reader, rx).await?;
        Ok(packet)
    }

    fn write<P: PacketToController>(&self, val: &P) -> impl Future<Output = Result<(), Self::Error>> {
        async move {
            let mut writer = self.tx.lock().await;
            let writer = TokioWriter { writer: &mut *writer };
            val.write_hci_async(writer).await?;
            Ok(())
        }
    }
}

impl embedded_io::ErrorType for Transport {
    type Error = Error;
}
