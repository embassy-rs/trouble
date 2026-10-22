//! H4 over Unix streams, reusing `bt-hci-serial` for packet framing.

use std::cell::RefCell;
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::rc::{Rc, Weak};
use std::task::Poll;

use bt_hci_serial::SerialTransport;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::waitqueue::WakerRegistration;

/// Standard H4 framing over the executor's nonblocking Unix stream.
pub type UnixTransport = SerialTransport<NoopRawMutex, Reader, Writer>;

struct Socket {
    stream: UnixStream,
    reader: RefCell<WakerRegistration>,
    writer: RefCell<WakerRegistration>,
}

/// Read half of an executor-owned HCI socket.
pub struct Reader(Rc<Socket>);

/// Write half of an executor-owned HCI socket.
pub struct Writer(Rc<Socket>);

impl embedded_io::ErrorType for Reader {
    type Error = io::Error;
}

impl embedded_io::ErrorType for Writer {
    type Error = io::Error;
}

impl embedded_io_async::Read for Reader {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        poll_fn(|cx| match (&self.0.stream).read(buf) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                self.0.reader.borrow_mut().register(cx.waker());
                Poll::Pending
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            result => Poll::Ready(result),
        })
        .await
    }
}

impl embedded_io_async::Write for Writer {
    async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        poll_fn(|cx| match (&self.0.stream).write(buf) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                self.0.writer.borrow_mut().register(cx.waker());
                Poll::Pending
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            result => Poll::Ready(result),
        })
        .await
    }

    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct Reactor(RefCell<Vec<Weak<Socket>>>);

impl Reactor {
    pub fn connect(&self, path: &Path) -> io::Result<UnixTransport> {
        let stream = UnixStream::connect(path)?;
        stream.set_nonblocking(true)?;
        let socket = Rc::new(Socket {
            stream,
            reader: RefCell::new(WakerRegistration::new()),
            writer: RefCell::new(WakerRegistration::new()),
        });
        self.0.borrow_mut().push(Rc::downgrade(&socket));
        Ok(SerialTransport::new(Reader(socket.clone()), Writer(socket)))
    }

    pub fn poll(&self) -> io::Result<()> {
        let mut sockets = self.0.borrow_mut();
        sockets.retain(|socket| socket.strong_count() != 0);
        for socket in sockets.iter().filter_map(Weak::upgrade) {
            let mut fd = libc::pollfd {
                fd: socket.stream.as_raw_fd(),
                events: if socket.reader.borrow().occupied() {
                    libc::POLLIN
                } else {
                    0
                } | if socket.writer.borrow().occupied() {
                    libc::POLLOUT
                } else {
                    0
                },
                revents: 0,
            };
            // SAFETY: fd points to one initialized pollfd for the duration of poll.
            if unsafe { libc::poll(&mut fd, 1, 0) } < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let failed = fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0;
            if failed || fd.revents & libc::POLLIN != 0 {
                socket.reader.borrow_mut().wake();
            }
            if failed || fd.revents & libc::POLLOUT != 0 {
                socket.writer.borrow_mut().wake();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    use super::*;

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl WakeCount {
        fn count(&self) -> usize {
            self.0.load(Ordering::Relaxed)
        }
    }

    fn counting_waker() -> (Arc<WakeCount>, Waker) {
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(count.clone());
        (count, waker)
    }

    fn socket_pair() -> (Reader, Writer, UnixStream, Reactor) {
        let (stream, peer) = UnixStream::pair().unwrap();
        stream.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let socket = Rc::new(Socket {
            stream,
            reader: RefCell::new(WakerRegistration::new()),
            writer: RefCell::new(WakerRegistration::new()),
        });
        let reactor = Reactor(RefCell::new(vec![Rc::downgrade(&socket)]));
        (Reader(socket.clone()), Writer(socket), peer, reactor)
    }

    #[test]
    fn cancelled_read_can_register_a_new_waiter_without_spurious_repeated_wakes() {
        let (mut reader, _writer, mut peer, reactor) = socket_pair();
        let (old_count, old_waker) = counting_waker();
        let (new_count, new_waker) = counting_waker();
        let mut buffer = [0; 4];
        {
            let mut read = pin!(embedded_io_async::Read::read(&mut reader, &mut buffer));
            let mut cx = Context::from_waker(&old_waker);
            assert!(read.as_mut().poll(&mut cx).is_pending());
            assert!(read.as_mut().poll(&mut cx).is_pending());
            assert_eq!(old_count.count(), 0);
        } // Cancel the first read while its waker is still registered.
        {
            let mut read = pin!(embedded_io_async::Read::read(&mut reader, &mut buffer));
            let mut cx = Context::from_waker(&new_waker);
            assert!(read.as_mut().poll(&mut cx).is_pending());
            assert_eq!(old_count.count(), 1); // Replacement wakes the previous waiter once.
            assert!(read.as_mut().poll(&mut cx).is_pending());
            assert_eq!(old_count.count(), 1);
            assert_eq!(new_count.count(), 0);

            peer.write_all(&[1, 2, 3, 4]).unwrap();
            reactor.poll().unwrap();
            assert_eq!(new_count.count(), 1);
            assert!(matches!(read.as_mut().poll(&mut cx), Poll::Ready(Ok(4))));
            reactor.poll().unwrap();
            assert_eq!(new_count.count(), 1);
        }
        assert_eq!(buffer, [1, 2, 3, 4]);
    }

    #[test]
    fn backpressured_write_replaces_cancelled_waiter_and_does_not_wake_reader() {
        let (mut reader, mut writer, mut peer, reactor) = socket_pair();
        let chunk = [0x5a; 8_192];
        let mut queued = 0;
        loop {
            match (&writer.0.stream).write(&chunk) {
                Ok(count) => {
                    assert_ne!(count, 0);
                    queued += count;
                    assert!(queued < 8 * 1_024 * 1_024, "socket did not apply backpressure");
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("{error}"),
            }
        }
        let (read_count, read_waker) = counting_waker();
        let (old_count, old_waker) = counting_waker();
        let (new_count, new_waker) = counting_waker();
        let mut input = [0];
        let mut read = pin!(embedded_io_async::Read::read(&mut reader, &mut input));
        assert!(read.as_mut().poll(&mut Context::from_waker(&read_waker)).is_pending());
        {
            let mut write = pin!(embedded_io_async::Write::write(&mut writer, b"x"));
            assert!(write.as_mut().poll(&mut Context::from_waker(&old_waker)).is_pending());
        }
        {
            let mut write = pin!(embedded_io_async::Write::write(&mut writer, b"x"));
            let mut cx = Context::from_waker(&new_waker);
            assert!(write.as_mut().poll(&mut cx).is_pending());
            assert_eq!(old_count.count(), 1);
            assert!(write.as_mut().poll(&mut cx).is_pending());
            assert_eq!(old_count.count(), 1);

            let mut drained = 0;
            let mut buffer = [0; 8_192];
            while drained < queued {
                drained += peer.read(&mut buffer).unwrap();
            }
            reactor.poll().unwrap();
            assert_eq!(read_count.count(), 0);
            assert_eq!(new_count.count(), 1);
            assert!(matches!(write.as_mut().poll(&mut cx), Poll::Ready(Ok(1))));
            reactor.poll().unwrap();
            assert_eq!(new_count.count(), 1);
        }
        let mut output = [0];
        peer.read_exact(&mut output).unwrap();
        assert_eq!(&output, b"x");
    }
}
