//! Alternative, event-based processing of incoming GATT attribute requests.
use core::cell::RefCell;

use bt_hci::controller::Controller;

use embassy_sync::blocking_mutex::{self, raw::RawMutex};
use embassy_sync::signal::Signal;

use crate::att::AttErrorCode;
use crate::attribute::Characteristic;
use crate::connection::Connection;
use crate::{BleHostError, Error};

use super::{GattAttrDesc, GattHandler, GattServer};

/// Represents a GATT attribute read request that needs to be replied with the attribute data.
pub struct GattReadRequest<'a, M: RawMutex, const L2CAP_MTU: usize>(&'a ExchangeArea<M, L2CAP_MTU>);

impl<'a, M: RawMutex, const L2CAP_MTU: usize> GattReadRequest<'a, M, L2CAP_MTU> {
    /// Replies to the GATT read request with the given data.
    pub fn reply_with(self, data: &[u8]) {
        self.0.buf.lock(|buf| {
            let mut buf = buf.borrow_mut();

            buf.clear();
            buf.extend_from_slice(data).unwrap();
        });

        self.0.response.signal(());
    }
}

/// Represents a GATT attribute write request that carries the attribute data.
pub struct GattWriteRequest<'a, M: RawMutex, const L2CAP_MTU: usize>(&'a ExchangeArea<M, L2CAP_MTU>);

impl<'a, M: RawMutex, const L2CAP_MTU: usize> GattWriteRequest<'a, M, L2CAP_MTU> {
    /// Fetches the data of the write request into the provided buffer.
    ///
    /// Returns the number of bytes fetched.
    pub fn fetch(self, buf: &mut [u8]) -> usize {
        self.0.buf.lock(|data| {
            let data = data.borrow();

            buf[..data.len()].copy_from_slice(&data);

            data.len()
        })
    }
}

/// Represents a GATT event that needs processing.
pub enum GattEvent<'a, M: RawMutex, const L2CAP_MTU: usize> {
    /// A GATT read request.
    // TODO: Uuid
    // TODO: Do we even need to expose the attribute handle?
    Read {
        /// The handle of the attribute being read.
        handle: u16,
        /// The offset of the read request.
        offset: u16,
        /// The read request.
        request: GattReadRequest<'a, M, L2CAP_MTU>,
    },
    /// A GATT write request.
    // TODO: Uuid
    // TODO: Do we even need to expose the attribute handle?
    Write {
        /// The handle of the attribute being written.
        handle: u16,
        /// The offset of the write request.
        offset: u16,
        /// The write request.
        request: GattWriteRequest<'a, M, L2CAP_MTU>,
    },
}

/// A GATT events' connection that can be polled for events that need processing.
pub struct GattEvents<'r, M: RawMutex, const L2CAP_MTU: usize> {
    exchange: &'r ExchangeArea<M, L2CAP_MTU>,
}

impl<'r, M: RawMutex, const L2CAP_MTU: usize> GattEvents<'r, M, L2CAP_MTU> {
    pub(crate) const fn new(exchange: &'r ExchangeArea<M, L2CAP_MTU>) -> Self {
        Self { exchange }
    }

    /// Returns the next GATT event that needs processing.
    ///
    /// Note that this method _must_ be polled, or else the GATT server will not be able to process
    /// incoming attribute requests.
    #[allow(clippy::should_implement_trait)]
    pub async fn next(&mut self) -> GattEvent<'_, M, L2CAP_MTU> {
        let request = self.exchange.request.wait().await;

        match request {
            Request::Read { handle, offset } => GattEvent::Read {
                handle,
                offset,
                request: GattReadRequest(self.exchange),
            },
            Request::Write { handle, offset } => GattEvent::Write {
                handle,
                offset,
                request: GattWriteRequest(self.exchange),
            },
        }
    }
}

/// A GATT runner spins the internal server processing loop.
pub struct GattRunner<'m, 'r, C: Controller, M: RawMutex, const MAX: usize, const L2CAP_MTU: usize> {
    server: &'m GattServer<'r, C, M, MAX, L2CAP_MTU>,
}

impl<'m, 'r, C: Controller, M: RawMutex, const MAX: usize, const L2CAP_MTU: usize>
    GattRunner<'m, 'r, C, M, MAX, L2CAP_MTU>
{
    pub(crate) fn new(server: &'m GattServer<'r, C, M, MAX, L2CAP_MTU>) -> Self {
        Self { server }
    }

    /// Runs the GATT server processing loop.
    pub async fn run(&mut self) -> Result<(), Error> {
        self.server.process(&self.server.exchange_area).await
    }
}

/// A GATT notifier that can be used to send notifications to connected clients.
pub struct GattNotifier<'m, 'r, C: Controller, M: RawMutex, const MAX: usize, const L2CAP_MTU: usize> {
    server: &'m GattServer<'r, C, M, MAX, L2CAP_MTU>,
}

impl<'m, 'r, C: Controller, M: RawMutex, const MAX: usize, const L2CAP_MTU: usize>
    GattNotifier<'m, 'r, C, M, MAX, L2CAP_MTU>
{
    pub(crate) fn new(server: &'m GattServer<'r, C, M, MAX, L2CAP_MTU>) -> Self {
        Self { server }
    }

    /// Sends a notification to a connected client.
    pub async fn notify(
        &mut self,
        handle: Characteristic,
        connection: &Connection<'_>,
        value: &[u8],
    ) -> Result<(), BleHostError<C::Error>> {
        self.server.notify(handle, connection, value).await
    }
}

enum Request {
    Read { handle: u16, offset: u16 },
    Write { handle: u16, offset: u16 },
}

// A work-area shared between `GattServer::process` and the GATT event processing loop.
//
// The GATT server will write incoming attribute requests to the `request` signal and buf,
// and will then wait to be signaled by the `response` signal that the processing of the
// request is complete. It would then fetch the processed data from the buffer (if applicable
// for the concrete request) and send it back to the client.
//
// NOTE: This is not the best possible representation of an exchange area.
// For example, the buffer could be protected with an async mutex, which would allow
// to avoid the double-copy in GattReadRequest::reply_with and GattWriteRequest::fetch.
//
// Moreover, something like this conditional async mutex would avoid the need for the
// request/response signals:
// https://github.com/project-chip/rs-matter/blob/3bf4f7980103700e7b8f51d77281d5c661761bbc/rs-matter/src/utils/sync/mutex.rs
pub(crate) struct ExchangeArea<M: RawMutex, const L2CAP_MTU: usize> {
    request: Signal<M, Request>,
    response: Signal<M, ()>,
    buf: blocking_mutex::Mutex<M, RefCell<heapless::Vec<u8, L2CAP_MTU>>>,
}

impl<M: RawMutex, const L2CAP_MTU: usize> ExchangeArea<M, L2CAP_MTU> {
    pub(crate) const fn new() -> Self {
        Self {
            request: Signal::new(),
            response: Signal::new(),
            buf: blocking_mutex::Mutex::new(RefCell::new(heapless::Vec::new())),
        }
    }
}

impl<M: RawMutex, const L2CAP_MTU: usize> GattHandler for &ExchangeArea<M, L2CAP_MTU> {
    async fn read(&mut self, attr: &GattAttrDesc<'_>, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        self.request.signal(Request::Read {
            // NOTE: We are a bit struggling with connections here as they are lifetimed
            // Perhaps we should use a connection handle instead of a reference to a connection
            // and then somehow restore the `Connection` ref from the handle when the `GattEvent` is created
            handle: attr.handle,
            offset: offset as u16,
        });

        self.response.wait().await;

        let len = self.buf.lock(|buf| {
            let buf = buf.borrow_mut();

            data[..buf.len()].copy_from_slice(&buf);

            buf.len()
        });

        Ok(len)
    }

    async fn write(&mut self, attr: &GattAttrDesc<'_>, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        self.buf.lock(|buf| {
            let mut buf = buf.borrow_mut();

            buf.clear();
            buf.extend_from_slice(data).unwrap();
        });

        self.request.signal(Request::Write {
            // NOTE: Ditto for connections here of course
            handle: attr.handle,
            offset: offset as u16,
        });

        self.response.wait().await;

        Ok(())
    }
}
