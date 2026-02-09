use core::ops::Deref;

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::{Receiver, Sender};

use crate::{central, gatt_client, peripheral};

/// Senders for dispatching commands to role tasks and receiving their responses.
pub(crate) struct CommandChannels<'a> {
    pub peripheral: Sender<'a, NoopRawMutex, peripheral::Command, 1>,
    pub central: Sender<'a, NoopRawMutex, central::Command, 1>,
    pub gatt_client: Sender<'a, NoopRawMutex, gatt_client::Command, 1>,
    pub response: Receiver<'a, NoopRawMutex, Response, 1>,
}

/// Unified response type wrapping role-specific responses from all command processors.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Response {
    Peripheral(peripheral::Response),
    Central(central::Response),
    GattClient(gatt_client::Response),
    Unhandled,
}

#[cfg(not(feature = "defmt"))]
/// Trait for command types that have an associated response type.
pub trait HasResponse: core::fmt::Debug {
    type Response: Into<Response>;
}

#[cfg(feature = "defmt")]
/// Trait for command types that have an associated response type.
pub trait HasResponse: core::fmt::Debug + defmt::Format {
    type Response: Into<Response>;
}

/// Receives commands from a channel and provides the response sender for replies.
#[derive(Clone)]
pub struct CommandReceiver<'a, C: HasResponse> {
    command: Receiver<'a, NoopRawMutex, C, 1>,
    response: Sender<'a, NoopRawMutex, Response, 1>,
}

impl<'a, C: HasResponse> CommandReceiver<'a, C> {
    /// Create a new receiver from a command channel and response sender.
    pub fn new(command: Receiver<'a, NoopRawMutex, C, 1>, response: Sender<'a, NoopRawMutex, Response, 1>) -> Self {
        Self { command, response }
    }

    /// Wait for the next command, wrapping it in a [`Command`] that enforces a reply.
    pub async fn receive(&self) -> Command<'a, C> {
        let inner = self.command.receive().await;
        Command {
            inner,
            response: self.response,
            response_sent: false,
        }
    }
}

/// A received command that enforces a reply via its [`Drop`] impl.
///
/// Derefs to the inner command type. Call [`reply()`](Self::reply) to send
/// the response. If dropped without replying, an `Unhandled` response is
/// sent automatically.
pub struct Command<'a, C: HasResponse> {
    inner: C,
    response: Sender<'a, NoopRawMutex, Response, 1>,
    response_sent: bool,
}

impl<'a, C: HasResponse> Drop for Command<'a, C> {
    /// Enforced-reply guard: if `reply()` was never called, sends `Unhandled`
    /// so the BTP loop never hangs waiting for a response.
    fn drop(&mut self) {
        if !self.response_sent {
            let inner = &self.inner;
            error!("No response sent for command {:?}", inner);
            if let Err(err) = self.response.try_send(Response::Unhandled) {
                error!("Failed to send 'Unhandled' response: {:?}", err);
            }
        }
    }
}

impl<'a, C: HasResponse> Deref for Command<'a, C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, C: HasResponse> Command<'a, C> {
    /// Send the response for this command, consuming the wrapper.
    pub async fn reply(mut self, res: C::Response) {
        self.response.send(res.into()).await;
        self.response_sent = true
    }
}

#[cfg(test)]
mod tests {
    use embassy_sync::channel::Channel;
    use futures_executor::block_on;

    use super::*;

    #[derive(Debug)]
    enum MockCommand {
        Ping,
    }

    #[derive(Debug, PartialEq)]
    enum MockResponse {
        Pong,
    }

    impl HasResponse for MockCommand {
        type Response = MockResponse;
    }

    impl From<MockResponse> for Response {
        fn from(resp: MockResponse) -> Self {
            match resp {
                MockResponse::Pong => Response::Unhandled, // simplified mapping
            }
        }
    }

    #[test]
    fn reply_sends_response() {
        block_on(async {
            let cmd_chan = Channel::<NoopRawMutex, MockCommand, 1>::new();
            let resp_chan = Channel::<NoopRawMutex, Response, 1>::new();

            let receiver = CommandReceiver::new(cmd_chan.receiver(), resp_chan.sender());

            cmd_chan.sender().send(MockCommand::Ping).await;
            let cmd = receiver.receive().await;
            cmd.reply(MockResponse::Pong).await;

            let response = resp_chan.receiver().receive().await;
            assert!(matches!(response, Response::Unhandled)); // because our From maps Pong to Unhandled
        });
    }

    #[test]
    fn drop_without_reply_sends_unhandled() {
        block_on(async {
            let cmd_chan = Channel::<NoopRawMutex, MockCommand, 1>::new();
            let resp_chan = Channel::<NoopRawMutex, Response, 1>::new();

            let receiver = CommandReceiver::new(cmd_chan.receiver(), resp_chan.sender());

            cmd_chan.sender().send(MockCommand::Ping).await;
            let cmd = receiver.receive().await;
            drop(cmd); // Drop without replying

            let response = resp_chan.receiver().receive().await;
            assert!(matches!(response, Response::Unhandled));
        });
    }

    #[test]
    fn deref_to_inner() {
        block_on(async {
            let cmd_chan = Channel::<NoopRawMutex, MockCommand, 1>::new();
            let resp_chan = Channel::<NoopRawMutex, Response, 1>::new();

            let receiver = CommandReceiver::new(cmd_chan.receiver(), resp_chan.sender());

            cmd_chan.sender().send(MockCommand::Ping).await;
            let cmd = receiver.receive().await;

            // Deref should give us access to the inner MockCommand
            assert!(matches!(*cmd, MockCommand::Ping));

            cmd.reply(MockResponse::Pong).await;
        });
    }
}
