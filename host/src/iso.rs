//! Isochronous (CIS/BIS) HCI commands and data.

use bt_hci::cmd::{AsyncCmd, SyncCmd};
use bt_hci::controller::{Controller, ControllerCmdAsync, ControllerCmdSync};
use bt_hci::data::IsoPacket;

use crate::host::BleHost;
use crate::{BleHostError, PacketPool};

/// A type for running isochronous-stream HCI commands and data.
pub struct Iso<'stack, C, P: PacketPool> {
    host: &'stack BleHost<'stack, C, P>,
}

impl<'stack, C: Controller, P: PacketPool> Iso<'stack, C, P> {
    pub(crate) fn new(host: &'stack BleHost<'stack, C, P>) -> Self {
        Self { host }
    }

    /// Run a synchronous HCI command and return its response.
    pub async fn command<Cmd>(&self, cmd: Cmd) -> Result<Cmd::Return, BleHostError<C::Error>>
    where
        Cmd: SyncCmd,
        C: ControllerCmdSync<Cmd>,
    {
        self.host.command(cmd).await
    }

    /// Run an asynchronous HCI command (one whose completion arrives as a separate event, e.g.
    /// `LE Accept CIS Request`'s `LE CIS Established`) without waiting for that event.
    pub async fn command_async<Cmd>(&self, cmd: Cmd) -> Result<(), BleHostError<C::Error>>
    where
        Cmd: AsyncCmd,
        C: ControllerCmdAsync<Cmd>,
    {
        self.host.async_command(cmd).await
    }

    /// Write a raw HCI ISO data packet to the controller.
    pub async fn send(&self, packet: &IsoPacket<'_>) -> Result<(), C::Error> {
        self.host.controller.write_iso_data(packet).await
    }
}
