use alloc::boxed::Box;

use embassy_futures::select::{Either, select};
use embassy_sync::channel::DynamicSender;
use embassy_time::Duration;
use trouble_host::prelude::*;

use crate::Event;

/// Extract the peer's [`Address`] from a connection.
pub(crate) fn peer_address<P: PacketPool>(conn: &Connection<'_, P>) -> Address {
    Address {
        kind: conn.peer_addr_kind(),
        addr: conn.peer_address(),
    }
}

/// Run the GATT connection event loop, shared between peripheral and central.
///
/// Handles connection events (disconnect, GATT writes, pairing, etc.) and
/// concurrently invokes `on_command` to process commands from the caller's channel.
pub async fn run<C: crate::Controller, P: PacketPool>(
    stack: &Stack<'_, C, P>,
    gatt_conn: &GattConnection<'_, '_, P>,
    address: Address,
    events: &DynamicSender<'_, Event>,
    mut on_command: impl AsyncFnMut(),
) -> Result<(), BleHostError<C::Error>> {
    trace!("connection::run addr={:?}", address);
    loop {
        match select(gatt_conn.next(), on_command()).await {
            Either::First(event) => match event {
                GattConnectionEvent::Disconnected { .. } => {
                    info!("Disconnected addr={:?}", address);
                    events.send(Event::DeviceDisconnected { address }).await;
                    break Ok(());
                }
                GattConnectionEvent::Gatt {
                    event: GattEvent::Write(w),
                } => {
                    info!("Gatt Write handle={}", w.handle());
                    let handle = w.handle();
                    let data = Box::from(w.data());
                    let reply = w.accept()?;
                    reply.send().await;
                    events.send(Event::AttrValueChanged { handle, data }).await;
                }
                GattConnectionEvent::Gatt { event } => {
                    trace!("Gatt event (non-write)");
                    let reply = event.accept()?;
                    reply.send().await;
                }
                GattConnectionEvent::ConnectionParamsUpdated {
                    conn_interval,
                    peripheral_latency,
                    supervision_timeout,
                } => {
                    info!("ConnParamUpdate addr={:?}", address);
                    events
                        .send(Event::ConnParamUpdate {
                            address,
                            conn_interval,
                            peripheral_latency,
                            supervision_timeout,
                        })
                        .await;
                }
                GattConnectionEvent::PassKeyDisplay(key) => {
                    info!("PassKeyDisplay addr={:?}", address);
                    events
                        .send(Event::PasskeyDisplay {
                            address,
                            passkey: key.value(),
                        })
                        .await;
                }
                GattConnectionEvent::PassKeyConfirm(key) => {
                    info!("PassKeyConfirm addr={:?}", address);
                    events
                        .send(Event::PasskeyConfirmRequest {
                            address,
                            passkey: key.value(),
                        })
                        .await;
                }
                GattConnectionEvent::PassKeyInput => {
                    info!("PassKeyInput addr={:?}", address);
                    events.send(Event::PasskeyEntryRequest { address }).await;
                }
                GattConnectionEvent::PairingComplete { security_level, .. } => {
                    info!("PairingComplete addr={:?} level={:?}", address, security_level);
                    events
                        .send(Event::SecLevelChanged {
                            address,
                            level: security_level,
                        })
                        .await;
                }
                GattConnectionEvent::PairingFailed(error) => {
                    info!("PairingFailed addr={:?}", address);
                    events.send(Event::PairingFailed { address, error }).await;
                }
                GattConnectionEvent::BondLost => {
                    info!("BondLost addr={:?}", address);
                    events.send(Event::BondLost { address }).await;
                }
                GattConnectionEvent::PhyUpdated { .. } => warn!("Ignored Phy update event"),
                GattConnectionEvent::RequestConnectionParams(req) => {
                    let params = req.params();
                    if params.min_connection_interval == Duration::from_secs(4)
                        && params.max_connection_interval == params.min_connection_interval
                        && params.max_latency == 0
                        && params.supervision_timeout == Duration::from_secs(32)
                    {
                        // Test case GAP/CONN/CPUP/BV-05-C
                        req.reject(stack).await?;
                    } else {
                        req.accept(None, stack).await?;
                    }
                }
                GattConnectionEvent::DataLengthUpdated { .. } => warn!("Ignored DLU event"),
                GattConnectionEvent::FrameSpaceUpdated { .. } => warn!("Ignored frame space update event"),
                GattConnectionEvent::ConnectionRateChanged { .. } => warn!("Ignored connection rate changed event"),
            },
            Either::Second(()) => {}
        }
    }
}
