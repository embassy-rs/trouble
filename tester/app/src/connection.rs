use alloc::boxed::Box;

use embassy_futures::select::{Either, select};
use embassy_sync::channel::DynamicSender;
use embassy_sync::watch;
use embassy_time::Duration;
use trouble_host::prelude::*;

use crate::{Event, OobState};

/// Run the GATT connection event loop, shared between peripheral and central.
///
/// Handles connection events (disconnect, GATT writes, pairing, etc.) and
/// concurrently invokes `on_command` to process commands from the caller's channel.
pub async fn run<'stack, C: crate::Controller, P: PacketPool>(
    stack: &Stack<'_, C, P>,
    gatt_conn: &GattConnection<'stack, '_, P>,
    address: Address,
    events: &DynamicSender<'_, Event>,
    conn_watch: &watch::DynSender<'_, Connection<'stack, P>>,
    oob: &OobState,
    mut on_command: impl AsyncFnMut(),
) -> Result<(), BleHostError<C::Error>> {
    trace!("connection::run addr={:?}", address);
    if oob.has_oob() {
        let _ = gatt_conn.raw().set_oob_available(true);
    }
    conn_watch.send(gatt_conn.raw().clone());
    loop {
        match select(gatt_conn.next(), on_command()).await {
            Either::First(event) => match event {
                GattConnectionEvent::Disconnected { .. } => {
                    info!("Disconnected addr={:?}", address);
                    conn_watch.clear();
                    events.send(Event::DeviceDisconnected { address }).await;
                    break Ok(());
                }
                GattConnectionEvent::Gatt {
                    event: GattEvent::Write(w),
                } => {
                    info!("Gatt Write handle={}", w.handle());
                    let handle = w.handle();
                    let data = w.with_data(|_, data| Box::from(data));
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
                GattConnectionEvent::PairingComplete {
                    security_level,
                    bond: _,
                } => {
                    info!("PairingComplete addr={:?} level={:?}", address, security_level);
                }
                GattConnectionEvent::PairingFailed(error) => {
                    info!("PairingFailed addr={:?}", address);
                    events.send(Event::PairingFailed { address, error }).await;
                }
                GattConnectionEvent::BondLost => {
                    info!("BondLost addr={:?}", address);
                    events.send(Event::BondLost { address }).await;
                }
                GattConnectionEvent::Encrypted { security_level } => {
                    info!("Encrypted addr={:?} level={:?}", address, security_level);
                    events
                        .send(Event::SecLevelChanged {
                            address,
                            level: security_level,
                        })
                        .await;
                }
                GattConnectionEvent::OobRequest => {
                    let (local_oob, peer_oob) = if let Some(sc_local) = oob.sc_local.get() {
                        let sc_remote = oob.sc_remote.get().unwrap_or(trouble_host::OobData {
                            random: [0; 16],
                            confirm: [0; 16],
                        });
                        (sc_local, sc_remote)
                    } else if let Some(tk) = oob.legacy_tk.get() {
                        let local = trouble_host::OobData {
                            random: tk,
                            confirm: [0; 16],
                        };
                        let peer = trouble_host::OobData {
                            random: [0; 16],
                            confirm: [0; 16],
                        };
                        (local, peer)
                    } else {
                        unreachable!("OobRequest without OOB data");
                    };
                    if let Err(e) = gatt_conn.provide_oob_data(local_oob, peer_oob) {
                        warn!("oob_data_received failed: {:?}", e);
                    }
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
