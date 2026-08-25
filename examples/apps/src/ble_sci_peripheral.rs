//! BLE Shorter Connection Intervals (SCI) — Peripheral role.
//!
//! Demonstrates the LE Connection Rate Request procedure from the peripheral side.
//! Run alongside `ble_sci_central` to observe the full negotiation.
//!
//! # Steps
//! 1. Wait for central to lock the connection interval at 2.5 ms.
//! 2. Peripheral requests 875 µs, which is below the central's minimum of
//!    2.5 ms. The ranges [875 µs, 875 µs] and [2.5 ms, 2.5 ms] do not
//!    overlap so the LL rejects the request.
//! 3. Wait for central to widen its range to [875 µs, 2.5 ms].
//! 4. Peripheral requests 875 µs again. The ranges now overlap so the LL
//!    accepts and both sides receive ConnectionRateChanged.

use bt_hci::cmd::le::LeSetPhy;
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};
use embassy_futures::join::join;
use embassy_time::{Duration, Timer, WithTimeout};
use trouble_host::prelude::*;

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 2;

pub async fn run<C>(controller: C)
where
    C: Controller + ControllerCmdSync<bt_hci::cmd::le::LeConnectionRateRequest> + ControllerCmdAsync<LeSetPhy>,
{
    let address: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
    info!("Peripheral address = {:?}", address);

    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(address)
        .build();
    let mut peripheral = stack.peripheral();
    let mut runner = stack.runner();

    let mut adv_data = [0; 31];
    let adv_data_len = AdStructure::encode_slice(
        &[AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED)],
        &mut adv_data[..],
    )
    .unwrap();

    let mut scan_data = [0; 31];
    let scan_data_len =
        AdStructure::encode_slice(&[AdStructure::CompleteLocalName(b"SCI")], &mut scan_data[..]).unwrap();

    let _ = join(runner.run(), async {
        info!("Advertising, waiting for connection...");
        let advertiser = peripheral
            .advertise(
                &Default::default(),
                Advertisement::ConnectableScannableUndirected {
                    adv_data: &adv_data[..adv_data_len],
                    scan_data: &scan_data[..scan_data_len],
                },
            )
            .await
            .unwrap();
        let conn = advertiser.accept().await.unwrap();
        info!("Connected! Switching to 2M PHY for shorter connection intervals...");
        match conn.set_phy(&stack, PhyKind::Le2M).await {
            Ok(_) => info!("PHY update requested."),
            Err(e) => error!("PHY update failed: {:?}", e),
        }

        // Both sides receive ConnectionRateChanged once the LL switches over.
        loop {
            match conn.next().await {
                ConnectionEvent::ConnectionRateChanged {
                    conn_interval,
                    subrate_factor,
                    ..
                } => {
                    info!(
                        "Step 1 confirmed: conn_interval={:?}, subrate_factor={}",
                        conn_interval, subrate_factor
                    );
                    break;
                }
                _ => {}
            }
        }

        // Brief delay so the central is ready to receive our request.
        Timer::after(Duration::from_millis(500)).await;

        // ── Step 2 ────────────────────────────────────────────────────────
        // Request 875 µs — the SCI minimum connection interval.
        //
        // The central's current range is [2.5 ms, 2.5 ms]. Our requested
        // range is [875 µs, 875 µs]. The intersection is empty (875 µs <
        // 2.5 ms), so the LL rejects the request.
        //
        // Unlike a subrate rejection (which immediately returns a
        // SubratingParamsUpdated event with a sentinel value), a connection
        // rate rejection may manifest as either no ConnectionRateChanged
        // event (the controller silently drops the request) or as a
        // ConnectionRateChanged with the interval unchanged. The exact
        // behaviour is controller-implementation-defined. We use a timer
        // to bound our wait and then proceed regardless.
        info!(
            "Step 2: requesting 875 µs interval (expecting rejection — \
                 central's min is 2.5 ms, our max is 875 µs, ranges do not overlap)."
        );
        let rejected_params = ConnectRateParams {
            min_connection_interval: Duration::from_micros(875),
            max_connection_interval: Duration::from_micros(875),
            subrate_min: 1,
            subrate_max: 1,
            max_latency: 0,
            continuation_number: 0,
            supervision_timeout: Duration::from_millis(2000),
            min_ce_length: Duration::from_micros(0),
            max_ce_length: Duration::from_micros(0),
        };
        conn.request_connection_rate(&stack, &rejected_params)
            .await
            .unwrap_or_else(|e| info!("Expected Request error: {:?}", e));

        // Wait up to 2 s for a ConnectionRateChanged event. If the controller
        // silently rejects the request we will time out and move on.
        let result = async {
            loop {
                match conn.next().await {
                    ConnectionEvent::ConnectionRateChanged { conn_interval, .. } => {
                        return Some(conn_interval);
                    }
                    _ => {}
                }
            }
        }
        .with_timeout(Duration::from_secs(2))
        .await;

        match result {
            Ok(interval) => {
                info!(
                    "Step 2: got ConnectionRateChanged with interval={:?}. \
                         If interval is still 2.5 ms the request was silently rejected.",
                    interval
                );
            }
            Err(_) => {
                // No event received within 2 s: the controller rejected the
                // request without sending a ConnectionRateChanged event.
                info!(
                    "Step 2: no event received — request was rejected \
                         as expected (controller did not send ConnectionRateChanged)."
                );
            }
        }

        // ── Wait for Step 3 ───────────────────────────────────────────────
        // Central will now widen its range to [875 µs, 2.5 ms]. Both sides
        // receive ConnectionRateChanged when the switch takes effect.
        info!("Waiting for central to widen range to [875 µs, 2.5 ms]...");
        loop {
            match conn.next().await {
                ConnectionEvent::ConnectionRateChanged { conn_interval, .. } => {
                    info!(
                        "Central widened range; current interval={:?}",
                        conn_interval
                    );
                    break;
                }
                _ => {}
            }
        }

        // Brief delay before our second attempt.
        Timer::after(Duration::from_millis(500)).await;

        // ── Step 4 ────────────────────────────────────────────────────────
        // Request 875 µs again. Central's range is now [875 µs, 2.5 ms].
        // The intersection of [875 µs, 875 µs] and [875 µs, 2.5 ms] is
        // [875 µs, 875 µs], so the LL accepts the request.
        info!("Step 4: requesting 875 µs again (expecting success).");
        let accepted_params = ConnectRateParams {
            min_connection_interval: Duration::from_micros(875),
            max_connection_interval: Duration::from_micros(875),
            subrate_min: 1,
            subrate_max: 1,
            max_latency: 0,
            continuation_number: 0,
            supervision_timeout: Duration::from_millis(2000),
            min_ce_length: Duration::from_micros(0),
            max_ce_length: Duration::from_micros(0),
        };
        conn.request_connection_rate(&stack, &accepted_params)
            .await
            .unwrap_or_else(|e| error!("Request error: {:?}", e));

        loop {
            match conn.next().await {
                ConnectionEvent::ConnectionRateChanged {
                    conn_interval,
                    subrate_factor,
                    peripheral_latency,
                    continuation_number,
                    supervision_timeout,
                } => {
                    info!(
                        "Step 4 result: conn_interval={:?}, subrate_factor={}, \
                             latency={}, continuation={}, timeout={:?}",
                        conn_interval, subrate_factor, peripheral_latency, continuation_number, supervision_timeout
                    );
                    if conn_interval.as_micros() <= 900 {
                        info!("Success! 875 µs interval accepted.");
                    } else {
                        warn!("Unexpected interval={:?}.", conn_interval);
                    }
                    break;
                }
                _ => {}
            }
        }

        info!("Negotiation complete. Staying connected.");
        loop {
            Timer::after(Duration::from_secs(60)).await;
        }
    })
    .await;
}
