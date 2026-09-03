//! BLE Shorter Connection Intervals (SCI) — Central role.
//!
//! Demonstrates the LE Connection Rate Request procedure, which allows
//! negotiating sub-millisecond connection intervals (as short as 875 µs)
//! on controllers that support the Shorter Connection Intervals feature.
//!
//! Unlike a subrate change (which takes only a few base connection events),
//! a connection rate change follows the same Link Layer scheduling rules as
//! a standard connection parameter update: the controller must wait at least
//! 6 * (1 + peripheral_latency) connection events before it is allowed to
//! apply the new parameters. In practice many controllers choose the first
//! suitable anchor point after that minimum, which can add further latency.
//!
//! Run alongside `ble_sci_peripheral` to observe the full negotiation.
//!
//! # Steps
//! 1. Central locks the connection interval at exactly 2.5 ms (min == max).
//! 2. Peripheral tries to request an interval of 875 µs, which is below the
//!    central's minimum of 2.5 ms. The ranges do not overlap so the LL rejects
//!    the request.
//! 3. Central widens the acceptable range to [875 µs, 2.5 ms].
//! 4. Peripheral requests 875 µs again. The ranges now overlap so the LL
//!    accepts and the connection rate changes to 875 µs.

use bt_hci::controller::ControllerCmdSync;
use embassy_futures::join::join;
use embassy_time::{Duration, Timer};
use trouble_host::prelude::*;

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 2;

pub async fn run<C>(controller: C)
where
    C: Controller + ControllerCmdSync<bt_hci::cmd::le::LeConnectionRateRequest>,
{
    let address: Address = Address::random([0xff, 0x8f, 0x1b, 0x05, 0xe4, 0xff]);
    info!("Central address = {:?}", address);

    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(address)
        .build();
    let mut central = stack.central();
    let mut runner = stack.runner();

    // Match the address advertised by the peripheral example.
    let target: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
    let config = ConnectConfig {
        connect_params: Default::default(),
        scan_config: ScanConfig {
            filter_accept_list: &[target],
            ..Default::default()
        },
    };

    let _ = join(runner.run(), async {
        info!("Scanning for peripheral...");
        let conn = central.connect(&config).await.unwrap();
        info!("Connected!");

        // Give the link layer a moment to settle.
        Timer::after(Duration::from_millis(500)).await;

        // ── Step 1 ────────────────────────────────────────────────────────────
        // Lock the connection interval at exactly 2.5 ms by setting min == max.
        //
        // A connection rate change (SCI) follows the same Link Layer scheduling
        // rules as a standard connection parameter update: the controller must
        // wait at least 6 * (1 + peripheral_latency) connection events before
        // applying the new parameters. With 0 peripheral latency and a default
        // base interval this is at least 6 events. Most controllers then choose
        // the first suitable anchor point after that minimum.
        //
        // This is slower than a subrate change (which takes only a few base
        // connection events) but allows sub-millisecond intervals that are not
        // achievable by changing only the base connection interval.
        info!("Step 1: locking connection interval at 2.5 ms (min=max=2500 µs).");
        let locked_params = ConnectRateParams {
            min_connection_interval: Duration::from_micros(2500),
            max_connection_interval: Duration::from_micros(2500),
            subrate_min: 1, // no subrating in this example
            subrate_max: 1,
            max_latency: 0,
            continuation_number: 0,
            supervision_timeout: Duration::from_millis(2000),
            min_ce_length: Duration::from_micros(0),
            max_ce_length: Duration::from_micros(0),
        };
        conn.request_connection_rate(&stack, &locked_params)
            .await
            .unwrap_or_else(|e| error!("Request error: {:?}", e));

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

        // Hold this interval long enough for the peripheral to observe the event
        // and then issue its (deliberately rejected) counter-request.
        Timer::after(Duration::from_secs(3)).await;

        // ── Step 3 ────────────────────────────────────────────────────────────
        // Widen the acceptable range to [875 µs, 2.5 ms].
        // 875 µs is the minimum connection interval supported by SCI.
        // Now the peripheral's request for 875 µs will fall inside [875 µs, 2.5 ms]
        // and be accepted by the LL.
        info!("Step 3: widening interval range to [875 µs, 2.5 ms].");
        let wide_params = ConnectRateParams {
            min_connection_interval: Duration::from_micros(875), // SCI minimum
            max_connection_interval: Duration::from_micros(2500),
            subrate_min: 1,
            subrate_max: 1,
            max_latency: 0,
            continuation_number: 0,
            supervision_timeout: Duration::from_millis(2000),
            min_ce_length: Duration::from_micros(0),
            max_ce_length: Duration::from_micros(0),
        };
        conn.request_connection_rate(&stack, &wide_params)
            .await
            .unwrap_or_else(|e| error!("Request error: {:?}", e));

        loop {
            match conn.next().await {
                ConnectionEvent::ConnectionRateChanged {
                    conn_interval,
                    subrate_factor,
                    ..
                } => {
                    info!(
                        "Step 3 confirmed: conn_interval={:?}, subrate_factor={}",
                        conn_interval, subrate_factor
                    );
                    break;
                }
                _ => {}
            }
        }

        // Wait for the peripheral's step 4 (its 875 µs request) to complete.
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
                        "Peripheral step 4 confirmed: conn_interval={:?}, \
                         subrate_factor={}, latency={}, continuation={}, timeout={:?}",
                        conn_interval, subrate_factor, peripheral_latency, continuation_number, supervision_timeout
                    );
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
