//! BLE Connection Subrating — Central role.
//!
//! Demonstrates the LE Subrate Request procedure from the central side.
//! Unlike a connection parameter update, a subrate change takes effect within
//! only a **few base connection intervals** — making it much faster to apply.
//!
//! Run alongside `ble_subrate_peripheral` to observe the full negotiation.
//!
//! # Steps
//! 1. Central sets an acceptable subrate factor range of [4, 12].
//! 2. Peripheral requests an out-of-range factor (50), which is rejected.
//! 3. Peripheral requests a valid factor (10), which is accepted.
//! 4. Peripheral requests a range [1, 5] that overlaps with the central's range,
//!    leading to an accepted factor (e.g., 4 or 5).
//!
//! The two sides use the `SubratingParamsUpdated` event to stay synchronised.

use bt_hci::controller::ControllerCmdAsync;
use embassy_futures::join::join;
use embassy_time::{Duration, Timer};
use trouble_host::prelude::*;

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 2;

pub async fn run<C>(controller: C)
where
    C: Controller + ControllerCmdAsync<bt_hci::cmd::le::LeSubrateRequest>,
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

        // Give the link layer a moment to settle before issuing subrate commands.
        Timer::after(Duration::from_millis(500)).await;

        // ── Step 1 ────────────────────────────────────────────────────────────
        // Set an acceptable subrate factor range of [4, 12].
        //
        // Subrate factor N means data is exchanged only on every Nth base
        // connection event; the remaining N-1 events are skipped. Factor 4
        // therefore reduces air-time by 75 % while maintaining the same
        // supervision timeout.
        //
        // Because a subrate change is applied directly at the Link Layer level,
        // it takes effect within a few base connection intervals — far quicker
        // than a full connection parameter update, which must wait at least
        // 6 * (1 + latency) connection events before the controller is allowed
        // to apply the new parameters.
        info!("Setting acceptable subrate factor range (min=4, max=12).");
        conn.request_conn_subrate(
            &stack,
            4,                           // subrate_min
            12,                          // subrate_max
            0,                           // max_latency in subrated connection events
            0,                           // continuation_number: stay awake for 0 extra events after data
            Duration::from_millis(2000), // supervision_timeout
        )
        .await
        .unwrap_or_else(|e| error!("subrate request failed: {:?}", e));

        // Both sides receive SubratingParamsUpdated once the LL has agreed.
        loop {
            if let ConnectionEvent::SubratingParamsUpdated { subrate_factor, .. } = conn.next().await {
                info!("Step 1 confirmed: subrate_factor={}", subrate_factor);
                break;
            }
        }

        // ── Step 2 ────────────────────────────────────────────────────────────
        // Peripheral tries to request an invalid subrate factor -> unnoticed by central

        // ── Step 3 ────────────────────────────────────────────────────────────
        // Wait for peripheral to request valid subrate factor and trigger a subrate change
        loop {
            if let ConnectionEvent::SubratingParamsUpdated { subrate_factor, .. } = conn.next().await {
                info!(
                    "Peripheral caused a change to subrate_factor={}",
                    subrate_factor
                );
                break;
            }
        }

        // ── Step 4 ────────────────────────────────────────────────────────────
        // Wait for peripheral to request valid subrate factor range and trigger a subrate change
        loop {
            if let ConnectionEvent::SubratingParamsUpdated { subrate_factor, .. } = conn.next().await {
                info!(
                    "Peripheral caused a change to subrate_factor={}",
                    subrate_factor
                );
                break;
            }
        }

        info!("Negotiation complete. Staying connected.");
        loop {
            Timer::after(Duration::from_secs(60)).await;
        }
    })
    .await;
}
