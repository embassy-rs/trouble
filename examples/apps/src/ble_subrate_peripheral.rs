//! BLE Connection Subrating — Peripheral role.
//!
//! Demonstrates the LE Subrate Request procedure from the peripheral side.
//! Run alongside `ble_subrate_central` to observe the full negotiation.
//!
//! # Steps
//! 1. Wait for the central to set a subrate factor range of [4, 12].
//! 2. Request an out-of-range factor (50), which is rejected.
//! 3. Request a valid factor (10), which is accepted.
//! 4. Request an overlapping range [1, 5], leading to an accepted factor (e.g., 4 or 5).
use bt_hci::controller::ControllerCmdAsync;
use embassy_futures::join::join;
use embassy_time::{Duration, Timer, WithTimeout};
use trouble_host::prelude::*;

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 2;

pub async fn run<C>(controller: C)
where
    C: Controller + ControllerCmdAsync<bt_hci::cmd::le::LeSubrateRequest>,
{
    let address: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
    info!("Peripheral address = {:?}", address);
    Timer::after(embassy_time::Duration::from_millis(50)).await;

    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(address)
        .build();
    let mut peripheral = stack.peripheral();
    let mut runner = stack.runner();

    let mut adv_data = [0u8; 31];
    let adv_len = AdStructure::encode_slice(
        &[AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED)],
        &mut adv_data[..],
    )
    .unwrap();

    info!("Starting main loop");
    Timer::after(Duration::from_millis(50)).await;

    let _ = join(
        async {
            if let Err(e) = runner.run().await {
                error!("runner died with error: {:?}", e);
            } else {
                info!("Runner stopped without error!")
            }
        },
        async {
            info!("Advertising...");
            Timer::after(Duration::from_millis(50)).await;

            let advertiser = peripheral
                .advertise(
                    &Default::default(),
                    Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..adv_len],
                        scan_data: &[],
                    },
                )
                .await
                .unwrap();

            let conn = advertiser.accept().await.unwrap();
            info!("Connected!");

            // ── Wait for Step 1 ───────────────────────────────────────────────
            // The central will set a subrate factor range of [4, 12].
            // We wait for SubratingParamsUpdated once the LL has agreed on the new factor.
            info!("Waiting for central to establish a subrate factor...");
            loop {
                if let ConnectionEvent::SubratingParamsUpdated { subrate_factor, .. } = conn.next().await {
                    info!("Central set subrate_factor={}", subrate_factor);
                    break;
                }
            }

            // Brief delay so the central is ready to process our request.
            Timer::after(Duration::from_millis(500)).await;

            // ── Step 2 ────────────────────────────────────────────────────────
            // Request an out-of-range subrate factor (50).
            //
            // The central's current range is [4, 12]. Our requested range is
            // [50, 50]. The intersection is empty, so the Link Layer MUST
            // reject the request.
            info!("Requesting a subrate factor of 50, that is out of range");
            conn.request_conn_subrate(
                &stack,
                50, // subrate_min
                50, // subrate_max (min == max == 50: request exactly factor 50)
                0,  // max_latency
                0,  // continuation_number
                Duration::from_millis(2000),
            )
            .await
            .unwrap_or_else(|e| info!("Subrate request failed as expected: {:?}", e));

            async {
                // Check for update event.
                loop {
                    if let ConnectionEvent::SubratingParamsUpdated { subrate_factor, .. } = conn.next().await {
                        error!(
                            "Successfully requested out of range subrate factor: {}",
                            subrate_factor
                        );
                        break;
                    }
                }
            }
            .with_timeout(Duration::from_millis(500))
            .await
            .unwrap_or_else(|_e| info!("No subrate change event for 500ms, as expected."));

            // ── Step 3 ────────────────────────────────────────────────────────
            info!("Request a valid subrate in range.");
            conn.request_conn_subrate(
                &stack,
                10, // subrate_min
                10, // subrate_max
                0,  // max_latency
                0,  // continuation_number
                Duration::from_millis(2000),
            )
            .await
            .unwrap_or_else(|e| error!("Subrate request failed unexpectedly: {:?}", e));

            loop {
                if let ConnectionEvent::SubratingParamsUpdated { subrate_factor, .. } = conn.next().await {
                    info!(
                        "Successfully requested subrate factor 10, got {}",
                        subrate_factor
                    );
                    break;
                }
            }

            // Brief delay so the controller is ready to process our request.
            Timer::after(Duration::from_millis(500)).await;

            // ── Step 4 ────────────────────────────────────────────────────────
            info!("Request an overlapping range: Central: 4-12, Peripheral: 1-5.");
            conn.request_conn_subrate(
                &stack,
                1, // subrate_min
                5, // subrate_max
                0, // max_latency
                0, // continuation_number
                Duration::from_millis(2000),
            )
            .await
            .unwrap_or_else(|e| error!("Subrate request failed unexpectedly: {:?}", e));

            loop {
                if let ConnectionEvent::SubratingParamsUpdated { subrate_factor, .. } = conn.next().await {
                    info!(
                        "Successfully requested subrate factor in range 1 to 5, got: {}",
                        subrate_factor
                    );
                    break;
                }
            }

            info!("Negotiation complete. Staying connected.");
            loop {
                Timer::after(Duration::from_secs(60)).await;
            }
        },
    )
    .await;
}
