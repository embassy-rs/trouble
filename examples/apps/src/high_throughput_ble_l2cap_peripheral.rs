use bt_hci::cmd::le::LeReadLocalSupportedFeatures;
use bt_hci::controller::ControllerCmdSync;
use embassy_futures::join::join;
use embassy_time::{Duration, Instant, Timer};
use trouble_host::prelude::*;

use crate::common::PSM_L2CAP_EXAMPLES;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 3; // Signal + att + CoC

pub async fn run<C, P>(controller: C)
where
    C: Controller + ControllerCmdSync<LeReadLocalSupportedFeatures>,
    P: PacketPool,
{
    // Hardcoded peripheral address
    let address: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
    info!("Our address = {:?}", address);

    let mut resources: HostResources<P, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
    let Host {
        mut peripheral,
        mut runner,
        ..
    } = stack.build();

    let mut adv_data = [0; 31];
    let adv_data_len = AdStructure::encode_slice(
        &[AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED)],
        &mut adv_data[..],
    )
    .unwrap();

    let mut scan_data = [0; 31];
    let scan_data_len = AdStructure::encode_slice(&[AdStructure::CompleteLocalName(b"TroubleHT")], &mut scan_data[..]).unwrap();

    let _ = join(runner.run(), async {
        loop {
            // Check that the controller used supports the necessary features for high throughput.
            let res = stack
                .command(LeReadLocalSupportedFeatures::new())
                .await
                .expect("LeReadLocalSupportedFeatures command failed");
            assert!(res.supports_le_data_packet_length_extension());
            assert!(res.supports_le_2m_phy());

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
                .expect("Advertising failed");
            let conn = advertiser.accept().await.expect("Connection failed");

            info!("Connection established");

            const PAYLOAD_LEN: usize = 2510;
            const L2CAP_MTU: usize = 251;
            let l2cap_channel_config = L2capChannelConfig {
                mtu: Some(PAYLOAD_LEN as u16 - 6),
                mps: Some(L2CAP_MTU as u16 - 4),
                // Ensure there will be enough credits to send data throughout the entire connection event.
                flow_policy: CreditFlowPolicy::Every(50),
                initial_credits: Some(200),
            };

            let mut ch1 = L2capChannel::accept(&stack, &conn, &[PSM_L2CAP_EXAMPLES], &l2cap_channel_config)
                .await
                .expect("L2capChannel create failed");

            info!("L2CAP channel accepted");

            // Size of payload we're expecting
            const NUM_PAYLOADS: u8 = 40;
            let mut rx = [0; PAYLOAD_LEN];
            for i in 0..NUM_PAYLOADS {
                let len = ch1.receive(&stack, &mut rx).await.expect("L2CAP receive failed");
                assert_eq!(len, rx.len());
                assert_eq!(rx, [i; PAYLOAD_LEN]);
            }

            info!("L2CAP data received, echoing");
            Timer::after(Duration::from_secs(1)).await;

            let start = Instant::now();

            for i in 0..NUM_PAYLOADS {
                let tx = [i; PAYLOAD_LEN];
                ch1.send(&stack, &tx).await.expect("L2CAP send failed");
            }

            let duration = start.elapsed();

            info!(
                "L2CAP data of {} bytes echoed at {} kbps.",
                (PAYLOAD_LEN as u64 * NUM_PAYLOADS as u64),
                ((PAYLOAD_LEN as u64 * NUM_PAYLOADS as u64 * 8).div_ceil(duration.as_millis()))
            );

            Timer::after(Duration::from_secs(60)).await;
        }
    })
    .await;
}
