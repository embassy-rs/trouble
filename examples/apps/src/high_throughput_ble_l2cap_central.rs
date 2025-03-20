use bt_hci::cmd::le::{LeReadLocalSupportedFeatures, LeSetDataLength, LeSetPhy};
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};
use embassy_futures::join::join;
use embassy_time::{Duration, Instant, Timer};
use trouble_host::prelude::*;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 3; // Signal + att + CoC

pub async fn run<C, const L2CAP_MTU: usize>(controller: C)
where
    C: Controller
        + ControllerCmdSync<LeSetDataLength>
        + ControllerCmdAsync<LeSetPhy>
        + ControllerCmdSync<LeReadLocalSupportedFeatures>,
{
    // Using a fixed "random" address can be useful for testing. In real scenarios, one would
    // use e.g. the MAC 6 byte array as the address (how to get that varies by the platform).
    let address: Address = Address::random([0xff, 0x8f, 0x1b, 0x05, 0xe4, 0xff]);
    info!("Our address = {:?}", address);

    let mut resources: HostResources<CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, L2CAP_MTU> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
    let Host {
        mut central,
        mut runner,
        ..
    } = stack.build();

    // NOTE: Modify this to match the address of the peripheral you want to connect to.
    // Currently, it matches the address used by the peripheral examples
    let target: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);

    let config = ConnectConfig {
        connect_params: ConnectParams {
            min_connection_interval: Duration::from_millis(80),
            max_connection_interval: Duration::from_millis(80),
            ..Default::default()
        },
        scan_config: ScanConfig {
            filter_accept_list: &[(target.kind, &target.addr)],
            ..Default::default()
        },
    };

    info!("Scanning for peripheral...");
    let _ = join(runner.run(), async {
        loop {
            // Check that the controller used supports the necessary features for high throughput.
            let res = stack
                .command(LeReadLocalSupportedFeatures::new())
                .await
                .expect("LeReadLocalSupportedFeatures command failed");
            assert!(res.supports_le_data_packet_length_extension());
            assert!(res.supports_le_2m_phy());

            let conn = central.connect(&config).await.expect("Connect failed");
            info!("Connected, creating l2cap channel");

            // Once connected, request a change in the PDU data length.
            stack
                .command(LeSetDataLength::new(conn.handle(), 251, 2120))
                .await
                .expect("LeSetDataLength command failed");

            // and request changing the physical link to 2M PHY.
            // *Note* Change to the PDU data length and PHY can also be initiated by the peripheral.
            conn.set_phy(&stack, PhyKind::Le2M)
                .await
                .expect("set phy command failed");
            let l2cap_channel_config = L2capChannelConfig {
                mtu: L2CAP_MTU as u16,
                // Ensure there will be enough credits to send data throughout the entire connection event.
                flow_policy: CreditFlowPolicy::Every(50),
                initial_credits: Some(200),
            };

            let mut ch1 = L2capChannel::create(&stack, &conn, 0x2349, &l2cap_channel_config)
                .await
                .expect("L2capChannel create failed");

            // Wait for the ratios to switch to 2M PHY.
            // If we do not wait, communication will still occur at 1M for the first 500 ms.
            Timer::after(Duration::from_secs(1)).await;

            info!("New l2cap channel created, sending some data!");

            const PAYLOAD_LEN: usize = 2510 - 6;
            const NUM_PAYLOADS: u8 = 40;

            let start = Instant::now();

            for i in 0..NUM_PAYLOADS {
                let tx = [i; PAYLOAD_LEN];
                ch1.send::<_, L2CAP_MTU>(&stack, &tx).await.expect("L2CAP send failed");
            }

            let duration = start.elapsed();

            info!(
                "Sent {} bytes at {} kbps, waiting for them to be sent back.",
                (PAYLOAD_LEN as u64 * NUM_PAYLOADS as u64),
                ((PAYLOAD_LEN as u64 * NUM_PAYLOADS as u64 * 8).div_ceil(duration.as_millis()))
            );

            let mut rx = [0; PAYLOAD_LEN];
            for i in 0..NUM_PAYLOADS {
                let len = ch1.receive(&stack, &mut rx).await.expect("L2CAP receive failed");
                assert_eq!(len, rx.len());
                assert_eq!(rx, [i; PAYLOAD_LEN]);
            }

            info!("Received successfully!");

            Timer::after(Duration::from_secs(60)).await;
        }
    })
    .await;
}
