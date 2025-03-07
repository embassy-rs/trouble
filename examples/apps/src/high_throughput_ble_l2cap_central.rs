use embassy_futures::join::join;
use embassy_time::{Duration, Timer};
use trouble_host::prelude::*;
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};
use bt_hci::cmd::le::{LeSetPhy, LeReadPhyReturn, LeSetDataLength, LeReadPhy, LeReadBufferSize,
                      LeReadMaxDataLength, LeReadLocalSupportedFeatures,
                      LeWriteSuggestedDefaultDataLength, LeReadSuggestedDefaultDataLength};
use bt_hci::param::{AllPhys, PhyMask, PhyOptions};

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 3; // Signal + att + CoC

pub async fn run<C, const L2CAP_MTU: usize>(controller: C)
where
    C: Controller
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
        connect_params: ConnectParams{
            min_connection_interval: Duration::from_micros(30_000),
            max_connection_interval: Duration::from_micros(30_000),
            max_latency: 0,
            event_length: Duration::from_millis(4000),
            supervision_timeout: Duration::from_millis(8000),
            ..Default::default()
        },
        scan_config: ScanConfig {
            // active: true,
            filter_accept_list: &[(target.kind, &target.addr)],
            phys: PhySet::M2,
            // interval: Duration::from_secs(1),
            // window: Duration::from_secs(1),
            // timeout: Duration::from_secs(0),
            ..Default::default()
        },
    };

    info!("Scanning for peripheral...");
    let _ = join(runner.run(), async {
        loop {
            // Check that the controller used supports the necessary features for high throughput.
            let res = stack.command(LeReadLocalSupportedFeatures::new()).await.unwrap();
            assert!(res.supports_le_data_packet_length_extension());
            assert!(res.supports_le_2m_phy());

            let conn = central.connect(&config).await.unwrap();
            info!("Connected, creating l2cap channel");

            let phy_mask = PhyMask::new().set_le_2m_preferred(true);
            stack.async_command(LeSetPhy::new(conn.handle(), AllPhys::default(), phy_mask.clone(), phy_mask, PhyOptions::S2CodingPreferred)).await.unwrap();

            const PAYLOAD_LEN: usize = ((251-4)*20)-2;

            let l2cap_channel_config = L2capChannelConfig {
                mtu: 251,
                flow_policy: CreditFlowPolicy::Every(50),
                initial_credits: Some(200),
            };

            let mut ch1 = L2capChannel::create(&stack, &conn, 0x2349, &l2cap_channel_config)
                .await
                .unwrap();
            info!("New l2cap channel created, sending some data!");
            for i in 0..10 {
                let tx = [i; PAYLOAD_LEN];
                info!("Sending data to l2cap channel with MTU: {}", L2CAP_MTU);
                ch1.send::<_, L2CAP_MTU>(&stack, &tx).await.unwrap();
            }
            info!("Sent data, waiting for them to be sent back");
            let mut rx = [0; PAYLOAD_LEN];
            for i in 0..10 {
                let len = ch1.receive(&stack, &mut rx).await.unwrap();
                assert_eq!(len, rx.len());
                assert_eq!(rx, [i; PAYLOAD_LEN]);
            }

            info!("Received successfully!");

            Timer::after(Duration::from_secs(60)).await;
        }
    })
        .await;
}
