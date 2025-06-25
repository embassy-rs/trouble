use embassy_futures::join::join;
use embassy_time::{Duration, Timer};
use trouble_host::IoCapabilities;
use trouble_host::prelude::*;

use crate::common::PSM_L2CAP_EXAMPLES;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 3; // Signal + att + CoC

pub async fn run<C>(controller: C)
where
    C: Controller,
{
    // Using a fixed "random" address can be useful for testing. In real scenarios, one would
    // use e.g. the MAC 6 byte array as the address (how to get that varies by the platform).
    let address: Address = Address::random([0xff, 0x8f, 0x1b, 0x05, 0xe4, 0xff]);
    info!("Our address = {:?}", address);

    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources, IoCapabilities::NoInputNoOutput).set_random_address(address);
    let Host {
        mut central,
        mut runner,
        ..
    } = stack.build();

    // NOTE: Modify this to match the address of the peripheral you want to connect to.
    // Currently, it matches the address used by the peripheral examples
    let target: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);

    let config = ConnectConfig {
        connect_params: Default::default(),
        scan_config: ScanConfig {
            filter_accept_list: &[(target.kind, &target.addr)],
            ..Default::default()
        },
    };

    info!("Scanning for peripheral...");
    let _ = join(runner.run(), async {
        loop {
            let conn = central.connect(&config).await.unwrap();
            info!("Connected, creating l2cap channel");
            const PAYLOAD_LEN: usize = 27;
            let config = L2capChannelConfig {
                mtu: Some(PAYLOAD_LEN as u16),
                ..Default::default()
            };
            let mut ch1 = L2capChannel::create(&stack, &conn, PSM_L2CAP_EXAMPLES, &config)
                .await
                .unwrap();
            info!("New l2cap channel created, sending some data!");
            for i in 0..10 {
                let tx = [i; PAYLOAD_LEN];
                ch1.send(&stack, &tx).await.unwrap();
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
