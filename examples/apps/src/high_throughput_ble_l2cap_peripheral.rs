use embassy_futures::join::join;
use embassy_time::{Duration, Timer};
use trouble_host::prelude::*;
use bt_hci::cmd::le::{LeReadLocalSupportedFeatures, LeReadMaxDataLength, LeSetDataLength, LeWriteSuggestedDefaultDataLength};
use bt_hci::controller::ControllerCmdSync;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 3; // Signal + att + CoC

pub async fn run<C, const L2CAP_MTU: usize>(controller: C)
where
    C: Controller
    + ControllerCmdSync<LeSetDataLength>,
{
    // Hardcoded peripheral address
    let address: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
    info!("Our address = {:?}", address);

    let mut resources: HostResources<CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, L2CAP_MTU> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
    let Host {
        mut peripheral,
        mut runner,
        ..
    } = stack.build();

    let mut adv_data = [0; 31];
    AdStructure::encode_slice(
        &[AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED)],
        &mut adv_data[..],
    )
        .unwrap();

    let mut scan_data = [0; 31];
    AdStructure::encode_slice(&[AdStructure::CompleteLocalName(b"Trouble")], &mut scan_data[..]).unwrap();

    let _ = join(runner.run(), async {
        loop {
            info!("Advertising, waiting for connection...");
            let advertiser = peripheral
                .advertise(
                    &Default::default(),
                    Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..],
                        scan_data: &scan_data[..],
                    },
                )
                .await
                .unwrap();
            let conn = advertiser.accept().await.unwrap();

            info!("Connection established");

            let res = stack.command(LeSetDataLength::new(conn.handle(), 251, 2120)).await;
            match res {
                Ok(_) => {
                    info!("LeSetDataLength OK");
                }
                Err(e) => {
                    info!("LeSetDataLength error: {:?}", e);
                }
            }

            let l2cap_channel_config = L2capChannelConfig {
                mtu: 2510,
                flow_policy: CreditFlowPolicy::Every(50),
                initial_credits: Some(200),
            };

            let mut ch1 = L2capChannel::accept(&stack, &conn, &[0x2349], &l2cap_channel_config)
                .await
                .unwrap();

            info!("L2CAP channel accepted");

            // Size of payload we're expecting
            const PAYLOAD_LEN: usize = 2510 - 6;
            let mut rx = [0; PAYLOAD_LEN];
            for i in 0..10 {
                let len = ch1.receive(&stack, &mut rx).await.unwrap();
                assert_eq!(len, rx.len());
                assert_eq!(rx, [i; PAYLOAD_LEN]);
            }

            info!("L2CAP data received, echoing");
            Timer::after(Duration::from_secs(1)).await;
            for i in 0..10 {
                let tx = [i; PAYLOAD_LEN];
                ch1.send::<_, L2CAP_MTU>(&stack, &tx).await.unwrap();
            }
            info!("L2CAP data echoed");

            Timer::after(Duration::from_secs(60)).await;
        }
    })
        .await;
}
