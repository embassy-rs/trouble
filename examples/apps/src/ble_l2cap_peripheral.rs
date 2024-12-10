use embassy_futures::join::join;
use embassy_time::{Duration, Timer};
use trouble_host::prelude::*;

/// How many outgoing L2CAP buffers per link
const L2CAP_TXQ: u8 = 20;

/// How many incoming L2CAP buffers per link
const L2CAP_RXQ: u8 = 20;

/// Size of L2CAP packets
const L2CAP_MTU: usize = 27;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 3; // Signal + att + CoC

type Resources<C> = HostResources<C, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, L2CAP_MTU>;

pub async fn run<C>(controller: C)
where
    C: Controller,
{
    let mut resources = Resources::new(PacketQos::None);

    let address: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
    info!("Our address = {:?}", address);

    let (stack, mut peripheral, _, mut runner) = trouble_host::new(controller, &mut resources)
        .set_random_address(address)
        .build();

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

            let mut ch1 = L2capChannel::accept(stack, &conn, &[0x2349], &Default::default())
                .await
                .unwrap();

            info!("L2CAP channel accepted");

            // Size of payload we're expecting
            const PAYLOAD_LEN: usize = 27;
            let mut rx = [0; PAYLOAD_LEN];
            for i in 0..10 {
                let len = ch1.receive(stack, &mut rx).await.unwrap();
                assert_eq!(len, rx.len());
                assert_eq!(rx, [i; PAYLOAD_LEN]);
            }

            info!("L2CAP data received, echoing");
            Timer::after(Duration::from_secs(1)).await;
            for i in 0..10 {
                let tx = [i; PAYLOAD_LEN];
                ch1.send::<_, PAYLOAD_LEN>(stack, &tx).await.unwrap();
            }
            info!("L2CAP data echoed");

            Timer::after(Duration::from_secs(60)).await;
        }
    })
    .await;
}
