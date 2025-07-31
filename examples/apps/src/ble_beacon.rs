// BLE beacon example
//
// A beacon is a device that advertises packets that are constantly being
// updated to reflect the current state of the device, but usually does not
// accept any conections. This allows broadcasting device information.
//

use bt_hci::cmd::le::*;
use bt_hci::controller::ControllerCmdSync;
use embassy_futures::join::join;
use embassy_time::{Duration, Instant, Timer};
use trouble_host::prelude::*;

// Use your company ID (register for free with Bluetooth SIG)
const COMPANY_ID: u16 = 0xFFFF;

fn make_adv_payload(start: Instant, update_count: u32) -> [u8; 8] {
    let mut data = [0u8; 8];
    let elapsed_ms = Instant::now().duration_since(start).as_millis() as u32;
    data[0..4].copy_from_slice(&update_count.to_be_bytes());
    data[4..8].copy_from_slice(&elapsed_ms.to_be_bytes());
    data
}

pub async fn run<C>(controller: C)
where
    C: Controller
        + for<'t> ControllerCmdSync<LeSetExtAdvData<'t>>
        + ControllerCmdSync<LeClearAdvSets>
        + ControllerCmdSync<LeSetExtAdvParams>
        + ControllerCmdSync<LeSetAdvSetRandomAddr>
        + ControllerCmdSync<LeReadNumberOfSupportedAdvSets>
        + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
        + for<'t> ControllerCmdSync<LeSetExtScanResponseData<'t>>,
{
    let address: Address = Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]);
    info!("Our address = {:?}", address);

    let mut resources: HostResources<DefaultPacketPool, 0, 0, 27> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
    let Host {
        mut peripheral,
        mut runner,
        ..
    } = stack.build();

    let mut adv_data = [0; 64];
    let mut update_count = 0u32;
    let start = Instant::now();
    let len = AdStructure::encode_slice(
        &[
            AdStructure::CompleteLocalName(b"Trouble Beacon"),
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::ManufacturerSpecificData {
                company_identifier: COMPANY_ID,
                payload: &make_adv_payload(start, update_count),
            },
        ],
        &mut adv_data[..],
    )
    .unwrap();

    info!("Starting advertising");
    let _ = join(runner.run(), async {
        loop {
            let mut params = AdvertisementParameters::default();
            params.interval_min = Duration::from_millis(25);
            params.interval_max = Duration::from_millis(150);
            let _advertiser = peripheral
                .advertise(
                    &params,
                    Advertisement::NonconnectableNonscannableUndirected {
                        adv_data: &adv_data[..len],
                    },
                )
                .await
                .unwrap();
            loop {
                Timer::after(Duration::from_millis(10)).await;
                update_count = update_count.wrapping_add(1);

                let len = AdStructure::encode_slice(
                    &[
                        AdStructure::CompleteLocalName(b"Trouble Beacon"),
                        AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                        AdStructure::ManufacturerSpecificData {
                            company_identifier: COMPANY_ID,
                            payload: &make_adv_payload(start, update_count),
                        },
                    ],
                    &mut adv_data[..],
                )
                .unwrap();

                peripheral
                    .update_adv_data(Advertisement::NonconnectableNonscannableUndirected {
                        adv_data: &adv_data[..len],
                    })
                    .await
                    .unwrap();

                if update_count % 100 == 0 {
                    info!("Still running: Updated the beacon {} times", update_count);
                }
            }
        }
    })
    .await;
}
