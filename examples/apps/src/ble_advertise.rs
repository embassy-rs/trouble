use bt_hci::cmd::le::*;
use bt_hci::controller::ControllerCmdSync;
use embassy_futures::join::join;
use embassy_time::{Duration, Timer};
use trouble_host::prelude::*;

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

    let mut resources: HostResources<StandardConfig, 0, 0> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
    let Host {
        mut peripheral,
        mut runner,
        ..
    } = stack.build();

    let mut adv_data = [0; 31];
    let len = AdStructure::encode_slice(
        &[
            AdStructure::CompleteLocalName(b"Trouble Advert"),
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
        ],
        &mut adv_data[..],
    )
    .unwrap();

    info!("Starting advertising");
    let _ = join(runner.run(), async {
        loop {
            let mut params = AdvertisementParameters::default();
            params.interval_min = Duration::from_millis(100);
            params.interval_max = Duration::from_millis(100);
            let _advertiser = peripheral
                .advertise(
                    &params,
                    Advertisement::NonconnectableScannableUndirected {
                        adv_data: &adv_data[..len],
                        scan_data: &[],
                    },
                )
                .await
                .unwrap();
            loop {
                info!("Still running");
                Timer::after(Duration::from_secs(60)).await;
            }
        }
    })
    .await;
}
