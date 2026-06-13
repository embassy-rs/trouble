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

    let mut resources: HostResources<_, DefaultPacketPool, 1, 0, 3> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(address)
        .build();
    let mut runner = stack.runner();
    let mut peripheral = stack.peripheral();

    let mut adv_data = [0; 31];
    let len = AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::CompleteLocalName(b"Trouble Multiadv"),
        ],
        &mut adv_data[..],
    )
    .unwrap();

    let mut params_1m = AdvertisementParameters::default();
    params_1m.primary_phy = PhyKind::Le1M;
    params_1m.secondary_phy = PhyKind::Le1M;
    params_1m.interval_min = Duration::from_millis(160);
    params_1m.interval_max = Duration::from_millis(160);

    let mut params_coded = AdvertisementParameters::default();
    params_coded.primary_phy = PhyKind::LeCoded;
    params_coded.secondary_phy = PhyKind::LeCoded;
    params_coded.interval_min = Duration::from_millis(400);
    params_coded.interval_max = Duration::from_millis(400);
    let sets = [
        AdvertisementSet {
            params: params_1m,
            data: Advertisement::ExtNonconnectableScannableUndirected {
                scan_data: &adv_data[..len],
            },
            address: None,
        },
        AdvertisementSet {
            params: params_coded,
            data: Advertisement::ExtNonconnectableScannableUndirected {
                scan_data: &adv_data[..len],
            },
            address: None,
        },
        AdvertisementSet {
            params: params_1m,
            data: Advertisement::ExtConnectableNonscannableUndirected {
                adv_data: &adv_data[..len],
            },
            address: None,
        },
    ];
    let mut handles = AdvertisementSet::handles(&sets);

    info!("Starting advertising");
    let _ = join(runner.run(), async {
        loop {
            let mut advertiser = peripheral.advertise_ext(&sets, &mut handles).await.unwrap();
            loop {
                match advertiser.accept_connectable().await {
                    Ok(conn) => {
                        info!("Connection established on adv set {:?}", conn.adv_handle());
                        Timer::after(Duration::from_secs(10)).await;
                        info!("Dropping connection, beacon sets keep advertising");
                    }
                    Err(e) => {
                        warn!("Advertiser stopped: {:?}", e);
                        break;
                    }
                }
            }
        }
    })
    .await;
}
