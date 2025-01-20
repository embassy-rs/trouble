use bt_hci::cmd::le::*;
use bt_hci::controller::ControllerCmdSync;
use embassy_futures::join::join;
use embassy_time::{Duration, Instant, Timer};
use trouble_host::prelude::*;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 2; // Signal + att

pub async fn run<C, const L2CAP_MTU: usize>(controller: C)
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

    let mut resources: HostResources<CONNECTIONS_MAX, L2CAP_CHANNELS_MAX, L2CAP_MTU> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources).set_random_address(address);
    let Host {
        mut peripheral,
        mut runner,
        ..
    } = stack.build();

    let mut adv_data = [0; 31];
    let len = AdStructure::encode_slice(
        &[
            AdStructure::CompleteLocalName(b"Trouble Multiadv"),
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
        ],
        &mut adv_data[..],
    )
    .unwrap();

    let sets = [
        AdvertisementSet {
            params: AdvertisementParameters {
                tx_power: TxPower::Plus8dBm,
                primary_phy: PhyKind::Le1M,
                secondary_phy: PhyKind::Le1M,
                max_events: Some(1), // Advertise set only once
                timeout: None,
                interval_min: Duration::from_secs(1),
                interval_max: Duration::from_secs(1),
                channel_map: None,
                filter_policy: AdvFilterPolicy::Unfiltered,
                fragment: false,
            },
            data: Advertisement::ExtNonconnectableScannableUndirected {
                scan_data: &adv_data[..len],
            },
        },
        AdvertisementSet {
            params: AdvertisementParameters {
                tx_power: TxPower::Plus8dBm,
                primary_phy: PhyKind::LeCoded,
                secondary_phy: PhyKind::LeCoded,
                max_events: None,
                timeout: Some(Duration::from_secs(4)), // Advertise this set for 4 seconds
                interval_min: Duration::from_secs(1),
                interval_max: Duration::from_secs(1),
                channel_map: None,
                fragment: false,
                filter_policy: AdvFilterPolicy::Unfiltered,
            },
            data: Advertisement::ExtNonconnectableScannableUndirected {
                scan_data: &adv_data[..len],
            },
        },
    ];
    let mut handles = AdvertisementSet::handles(&sets);

    info!("Starting advertising");
    let _ = join(runner.run(), async {
        loop {
            let start = Instant::now();
            let advertiser = peripheral.advertise_ext(&sets, &mut handles).await.unwrap();
            match advertiser.accept().await {
                Ok(_) => {}
                Err(trouble_host::Error::Timeout) => {
                    let d: Duration = Instant::now() - start;
                    info!("timeout/done after {} millis", d.as_millis());
                    Timer::after(Duration::from_secs(2)).await;
                }
                Err(e) => {
                    warn!("advertising error: {:?}", e);
                    Timer::after(Duration::from_secs(2)).await;
                }
            };
        }
    })
    .await;
}
