use bt_hci::cmd::le::{
    LeClearAdvSets, LeReadNumberOfSupportedAdvSets, LeSetAdvData, LeSetAdvEnable, LeSetAdvParams,
    LeSetAdvSetRandomAddr, LeSetExtAdvData, LeSetExtAdvEnable, LeSetExtAdvParams, LeSetExtScanResponseData,
    LeSetScanResponseData,
};
use bt_hci::controller::{Controller, ControllerCmdSync};
use bt_hci::param::{AddrKind, AdvChannelMap, AdvHandle, AdvKind, AdvSet, BdAddr, LeConnRole, Operation};
#[cfg(feature = "controller-host-flow-control")]
use bt_hci::param::{ConnHandleCompletedPackets, ControllerToHostFlowControl};
use embassy_futures::select::{select, Either};

use crate::advertise::{Advertisement, AdvertisementParameters, AdvertisementSet, RawAdvertisement};
use crate::command::CommandState;
use crate::connection::Connection;
use crate::connection_manager::ConnectionManager;
use crate::host::{AdvState, BleHost};
use crate::{Address, BleHostError, Error};

pub struct Peripheral<'d, C: Controller> {
    host: &'d BleHost<'d, C>,
}

impl<'d, C: Controller> Peripheral<'d, C> {
    pub(crate) fn new(host: &'d BleHost<'d, C>) -> Self {
        Self { host }
    }

    pub async fn advertise<'k>(
        &mut self,
        params: &AdvertisementParameters,
        data: Advertisement<'k>,
    ) -> Result<Advertiser<'_, 'd>, BleHostError<C::Error>>
    where
        C: for<'t> ControllerCmdSync<LeSetAdvData>
            + ControllerCmdSync<LeSetAdvParams>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetScanResponseData>,
    {
        // Ensure no other advertise ongoing.
        let drop = crate::host::OnDrop::new(|| {
            self.host.advertise_command_state.cancel(false);
        });
        self.host.advertise_command_state.request().await;

        // Clear current advertising terminations
        self.host.advertise_state.reset();

        let data: RawAdvertisement = data.into();
        if !data.props.legacy_adv() {
            return Err(Error::InvalidValue.into());
        }

        let kind = match (data.props.connectable_adv(), data.props.scannable_adv()) {
            (true, true) => AdvKind::AdvInd,
            (true, false) => AdvKind::AdvDirectIndLow,
            (false, true) => AdvKind::AdvScanInd,
            (false, false) => AdvKind::AdvNonconnInd,
        };
        let peer = data.peer.unwrap_or(Address {
            kind: AddrKind::PUBLIC,
            addr: BdAddr::default(),
        });

        self.host
            .command(LeSetAdvParams::new(
                params.interval_min.into(),
                params.interval_max.into(),
                kind,
                self.host.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
                peer.kind,
                peer.addr,
                params.channel_map.unwrap_or(AdvChannelMap::ALL),
                params.filter_policy,
            ))
            .await?;

        if !data.adv_data.is_empty() {
            let mut buf = [0; 31];
            let to_copy = data.adv_data.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&data.adv_data[..to_copy]);
            self.host.command(LeSetAdvData::new(to_copy as u8, buf)).await?;
        }

        if !data.scan_data.is_empty() {
            let mut buf = [0; 31];
            let to_copy = data.scan_data.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&data.scan_data[..to_copy]);
            self.host
                .command(LeSetScanResponseData::new(to_copy as u8, buf))
                .await?;
        }

        let advset: [AdvSet; 1] = [AdvSet {
            adv_handle: AdvHandle::new(0),
            duration: bt_hci::param::Duration::from_secs(0),
            max_ext_adv_events: 0,
        }];

        trace!("[host] enabling advertising");
        self.host.advertise_state.start(&advset[..]);
        self.host.command(LeSetAdvEnable::new(true)).await?;
        drop.defuse();
        Ok(Advertiser {
            advertise_state: &self.host.advertise_state,
            advertise_command_state: &self.host.advertise_command_state,
            connections: &self.host.connections,
            extended: false,
        })
    }

    /// Starts sending BLE advertisements according to the provided config.
    ///
    /// The handles are required to provide the storage while advertising, and
    /// can be created by calling AdvertisementSet::handles(sets).
    ///
    /// Advertisements are stopped when a connection is made against this host,
    /// in which case a handle for the connection is returned.
    pub async fn advertise_ext<'k>(
        &mut self,
        sets: &[AdvertisementSet<'k>],
        handles: &mut [AdvSet],
    ) -> Result<Advertiser<'_, 'd>, BleHostError<C::Error>>
    where
        C: for<'t> ControllerCmdSync<LeSetExtAdvData<'t>>
            + ControllerCmdSync<LeClearAdvSets>
            + ControllerCmdSync<LeSetExtAdvParams>
            + ControllerCmdSync<LeSetAdvSetRandomAddr>
            + ControllerCmdSync<LeReadNumberOfSupportedAdvSets>
            + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
            + for<'t> ControllerCmdSync<LeSetExtScanResponseData<'t>>,
    {
        assert_eq!(sets.len(), handles.len());
        // Check host supports the required advertisement sets
        {
            let result = self.host.command(LeReadNumberOfSupportedAdvSets::new()).await?;
            if result < sets.len() as u8 || self.host.advertise_state.len() < sets.len() {
                return Err(Error::InsufficientSpace.into());
            }
        }

        // Ensure no other advertise ongoing.
        let drop = crate::host::OnDrop::new(|| {
            self.host.advertise_command_state.cancel(true);
        });
        self.host.advertise_command_state.request().await;

        // Clear current advertising terminations
        self.host.advertise_state.reset();

        for (i, set) in sets.iter().enumerate() {
            let handle = AdvHandle::new(i as u8);
            let data: RawAdvertisement<'k> = set.data.into();
            let params = set.params;
            let peer = data.peer.unwrap_or(Address {
                kind: AddrKind::PUBLIC,
                addr: BdAddr::default(),
            });
            self.host
                .command(LeSetExtAdvParams::new(
                    handle,
                    data.props,
                    params.interval_min.into(),
                    params.interval_max.into(),
                    params.channel_map.unwrap_or(AdvChannelMap::ALL),
                    self.host.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
                    peer.kind,
                    peer.addr,
                    params.filter_policy,
                    params.tx_power as i8,
                    params.primary_phy,
                    0,
                    params.secondary_phy,
                    0,
                    false,
                ))
                .await?;

            if let Some(address) = self.host.address.as_ref() {
                self.host
                    .command(LeSetAdvSetRandomAddr::new(handle, address.addr))
                    .await?;
            }

            if !data.adv_data.is_empty() {
                self.host
                    .command(LeSetExtAdvData::new(
                        handle,
                        Operation::Complete,
                        params.fragment,
                        data.adv_data,
                    ))
                    .await?;
            }

            if !data.scan_data.is_empty() {
                self.host
                    .command(LeSetExtScanResponseData::new(
                        handle,
                        Operation::Complete,
                        params.fragment,
                        data.scan_data,
                    ))
                    .await?;
            }
            handles[i].adv_handle = handle;
            handles[i].duration = set
                .params
                .timeout
                .unwrap_or(embassy_time::Duration::from_micros(0))
                .into();
            handles[i].max_ext_adv_events = set.params.max_events.unwrap_or(0);
        }

        trace!("[host] enabling extended advertising");
        self.host.advertise_state.start(handles);
        self.host.command(LeSetExtAdvEnable::new(true, handles)).await?;
        drop.defuse();
        Ok(Advertiser {
            advertise_state: &self.host.advertise_state,
            advertise_command_state: &self.host.advertise_command_state,
            connections: &self.host.connections,
            extended: true,
        })
    }
}

/// Handle to an active advertiser which can accept connections.
pub struct Advertiser<'a, 'd> {
    advertise_state: &'a AdvState<'d>,
    advertise_command_state: &'a CommandState<bool>,
    connections: &'a ConnectionManager<'d>,
    extended: bool,
}

impl<'a, 'd> Advertiser<'a, 'd> {
    /// Accept the next peripheral connection for this advertiser.
    ///
    /// Returns Error::Timeout if advertiser stopped.
    pub async fn accept(&mut self) -> Result<Connection<'a>, Error> {
        match select(
            self.connections.accept(LeConnRole::Peripheral, &[]),
            self.advertise_state.wait(),
        )
        .await
        {
            Either::First(conn) => Ok(conn),
            Either::Second(_) => Err(Error::Timeout),
        }
    }
}

impl<'a, 'd> Drop for Advertiser<'a, 'd> {
    fn drop(&mut self) {
        self.advertise_command_state.cancel(self.extended);
    }
}
