//! Functionality for the BLE peripheral role.
use core::task::Poll;

use bt_hci::cmd::le::{
    LeClearAdvSets, LeReadNumberOfSupportedAdvSets, LeSetAdvData, LeSetAdvEnable, LeSetAdvParams,
    LeSetAdvSetRandomAddr, LeSetExtAdvData, LeSetExtAdvEnable, LeSetExtAdvParams, LeSetExtScanResponseData,
    LeSetScanResponseData,
};
use bt_hci::controller::{Controller, ControllerCmdSync};
use bt_hci::param::{AddrKind, AdvChannelMap, AdvHandle, AdvKind, AdvSet, BdAddr, LeConnRole, Operation};
use embassy_futures::select::{select, Either};

use crate::advertise::{Advertisement, AdvertisementParameters, AdvertisementSet, RawAdvertisement};
use crate::connection::Connection;
use crate::{Address, BleHostError, Error, Stack};

/// Type which implements the BLE peripheral role.
pub struct Peripheral<'d, C> {
    stack: &'d Stack<'d, C>,
}

impl<'d, C: Controller> Peripheral<'d, C> {
    pub(crate) fn new(stack: &'d Stack<'d, C>) -> Self {
        Self { stack }
    }

    /// Start advertising with the provided parameters and return a handle to accept connections.
    pub async fn advertise<'k>(
        &mut self,
        params: &AdvertisementParameters,
        data: Advertisement<'k>,
    ) -> Result<Advertiser<'d, C>, BleHostError<C::Error>>
    where
        C: for<'t> ControllerCmdSync<LeSetAdvData>
            + ControllerCmdSync<LeSetAdvParams>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetScanResponseData>,
    {
        let host = &self.stack.host;

        // Ensure no other advertise ongoing.
        let drop = crate::host::OnDrop::new(|| {
            host.advertise_command_state.cancel(false);
        });
        host.advertise_command_state.request().await;

        // Clear current advertising terminations
        host.advertise_state.reset();

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

        host.command(LeSetAdvParams::new(
            params.interval_min.into(),
            params.interval_max.into(),
            kind,
            host.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
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
            host.command(LeSetAdvData::new(to_copy as u8, buf)).await?;
        }

        if !data.scan_data.is_empty() {
            let mut buf = [0; 31];
            let to_copy = data.scan_data.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&data.scan_data[..to_copy]);
            host.command(LeSetScanResponseData::new(to_copy as u8, buf)).await?;
        }

        let advset: [AdvSet; 1] = [AdvSet {
            adv_handle: AdvHandle::new(0),
            duration: params.timeout.unwrap_or(embassy_time::Duration::from_micros(0)).into(),
            max_ext_adv_events: 0,
        }];

        trace!("[host] enabling advertising");
        host.advertise_state.start(&advset[..]);
        host.command(LeSetAdvEnable::new(true)).await?;
        drop.defuse();
        Ok(Advertiser {
            stack: self.stack,
            extended: false,
            done: false,
        })
    }

    /// Starts sending BLE advertisements according to the provided config.
    ///
    /// The handles are required to provide the storage while advertising, and
    /// can be created by calling AdvertisementSet::handles(sets).
    ///
    /// Advertisements are stopped when a connection is made against this host,
    /// in which case a handle for the connection is returned.
    ///
    /// Returns a handle to accept connections.
    pub async fn advertise_ext<'k>(
        &mut self,
        sets: &[AdvertisementSet<'k>],
        handles: &mut [AdvSet],
    ) -> Result<Advertiser<'d, C>, BleHostError<C::Error>>
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
        let host = &self.stack.host;
        // Check host supports the required advertisement sets
        {
            let result = host.command(LeReadNumberOfSupportedAdvSets::new()).await?;
            if result < sets.len() as u8 || host.advertise_state.len() < sets.len() {
                return Err(Error::InsufficientSpace.into());
            }
        }

        // Ensure no other advertise ongoing.
        let drop = crate::host::OnDrop::new(|| {
            host.advertise_command_state.cancel(true);
        });
        host.advertise_command_state.request().await;

        // Clear current advertising terminations
        host.advertise_state.reset();

        for (i, set) in sets.iter().enumerate() {
            let handle = AdvHandle::new(i as u8);
            let data: RawAdvertisement<'k> = set.data.into();
            let params = set.params;
            let peer = data.peer.unwrap_or(Address {
                kind: AddrKind::PUBLIC,
                addr: BdAddr::default(),
            });
            host.command(LeSetExtAdvParams::new(
                handle,
                data.props,
                params.interval_min.into(),
                params.interval_max.into(),
                params.channel_map.unwrap_or(AdvChannelMap::ALL),
                host.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
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

            if let Some(address) = host.address.as_ref() {
                host.command(LeSetAdvSetRandomAddr::new(handle, address.addr)).await?;
            }

            if !data.adv_data.is_empty() {
                host.command(LeSetExtAdvData::new(
                    handle,
                    Operation::Complete,
                    params.fragment,
                    data.adv_data,
                ))
                .await?;
            }

            if !data.scan_data.is_empty() {
                host.command(LeSetExtScanResponseData::new(
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
        host.advertise_state.start(handles);
        host.command(LeSetExtAdvEnable::new(true, handles)).await?;
        drop.defuse();
        Ok(Advertiser {
            stack: self.stack,
            extended: true,
            done: false,
        })
    }

    /// Accept any pending available connection.
    ///
    /// Accepts the next pending connection if there are any.
    pub fn try_accept(&mut self) -> Option<Connection<'d>> {
        if let Poll::Ready(conn) = self
            .stack
            .host
            .connections
            .poll_accept(LeConnRole::Peripheral, &[], None)
        {
            Some(conn)
        } else {
            None
        }
    }
}

/// Handle to an active advertiser which can accept connections.
pub struct Advertiser<'d, C: Controller> {
    stack: &'d Stack<'d, C>,
    extended: bool,
    done: bool,
}

impl<'d, C: Controller> Advertiser<'d, C> {
    /// Accept the next peripheral connection for this advertiser.
    ///
    /// Returns Error::Timeout if advertiser stopped.
    pub async fn accept(mut self) -> Result<Connection<'d>, Error> {
        let result = match select(
            self.stack.host.connections.accept(LeConnRole::Peripheral, &[]),
            self.stack.host.advertise_state.wait(),
        )
        .await
        {
            Either::First(conn) => Ok(conn),
            Either::Second(_) => Err(Error::Timeout),
        };
        self.done = true;
        result
    }
}

impl<C: Controller> Drop for Advertiser<'_, C> {
    fn drop(&mut self) {
        if !self.done {
            self.stack.host.advertise_command_state.cancel(self.extended);
        } else {
            self.stack.host.advertise_command_state.canceled();
        }
    }
}
