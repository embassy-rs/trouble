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
use crate::{bt_hci_duration, bt_hci_ext_duration, Address, BleHostError, Error, PacketPool, Stack};

/// Type which implements the BLE peripheral role.
pub struct Peripheral<'d, C, P: PacketPool> {
    stack: &'d Stack<'d, C, P>,
}

impl<'d, C: Controller, P: PacketPool> Peripheral<'d, C, P> {
    pub(crate) fn new(stack: &'d Stack<'d, C, P>) -> Self {
        Self { stack }
    }

    /// Start advertising with the provided parameters and return a handle to accept connections.
    pub async fn advertise<'k>(
        &mut self,
        params: &AdvertisementParameters,
        data: Advertisement<'k>,
    ) -> Result<Advertiser<'d, C, P>, BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeSetAdvData>
            + ControllerCmdSync<LeSetAdvParams>
            + ControllerCmdSync<LeSetAdvEnable>
            + ControllerCmdSync<LeSetScanResponseData>,
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
            return Err(Error::ExtendedAdvertisingNotSupported.into());
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
            bt_hci_duration(params.interval_min),
            bt_hci_duration(params.interval_max),
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
            duration: bt_hci_duration(params.timeout.unwrap_or(embassy_time::Duration::from_micros(0))),
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

    /// Update the advertisement adv_data and/or scan_data. Does not change any
    /// other advertising parameters. If no advertising is active, this will not
    /// produce any observable effect. This is typically useful when
    /// implementing a BLE beacon that only broadcasts advertisement data and
    /// does not accept any connections.
    pub async fn update_adv_data<'k>(&mut self, data: Advertisement<'k>) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeSetAdvData> + ControllerCmdSync<LeSetScanResponseData>,
    {
        let host = &self.stack.host;
        let data: RawAdvertisement = data.into();
        if !data.props.legacy_adv() {
            return Err(Error::ExtendedAdvertisingNotSupported.into());
        }
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
        Ok(())
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
    ) -> Result<Advertiser<'d, C, P>, BleHostError<C::Error>>
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
                bt_hci_ext_duration(params.interval_min),
                bt_hci_ext_duration(params.interval_max),
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
            handles[i].duration = bt_hci_duration(set.params.timeout.unwrap_or(embassy_time::Duration::from_micros(0)));
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

    /// Update the extended advertisement adv_data and/or scan_data for multiple
    /// advertising sets. Does not change any other advertising parameters. If
    /// no advertising is active, this will not produce any observable effect.
    /// This is typically useful when implementing a BLE beacon that only
    /// broadcasts advertisement data and does not accept any connections.
    pub async fn update_adv_data_ext<'k>(
        &mut self,
        sets: &[AdvertisementSet<'k>],
        handles: &mut [AdvSet],
    ) -> Result<(), BleHostError<C::Error>>
    where
        C: for<'t> ControllerCmdSync<LeSetExtAdvData<'t>> + for<'t> ControllerCmdSync<LeSetExtScanResponseData<'t>>,
    {
        assert_eq!(sets.len(), handles.len());
        let host = &self.stack.host;
        for (i, set) in sets.iter().enumerate() {
            let handle = handles[i].adv_handle;
            let data: RawAdvertisement<'k> = set.data.into();
            if !data.adv_data.is_empty() {
                host.command(LeSetExtAdvData::new(
                    handle,
                    Operation::Complete,
                    set.params.fragment,
                    data.adv_data,
                ))
                .await?;
            }
            if !data.scan_data.is_empty() {
                host.command(LeSetExtScanResponseData::new(
                    handle,
                    Operation::Complete,
                    set.params.fragment,
                    data.scan_data,
                ))
                .await?;
            }
        }
        Ok(())
    }

    /// Accept any pending available connection.
    ///
    /// Accepts the next pending connection if there are any.
    pub fn try_accept(&mut self) -> Option<Connection<'d, P>> {
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
pub struct Advertiser<'d, C, P: PacketPool> {
    stack: &'d Stack<'d, C, P>,
    extended: bool,
    done: bool,
}

impl<'d, C: Controller, P: PacketPool> Advertiser<'d, C, P> {
    /// Accept the next peripheral connection for this advertiser.
    ///
    /// Returns Error::Timeout if advertiser stopped.
    pub async fn accept(mut self) -> Result<Connection<'d, P>, Error> {
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

impl<C, P: PacketPool> Drop for Advertiser<'_, C, P> {
    fn drop(&mut self) {
        if !self.done {
            self.stack.host.advertise_command_state.cancel(self.extended);
        } else {
            self.stack.host.advertise_command_state.canceled();
        }
    }
}
