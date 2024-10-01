//! Functionality for the BLE central role.
#[cfg(feature = "scan")]
use bt_hci::cmd::le::LeSetScanParams;
use bt_hci::cmd::le::{
    LeAddDeviceToFilterAcceptList, LeClearFilterAcceptList, LeCreateConn, LeExtCreateConn, LeSetExtScanEnable,
    LeSetExtScanParams, LeSetScanEnable,
};
use bt_hci::controller::{Controller, ControllerCmdAsync, ControllerCmdSync};
use bt_hci::param::{AddrKind, BdAddr, FilterDuplicates, InitiatingPhy, LeConnRole, PhyParams, ScanningPhy};
#[cfg(feature = "controller-host-flow-control")]
use bt_hci::param::{ConnHandleCompletedPackets, ControllerToHostFlowControl};
use embassy_futures::select::{select, Either};

use crate::connection::{ConnectConfig, Connection};
#[cfg(feature = "scan")]
use crate::scan::ScanReport;
use crate::scan::{PhySet, ScanConfig};
use crate::{BleHostError, Error, Stack};

/// A type implementing the BLE central role.
pub struct Central<'d, C: Controller> {
    stack: Stack<'d, C>,
}

impl<'d, C: Controller> Central<'d, C> {
    pub(crate) fn new(stack: Stack<'d, C>) -> Self {
        Self { stack }
    }

    /// Attempt to create a connection with the provided config.
    pub async fn connect(&mut self, config: &ConnectConfig<'_>) -> Result<Connection<'_>, BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
            + ControllerCmdAsync<LeCreateConn>,
    {
        if config.scan_config.filter_accept_list.is_empty() {
            return Err(Error::InvalidValue.into());
        }

        let host = self.stack.host;
        let _drop = crate::host::OnDrop::new(|| {
            host.connect_command_state.cancel(true);
        });
        host.connect_command_state.request().await;

        self.set_accept_filter(config.scan_config.filter_accept_list).await?;

        host.async_command(LeCreateConn::new(
            config.scan_config.interval.into(),
            config.scan_config.window.into(),
            true,
            AddrKind::PUBLIC,
            BdAddr::default(),
            host.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
            config.connect_params.min_connection_interval.into(),
            config.connect_params.max_connection_interval.into(),
            config.connect_params.max_latency,
            config.connect_params.supervision_timeout.into(),
            config.connect_params.event_length.into(),
            config.connect_params.event_length.into(),
        ))
        .await?;
        match select(
            host.connections
                .accept(LeConnRole::Central, config.scan_config.filter_accept_list),
            host.connect_command_state.wait_idle(),
        )
        .await
        {
            Either::First(conn) => {
                _drop.defuse();
                host.connect_command_state.done();
                Ok(conn)
            }
            Either::Second(_) => Err(Error::Timeout.into()),
        }
    }

    /// Attempt to create a connection with the provided config.
    pub async fn connect_ext(&mut self, config: &ConnectConfig<'_>) -> Result<Connection<'d>, BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
            + ControllerCmdAsync<LeExtCreateConn>
            + ControllerCmdSync<LeSetExtScanEnable>
            + ControllerCmdSync<LeSetExtScanParams>,
    {
        if config.scan_config.filter_accept_list.is_empty() {
            return Err(Error::InvalidValue.into());
        }

        let host = self.stack.host;
        // Ensure no other connect ongoing.
        let _drop = crate::host::OnDrop::new(|| {
            host.connect_command_state.cancel(true);
        });
        host.connect_command_state.request().await;

        self.set_accept_filter(config.scan_config.filter_accept_list).await?;

        let initiating = InitiatingPhy {
            scan_interval: config.scan_config.interval.into(),
            scan_window: config.scan_config.window.into(),
            conn_interval_min: config.connect_params.min_connection_interval.into(),
            conn_interval_max: config.connect_params.max_connection_interval.into(),
            max_latency: config.connect_params.max_latency,
            supervision_timeout: config.connect_params.supervision_timeout.into(),
            min_ce_len: config.connect_params.event_length.into(),
            max_ce_len: config.connect_params.event_length.into(),
        };
        let phy_params = Self::create_phy_params(initiating, config.scan_config.phys);

        host.async_command(LeExtCreateConn::new(
            true,
            host.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
            AddrKind::PUBLIC,
            BdAddr::default(),
            phy_params,
        ))
        .await?;

        match select(
            host.connections
                .accept(LeConnRole::Central, config.scan_config.filter_accept_list),
            host.connect_command_state.wait_idle(),
        )
        .await
        {
            Either::First(conn) => {
                _drop.defuse();
                host.connect_command_state.done();
                Ok(conn)
            }
            Either::Second(_) => Err(Error::Timeout.into()),
        }
    }

    fn create_phy_params<P: Copy>(phy: P, phys: PhySet) -> PhyParams<P> {
        let phy_params: PhyParams<P> = PhyParams {
            le_1m_phy: match phys {
                PhySet::M1 | PhySet::M1M2 | PhySet::M1Coded | PhySet::M1M2Coded => Some(phy),
                _ => None,
            },
            le_2m_phy: match phys {
                PhySet::M2 | PhySet::M1M2 | PhySet::M2Coded | PhySet::M1M2Coded => Some(phy),
                _ => None,
            },
            le_coded_phy: match phys {
                PhySet::M2Coded | PhySet::Coded | PhySet::M1Coded | PhySet::M1M2Coded => Some(phy),
                _ => None,
            },
        };
        phy_params
    }

    pub(crate) async fn set_accept_filter(
        &mut self,
        filter_accept_list: &[(AddrKind, &BdAddr)],
    ) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeClearFilterAcceptList> + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        let host = self.stack.host;
        host.command(LeClearFilterAcceptList::new()).await?;
        for entry in filter_accept_list {
            host.command(LeAddDeviceToFilterAcceptList::new(entry.0, *entry.1))
                .await?;
        }
        Ok(())
    }

    #[cfg(feature = "scan")]
    async fn start_scan(&mut self, config: &ScanConfig<'_>) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeSetScanParams>
            + ControllerCmdSync<LeSetScanEnable>
            + ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        let host = self.stack.host;
        self.set_accept_filter(config.filter_accept_list).await?;

        let params = LeSetScanParams::new(
            if config.active {
                bt_hci::param::LeScanKind::Active
            } else {
                bt_hci::param::LeScanKind::Passive
            },
            config.interval.into(),
            config.interval.into(),
            bt_hci::param::AddrKind::PUBLIC,
            if config.filter_accept_list.is_empty() {
                bt_hci::param::ScanningFilterPolicy::BasicUnfiltered
            } else {
                bt_hci::param::ScanningFilterPolicy::BasicFiltered
            },
        );
        host.command(params).await?;
        host.command(LeSetScanEnable::new(true, true)).await?;
        Ok(())
    }

    async fn start_scan_ext(&mut self, config: &ScanConfig<'_>) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeSetExtScanEnable>
            + ControllerCmdSync<LeSetExtScanParams>
            + ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        self.set_accept_filter(config.filter_accept_list).await?;

        let scanning = ScanningPhy {
            active_scan: config.active,
            scan_interval: config.interval.into(),
            scan_window: config.window.into(),
        };
        let phy_params = Self::create_phy_params(scanning, config.phys);
        let host = self.stack.host;
        host.command(LeSetExtScanParams::new(
            host.address.map(|s| s.kind).unwrap_or(AddrKind::PUBLIC),
            if config.filter_accept_list.is_empty() {
                bt_hci::param::ScanningFilterPolicy::BasicUnfiltered
            } else {
                bt_hci::param::ScanningFilterPolicy::BasicFiltered
            },
            phy_params,
        ))
        .await?;
        host.command(LeSetExtScanEnable::new(
            true,
            FilterDuplicates::Disabled,
            config.timeout.into(),
            bt_hci::param::Duration::from_secs(0),
        ))
        .await?;
        Ok(())
    }

    async fn stop_scan(&mut self) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeSetScanEnable>,
    {
        let host = self.stack.host;
        host.command(LeSetScanEnable::new(false, false)).await?;
        Ok(())
    }

    async fn stop_scan_ext(&mut self) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeSetExtScanEnable>,
    {
        let host = self.stack.host;
        host.command(LeSetExtScanEnable::new(
            false,
            FilterDuplicates::Disabled,
            bt_hci::param::Duration::from_secs(0),
            bt_hci::param::Duration::from_secs(0),
        ))
        .await?;
        Ok(())
    }

    /// Performs an extended BLE scan, return a report for discovering peripherals.
    ///
    /// Scan is stopped when a report is received. Call this method repeatedly to continue scanning.
    #[cfg(feature = "scan")]
    pub async fn scan_ext(&mut self, config: &ScanConfig<'_>) -> Result<ScanReport, BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeSetExtScanEnable>
            + ControllerCmdSync<LeSetExtScanParams>
            + ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        let host = self.stack.host;
        self.start_scan_ext(config).await?;
        let Some(report) = host.scanner.receive().await else {
            return Err(Error::Timeout.into());
        };
        self.stop_scan_ext().await?;
        Ok(report)
    }

    /// Performs a BLE scan, return a report for discovering peripherals.
    ///
    /// Scan is stopped when a report is received. Call this method repeatedly to continue scanning.
    #[cfg(feature = "scan")]
    pub async fn scan(&mut self, config: &ScanConfig<'_>) -> Result<ScanReport, BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeSetScanParams>
            + ControllerCmdSync<LeSetScanEnable>
            + ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        let host = self.stack.host;
        self.start_scan(config).await?;
        let Some(report) = host.scanner.receive().await else {
            return Err(Error::Timeout.into());
        };
        self.stop_scan().await?;
        Ok(report)
    }
}
