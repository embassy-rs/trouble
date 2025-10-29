//! Scan config.
use bt_hci::cmd::le::{
    LeAddDeviceToFilterAcceptList, LeClearFilterAcceptList, LeSetExtScanEnable, LeSetExtScanParams, LeSetScanEnable,
    LeSetScanParams,
};
use bt_hci::controller::{Controller, ControllerCmdSync};
use bt_hci::param::{AddrKind, FilterDuplicates, ScanningPhy};
pub use bt_hci::param::{LeAdvReportsIter, LeExtAdvReportsIter};
use embassy_time::Instant;

use crate::command::CommandState;
use crate::connection::ScanConfig;
use crate::{bt_hci_duration, BleHostError, Central, PacketPool};

/// A scanner that wraps a central to provide additional functionality
/// around BLE scanning.
///
/// The buffer size can be tuned if in a noisy environment that
/// returns a lot of results.
pub struct Scanner<'d, C: Controller, P: PacketPool> {
    central: Central<'d, C, P>,
}

impl<'d, C: Controller, P: PacketPool> Scanner<'d, C, P> {
    /// Create a new scanner with the provided central.
    pub fn new(central: Central<'d, C, P>) -> Self {
        Self { central }
    }

    /// Retrieve the underlying central
    pub fn into_inner(self) -> Central<'d, C, P> {
        self.central
    }

    /// Performs an extended BLE scan, return a report for discovering peripherals.
    ///
    /// Scan is stopped when a report is received. Call this method repeatedly to continue scanning.
    pub async fn scan_ext(&mut self, config: &ScanConfig<'_>) -> Result<ScanSession<'_, true>, BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeSetExtScanEnable>
            + ControllerCmdSync<LeSetExtScanParams>
            + ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        let host = &self.central.stack.host;
        let drop = crate::host::OnDrop::new(|| {
            host.scan_command_state.cancel(true);
        });
        host.scan_command_state.request().await;
        self.central.set_accept_filter(config.filter_accept_list).await?;

        let scanning = ScanningPhy {
            active_scan: config.active,
            scan_interval: bt_hci_duration(config.interval),
            scan_window: bt_hci_duration(config.window),
        };
        let phy_params = crate::central::create_phy_params(scanning, config.phys);
        let host = &self.central.stack.host;
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
            bt_hci_duration(config.timeout),
            bt_hci::param::Duration::from_secs(0),
        ))
        .await?;
        drop.defuse();
        Ok(ScanSession {
            command_state: &self.central.stack.host.scan_command_state,
            deadline: if config.timeout.as_ticks() == 0 {
                None
            } else {
                Some(Instant::now() + config.timeout)
            },
            done: false,
        })
    }

    /// Performs a BLE scan, return a report for discovering peripherals.
    ///
    /// Scan is stopped when a report is received. Call this method repeatedly to continue scanning.
    pub async fn scan(&mut self, config: &ScanConfig<'_>) -> Result<ScanSession<'_, false>, BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeSetScanParams>
            + ControllerCmdSync<LeSetScanEnable>
            + ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        let host = &self.central.stack.host;
        let drop = crate::host::OnDrop::new(|| {
            host.scan_command_state.cancel(false);
        });
        host.scan_command_state.request().await;

        self.central.set_accept_filter(config.filter_accept_list).await?;

        let params = LeSetScanParams::new(
            if config.active {
                bt_hci::param::LeScanKind::Active
            } else {
                bt_hci::param::LeScanKind::Passive
            },
            bt_hci_duration(config.interval),
            bt_hci_duration(config.window),
            host.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
            if config.filter_accept_list.is_empty() {
                bt_hci::param::ScanningFilterPolicy::BasicUnfiltered
            } else {
                bt_hci::param::ScanningFilterPolicy::BasicFiltered
            },
        );
        host.command(params).await?;

        host.command(LeSetScanEnable::new(true, true)).await?;
        drop.defuse();
        Ok(ScanSession {
            command_state: &self.central.stack.host.scan_command_state,
            deadline: if config.timeout.as_ticks() == 0 {
                None
            } else {
                Some(Instant::now() + config.timeout)
            },
            done: false,
        })
    }
}

/// Handle to an active advertiser which can accept connections.
pub struct ScanSession<'d, const EXTENDED: bool> {
    command_state: &'d CommandState<bool>,
    deadline: Option<Instant>,
    done: bool,
}

impl<const EXTENDED: bool> Drop for ScanSession<'_, EXTENDED> {
    fn drop(&mut self) {
        self.command_state.cancel(EXTENDED);
    }
}
