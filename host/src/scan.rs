//! Scan config.
use core::future::Future;

use bt_hci::cmd::le::{
    LeAddDeviceToFilterAcceptList, LeClearFilterAcceptList, LeSetExtScanEnable, LeSetExtScanParams, LeSetScanEnable,
    LeSetScanParams,
};
use bt_hci::controller::{Controller, ControllerCmdSync};
use bt_hci::param::{FilterDuplicates, ScanningPhy};
pub use bt_hci::param::{LeAdvReportsIter, LeExtAdvReportsIter};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::Instant;

use crate::command::CommandState;
use crate::connection::ScanConfig;
use crate::{bt_hci_duration, BleHostError, Central, PacketPool};

/// A scanner that wraps a central to provide additional functionality
/// around BLE scanning.
///
/// The buffer size can be tuned if in a noisy environment that
/// returns a lot of results.
pub struct Scanner<'d, 'stack, C: Controller, P: PacketPool> {
    central: &'d mut Central<'stack, C, P>,
}

impl<'d, 'stack, C: Controller, P: PacketPool> Scanner<'d, 'stack, C, P> {
    /// Create a new scanner with the provided central.
    pub fn new(central: &'d mut Central<'stack, C, P>) -> Self {
        Self { central }
    }

    /// Performs an extended BLE scan, return a report for discovering peripherals.
    ///
    /// Scan is stopped when a report is received. Call this method repeatedly to continue scanning.
    pub async fn scan_ext(
        &mut self,
        config: &ScanConfig<'_>,
    ) -> Result<ScanSession<'stack, true>, BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeSetExtScanEnable>
            + ControllerCmdSync<LeSetExtScanParams>
            + ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        let host = &self.central.host;
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
        let host = &self.central.host;
        host.command(LeSetExtScanParams::new(
            host.own_addr_kind(),
            if config.filter_accept_list.is_empty() {
                bt_hci::param::ScanningFilterPolicy::BasicUnfiltered
            } else {
                bt_hci::param::ScanningFilterPolicy::BasicFiltered
            },
            phy_params,
        ))
        .await?;

        host.scan_timeout.reset();
        host.command(LeSetExtScanEnable::new(
            true,
            config.filter_duplicates,
            bt_hci_duration(config.timeout),
            bt_hci::param::Duration::from_secs(0),
        ))
        .await?;
        drop.defuse();
        Ok(ScanSession {
            command_state: &self.central.host.scan_command_state,
            deadline: if config.timeout.as_ticks() == 0 {
                None
            } else {
                Some(Instant::now() + config.timeout)
            },
            timeout: &host.scan_timeout,
            done: false,
        })
    }

    /// Performs a BLE scan, return a report for discovering peripherals.
    ///
    /// Scan is stopped when a report is received. Call this method repeatedly to continue scanning.
    pub async fn scan(&mut self, config: &ScanConfig<'_>) -> Result<ScanSession<'stack, false>, BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeSetScanParams>
            + ControllerCmdSync<LeSetScanEnable>
            + ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        let host = self.central.host;
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
            host.own_addr_kind(),
            if config.filter_accept_list.is_empty() {
                bt_hci::param::ScanningFilterPolicy::BasicUnfiltered
            } else {
                bt_hci::param::ScanningFilterPolicy::BasicFiltered
            },
        );
        host.command(params).await?;

        let filter_duplicates = !matches!(config.filter_duplicates, FilterDuplicates::Disabled);
        host.command(LeSetScanEnable::new(true, filter_duplicates)).await?;
        drop.defuse();
        Ok(ScanSession {
            command_state: &self.central.host.scan_command_state,
            deadline: if config.timeout.as_ticks() == 0 {
                None
            } else {
                Some(Instant::now() + config.timeout)
            },
            timeout: &host.scan_timeout,
            done: false,
        })
    }
}

/// Handle to an active advertiser which can accept connections.
pub struct ScanSession<'d, const EXTENDED: bool> {
    command_state: &'d CommandState<bool>,
    deadline: Option<Instant>,
    timeout: &'d Signal<NoopRawMutex, ()>,
    done: bool,
}

impl<const EXTENDED: bool> Drop for ScanSession<'_, EXTENDED> {
    fn drop(&mut self) {
        self.command_state.cancel(EXTENDED);
    }
}

impl<'d> Future for ScanSession<'d, true> {
    type Output = ();

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        let this = self.get_mut();
        core::pin::pin!(this.timeout.wait()).poll(cx)
    }
}
