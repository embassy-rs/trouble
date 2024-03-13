use bt_hci::{
    cmd::{
        le::{LeSetScanEnable, LeSetScanParams},
        SyncCmd,
    },
    param::{LeAdvReports, RemainingBytes},
    ControllerCmdSync, FromHciBytes,
};
use embassy_sync::{blocking_mutex::raw::RawMutex, channel::DynamicReceiver};
use heapless::Vec;

use crate::{adapter::Adapter, Error};

pub struct ScanConfig {
    pub params: Option<LeSetScanParams>,
}

pub struct Scanner<'d> {
    config: ScanConfig,
    data: Vec<u8, 255>,
    reports: DynamicReceiver<'d, ScanReports>,
}

impl<'d> Scanner<'d> {
    pub(crate) fn new(config: ScanConfig, reports: DynamicReceiver<'d, ScanReports>) -> Self {
        Self {
            config,
            data: Vec::new(),
            reports,
        }
    }

    pub async fn scan<
        'm,
        M,
        T,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        &mut self,
        adapter: &'m Adapter<'_, M, T, CONNS, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
    ) -> Result<LeAdvReports<'_>, Error<T::Error>>
    where
        M: RawMutex,
        T: ControllerCmdSync<LeSetScanEnable> + ControllerCmdSync<LeSetScanParams>,
    {
        let params = &self.config.params.unwrap_or(LeSetScanParams::new(
            bt_hci::param::LeScanKind::Passive,
            bt_hci::param::Duration::from_millis(1_000),
            bt_hci::param::Duration::from_millis(1_000),
            bt_hci::param::AddrKind::PUBLIC,
            bt_hci::param::ScanningFilterPolicy::BasicUnfiltered,
        ));
        params.exec(&adapter.controller).await?;

        LeSetScanEnable::new(true, true).exec(&adapter.controller).await?;

        let next = self.reports.receive().await;
        self.data = next.reports;
        let (bytes, _) = RemainingBytes::from_hci_bytes(&self.data).unwrap();
        let reports = LeAdvReports {
            num_reports: next.num_reports,
            bytes,
        };

        LeSetScanEnable::new(false, false).exec(&adapter.controller).await?;
        Ok(reports)
    }
}

pub struct ScanReports {
    pub(crate) num_reports: u8,
    pub(crate) reports: Vec<u8, 255>,
}
