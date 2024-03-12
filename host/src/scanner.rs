use bt_hci::{
    param::{LeAdvReports, RemainingBytes},
    FromHciBytes,
};
use embassy_sync::channel::DynamicReceiver;
use heapless::Vec;

pub struct Scanner<'d> {
    data: Vec<u8, 255>,
    reports: DynamicReceiver<'d, ScanReports>,
}

impl<'d> Scanner<'d> {
    pub(crate) fn new(reports: DynamicReceiver<'d, ScanReports>) -> Self {
        Self {
            data: Vec::new(),
            reports,
        }
    }

    pub async fn next(&mut self) -> LeAdvReports {
        let next = self.reports.receive().await;
        self.data = next.reports;
        let (bytes, _) = RemainingBytes::from_hci_bytes(&self.data).unwrap();
        LeAdvReports {
            num_reports: next.num_reports,
            bytes,
        }
    }
}

pub struct ScanReports {
    pub(crate) num_reports: u8,
    pub(crate) reports: Vec<u8, 255>,
}
