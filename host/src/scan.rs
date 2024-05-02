//! Scan config.
use core::iter::FusedIterator;

use bt_hci::param::{AddrKind, BdAddr, LeAdvReport, LeExtAdvReport};
use bt_hci::{FromHciBytes, FromHciBytesError};
use embassy_time::Duration;
use heapless::Vec;

pub struct ScanConfig<'d> {
    pub active: bool,
    pub filter_accept_list: &'d [(AddrKind, &'d BdAddr)],
    pub phys: PhySet,
    pub interval: Duration,
    pub window: Duration,
    pub timeout: Duration,
}

impl<'d> Default for ScanConfig<'d> {
    fn default() -> Self {
        Self {
            active: true,
            filter_accept_list: &[],
            phys: PhySet::M1,
            interval: Duration::from_secs(1),
            window: Duration::from_secs(1),
            timeout: Duration::from_secs(0),
        }
    }
}

pub struct ScanReport {
    num_reports: u8,
    reports: Vec<u8, 255>,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum PhySet {
    /// 1Mbps phy
    M1 = 1,
    /// 2Mbps phy
    M2 = 2,
    /// 1Mbps + 2Mbps phys
    M1M2 = 3,
    /// Coded phy (125kbps, S=8)
    Coded = 4,
    /// 1Mbps and Coded phys
    M1Coded = 5,
    /// 2Mbps and Coded phys
    M2Coded = 6,
    /// 1Mbps, 2Mbps and Coded phys
    M1M2Coded = 7,
}

impl ScanReport {
    pub(crate) fn new(num_reports: u8, reports: &[u8]) -> Self {
        Self {
            num_reports,
            reports: Vec::from_slice(reports).unwrap(),
        }
    }

    pub fn iter(&self) -> ScanReportIter<'_> {
        ScanReportIter {
            len: self.num_reports as usize,
            bytes: &self.reports,
        }
    }

    pub fn iter_ext(&self) -> ExtScanReportIter<'_> {
        ExtScanReportIter {
            len: self.num_reports as usize,
            bytes: &self.reports,
        }
    }
}

pub struct ScanReportIter<'a> {
    len: usize,
    bytes: &'a [u8],
}

impl<'a> Iterator for ScanReportIter<'a> {
    type Item = Result<LeAdvReport<'a>, FromHciBytesError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.len == 0 {
            None
        } else {
            match LeAdvReport::from_hci_bytes(self.bytes) {
                Ok((report, rest)) => {
                    self.bytes = rest;
                    self.len -= 1;
                    Some(Ok(report))
                }
                Err(err) => {
                    self.len = 0;
                    Some(Err(err))
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len, Some(self.len))
    }
}

impl<'a> ExactSizeIterator for ScanReportIter<'a> {
    fn len(&self) -> usize {
        self.len
    }
}

impl<'a> FusedIterator for ScanReportIter<'a> {}

pub struct ExtScanReportIter<'a> {
    len: usize,
    bytes: &'a [u8],
}

impl<'a> Iterator for ExtScanReportIter<'a> {
    type Item = Result<LeExtAdvReport<'a>, FromHciBytesError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.len == 0 {
            None
        } else {
            match LeExtAdvReport::from_hci_bytes(self.bytes) {
                Ok((report, rest)) => {
                    self.bytes = rest;
                    self.len -= 1;
                    Some(Ok(report))
                }
                Err(err) => {
                    self.len = 0;
                    Some(Err(err))
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len, Some(self.len))
    }
}

impl<'a> ExactSizeIterator for ExtScanReportIter<'a> {
    fn len(&self) -> usize {
        self.len
    }
}

impl<'a> FusedIterator for ExtScanReportIter<'a> {}
