use core::iter::FusedIterator;

use bt_hci::{
    cmd::le::LeSetScanParams,
    param::{AddrKind, BdAddr, LeAdvReport},
    FromHciBytes, FromHciBytesError,
};
use heapless::Vec;

pub struct ScanConfig<'d> {
    pub params: Option<LeSetScanParams>,
    pub filter_accept_list: &'d [(AddrKind, &'d BdAddr)],
}

pub struct ScanReport {
    num_reports: u8,
    reports: Vec<u8, 255>,
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
