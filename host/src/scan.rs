//! Scan config.
use crate::central::ScanConfig;
use crate::command::CommandState;
use crate::host::ScanState;
use crate::BleHostError;
use crate::Error;
use bt_hci::cmd::le::LeSetScanParams;
use bt_hci::cmd::le::{
    LeAddDeviceToFilterAcceptList, LeClearFilterAcceptList, LeSetExtScanEnable, LeSetExtScanParams, LeSetScanEnable,
};
use bt_hci::controller::{Controller, ControllerCmdSync};
use bt_hci::param::{AddrKind, FilterDuplicates, LeAdvReport, LeExtAdvReport, ScanningPhy};
use bt_hci::FromHciBytes;
use embassy_futures::yield_now;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::pipe::DynamicWriter;
use embassy_sync::pipe::{DynamicReader, Pipe};
use embassy_time::with_deadline;
use embassy_time::Instant;

use crate::Central;

/// A scanner that wraps a central to provide additional functionality
/// around BLE scanning.
///
/// The buffer size can be tuned if in a noisy environment that
/// returns a lot of results.
pub struct Scanner<'d, C: Controller, const BUFFER_SIZE: usize> {
    buffer: Pipe<NoopRawMutex, BUFFER_SIZE>,
    central: Central<'d, C>,
}

impl<'d, C: Controller, const BUFFER_SIZE: usize> Scanner<'d, C, BUFFER_SIZE> {
    /// Create a new scanner with the provided central.
    pub fn new(central: Central<'d, C>) -> Self {
        Self {
            central,
            buffer: Pipe::new(),
        }
    }

    /// Retrieve the underlying central
    pub fn into_inner(self) -> Central<'d, C> {
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
        let host = self.central.stack.host;
        let drop = crate::host::OnDrop::new(|| {
            host.scan_command_state.cancel(false);
            host.scan_state.stop();
        });
        host.scan_command_state.request().await;
        self.central.set_accept_filter(config.filter_accept_list).await?;

        let scanning = ScanningPhy {
            active_scan: config.active,
            scan_interval: config.interval.into(),
            scan_window: config.window.into(),
        };
        let phy_params = crate::central::create_phy_params(scanning, config.phys);
        let host = self.central.stack.host;
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

        self.buffer.clear();
        let (reader, writer) = self.buffer.split();
        let writer: DynamicWriter<'_> = writer.into();
        // Safety: writer and reader is dropped by this or scan session
        let writer = unsafe { core::mem::transmute(writer) };
        self.central.stack.host.scan_state.reset(writer);

        host.command(LeSetExtScanEnable::new(
            true,
            FilterDuplicates::Disabled,
            config.timeout.into(),
            bt_hci::param::Duration::from_secs(0),
        ))
        .await?;
        drop.defuse();
        Ok(ScanSession {
            reader: reader.into(),
            command_state: &self.central.stack.host.scan_command_state,
            scan_state: &self.central.stack.host.scan_state,
            deadline: if config.timeout.as_ticks() == 0 {
                None
            } else {
                Some(Instant::now() + config.timeout.into())
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
        let host = self.central.stack.host;
        let drop = crate::host::OnDrop::new(|| {
            host.scan_command_state.cancel(false);
            host.scan_state.stop();
        });
        host.scan_command_state.request().await;

        self.central.set_accept_filter(config.filter_accept_list).await?;

        let params = LeSetScanParams::new(
            if config.active {
                bt_hci::param::LeScanKind::Active
            } else {
                bt_hci::param::LeScanKind::Passive
            },
            config.interval.into(),
            config.interval.into(),
            host.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
            if config.filter_accept_list.is_empty() {
                bt_hci::param::ScanningFilterPolicy::BasicUnfiltered
            } else {
                bt_hci::param::ScanningFilterPolicy::BasicFiltered
            },
        );
        host.command(params).await?;

        self.buffer.clear();
        let (reader, writer) = self.buffer.split();
        // Safety: writer and reader is dropped before we are permitted to create a reader again.
        let writer: DynamicWriter<'_> = writer.into();
        let writer = unsafe { core::mem::transmute(writer) };
        self.central.stack.host.scan_state.reset(writer);

        host.command(LeSetScanEnable::new(true, true)).await?;
        drop.defuse();
        Ok(ScanSession {
            reader: reader.into(),
            command_state: &self.central.stack.host.scan_command_state,
            scan_state: &self.central.stack.host.scan_state,
            deadline: if config.timeout.as_ticks() == 0 {
                None
            } else {
                Some(Instant::now() + config.timeout.into())
            },
            done: false,
        })
    }
}

/// Handle to an active advertiser which can accept connections.
pub struct ScanSession<'d, const EXTENDED: bool> {
    reader: DynamicReader<'d>,
    scan_state: &'d ScanState,
    command_state: &'d CommandState<bool>,
    deadline: Option<Instant>,
    done: bool,
}

impl<'d> ScanSession<'d, false> {
    /// Process the advertising reports in the provided closure.
    pub async fn process(&mut self, mut f: impl FnMut(LeAdvReport)) -> Result<(), Error> {
        self.do_process(|data| {
            let mut remaining = data;
            loop {
                match LeAdvReport::from_hci_bytes(remaining) {
                    Ok((report, rest)) => {
                        f(report);
                        remaining = rest;
                    }
                    Err(err) => {
                        //warn!("[scan] error: {:?}, available {}", err, data.len());
                        break;
                    }
                }
            }
            remaining
        })
        .await
    }
}

impl<'d> ScanSession<'d, true> {
    /// Process the advertising reports in the provided closure.
    pub async fn process(&mut self, mut f: impl FnMut(LeExtAdvReport)) -> Result<(), Error> {
        self.do_process(|data| {
            let mut remaining = data;
            loop {
                match LeExtAdvReport::from_hci_bytes(remaining) {
                    Ok((report, rest)) => {
                        f(report);
                        remaining = rest;
                    }
                    Err(err) => {
                        //warn!("[scan] error: {:?}, available {}", err, data.len());
                        break;
                    }
                }
            }
            remaining
        })
        .await
    }
}

impl<const EXTENDED: bool> ScanSession<'_, EXTENDED> {
    async fn do_process(&mut self, mut f: impl FnMut(&[u8]) -> &[u8]) -> Result<(), Error> {
        let process_fut = async {
            loop {
                let data = self.reader.fill_buf().await;
                let remaining = f(data);
                let consumed = data.len() - remaining.len();
                self.reader.consume(consumed);
                yield_now().await;
            }
        };
        if let Some(deadline) = self.deadline {
            let r = with_deadline(deadline, process_fut).await.map_err(|_| Error::Timeout);
            self.command_state.cancel(EXTENDED);
            self.done = true;
            r
        } else {
            process_fut.await;
            self.command_state.cancel(EXTENDED);
            self.done = true;
            Ok(())
        }
    }
}

impl<const EXTENDED: bool> Drop for ScanSession<'_, EXTENDED> {
    fn drop(&mut self) {
        if !self.done {
            self.command_state.cancel(EXTENDED);
        }
        self.scan_state.stop();
    }
}
