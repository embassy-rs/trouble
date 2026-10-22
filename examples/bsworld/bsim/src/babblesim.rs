//! BabbleSim FIFO clock participant. No simulated radio is needed in the Host.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::Clock;

const WAIT: u32 = 0x01;
const WAIT_END: u32 = 0x81;
const DISCONNECT: u32 = 0xffff;
const WATCHDOG: Duration = Duration::from_secs(30);

/// A Host participating directly in BabbleSim's device scheduling protocol.
pub struct BabbleSim {
    now_us: u64,
    reader: Option<File>,
    writer: Option<File>,
    lock: PathBuf,
}

impl BabbleSim {
    /// Register a reserved device ID and open its PHY FIFOs.
    /// `sim_dir` is BabbleSim's existing simulation directory, normally
    /// `/tmp/bs_USER/SIM_ID`; `phy_id` is normally `2G4`.
    /// Wall time is used only for startup and stalled-PHY watchdogs.
    pub fn connect(sim_dir: impl AsRef<Path>, phy_id: &str, dev_id: u32) -> io::Result<Self> {
        if phy_id.is_empty() || phy_id.contains('/') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid PHY id"));
        }
        let path = |suffix| sim_dir.as_ref().join(format!("{phy_id}.d{dev_id}.{suffix}"));
        let lock = path("lock");
        let mut registration = OpenOptions::new().write(true).create_new(true).open(&lock)?;
        let mut clock = Self {
            now_us: 0,
            reader: None,
            writer: None,
            lock,
        };
        let stat = fs::read_to_string("/proc/self/stat")?;
        let start = stat
            .rsplit_once(')')
            .and_then(|(_, fields)| fields.split_whitespace().nth(19))
            .ok_or_else(|| io::Error::other("invalid process start time"))?;
        writeln!(registration, "{}\n{start}", std::process::id())?;
        drop(registration);

        let deadline = Instant::now() + WATCHDOG;
        loop {
            let result: io::Result<()> = (|| {
                if clock.reader.is_none() {
                    clock.reader = Some(open_fifo(&path("ptd"), false)?);
                }
                clock.writer = Some(open_fifo(&path("dtp"), true)?);
                Ok(())
            })();
            match result {
                Ok(()) => return Ok(clock),
                Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENXIO)) => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "PHY FIFOs did not open"));
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(error),
            }
        }
    }
}

impl Clock for BabbleSim {
    fn now_us(&self) -> u64 {
        self.now_us
    }

    fn wait_until(&mut self, target_us: u64) -> io::Result<()> {
        if target_us < self.now_us || target_us == u64::MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid PHY wait target"));
        }
        // BabbleSim uses native-endian uint32 headers followed by packed uint64 times.
        let mut request = [0; 12];
        request[..4].copy_from_slice(&WAIT.to_ne_bytes());
        request[4..].copy_from_slice(&target_us.to_ne_bytes());
        let deadline = Instant::now() + WATCHDOG;
        let writer = self.writer.as_mut().unwrap();
        let mut written = 0;
        while written < request.len() {
            match writer.write(&request[written..]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "PHY write stalled")),
                Ok(count) => written += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => wait_io(writer, libc::POLLOUT, deadline)?,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        let reader = self.reader.as_mut().unwrap();
        let mut response = [0; 4];
        let mut received = 0;
        while received < response.len() {
            wait_io(reader, libc::POLLIN, deadline)?;
            match reader.read(&mut response[received..]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "PHY disconnected")),
                Ok(count) => received += count,
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        match u32::from_ne_bytes(response) {
            WAIT_END => self.now_us = target_us,
            DISCONNECT => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "PHY disconnected")),
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid PHY wait response")),
        }
        Ok(())
    }
}

impl Drop for BabbleSim {
    fn drop(&mut self) {
        if let Some(writer) = self.writer.as_mut() {
            let _ = writer.write(&DISCONNECT.to_ne_bytes());
        }
        let _ = fs::remove_file(&self.lock);
    }
}

fn open_fifo(path: &Path, write: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(!write)
        .write(write)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.file_type().is_fifo() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "PHY path is not a FIFO"));
    }
    Ok(file)
}

fn wait_io(file: &File, events: i16, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "PHY watchdog expired"));
        }
        let mut fd = libc::pollfd {
            fd: file.as_raw_fd(),
            events,
            revents: 0,
        };
        let timeout = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        // SAFETY: fd points to one initialized pollfd for the duration of poll.
        let count = unsafe { libc::poll(&mut fd, 1, timeout) };
        if count > 0 {
            return Ok(());
        }
        if count < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
}
