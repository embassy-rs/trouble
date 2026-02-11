use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::pipe::Pipe;

static PIPE: Pipe<CriticalSectionRawMutex, 4096> = Pipe::new();

/// Read encoded defmt frames from the internal pipe.
/// Called by the USB drain task.
pub async fn read(buf: &mut [u8]) -> usize {
    PIPE.read(buf).await
}

/// Writes encoded bytes into the pipe, discarding complete frames on overflow.
///
/// When the pipe is full, discards bytes up through the next 0x00 frame
/// delimiter so the receiver stays aligned to frame boundaries.
fn write_to_pipe(data: &[u8]) {
    let mut remaining = data;
    while !remaining.is_empty() {
        match PIPE.try_write(remaining) {
            Ok(written) => {
                remaining = &remaining[written..];
            }
            Err(_) => {
                // Discard one complete frame: read until we consume a 0x00 delimiter.
                let mut byte = 0u8;
                while PIPE.try_read(core::slice::from_mut(&mut byte)).is_ok() {
                    if byte == 0 {
                        break;
                    }
                }
            }
        }
    }
}

struct UsbLogger {
    /// Nesting depth. 0 = idle, 1 = active, >1 = reentrant (suppressed).
    /// MPSL's critical-section impl leaves high-priority radio interrupts
    /// (RADIO, TIMER0, RTC0) enabled, so their handlers can preempt a
    /// task-level log in progress. We use a counter instead of panicking
    /// to silently drop reentrant log frames.
    nesting: AtomicU8,
    cs_restore: UnsafeCell<critical_section::RestoreState>,
    encoder: UnsafeCell<defmt::Encoder>,
}

unsafe impl Sync for UsbLogger {}

impl UsbLogger {
    const fn new() -> Self {
        Self {
            nesting: AtomicU8::new(0),
            cs_restore: UnsafeCell::new(critical_section::RestoreState::invalid()),
            encoder: UnsafeCell::new(defmt::Encoder::new()),
        }
    }

    fn acquire(&self) {
        if self.nesting.fetch_add(1, Ordering::Acquire) > 0 {
            // Reentrant call from a higher-priority interrupt — suppress this frame.
            return;
        }
        let restore = unsafe { critical_section::acquire() };
        unsafe {
            self.cs_restore.get().write(restore);
            (*self.encoder.get()).start_frame(write_to_pipe);
        }
    }

    unsafe fn release(&self) {
        if self.nesting.fetch_sub(1, Ordering::Release) > 1 {
            // Reentrant release — nothing to clean up.
            return;
        }
        unsafe { (*self.encoder.get()).end_frame(write_to_pipe) };
        let restore = unsafe { self.cs_restore.get().read() };
        unsafe { critical_section::release(restore) };
    }

    unsafe fn write(&self, bytes: &[u8]) {
        if self.nesting.load(Ordering::Relaxed) > 1 {
            return;
        }
        unsafe { (*self.encoder.get()).write(bytes, write_to_pipe) };
    }
}

static LOGGER: UsbLogger = UsbLogger::new();

#[defmt::global_logger]
struct Logger;

unsafe impl defmt::Logger for Logger {
    fn acquire() {
        LOGGER.acquire();
    }

    unsafe fn release() {
        unsafe { LOGGER.release() };
    }

    unsafe fn write(bytes: &[u8]) {
        unsafe { LOGGER.write(bytes) };
    }

    unsafe fn flush() {
        // no-op: flushing happens in the async USB drain task
    }
}
