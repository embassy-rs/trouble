use std::collections::BTreeMap;
use std::fmt::Write;
use std::io::Cursor;
use std::time::Duration;

use super::Firmware;
use anyhow::{anyhow, bail};
use defmt_decoder::{DecodeError, Location, StreamDecoder, Table};
use log::info;
use object::read::{File as ElfFile, Object as _};
use object::ObjectSymbol;
use probe_rs::debug::{DebugInfo, DebugRegisters};
use probe_rs::flashing::{DownloadOptions, Format};
use probe_rs::rtt::{Rtt, ScanRegion};
use probe_rs::{Core, MemoryInterface, Session};
use tokio::sync::oneshot;

const THUMB_BIT: u32 = 1;
const TIMEOUT: Duration = Duration::from_secs(1);

const POLL_SLEEP_MILLIS: u64 = 100;

pub(crate) struct Flasher {
    firmware: Firmware,
}

pub(crate) struct Runner {
    elf: Option<ElfRunner>,
}

struct ElfRunner {
    rtt: Rtt,
    di: DebugInfo,
    defmt_table: Box<Table>,
    defmt_locs: BTreeMap<u64, Location>,
    defmt_stream: Box<dyn StreamDecoder>,
}

unsafe fn fuck_it<'a, 'b, T>(wtf: &'a T) -> &'b T {
    std::mem::transmute(wtf)
}

impl Flasher {
    pub fn new(firmware: Firmware) -> Self {
        Self { firmware }
    }

    pub fn flash(&mut self, sess: &mut Session) -> anyhow::Result<()> {
        // reset ALL cores other than the main one.
        // This is needed for rp2040 core1.
        for (i, _) in sess.list_cores() {
            if i != 0 {
                sess.core(i)?.reset()?;
            }
        }

        sess.core(0)?.reset_and_halt(TIMEOUT)?;

        log::info!("flashing program...");
        let mut dopts = DownloadOptions::new();
        dopts.keep_unwritten_bytes = true;
        dopts.verify = true;

        let mut loader = sess.target().flash_loader();
        let instruction_set = sess.core(0)?.instruction_set().ok();
        loader.load_image(
            sess,
            &mut Cursor::new(&self.firmware.data),
            self.firmware.format.clone(),
            instruction_set,
        )?;
        loader.commit(sess, dopts)?;

        //flashing::download_file_with_options(sess, &opts.elf, Format::Elf, dopts)?;
        log::info!("flashing done!");

        Ok(())
    }

    pub(crate) fn start(&mut self, sess: &mut Session) -> anyhow::Result<Runner> {
        if self.firmware.format == Format::Elf {
            let elf_bytes = &self.firmware.data[..];
            let elf = ElfFile::parse(elf_bytes)?;
            let di = DebugInfo::from_raw(elf_bytes)?;

            let table = Box::new(defmt_decoder::Table::parse(elf_bytes)?.unwrap());
            let locs = table.get_locations(elf_bytes)?;
            if !table.is_empty() && locs.is_empty() {
                log::warn!("insufficient DWARF info; compile your program with `debug = 2` to enable location info");
            }

            let (rtt_addr, main_addr) = get_rtt_main_from(&elf)?;
            let rtt_addr = rtt_addr.ok_or_else(|| anyhow!("RTT is missing"))?;

            {
                let mut core = sess.core(0)?;

                core.reset_and_halt(TIMEOUT)?;

                log::debug!("starting device");
                if core.available_breakpoint_units()? == 0 {
                    bail!("RTT not supported on device without HW breakpoints");
                }

                // Corrupt the rtt control block so that it's setup fresh again
                // Only do this when running from flash, because when running from RAM the
                // "fake-flashing to RAM" is what initializes it.
                core.write_word_32(rtt_addr as _, 0xdeadc0de)?;

                // RTT control block is initialized pre-main. Run until main before
                // changing to BlockIfFull.
                core.set_hw_breakpoint(main_addr as _)?;
                core.run()?;
                core.wait_for_core_halted(Duration::from_secs(5))?;
                core.clear_hw_breakpoint(main_addr as _)?;

                const OFFSET: u32 = 44;
                const FLAG: u32 = 2; // BLOCK_IF_FULL
                core.write_word_32((rtt_addr + OFFSET) as _, FLAG)?;

                core.run()?;
            }

            let rtt = setup_logging_channel(rtt_addr as u64, sess)?;
            let defmt_stream = unsafe { fuck_it(&table) }.new_stream_decoder();

            Ok(Runner {
                elf: Some(ElfRunner {
                    defmt_table: table,
                    defmt_locs: locs,
                    rtt,
                    defmt_stream,
                    di,
                }),
            })
        } else {
            let mut core = sess.core(0)?;
            core.reset_and_halt(TIMEOUT)?;
            core.run()?;
            Ok(Runner { elf: None })
        }
    }
}

impl ElfRunner {
    fn poll(&mut self, sess: &mut Session) -> anyhow::Result<()> {
        let current_dir = std::env::current_dir()?;

        let mut read_buf = [0; 1024];
        let defmt = self
            .rtt
            .up_channel(0)
            .ok_or_else(|| anyhow!("RTT up channel 0 not found"))?;
        match defmt.read(&mut sess.core(0).unwrap(), &mut read_buf)? {
            0 => {
                // Sleep to reduce CPU usage when defmt didn't return any data.
                std::thread::sleep(Duration::from_millis(POLL_SLEEP_MILLIS));
                return Ok(());
            }
            n => self.defmt_stream.received(&read_buf[..n]),
        }

        loop {
            match self.defmt_stream.decode() {
                Ok(frame) => {
                    let loc = self.defmt_locs.get(&frame.index());

                    let (mut file, mut line) = (None, None);
                    if let Some(loc) = loc {
                        let relpath = if let Ok(relpath) = loc.file.strip_prefix(&current_dir) {
                            relpath
                        } else {
                            // not relative; use full path
                            &loc.file
                        };
                        file = Some(relpath.display().to_string());
                        line = Some(loc.line as u32);
                    };

                    let mut timestamp = String::new();
                    if let Some(ts) = frame.display_timestamp() {
                        timestamp = format!("{} ", ts);
                    }

                    log::logger().log(
                        &log::Record::builder()
                            .level(match frame.level() {
                                Some(level) => match level.as_str() {
                                    "trace" => log::Level::Trace,
                                    "debug" => log::Level::Debug,
                                    "info" => log::Level::Info,
                                    "warn" => log::Level::Warn,
                                    "error" => log::Level::Error,
                                    _ => log::Level::Error,
                                },
                                None => log::Level::Info,
                            })
                            .file(file.as_deref())
                            .line(line)
                            .target("device")
                            //.args(format_args!("{} {:?} {:?}", frame.display_message(), file, line))
                            .args(format_args!("{}{}", timestamp, frame.display_message()))
                            .build(),
                    );
                }
                Err(DecodeError::UnexpectedEof) => break,
                Err(DecodeError::Malformed) => match self.defmt_table.encoding().can_recover() {
                    // if recovery is impossible, abort
                    false => bail!("failed to decode defmt data"),
                    // if recovery is possible, skip the current frame and continue with new data
                    true => log::warn!("failed to decode defmt data"),
                },
            }
        }

        Ok(())
    }

    fn traceback(&mut self, core: &mut Core) -> anyhow::Result<()> {
        let mut r = [0; 17];
        for (i, val) in r.iter_mut().enumerate() {
            *val = core.read_core_reg::<u32>(i as u16)?;
        }
        info!(
            "  R0: {:08x}   R1: {:08x}   R2: {:08x}   R3: {:08x}",
            r[0], r[1], r[2], r[3],
        );
        info!(
            "  R4: {:08x}   R5: {:08x}   R6: {:08x}   R7: {:08x}",
            r[4], r[5], r[6], r[7],
        );
        info!(
            "  R8: {:08x}   R9: {:08x}  R10: {:08x}  R11: {:08x}",
            r[8], r[9], r[10], r[11],
        );
        info!(
            " R12: {:08x}   SP: {:08x}   LR: {:08x}   PC: {:08x}",
            r[12], r[13], r[14], r[15],
        );
        info!("XPSR: {:08x}", r[16]);

        info!("");
        info!("Stack:");
        let mut stack = [0u32; 32];
        core.read_32(r[13] as _, &mut stack)?;
        for i in 0..(stack.len() / 4) {
            info!(
                "{:08x}: {:08x} {:08x} {:08x} {:08x}",
                r[13] + i as u32 * 16,
                stack[i * 4 + 0],
                stack[i * 4 + 1],
                stack[i * 4 + 2],
                stack[i * 4 + 3],
            );
        }

        info!("");
        info!("Backtrace:");
        let di = &self.di;
        let initial_registers = DebugRegisters::from_core(core);
        let exception_handler = probe_rs::exception_handler_for_core(core.core_type());
        let instruction_set = core.instruction_set().ok();
        let stack_frames = di.unwind(core, initial_registers, exception_handler.as_ref(), instruction_set)?;

        for (i, frame) in stack_frames.iter().enumerate() {
            let mut s = String::new();
            write!(&mut s, "Frame {}: {} @ {}", i, frame.function_name, frame.pc).unwrap();

            if frame.is_inlined {
                write!(&mut s, " inline").unwrap();
            }
            info!("{}", s);

            if let Some(location) = &frame.source_location {
                let mut s = String::new();
                let file = location.path.to_string_lossy();
                write!(&mut s, "  {file}").unwrap();

                if let Some(line) = location.line {
                    write!(&mut s, ":{line}").unwrap();
                    if let Some(col) = location.column {
                        match col {
                            probe_rs::debug::ColumnType::LeftEdge => {
                                write!(&mut s, ":1").unwrap();
                            }
                            probe_rs::debug::ColumnType::Column(c) => {
                                write!(&mut s, ":{c}").unwrap();
                            }
                        }
                    }
                }
                info!("{}", s);
            }
        }

        Ok(())
    }
}

impl Runner {
    fn poll(&mut self, sess: &mut Session) -> anyhow::Result<()> {
        if let Some(elf) = self.elf.as_mut() {
            return elf.poll(sess);
        }
        Ok(())
    }

    pub(crate) fn run(&mut self, sess: &mut Session, mut cancel: oneshot::Receiver<()>) -> anyhow::Result<bool> {
        let mut was_halted = false;

        loop {
            match cancel.try_recv() {
                Ok(_) | Err(oneshot::error::TryRecvError::Closed) => {
                    break;
                }
                _ => {}
            }

            self.poll(sess)?;

            let mut core = sess.core(0)?;
            let is_halted = core.core_halted()?;

            if is_halted && was_halted {
                break;
            }
            was_halted = is_halted;
        }
        if was_halted {
            let mut core = sess.core(0)?;
            if let Some(elf) = self.elf.as_mut() {
                elf.traceback(&mut core)?;
            }
        }

        Ok(was_halted)
    }
}

fn setup_logging_channel(rtt_addr: u64, sess: &mut Session) -> anyhow::Result<Rtt> {
    const NUM_RETRIES: usize = 10; // picked at random, increase if necessary
    let mut rtt_res: Result<Rtt, probe_rs::rtt::Error> = Err(probe_rs::rtt::Error::ControlBlockNotFound);

    let mut core = sess.core(0).unwrap();

    for try_index in 0..=NUM_RETRIES {
        rtt_res = Rtt::attach_region(&mut core, &ScanRegion::Exact(rtt_addr));
        match rtt_res {
            Ok(_) => {
                log::debug!("Successfully attached RTT");
                break;
            }
            Err(probe_rs::rtt::Error::ControlBlockNotFound) => {
                if try_index < NUM_RETRIES {
                    log::trace!(
                        "Could not attach because the target's RTT control block isn't initialized (yet). retrying"
                    );
                } else {
                    log::error!("Max number of RTT attach retries exceeded.");
                    return Err(anyhow!(probe_rs::rtt::Error::ControlBlockNotFound));
                }
            }
            Err(e) => {
                return Err(anyhow!(e));
            }
        }
    }

    // this block is only executed when rtt was successfully attached before
    let mut rtt = rtt_res.expect("unreachable");
    for ch in rtt.up_channels().iter() {
        log::debug!(
            "up channel {}: {:?}, buffer size {} bytes",
            ch.number(),
            ch.name(),
            ch.buffer_size()
        );
    }
    for ch in rtt.down_channels().iter() {
        log::debug!(
            "down channel {}: {:?}, buffer size {} bytes",
            ch.number(),
            ch.name(),
            ch.buffer_size()
        );
    }

    Ok(rtt)
}

fn get_rtt_main_from(elf: &ElfFile) -> anyhow::Result<(Option<u32>, u32)> {
    let mut rtt = None;
    let mut main = None;

    for symbol in elf.symbols() {
        let name = match symbol.name() {
            Ok(name) => name,
            Err(_) => continue,
        };

        match name {
            "main" => main = Some(symbol.address() as u32 & !THUMB_BIT),
            "_SEGGER_RTT" => rtt = Some(symbol.address() as u32),
            _ => {}
        }
    }

    Ok((rtt, main.ok_or_else(|| anyhow!("`main` symbol not found"))?))
}
