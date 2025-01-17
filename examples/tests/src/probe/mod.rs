use std::process::Stdio;
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader;
use tokio::process::Command;
use tokio::select;
use tokio_util::sync::CancellationToken;

use hilbench_agent::ProbeConfig;
use hilbench_agent::Target;

pub fn init(config: ProbeConfig) {
    hilbench_agent::init(config);
}

pub struct Firmware {
    pub data: Vec<u8>,
}

pub struct DeviceUnderTest<'d> {
    target: Target<'d>,
    token: CancellationToken,
}

impl<'d> DeviceUnderTest<'d> {
    pub(crate) fn new(target: Target<'d>) -> Self {
        Self {
            target,
            token: CancellationToken::new(),
        }
    }
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    pub async fn run(self, firmware: String) -> Result<FirmwareLogs, anyhow::Error> {
        let mut flasher = Command::new("probe-rs")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .arg("run")
            .arg(&firmware)
            .arg("--chip")
            .arg(&self.target.config().chip)
            .arg("--probe")
            .arg(&self.target.config().probe)
            .spawn()
            .unwrap();

        let stdout = flasher.stdout.take().unwrap();
        let stderr = flasher.stderr.take().unwrap();
        let mut stdout_reader = BufReader::new(stdout).lines();
        let mut stderr_reader = BufReader::new(stderr).lines();

        let mut lines: Vec<String> = Vec::new();
        select! {
            r = flasher.wait() => {
                log::warn!("flasher exited unexpectedly: {:?}", r);
            }
            _ = self.token.cancelled() => {
                flasher.kill().await.unwrap();
            }
            _ = async {
                loop {
                    select! {
                        r = stdout_reader.next_line() => {
                            if let Ok(Some(r)) = r {
                                lines.push(r);
                            }
                        }
                        r = stderr_reader.next_line() => {
                            if let Ok(Some(r)) = r {
                                lines.push(r);
                            }
                        }
                    }
                }
            } => {

            }
        }
        log::info!("waiting for process exit");
        flasher.wait().await.unwrap();
        Ok(FirmwareLogs { lines })
    }
}

pub struct FirmwareLogs {
    pub lines: Vec<String>,
}
