use std::io::Write;
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

    pub async fn run(self, fw: Firmware) -> Result<FirmwareLogs, anyhow::Error> {
        let mut temp = tempfile::NamedTempFile::new()?;
        temp.write_all(&fw.data)?;
        let path = temp.path().to_str().unwrap().to_string();
        drop(temp);
        let mut flasher = Command::new("probe-rs")
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .arg("run")
            .arg("--elf")
            .arg(&path)
            .arg("--chip")
            .arg(&self.target.config().chip)
            .arg("--probe")
            .arg(&self.target.config().probe)
            .spawn()
            .unwrap();

        let stderr = flasher.stderr.as_mut().unwrap();
        let mut stderr_reader = BufReader::new(stderr);

        let mut lines: Vec<String> = Vec::new();
        select! {
            _ = self.token.cancelled() => {
                flasher.kill().await.unwrap();
            }
            _ = async {
                loop {
                    let mut line = String::new();
                    stderr_reader.read_line(&mut line).await.unwrap();
                    lines.push(line);
                }
            } => {

            }
        }
        flasher.wait().await.unwrap();
        Ok(FirmwareLogs { lines })
    }
}

pub struct FirmwareLogs {
    pub lines: Vec<String>,
}
