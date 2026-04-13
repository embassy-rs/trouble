use std::fmt::Debug;
use std::time::Duration;

use hilbench_agent::ProbeConfig;
use probe::{DeviceUnderTest, FirmwareLogs};
use tokio::task::JoinHandle;

pub mod probe;
pub mod serial;

pub struct TestContext {
    pub serial_adapters: Vec<String>,
    pub probe_config: ProbeConfig,
}

impl TestContext {
    pub fn new() -> Self {
        let serial_adapters = serial::find_controllers();
        let config = std::env::var("PROBE_CONFIG").unwrap();
        let probe_config: ProbeConfig = serde_json::from_str(&config).unwrap();
        log::info!("Using probe config {:?}", probe_config);

        verify_probes_reachable(&probe_config);

        Self {
            serial_adapters,
            probe_config,
        }
    }

    pub async fn find_dut(&self, labels: &[(&str, &str)]) -> Result<DeviceUnderTest, anyhow::Error> {
        let db_path = std::env::temp_dir().join("hilbench-probes.db");
        let selector = hilbench_agent::init(&db_path, self.probe_config.clone(), Duration::from_secs(300))?;
        let target = selector.select(labels).await?;
        Ok(DeviceUnderTest::new(target, selector.server().cloned()))
    }
}

/// Runs `probe-rs list` and verifies that all probes in the config are reachable.
/// Panics if any configured probe is not found in the output.
fn verify_probes_reachable(config: &ProbeConfig) {
    let mut cmd = std::process::Command::new("probe-rs");
    cmd.arg("list");
    if let Some(server) = config.server.as_ref() {
        cmd.arg("--host").arg(&server.url);
        cmd.arg("--token").arg(&server.token);
    }

    let output = cmd.output().expect("failed to run probe-rs list");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    log::info!("probe-rs list output:\n{}{}", stdout, stderr);

    if !output.status.success() {
        panic!("probe-rs list failed with status {}: {}", output.status, stderr);
    }

    let list_output = format!("{}{}", stdout, stderr);
    for target in &config.targets {
        // The probe field is VID:PID:SERIAL — extract the serial portion for matching,
        // since probe-rs list may format the VID:PID differently (e.g. with bus number).
        let serial = target.probe.rsplitn(2, ':').next().unwrap();
        if !list_output.contains(serial) {
            panic!(
                "Probe not reachable: {} (chip={}, serial={})\nprobe-rs list output:\n{}",
                target.probe, target.chip, serial, list_output
            );
        }
        log::info!("Probe reachable: {} (chip={})", target.probe, target.chip);
    }
}

/// Waits for DUT and the other test side to complete with a timeout.
/// On failure (timeout or error), prints the DUT firmware logs before panicking.
pub async fn await_test<E: Debug>(
    mut dut: JoinHandle<Result<FirmwareLogs, anyhow::Error>>,
    other: JoinHandle<Result<(), E>>,
    cancel: tokio_util::sync::CancellationToken,
) {
    match tokio::time::timeout(Duration::from_secs(30), futures::future::join(&mut dut, other)).await {
        Err(_) => {
            println!("Test timed out");
            cancel.cancel();
            if let Ok(Ok(Ok(logs))) = tokio::time::timeout(Duration::from_secs(1), dut).await {
                logs.print();
            }
            panic!("Test timed out");
        }
        Ok((dut_result, other_result)) => {
            let dut_result = dut_result.expect("dut task panicked");
            let other_result = other_result.expect("test task panicked");
            if dut_result.is_err() || other_result.is_err() {
                if let Ok(logs) = &dut_result {
                    logs.print();
                }
            }
            dut_result.unwrap();
            other_result.unwrap();
        }
    }
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
}
