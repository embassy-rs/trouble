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
        log::info!("Using probe config {}", config);
        let probe_config = serde_json::from_str(&config).unwrap();

        Self {
            serial_adapters,
            probe_config,
        }
    }

    pub async fn find_dut(&self, labels: &[(&str, &str)]) -> Result<DeviceUnderTest, anyhow::Error> {
        let db_path = std::env::temp_dir().join("hilbench-probes.db");
        let selector =
            hilbench_agent::init(&db_path, self.probe_config.clone(), Duration::from_secs(300))?;
        let target = selector.select(labels).await?;
        Ok(DeviceUnderTest::new(target, selector.server().cloned()))
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
}
