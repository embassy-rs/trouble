use std::time::Duration;

use hilbench_agent::ProbeConfig;
use probe::DeviceUnderTest;

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
