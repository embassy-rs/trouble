use anyhow::anyhow;
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

    pub fn find_dut(&self, labels: &[(&str, &str)]) -> Result<DeviceUnderTest<'static>, anyhow::Error> {
        let selector = hilbench_agent::init(self.probe_config.clone());
        let target = selector
            .select(labels)
            .ok_or(anyhow!("Unable to find DUT for {:?}", labels))?;
        Ok(DeviceUnderTest::new(target))
    }
}

impl Default for TestContext {
    fn default() -> Self {
        Self::new()
    }
}
