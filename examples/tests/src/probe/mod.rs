use probe_rs::probe::list::Lister;
use probe_rs::probe::DebugProbeSelector;
use probe_rs::{Permissions, Session};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use tokio::sync::oneshot;
use tokio::task::spawn_blocking;

mod run;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProbeConfig {
    pub targets: Vec<TargetConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TargetConfig {
    pub chip: String,
    pub probe: String,
    pub labels: HashMap<String, String>,
}

static SELECTOR: OnceLock<ProbeSelector> = OnceLock::new();

pub fn init(config: ProbeConfig) -> &'static ProbeSelector {
    SELECTOR.get_or_init(|| ProbeSelector::new(config))
}

pub struct ProbeSelector {
    targets: Vec<(AtomicBool, TargetConfig)>,
}

pub struct Target<'d> {
    config: TargetConfig,
    taken: &'d AtomicBool,
}

impl ProbeSelector {
    fn new(config: ProbeConfig) -> Self {
        let mut targets = Vec::new();
        for t in config.targets {
            targets.push((AtomicBool::new(false), t));
        }
        Self { targets }
    }

    /// Select a target with the provided labels
    pub fn select<'m>(&'m self, labels: &[(&str, &str)]) -> Option<Target<'m>> {
        for (taken, config) in &self.targets {
            let mut matched = true;
            for (key, value) in labels {
                let v = config.labels.get(*key);
                if let Some(v) = v {
                    if v != value {
                        matched = false;
                        break;
                    }
                }
            }
            if matched && taken.swap(true, Ordering::Acquire) == false {
                return Some(Target {
                    config: config.clone(),
                    taken,
                });
            }
        }
        None
    }
}

impl<'d> Target<'d> {
    pub fn flash(self, elf: Vec<u8>) -> Result<TargetRunner<'d>, anyhow::Error> {
        let probe = self.config.probe.clone();
        let p: DebugProbeSelector = probe.try_into()?;
        info!("Debug probe selector created");
        let t = probe_rs::config::get_target_by_name(&self.config.chip)?;
        info!("Target created");

        let lister = Lister::new();
        info!("Opening probe");
        let probe = lister.open(p)?;

        let perms = Permissions::new().allow_erase_all();
        info!("Attaching probe");
        let mut session = probe.attach(t, perms)?;
        let opts = run::Options { do_flash: true };
        let mut flasher = run::Flasher::new(elf, opts);
        flasher.flash(&mut session)?;
        Ok(TargetRunner {
            _target: self,
            flasher,
            session,
        })
    }
}

impl<'d> Drop for Target<'d> {
    fn drop(&mut self) {
        self.taken.store(false, Ordering::Release);
    }
}

pub struct TargetRunner<'d> {
    _target: Target<'d>,
    flasher: run::Flasher,
    session: Session,
}

impl<'d> TargetRunner<'d> {
    pub async fn run(mut self, cancel: oneshot::Receiver<()>) -> Result<(), anyhow::Error> {
        let result = spawn_blocking(move || {
            let mut runner = self.flasher.start(&mut self.session).unwrap();
            runner.run(&mut self.session, cancel)
        })
        .await
        .unwrap();
        result

        //let mut res = String::new();
        //for entry in entries {
        //    writeln!(&mut res, "{} - {}", entry.level, entry.message).unwrap();
        //}
        //(ok, res.into_bytes())
    }
}
