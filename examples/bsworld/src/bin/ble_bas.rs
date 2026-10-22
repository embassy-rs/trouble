//! Reuse the upstream applications; only transport and execution change.

use std::io;
use std::path::Path;

use bt_hci::controller::ExternalController;
use trouble_bsim::Executor;
use trouble_bsim::babblesim::BabbleSim;
use trouble_example_apps::{ble_bas_central, ble_bas_peripheral};

fn main() -> io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 || !matches!(args[1].as_str(), "central" | "peripheral") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: ble_bas central|peripheral SIM_DIR PHY_ID DEV_ID HCI_SOCKET",
        ));
    }
    let dev_id = args[4]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid device ID"))?;
    let clock = BabbleSim::connect(Path::new(&args[2]), &args[3], dev_id)?;
    let mut executor = Executor::new(clock)?;
    let controller = ExternalController::<_, 8>::new(executor.connect_hci(&args[5])?);
    executor.block_on(async {
        if args[1] == "central" {
            ble_bas_central::run(controller).await;
        } else {
            ble_bas_peripheral::run(controller).await;
        }
    })
}
