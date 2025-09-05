use bt_hci::controller::ExternalController;
use bt_hci_linux::Transport;
use trouble_example_apps::{BigAlloc, high_throughput_ble_l2cap_central};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), std::io::Error> {
    env_logger::init();
    let dev = match std::env::args().collect::<Vec<_>>()[..] {
        [_] => 0,
        [_, ref s] => s.parse::<u16>().expect("Could not parse device number"),
        _ => panic!(
            "Provide the device number as the one and only command line argument, or no arguments to use device 0."
        ),
    };
    let transport = Transport::new(dev)?;
    let controller = ExternalController::<_, 8>::new(transport);
    high_throughput_ble_l2cap_central::run::<_, BigAlloc>(controller).await;
    Ok(())
}
