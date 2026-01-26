use bt_hci::controller::ExternalController;
use bt_hci_linux::Transport;
use getrandom;
use trouble_host::TrulyRandomBits;
use trouble_example_apps::ble_bas_peripheral_sec;

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

    let seed: TrulyRandomBits = {
        let mut buf: [u8; 32] = [0;_];
        getrandom::fill(&mut buf).unwrap();
        TrulyRandomBits(buf)
    };

    let transport = Transport::new(dev)?;
    let controller = ExternalController::<_, 8>::new(transport);
    ble_bas_peripheral_sec::run(controller, seed).await;
    Ok(())
}
