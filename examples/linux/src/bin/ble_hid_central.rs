use bt_hci::controller::ExternalController;
use bt_hci_linux::Transport;
use embedded_storage_file::{NorMemoryAsync, NorMemoryInFile};
use rand::rngs::OsRng;
use trouble_example_apps::ble_hid_central;

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
    let nor = NorMemoryInFile::<1, 32, 4096>::new("ble_hid_central.nor", 0x8000)?;
    let mut storage = NorMemoryAsync::new(nor.storage().nor_flash());
    ble_hid_central::run(controller, &mut OsRng, &mut storage).await;
    Ok(())
}
