use bt_hci::controller::ExternalController;
use bt_hci_usb::Transport;
use trouble_example_apps::{BigAlloc, high_throughput_ble_l2cap_peripheral};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::init();
    let device = bt_hci_usb::list_devices().await.unwrap().next().unwrap();
    println!("Using device: {device:?}");

    let device = device.open().await.unwrap();
    let transport = Transport::new(device).await.unwrap();
    let controller = ExternalController::<_, 8>::new(transport);

    high_throughput_ble_l2cap_peripheral::run::<_, BigAlloc>(controller).await;
}
