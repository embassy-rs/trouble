use trouble_host::prelude::*;

#[gatt_service(uuid = "0x180f")]
struct HeartRateService {
    #[characteristic(uuid = "0x2A37", read, notify)]
    rate: f32,
    #[characteristic(uuid = "0x2A38", read)]
    location: f32,
    #[characteristic(uuid = "0x2A39", write)]
    control: u8,
    #[characteristic(uuid = "0x2A63", read, notify)]
    energy_expended: u16,
}

fn main() {
    let service = HeartRateService::new().unwrap();
}
