use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use trouble_host::prelude::*;

#[gatt_service(uuid = "7e701cf1-b1df-42a1-bb5f-6a1028c793b0")]
struct HeartRateService {
    #[characteristic(uuid = "2A37", read, notify)]
    rate: f32,
    #[characteristic(uuid = "2A38", read)]
    location: f32,
    #[characteristic(uuid = "2A39", write)]
    control: u8,
    #[characteristic(uuid = "2A63", read, notify)]
    energy_expended: u16,
}

fn main() {
    let mut table: AttributeTable<NoopRawMutex, 10> = AttributeTable::new();
    let service = HeartRateService::new(&mut table).unwrap();
}
