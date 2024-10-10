//! This test is for the gatt_service derive macro. It will check that all attributes and arguments are able to be processed by the macro

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use trouble_host::prelude::*;

#[gatt_service(uuid = "7e701cf1-b1df-42a1-bb5f-6a1028c793b0")]
struct CustomService {
    #[characteristic(uuid = "2a37", read, write)]
    short_uuid: u8,
    #[characteristic(uuid = "7e711cf1-b1df-42a1-bb5f-6a1028c793b0", write_without_response, indicate)]
    long_uuid: f32,
    #[characteristic(uuid = "2a38", read, notify)]
    notify: [u8; 8],
    non_characteristic_field: u8,
}

#[tokio::test]
async fn gatt_service_derive() {
    let mut table: AttributeTable<NoopRawMutex, 10> = AttributeTable::new();
    let service = CustomService::new(&mut table);

    // Check all fields of service have been generated and are accessible
    let _handle = service.handle;
    let _non_characteristic_field = service.non_characteristic_field;
    let _characteristic_short_uuid = service.short_uuid;
    let _characteristic_long_uuid = service.long_uuid;
    let _notify = service.notify;
}
