//! Uses the GATT macros without the prelude glob import, so their output has to
//! name everything it uses by its full path.
#![allow(dead_code)]
use trouble_host::prelude::{gatt_server, gatt_service};

#[gatt_server]
struct Server {
    service: TestService,
}

#[gatt_service(uuid = "408813df-5dd4-1f87-ec11-cdb000100000")]
struct TestService {
    #[characteristic(uuid = "408813df-5dd4-1f87-ec11-cdb001100000", read, write, notify)]
    value: u8,
}

#[test]
fn macros_without_prelude() {
    assert!(Server::new_default("TrouBLE").is_ok());
}
