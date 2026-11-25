use trouble_host::prelude::*;

#[gatt_service(uuid = service::BATTERY)]
struct BatteryService {
    #[characteristic(uuid = characteristic::BATTERY_LEVEL, read, notify, value = 10)]
    level: u8,
}

mod plain {
    use super::BatteryService;
    use trouble_host::prelude::*;

    #[gatt_server]
    pub struct Server {
        pub bas: BatteryService,
    }
}

mod with_service_changed {
    use super::BatteryService;
    use trouble_host::prelude::*;

    #[gatt_server(service_changed = true)]
    pub struct Server {
        pub bas: BatteryService,
    }
}

#[test]
fn gatt_server_omits_service_changed_by_default() {
    let server = plain::Server::new_default("trouble").unwrap();
    assert_eq!(
        server.table().len(),
        GAP_SERVICE_ATTRIBUTE_COUNT + BatteryService::ATTRIBUTE_COUNT
    );
    assert!(matches!(server.table().service_changed(), Err(Error::NotFound)));
    assert_eq!(server.get(&server.bas.level).unwrap(), 10);
}

#[test]
fn gatt_server_option_adds_service_changed() {
    let server = with_service_changed::Server::new_default("trouble").unwrap();
    assert_eq!(
        server.table().len(),
        GAP_SERVICE_ATTRIBUTE_COUNT + SERVICE_CHANGED_ATTRIBUTE_COUNT + BatteryService::ATTRIBUTE_COUNT
    );
    let service_changed = server.table().service_changed().unwrap();
    assert!(service_changed.cccd_handle.is_some());
    assert_eq!(server.get(&service_changed).unwrap(), ServiceChanged::ALL);
    assert_eq!(server.get(&server.bas.level).unwrap(), 10);
}
