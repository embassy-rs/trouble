use bt_hci::param::{AddrKind, BdAddr};
use core::{array, ops::DerefMut};
use embassy_futures::join::{join, join3, join_array};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex, signal::Signal};
use embassy_time::{Duration, Timer};
use embedded_storage_async::nor_flash::NorFlash;
use heapless::index_map::FnvIndexMap;
use rand_core::{CryptoRng, RngCore};
use sequential_storage::{
    cache::NoCache,
    map::{MapConfig, MapStorage, PostcardValue},
};
use serde::{Deserialize, Serialize};
use trouble_host::{
    gatt::GattClient,
    prelude::{
        Characteristic, ConnectConfig, ConnectionEvent, DefaultPacketPool, RequestedConnParams, ScanConfig, Uuid,
    },
    Address, BondInformation, Controller, Host, HostResources,
};

/// Max number of connections
const CONNECTIONS_MAX: usize = 2;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 3; // Signal + att + CoC

#[derive(Serialize, Deserialize)]
struct StoredBondInformation(Option<BondInformation>);
impl<'a> PostcardValue<'a> for StoredBondInformation {}

pub async fn run<C, RNG, S>(controller: C, random_generator: &mut RNG, storage: &mut S)
where
    C: Controller,
    RNG: RngCore + CryptoRng,
    S: NorFlash,
{
    // Using a fixed "random" address can be useful for testing. In real scenarios, one would
    // use e.g. the MAC 6 byte array as the address (how to get that varies by the platform).
    let address = Address::random([0xff, 0x8f, 0x28, 0x05, 0xe4, 0xff]);
    info!("Our address = {:?}", address);

    let mut resources = HostResources::<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX>::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(address)
        .set_random_generator_seed(random_generator);
    // Replace these with the addresses of your HID devices
    let peripheral_addresses = [
        // My Xbox Series X | S controller
        Address {
            kind: AddrKind::PUBLIC,
            addr: BdAddr::new([0x1D, 0x85, 0xD7, 0x0B, 0xEA, 0x28]),
        },
        // My Xbox One S controller
        Address {
            kind: AddrKind::PUBLIC,
            addr: BdAddr::new([0x00, 0x4D, 0x8D, 0x26, 0x3F, 0xC8]),
        },
    ];

    let mut map_storage =
        MapStorage::<[u8; 7], _, _>::new(storage, MapConfig::new(0..S::ERASE_SIZE as u32 * 2), NoCache::new());
    let mut data_buffer = [0; 512];
    // Note that we will also be iterating through all old, overwritten bonds.
    // This is okay, because stack.add_bond_information will overwrite the previously added bond info for that address.
    // Set the IndexMap capacityu to CONNECTIONS_MAX.next_power_of_two()
    let mut bonds_map = peripheral_addresses
        .iter()
        .map(|address| (address.to_bytes(), None))
        .collect::<FnvIndexMap<_, _, 2>>();
    let mut stored_bonds = map_storage.fetch_all_items(&mut data_buffer).await.unwrap();
    while let Some((key, StoredBondInformation(bond_info))) = stored_bonds.next(&mut data_buffer).await.unwrap() {
        if let Some(value) = bonds_map.get_mut(&key) {
            *value = bond_info;
        }
    }
    for (address, stored_bond_info) in &bonds_map {
        match stored_bond_info {
            Some(bond_info) => {
                info!("Loaded bond information: {:?}", bond_info);
                stack.add_bond_information(bond_info.clone()).unwrap();
            }
            None => {
                let address = Address {
                    kind: AddrKind::new(address[0]),
                    addr: BdAddr(address[1..].try_into().unwrap()),
                };
                info!("No saved bond information for {}", address);
            }
        }
    }

    let bonds_mutex = Mutex::<CriticalSectionRawMutex, _>::new((map_storage, data_buffer));

    let Host {
        mut runner,
        mut central,
        ..
    } = stack.build();

    let signals = peripheral_addresses.map(|_| Signal::<CriticalSectionRawMutex, _>::new());
    let security_mutex = Mutex::<CriticalSectionRawMutex, _>::new(());
    let used_small_interval = Mutex::<CriticalSectionRawMutex, _>::new(false);
    join3(
        async {
            runner.run().await.unwrap();
        },
        async {
            // TODO: On disconnect, start scanning / connecting again
            // let mut connections_count = 0;
            loop {
                info!("Scanning for peripherals to connect to");
                let conn = central
                    .connect(&ConnectConfig {
                        scan_config: ScanConfig {
                            filter_accept_list: &peripheral_addresses
                                .each_ref()
                                .map(|peripheral_address| (peripheral_address.kind, &peripheral_address.addr)),
                            ..Default::default()
                        },
                        connect_params: Default::default(),
                    })
                    .await
                    .unwrap();
                let peer_address = Address {
                    kind: conn.peer_addr_kind(),
                    addr: conn.peer_address(),
                };
                let peripheral_index = peripheral_addresses
                    .iter()
                    .position(|address| address == &peer_address)
                    .unwrap();
                signals[peripheral_index].signal(conn);
                // connections_count += 1;
            }
            // info!("Connected to all peripherals. No longer trying to scan / connect to a new peripheral");
        },
        join_array(array::from_fn::<_, CONNECTIONS_MAX, _>(|i| i).map(async |i| {
            let signal = &signals[i];
            let peripheral_address = &peripheral_addresses[i];
            'connect_loop: loop {
                info!("[{}] Connecting...", peripheral_address);
                let conn = signal.wait().await;
                info!(
                    "[{}] Connected, acquiring lock to security manager...",
                    peripheral_address
                );
                // Set bondable if no bond is stored for this peripheral
                // conn.set_bondable(bonds_map.get(&peripheral_address.to_bytes()).unwrap().is_none())
                //     .unwrap();
                conn.set_bondable(true).unwrap();
                // Se cannot call request_security for two connections at the same time

                let security_lock = security_mutex.lock().await;
                info!(
                    "[{}] Acquired lock to security manager. Calling request_security...",
                    peripheral_address
                );
                conn.request_security().unwrap();
                loop {
                    match conn.next().await {
                        ConnectionEvent::PairingComplete { security_level, bond } => {
                            info!("[{}] Pairing complete: {:?}", peripheral_address, security_level);
                            if let Some(bond) = bond {
                                info!("[{}] Storing bond...", peripheral_address);
                                let mut guard = bonds_mutex.lock().await;
                                let (map_storage, data_buffer) = guard.deref_mut();
                                map_storage
                                    .store_item(
                                        data_buffer,
                                        &peripheral_address.to_bytes(),
                                        &StoredBondInformation(Some(bond)),
                                    )
                                    .await
                                    .unwrap();
                            }
                            break;
                        }
                        ConnectionEvent::PairingFailed(err) => {
                            error!("[{}] Pairing failed: {:?}", peripheral_address, err);
                            continue 'connect_loop;
                        }
                        ConnectionEvent::Disconnected { reason } => {
                            error!("[{}] Disconnected: {:?}", peripheral_address, reason);
                            continue 'connect_loop;
                        }
                        ConnectionEvent::RequestConnectionParams(req) => {
                            // Note that if we don't respond to this request the Xbox controller will automatically disconnecting in ~60s.
                            info!("[{}] Accepting {:?}", peripheral_address, req);
                            let params = RequestedConnParams {
                                // min_connection_interval: Duration::from_millis(15),
                                // max_connection_interval: Duration::from_millis(15),
                                ..req.params().clone()
                            };
                            if let Err(e) = req.accept(Some(&params), &stack).await {
                                error!("[{}] Error accepting connection params: {:?}", peripheral_address, e);
                            }
                            // if let Err(e) = req.reject(&stack).await {
                            //     error!("[{}] Error rejecting connection params: {:?}", peripheral_address, e);
                            // }
                        }
                        ConnectionEvent::BondLost => {
                            info!(
                                "[{}] Bond lost. Deleting bond from non-volatile storage",
                                peripheral_address
                            );
                            let mut guard = bonds_mutex.lock().await;
                            let (map_storage, data_buffer) = guard.deref_mut();
                            map_storage
                                .store_item(
                                    data_buffer,
                                    &peripheral_address.to_bytes(),
                                    &StoredBondInformation(None),
                                )
                                .await
                                .unwrap();
                            // TODO: Also remove from resources?
                        }
                        event => {
                            info!("Other connection event: {:?}", event);
                        }
                    }
                }
                drop(security_lock);
                info!("[{}] Encrypted. Creating GATT client...", peripheral_address);
                join(
                    async {
                        // Timer::after_secs(1).await;
                        let client = GattClient::<_, DefaultPacketPool, 1>::new(&stack, &conn).await.unwrap();
                        join(async { client.task().await.unwrap() }, async {
                            info!("[{}] Created GATT client", peripheral_address);
                            info!("[{}] Getting HID service", peripheral_address);
                            let hid_service = client.services_by_uuid(&Uuid::new_short(0x1812)).await.unwrap();
                            let hid_service = hid_service.first().unwrap();
                            info!("[{}] Got HID service", peripheral_address);

                            // The descriptor characteristic tells us about the data structure for inputs
                            // (button presses, etc) and outputs (rumble)
                            // Normally we would actually parse this but for this example we won't
                            info!("[{}] Getting descriptor characteristic", peripheral_address);
                            let descriptor_characteristic: Characteristic<[u8; 512]> = client
                                .characteristic_by_uuid(&hid_service, &Uuid::new_short(0x2A4B))
                                .await
                                .unwrap();
                            info!("[{}] Reading descriptor characteristic", peripheral_address);
                            let mut data = [0_u8; 512];
                            let bytes_read = client
                                .read_characteristic(&descriptor_characteristic, &mut data)
                                .await
                                .unwrap();
                            let feature_report = &data[..bytes_read];
                            info!("[{}] Feature report: {:X?}", peripheral_address, feature_report);

                            // Set this to whatever max characteristics you want to support
                            // Xbox controllers have 5 characteristics within the HID service
                            let characteristics = client.characteristics::<10>(&hid_service).await.unwrap();
                            for characteristic in characteristics {
                                if characteristic.uuid == Uuid::new_short(0x2A4D) {
                                    // Read the Report Reference Descriptor
                                    // The descriptor is two bytes
                                    // The first byte is the report ID
                                    // The second byte is if the characteristic is the report type
                                    // 0x1 - Input
                                    // 0x2 - Output
                                    // 0x3 - Feature
                                    let report_reference_descriptor = client
                                        .descriptor_by_uuid::<_, [u8; 2]>(&characteristic, &Uuid::new_short(0x2908))
                                        .await
                                        .unwrap();
                                    let mut buffer = [Default::default(); 2];
                                    let bytes_read = client
                                        .read_descriptor(&report_reference_descriptor, &mut buffer)
                                        .await
                                        .unwrap();
                                    let [report_id, report_type] = <[u8; 2]>::try_from(&buffer[..bytes_read]).unwrap();
                                    match report_type {
                                        0x1 => {
                                            info!(
                                                "[{}] Found input report with id {:#X}",
                                                peripheral_address, report_id
                                            );
                                        }
                                        0x2 => {
                                            info!(
                                                "[{}] Found output report with id {:#X}",
                                                peripheral_address, report_id
                                            );
                                        }
                                        0x3 => {
                                            info!(
                                                "[{}] Found feature report with id {:#X}",
                                                peripheral_address, report_id
                                            );
                                        }
                                        report_type => {
                                            warn!(
                                                "[{}] Unexpected report type: {:#X}",
                                                peripheral_address, report_type
                                            );
                                        }
                                    }
                                }
                            }
                        })
                        .await;
                    },
                    async {
                        loop {
                            let event = conn.next().await;
                            match event {
                                ConnectionEvent::RequestConnectionParams(req) => {
                                    // Note that if we don't respond to this request the Xbox controller will automatically disconnecting in ~60s.
                                    info!("connection params request AFTER encrypted");
                                    let params = RequestedConnParams {
                                        // min_connection_interval: Duration::from_millis(15),
                                        // max_connection_interval: Duration::from_millis(15),
                                        ..req.params().clone()
                                    };
                                    if let Err(e) = req.accept(Some(&params), &stack).await {
                                        error!(
                                            "[{}] Error accepting connection params AFTER encrypted: {:?}",
                                            peripheral_address, e
                                        );
                                    }
                                    // if let Err(e) = req.reject(&stack).await {
                                    //     error!("[{}] Error accepting connection params: {:?}", peripheral_address, e);
                                    // }
                                }
                                event => {
                                    info!("ConnectionEvent: {:?}", event);
                                }
                            }
                        }
                    },
                )
                .await;
            }
        })),
    )
    .await;
}
