use bt_hci::param::{AddrKind, BdAddr};
use core::ops::DerefMut;
use embassy_futures::join::{join, join_array};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
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
    Address, BondInformation, Controller, Host, HostResources, Identity,
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
        // Address {
        //     kind: AddrKind::PUBLIC,
        //     addr: BdAddr::new([0x1D, 0x85, 0xD7, 0x0B, 0xEA, 0x28]),
        // },
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

    join(
        async {
            runner.run().await.unwrap();
        },
        // join_array(peripheral_addresses.map(async |peripheral_address| {
        // let Host { mut central, .. } = stack.build();
        async {
            'connect_loop: loop {
                let peripheral_address = peripheral_addresses[0];
                info!("Connecting to {}", peripheral_address);
                let config = ConnectConfig {
                    connect_params: RequestedConnParams {
                        supervision_timeout: Duration::from_secs(15),
                        ..Default::default()
                    },
                    scan_config: ScanConfig {
                        filter_accept_list: &[(peripheral_address.kind, &peripheral_address.addr)],
                        ..Default::default()
                    },
                };
                let conn = central.connect(&config).await.unwrap();
                info!("Connected, pairing / bonding...");
                // Set bondable if no bond is stored for this peripheral
                conn.set_bondable(bonds_map.get(&peripheral_address.to_bytes()).unwrap().is_none())
                    .unwrap();
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
                            if let Err(e) = req.accept(None, &stack).await {
                                error!("[{}] Error accepting connection params: {:?}", peripheral_address, e);
                            }
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
                info!("[{}] Encrypted", peripheral_address);
                join(
                    async {
                        Timer::after_secs(1).await;
                        let client = GattClient::<_, DefaultPacketPool, 1>::new(&stack, &conn).await.unwrap();
                        join(async { client.task().await.unwrap() }, async {
                            info!("Created GATT client");
                            info!("Getting HID service");
                            let hid_service = client.services_by_uuid(&Uuid::new_short(0x1812)).await.unwrap();
                            let hid_service = hid_service.first().unwrap();

                            // The descriptor characteristic tells us about the data structure for inputs
                            // (button presses, etc) and outputs (rumble)
                            // Normally we would actually parse this but for this example we won't
                            info!("Getting descriptor characteristic");
                            let descriptor_characteristic: Characteristic<[u8; 512]> = client
                                .characteristic_by_uuid(&hid_service, &Uuid::new_short(0x2A4B))
                                .await
                                .unwrap();
                            info!("Reading descriptor characteristic");
                            let mut data = [0_u8; 512];
                            let bytes_read = client
                                .read_characteristic(&descriptor_characteristic, &mut data)
                                .await
                                .unwrap();
                            let feature_report = &data[..bytes_read];
                            info!("feature report: {:X?}", feature_report);
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
                                    if let Err(e) = req.accept(None, &stack).await {
                                        error!(
                                            "[{}] Error accepting connection params AFTER encrypted: {:?}",
                                            peripheral_address, e
                                        );
                                    }
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
        },
    )
    .await;
}
