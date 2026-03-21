use bt_hci::param::{AddrKind, BdAddr};
use core::ops::DerefMut;
use embassy_futures::join::{join, join_array};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
use embedded_storage_async::nor_flash::NorFlash;
use rand_core::{CryptoRng, RngCore};
use sequential_storage::{
    cache::NoCache,
    map::{MapConfig, MapStorage, PostcardValue},
};
use serde::{Deserialize, Serialize};
use trouble_host::{
    prelude::{ConnectConfig, ConnectionEvent, DefaultPacketPool, ScanConfig},
    Address, BondInformation, Controller, Host, HostResources,
};

/// Max number of connections
const CONNECTIONS_MAX: usize = 2;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 3; // Signal + att + CoC

#[derive(Serialize, Deserialize)]
struct StoredBondInformation(BondInformation);
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
    // Make sure CONNECTIONS_MAX >= this len
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
    let mut data_buffer = [0; 32];
    // Note that we will also be iterating through all old, overwritten bonds.
    // This is okay, because stack.add_bond_information will overwrite the previously added bond info for that address.
    let mut stored_bonds = map_storage.fetch_all_items(&mut data_buffer).await.unwrap();
    while let Some((_key, StoredBondInformation(bond_info))) = stored_bonds.next(&mut data_buffer).await.unwrap() {
        stack.add_bond_information(bond_info).unwrap();
    }
    let loaded_bond_information = stack.get_bond_information();
    info!("Loaded bonds: {:?}", loaded_bond_information);

    let bonds_mutex = Mutex::<CriticalSectionRawMutex, _>::new((map_storage, data_buffer));

    let Host { mut runner, .. } = stack.build();

    join(
        async {
            runner.run().await.unwrap();
        },
        join_array(peripheral_addresses.map(async |peripheral_address| {
            let Host { mut central, .. } = stack.build();
            info!("Connecting to {}", peripheral_address);
            let config = ConnectConfig {
                connect_params: Default::default(),
                scan_config: ScanConfig {
                    filter_accept_list: &[(peripheral_address.kind, &peripheral_address.addr)],
                    ..Default::default()
                },
            };
            let conn = central.connect(&config).await.unwrap();
            info!("Connected, pairing / bonding...");
            // Even if we loaded a previously-saved bond, the peripheral may have deleted its bond.
            // So we always allow creating a new bond for this example.
            conn.set_bondable(true).unwrap();
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
                                    &StoredBondInformation(bond),
                                )
                                .await
                                .unwrap();
                        }
                        break;
                    }
                    ConnectionEvent::PairingFailed(err) => {
                        error!("[{}] Pairing failed: {:?}", peripheral_address, err);
                        break;
                    }
                    ConnectionEvent::Disconnected { reason } => {
                        error!("[{}] Disconnected: {:?}", peripheral_address, reason);
                        break;
                    }
                    ConnectionEvent::RequestConnectionParams(req) => {
                        // Note that if we don't respond to this request the Xbox controller will automatically disconnecting in ~60s.
                        info!("[{}] Accepting {:?}", peripheral_address, req);
                        req.accept(None, &stack).await.unwrap()
                    }
                    event => {
                        info!("Other connection event: {:?}", event);
                    }
                }
            }
            info!("Done with loop");
        })),
    )
    .await;
}
