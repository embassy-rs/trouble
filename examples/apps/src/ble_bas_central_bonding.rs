use core::ops::Range;
use embassy_futures::join::join;
use embassy_time::{Duration, Timer};
use embedded_storage_async::nor_flash::{NorFlash};
use rand_core::{CryptoRng, RngCore};
use sequential_storage::cache::NoCache;
use sequential_storage::map::{Key, SerializationError, Value};
use trouble_host::prelude::*;

/// Max number of connections
const CONNECTIONS_MAX: usize = 1;

/// Max number of L2CAP channels.
const L2CAP_CHANNELS_MAX: usize = 3; // Signal + att + CoC

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredAddr(BdAddr);

impl Key for StoredAddr {
    fn serialize_into(&self, buffer: &mut [u8]) -> Result<usize, SerializationError> {
        if buffer.len() < 6 {
            return Err(SerializationError::BufferTooSmall);
        }
        buffer[0..6].copy_from_slice(self.0.raw());
        Ok(6)
    }

    fn deserialize_from(buffer: &[u8]) -> Result<(Self, usize), SerializationError> {
        if buffer.len() < 6 {
            Err(SerializationError::BufferTooSmall)
        }
        else {
            Ok((StoredAddr(BdAddr::new(buffer[0..6].try_into().unwrap())), 6))
        }
    }
}

struct StoredBondInformation {
    ltk: LongTermKey,
    security_level: SecurityLevel,
}

impl<'a> Value<'a> for StoredBondInformation {
    fn serialize_into(&self, buffer: &mut [u8]) -> Result<usize, SerializationError> {
        if buffer.len() < 17 {
            return Err(SerializationError::BufferTooSmall);
        }
        buffer[0..16].copy_from_slice(self.ltk.to_le_bytes().as_slice());
        buffer[16] = match self.security_level {
            SecurityLevel::NoEncryption => 0,
            SecurityLevel::Encrypted => 1,
            SecurityLevel::EncryptedAuthenticated => 2,
        };
        Ok(17)
    }

    fn deserialize_from(buffer: &'a [u8]) -> Result<Self, SerializationError>
    where
        Self: Sized
    {
        if buffer.len() < 17 {
            Err(SerializationError::BufferTooSmall)
        }
        else {
            let ltk = LongTermKey::from_le_bytes(buffer[0..16].try_into().unwrap());
            let security_level = match buffer[16] {
                0 => SecurityLevel::NoEncryption,
                1 => SecurityLevel::Encrypted,
                2 => SecurityLevel::EncryptedAuthenticated,
                _ => return Err(SerializationError::InvalidData)
            };
            Ok(StoredBondInformation { ltk, security_level })
        }
    }
}

fn flash_range<S: NorFlash>() -> Range<u32> {
    0..2*S::ERASE_SIZE as u32
}

async fn store_bonding_info<S: NorFlash>(storage: &mut S, info: &BondInformation) -> Result<(), sequential_storage::Error<S::Error>> {
    // Assumes that S::ERASE_SIZE is large enough
    sequential_storage::erase_all(storage, 0..S::ERASE_SIZE as u32).await?;
    let mut buffer = [0;32];
    let key = StoredAddr(info.identity.bd_addr);
    let value = StoredBondInformation { ltk: info.ltk, security_level: info.security_level };
    sequential_storage::map::store_item(storage, flash_range::<S>(), &mut NoCache::new(), &mut buffer, &key, &value).await?;
    Ok(())
}

async fn load_bonding_info<S: NorFlash>(storage: &mut S) -> Option<BondInformation>
{
    let mut buffer = [0;32];
    let mut cache = NoCache::new();
    let mut iter = sequential_storage::map::fetch_all_items::<StoredAddr, _, _>(storage, flash_range::<S>(), &mut cache, &mut buffer).await.ok()?;
    while let Some((key, value)) = iter.next::<StoredBondInformation>(&mut buffer).await.ok()? {
        return Some(BondInformation {
            identity: Identity {
                bd_addr: key.0,
                irk: None,
            },
            security_level: value.security_level,
            is_bonded: true,
            ltk: value.ltk
        });
    }
    None
}

pub async fn run<C, RNG, S>(controller: C, random_generator: &mut RNG, storage: &mut S)
where
    C: Controller,
    RNG: RngCore + CryptoRng,
    S: NorFlash
{
    // Using a fixed "random" address can be useful for testing. In real scenarios, one would
    // use e.g. the MAC 6 byte array as the address (how to get that varies by the platform).
    let address: Address = Address::random([0xff, 0x8f, 0x28, 0x05, 0xe4, 0xff]);
    info!("Our address = {:?}", address);

    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(address)
        .set_random_generator_seed(random_generator);

    let mut has_bond_info =
    if let Some(bond_info) = load_bonding_info(storage).await {
        info!("Bond stored. Adding to stack.");
        stack.add_bond_information(bond_info).unwrap();
        true
    }
    else {
        info!("No bond stored.");
        false
    };

    let Host {
        mut central,
        mut runner,
        ..
    } = stack.build();

    // NOTE: Modify this to match the address of the peripheral you want to connect to.
    // Currently it matches the address used by the peripheral examples
    let target: Address = Address::random([0xff, 0x8f, 0x08, 0x05, 0xe4, 0xff]);

    let config = ConnectConfig {
        connect_params: Default::default(),
        scan_config: ScanConfig {
            filter_accept_list: &[(target.kind, &target.addr)],
            ..Default::default()
        },
    };

    info!("Scanning for peripheral...");
    let _ = join(runner.run(), async {
        info!("Connecting");

        let conn = central.connect(&config).await.unwrap();
        // Allow bonding if a bond isn't already stored
        conn.set_bondable(!has_bond_info).unwrap();
        info!("Connected, creating gatt client");

        #[cfg(feature = "security")]
        {
            conn.request_security().unwrap();
            loop {
                match conn.next().await {
                    ConnectionEvent::PairingComplete { security_level, bond } => {
                        info!("Pairing complete: {:?}", security_level);
                        if let Some(bond) = bond {
                            store_bonding_info(storage, &bond).await.unwrap();
                            has_bond_info = true;
                        }
                        break;
                    },
                    ConnectionEvent::PairingFailed(err) => {
                        error!("Pairing failed: {:?}", err);
                        break;
                    },
                    ConnectionEvent::Disconnected { reason } => {
                        error!("Disconnected: {:?}", reason);
                        break;
                    }
                    _ => {}
                }
            }
        }

        let client = GattClient::<C, DefaultPacketPool, 10>::new(&stack, &conn)
            .await
            .unwrap();

        let _ = join(client.task(), async {
            info!("Looking for battery service");
            let services = client.services_by_uuid(&Uuid::new_short(0x180f)).await.unwrap();
            let service = services.first().unwrap().clone();

            info!("Looking for value handle");
            let c: Characteristic<u8> = client
                .characteristic_by_uuid(&service, &Uuid::new_short(0x2a19))
                .await
                .unwrap();

            info!("Subscribing notifications");
            let mut listener = client.subscribe(&c, false).await.unwrap();

            let _ = join(
                async {
                    loop {
                        let mut data = [0; 1];
                        client.read_characteristic(&c, &mut data[..]).await.unwrap();
                        info!("Read value: {}", data[0]);
                        Timer::after(Duration::from_secs(10)).await;
                    }
                },
                async {
                    loop {
                        let data = listener.next().await;
                        info!("Got notification: {:?} (val: {})", data.as_ref(), data.as_ref()[0]);
                    }
                },
            )
                .await;
        })
            .await;
    })
        .await;
}
