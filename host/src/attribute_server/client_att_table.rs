use core::cell::RefCell;

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::blocking_mutex::Mutex;

use super::{AttributeData, AttributeTable, Client};
use crate::att::AttErrorCode;
use crate::config::CLIENT_ATT_TABLE_SIZE;
use crate::{Error, Identity};

/// A compact, fixed-size map of client-specific attribute values (e.g. CCCDs).
///
/// Entries are stored in a flat byte buffer with a sorted index for binary-search lookups.
/// [`CLIENT_ATT_TABLE_SIZE`] determines the total storage available for both the index and values.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Debug)]
#[repr(align(2))]
pub struct ClientAttTable {
    buf: [u8; CLIENT_ATT_TABLE_SIZE],
}

impl ClientAttTable {
    const HEADER_SIZE: usize = 2;
    const ENTRY_SIZE: usize = 4;
    const END_OF_VALUES: u16 = 0x8000;

    /// Creates a new [`ClientAttTableBuilder`] for constructing a `ClientAttTable`.
    pub const fn builder() -> ClientAttTableBuilder {
        const {
            core::assert!(
                CLIENT_ATT_TABLE_SIZE >= ClientAttTable::HEADER_SIZE && CLIENT_ATT_TABLE_SIZE <= u16::MAX as usize
            )
        };

        ClientAttTableBuilder {
            buf: [0; CLIENT_ATT_TABLE_SIZE],
            values_len: 0,
        }
    }

    /// Get a read-only view of the table
    pub fn view(&self) -> ClientAttTableView<'_> {
        ClientAttTableView { buf: &self.buf }
    }

    // If `i` is a variable length attribute, set its length to `len`. For fixed length attributes, do nothing.
    fn set_variable_len(&mut self, i: usize, len: u16) {
        assert!(len as usize <= self.view().value_capacity(i));
        if self.view().index()[i].is_variable_len() {
            let start = self.view().raw_value_start(i);
            self.buf[start..][..2].copy_from_slice(&len.to_le_bytes());
        }
    }

    /// Returns a reference to the value associated with the given attribute handle, or `None` if not found.
    pub fn get(&self, key: u16) -> Option<&[u8]> {
        self.view().get(key)
    }

    /// Writes `data` to `key` starting at `offset`.
    pub fn write(&mut self, key: u16, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        if key >= Self::END_OF_VALUES {
            return Err(AttErrorCode::ATTRIBUTE_NOT_FOUND);
        }

        let i = self.view().find(key).ok_or(AttErrorCode::ATTRIBUTE_NOT_FOUND)?;
        if offset > self.view().value_len(i) {
            Err(AttErrorCode::INVALID_OFFSET)
        } else if offset + data.len() > self.view().value_capacity(i) {
            Err(AttErrorCode::INVALID_ATTRIBUTE_VALUE_LENGTH)
        } else {
            let start = self.view().value_start(i) + offset;
            let end = start + data.len();
            self.buf[start..end].copy_from_slice(data);

            self.set_variable_len(i, (offset + data.len()) as u16);

            Ok(())
        }
    }

    /// Copies values from `src` into this map for all matching keys.
    ///
    /// Keys present in this map but not in `src` are zeroed. If value sizes differ,
    /// only the smaller length is copied and the remainder is zeroed.
    pub fn set_values(&mut self, src: &ClientAttTableView<'_>) {
        for i in 0..self.view().att_count() {
            let view = self.view();
            let key = view.index()[i].key();
            match src.get(key) {
                Some(src) => {
                    let start = view.value_start(i);
                    let capacity = view.value_capacity(i);
                    let dest = &mut self.buf[start..][..capacity];

                    let copy_len = dest.len().min(src.len());
                    dest[..copy_len].copy_from_slice(&src[..copy_len]);
                    dest[copy_len..].fill(0);

                    self.set_variable_len(i, copy_len as u16);
                }
                None => {
                    let start = view.raw_value_start(i);
                    let end = view.value_end(i);
                    self.buf[start..end].fill(0);
                }
            }
        }
    }

    /// Zeros all values in the map, leaving the index structure intact.
    pub fn clear(&mut self) {
        let values_base = self.view().values_base();
        let values_end = values_base + self.view().values_len();
        self.buf[values_base..values_end].fill(0);
    }

    /// Returns the raw byte representation of the map, suitable for serialization or storage.
    pub fn raw(&self) -> &[u8] {
        self.view().raw()
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct ClientAttTableEntry([u8; 4]);

impl ClientAttTableEntry {
    const fn key(&self) -> u16 {
        let key = u16::from_le_bytes([self.0[0], self.0[1]]);
        if key == ClientAttTable::END_OF_VALUES {
            key
        } else {
            key & 0x7fff
        }
    }

    const fn offset(&self) -> usize {
        u16::from_le_bytes([self.0[2], self.0[3]]) as usize
    }

    const fn is_variable_len(&self) -> bool {
        let key = u16::from_le_bytes([self.0[0], self.0[1]]);
        key != ClientAttTable::END_OF_VALUES && (key & 0x8000) != 0
    }

    const fn set(&mut self, key: u16, offset: u16, variable_len: bool) {
        let flag = if variable_len { 0x8000 } else { 0 };
        let key = (key | flag).to_le_bytes();
        let offset = offset.to_le_bytes();
        self.0 = [key[0], key[1], offset[0], offset[1]];
    }
}

/// A read-only view over a serialized [`ClientAttTable`].
///
/// The view borrows the raw table format directly: a little-endian entry count, a sorted index of 4-byte entries, and
/// the value bytes. Unlike [`ClientAttTable`], the borrowed bytes may come from arbitrary storage and do not need the
/// owning table's alignment. Use [`try_from_raw()`](Self::try_from_raw) to validate the buffer before reading values.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClientAttTableView<'a> {
    buf: &'a [u8],
}

impl<'a> ClientAttTableView<'a> {
    /// Constructs a `ClientAttTableView` from raw serialized table bytes.
    ///
    /// The bytes are typically obtained from [`ClientAttTable::raw()`], but may also come from persistent storage or
    /// another byte buffer. Returns an error if the slice is too short, the index is malformed, or any value length is
    /// outside its encoded capacity.
    pub fn try_from_raw(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < ClientAttTable::HEADER_SIZE {
            return Err(Error::InvalidValue);
        }

        let map = Self { buf: data };

        if map.values_base() > data.len() {
            return Err(Error::InvalidValue);
        }

        // Validate the index
        let mut last_key = 0;
        let mut last_offset = 0;
        for e in map.index().iter() {
            let key = e.key();
            let offset = e.offset();
            if key <= core::mem::replace(&mut last_key, key)
                || offset < core::mem::replace(&mut last_offset, offset)
                || map.values_base() + offset > data.len()
            {
                return Err(Error::InvalidValue);
            }
        }

        // Validate variable length attributes
        for i in 0..map.att_count() {
            if map.value_end(i) < map.value_start(i) || map.value_len(i) > map.value_capacity(i) {
                return Err(Error::InvalidValue);
            }
        }

        Ok(map)
    }

    const fn att_count(&self) -> usize {
        u16::from_le_bytes([self.buf[0], self.buf[1]]) as usize
    }

    const fn values_base(&self) -> usize {
        ClientAttTable::HEADER_SIZE + self.att_count() * ClientAttTable::ENTRY_SIZE
    }

    fn values_len(&self) -> usize {
        if let Some(entry) = self.index().last() {
            if entry.key() == ClientAttTable::END_OF_VALUES {
                return entry.offset();
            }
        }

        self.buf.len() - self.values_base()
    }

    fn index(&self) -> &[ClientAttTableEntry] {
        let chunks = self.buf[ClientAttTable::HEADER_SIZE..self.values_base()]
            .as_chunks::<4>()
            .0;
        // SAFETY: ClientAttTableEntry is repr(transparent) over [u8; 4], so it has the same size and alignment as
        // [u8; 4]. Every 4-byte chunk is therefore aligned and valid for reads as a ClientAttTableEntry.
        unsafe { core::slice::from_raw_parts(chunks.as_ptr().cast::<ClientAttTableEntry>(), chunks.len()) }
    }

    fn raw_value_start(&self, i: usize) -> usize {
        let entry = self.index()[i];
        entry.offset() + self.values_base()
    }

    fn value_start(&self, i: usize) -> usize {
        let entry = self.index()[i];
        let start = entry.offset() + self.values_base();
        if entry.is_variable_len() {
            start + 2
        } else {
            start
        }
    }

    fn value_end(&self, i: usize) -> usize {
        self.index()
            .get(i + 1)
            .map(ClientAttTableEntry::offset)
            .unwrap_or(self.values_len())
            + self.values_base()
    }

    fn value_capacity(&self, i: usize) -> usize {
        self.value_end(i).saturating_sub(self.value_start(i))
    }

    fn value_len(&self, i: usize) -> usize {
        let index = self.index();
        if index[i].is_variable_len() {
            let start = self.raw_value_start(i);
            u16::from_le_bytes([self.buf[start], self.buf[start + 1]]) as usize
        } else {
            self.value_capacity(i)
        }
    }

    fn find(&self, key: u16) -> Option<usize> {
        self.index().binary_search_by_key(&key, ClientAttTableEntry::key).ok()
    }

    /// Returns a reference to the value associated with the given attribute handle, or `None` if not found.
    pub fn get(&self, key: u16) -> Option<&'a [u8]> {
        if key >= ClientAttTable::END_OF_VALUES {
            None
        } else {
            let i = self.find(key)?;
            Some(&self.buf[self.value_start(i)..][..self.value_len(i)])
        }
    }

    /// Returns the raw byte representation of the map, suitable for serialization or storage.
    pub fn raw(&self) -> &'a [u8] {
        let end = self.values_base() + self.values_len();
        &self.buf[..end]
    }
}

/// A builder for [`ClientAttTable`].
///
/// Entries must be pushed in ascending key order. Use [`build()`](Self::build) to finalize.
#[derive(Debug, Clone)]
pub struct ClientAttTableBuilder {
    buf: [u8; CLIENT_ATT_TABLE_SIZE],
    values_len: u16,
}

impl ClientAttTableBuilder {
    const HEADER_SIZE: usize = ClientAttTable::HEADER_SIZE;
    const ENTRY_SIZE: usize = ClientAttTable::ENTRY_SIZE;

    /// Adds an entry with the given attribute handle and value size.
    ///
    /// # Panics
    ///
    /// Panics if `key` is not greater than the previously pushed keys.
    pub fn push(&mut self, key: u16, value_len: u16, variable_len: bool) {
        assert!(value_len <= 512, "Bluetooth attributes must be at most 512 bytes");
        assert!(key > 0, "Bluetooth handles must be greater than 0");
        assert!(key <= 0x7fff, "Handle values above 0x7fff are reserved");
        self.push_inner(key, value_len, variable_len);
    }

    fn push_inner(&mut self, key: u16, mut value_len: u16, variable_len: bool) {
        let old_att_count = self.att_count();
        self.set_att_count(old_att_count + 1);
        let offset = self.values_len;

        if variable_len {
            value_len += 2;
        }

        self.values_len = self
            .values_len
            .checked_add(value_len)
            .expect("ClientAttTable buffer overflow");

        // If we overflow, just keep tracking the total needed size so we can report it in build()
        if self.end() <= CLIENT_ATT_TABLE_SIZE {
            let index = self.index_mut();
            if old_att_count > 0 {
                let last_key = index[old_att_count - 1].key();
                assert!(key > last_key, "keys must be inserted in ascending order");
            }
            index[old_att_count].set(key, offset, variable_len);
        }
    }

    /// Consumes the builder and returns the completed [`ClientAttTable`].
    pub fn build(mut self) -> ClientAttTable {
        let end = self.end();
        if end < CLIENT_ATT_TABLE_SIZE {
            // Add a dummy value to define the length of the last attribute value
            self.push_inner(ClientAttTable::END_OF_VALUES, 0, false)
        }

        if self.end() > CLIENT_ATT_TABLE_SIZE {
            panic!(
                "ClientAttTable buffer ({} bytes) overflow. Need {} bytes for exact size",
                CLIENT_ATT_TABLE_SIZE, end
            );
        } else if end < CLIENT_ATT_TABLE_SIZE {
            warn!(
                "ClientAttTable buffer ({} bytes) oversized. Only need {} bytes for exact size",
                CLIENT_ATT_TABLE_SIZE, end
            );
        }

        ClientAttTable { buf: self.buf }
    }

    const fn att_count(&self) -> usize {
        u16::from_le_bytes([self.buf[0], self.buf[1]]) as usize
    }

    fn set_att_count(&mut self, len: usize) {
        self.buf[..2].copy_from_slice(&(len as u16).to_le_bytes())
    }

    const fn index_mut(&mut self) -> &mut [ClientAttTableEntry] {
        let end = self.att_count() * Self::ENTRY_SIZE;
        let (_, slice) = self.buf.split_at_mut(Self::HEADER_SIZE);
        let (slice, _) = slice.split_at_mut(end);
        let chunks = slice.as_chunks_mut::<4>().0;
        // SAFETY: ClientAttTableEntry is repr(transparent) over [u8; 4], so it has the same size and alignment as
        // [u8; 4]. The mutable chunks come from the table's uniquely borrowed buffer, so the returned entries are
        // uniquely borrowed for the same lifetime.
        unsafe { core::slice::from_raw_parts_mut(chunks.as_mut_ptr() as *mut _, chunks.len()) }
    }

    const fn values_base(&self) -> usize {
        Self::HEADER_SIZE + self.att_count() * Self::ENTRY_SIZE
    }

    const fn end(&self) -> usize {
        self.values_base() + self.values_len as usize
    }
}

/// A table of CCCD values for each connected client.
pub(crate) struct ClientAttTables<M: RawMutex, const CONN_MAX: usize> {
    state: Mutex<M, RefCell<[(Client, ClientAttTable); CONN_MAX]>>,
}

impl<M: RawMutex, const CONN_MAX: usize> ClientAttTables<M, CONN_MAX> {
    pub(crate) fn new<const ATT_MAX: usize>(att_table: &AttributeTable<'_, M, ATT_MAX>) -> Self {
        let mut builder = ClientAttTable::builder();
        att_table.iterate(|at| {
            for (handle, att) in at {
                if let AttributeData::ClientSpecific { variable_len, capacity } = att.data {
                    builder.push(handle, capacity, variable_len);
                }
            }
        });
        let base = builder.build();
        let values: [(Client, ClientAttTable); CONN_MAX] = core::array::from_fn(|_| (Client::default(), base.clone()));
        Self {
            state: Mutex::new(RefCell::new(values)),
        }
    }

    pub(crate) fn connect(&self, peer_identity: &Identity) -> Result<(), Error> {
        self.state.lock(|n| {
            trace!("[server] searching for peer {:?}", peer_identity);
            let mut n = n.borrow_mut();
            let empty_slot = Identity::default();
            for (client, table) in n.iter_mut() {
                if client.identity.match_identity(peer_identity) {
                    // trace!("[server] found! table = {:?}", *table);
                    client.is_connected = true;
                    return Ok(());
                } else if client.identity == empty_slot {
                    //  trace!("[server] empty slot: connecting");
                    client.is_connected = true;
                    client.set_identity(*peer_identity);
                    return Ok(());
                }
            }
            trace!("[server] all slots full...");
            // if we got here all slots are full; replace the first disconnected client
            for (client, table) in n.iter_mut() {
                if !client.is_connected {
                    trace!("[server] booting disconnected peer {:?}", client.identity);
                    client.is_connected = true;
                    client.set_identity(*peer_identity);
                    // erase the previous client's config
                    table.clear();
                    return Ok(());
                }
            }
            // Should be unreachable if the max connections (CONN_MAX) matches that defined
            // in HostResources...
            warn!("[server] unable to obtain client attributes slot");
            Err(Error::ConnectionLimitReached)
        })
    }

    pub(crate) fn disconnect(&self, peer_identity: &Identity, bonded: bool) {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, table) in n.iter_mut() {
                if client.identity.match_identity(peer_identity) {
                    if !bonded {
                        *client = Client::default();
                        table.clear();
                    } else {
                        client.is_connected = false;
                    }
                    break;
                }
            }
        })
    }

    pub(crate) fn with_value<R>(
        &self,
        peer_identity: &Identity,
        att_handle: u16,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Option<R> {
        self.state.lock(|n| {
            let n = n.borrow();
            for (client, table) in n.iter() {
                if client.identity.match_identity(peer_identity) {
                    return table.get(att_handle).map(f);
                }
            }
            None
        })
    }

    pub(crate) fn read(
        &self,
        peer_identity: &Identity,
        att_handle: u16,
        offset: usize,
        data: &mut [u8],
    ) -> Result<usize, AttErrorCode> {
        self.state.lock(|n| {
            let n = n.borrow();
            for (client, table) in n.iter() {
                if client.identity.match_identity(peer_identity) {
                    let value = table.get(att_handle).ok_or(AttErrorCode::ATTRIBUTE_NOT_FOUND)?;
                    if offset > value.len() {
                        return Err(AttErrorCode::INVALID_OFFSET);
                    }
                    let value = &value[offset..];
                    let len = value.len().min(data.len());
                    data[..len].copy_from_slice(value);
                    return Ok(len);
                }
            }
            Err(AttErrorCode::ATTRIBUTE_NOT_FOUND)
        })
    }

    pub(crate) fn write(
        &self,
        peer_identity: &Identity,
        att_handle: u16,
        offset: usize,
        data: &[u8],
    ) -> Result<(), AttErrorCode> {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, table) in n.iter_mut() {
                if client.identity.match_identity(peer_identity) {
                    return table.write(att_handle, offset, data);
                }
            }
            Err(AttErrorCode::ATTRIBUTE_NOT_FOUND)
        })
    }

    pub(crate) fn get_client_att_table(&self, peer_identity: &Identity) -> Option<ClientAttTable> {
        self.state.lock(|n| {
            let n = n.borrow();
            for (client, table) in n.iter() {
                if client.identity.match_identity(peer_identity) {
                    return Some(table.clone());
                }
            }
            None
        })
    }

    pub(crate) fn set_client_att_table(&self, peer_identity: &Identity, table: &ClientAttTableView<'_>) {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, t) in n.iter_mut() {
                if client.identity.match_identity(peer_identity) {
                    trace!("Setting client attribute table {:?} for {:?}", table, peer_identity);
                    t.set_values(table);
                    break;
                }
            }
        })
    }

    pub(crate) fn update_identity(&self, identity: Identity) -> Result<(), Error> {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, _) in n.iter_mut() {
                if identity.match_identity(&client.identity) {
                    client.set_identity(identity);
                    return Ok(());
                }
            }
            Err(Error::NotFound)
        })
    }
}
