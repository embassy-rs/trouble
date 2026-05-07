use core::cell::RefCell;

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::blocking_mutex::Mutex;

use super::{AttributeData, AttributeTable, Client};
use crate::att::AttErrorCode;
use crate::config::CLIENT_ATT_TABLE_SIZE;
use crate::{Error, Identity};

const HEADER_SIZE: usize = core::mem::size_of::<Header>();
const ENTRY_SIZE: usize = core::mem::size_of::<Entry>();
const VARIABLE_LEN_FLAG: u16 = 0x8000;

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
    /// Creates a new [`ClientAttTableBuilder`] for constructing a `ClientAttTable`.
    pub const fn builder() -> ClientAttTableBuilder {
        const { core::assert!(CLIENT_ATT_TABLE_SIZE >= HEADER_SIZE && CLIENT_ATT_TABLE_SIZE <= u16::MAX as usize) };

        ClientAttTableBuilder {
            buf: [0; CLIENT_ATT_TABLE_SIZE],
            values_len: 0,
        }
    }

    /// Get a read-only view of the table
    pub const fn view(&self) -> ClientAttTableView<'_> {
        ClientAttTableView { buf: &self.buf }
    }

    const fn header(&self) -> Header {
        self.view().header()
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
        if key >= VARIABLE_LEN_FLAG {
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
        for i in 0..self.header().att_count() {
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
        let header = self.header();
        self.buf[header.values_base()..header.values_end()].fill(0);
    }

    /// Returns the raw byte representation of the map, suitable for serialization or storage.
    pub fn raw(&self) -> &[u8] {
        self.view().raw()
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct Header([u8; 4]);

impl Header {
    const fn att_count(&self) -> usize {
        u16::from_le_bytes([self.0[0], self.0[1]]) as usize
    }

    const fn values_base(&self) -> usize {
        HEADER_SIZE + self.att_count() * ENTRY_SIZE
    }

    const fn values_len(&self) -> usize {
        u16::from_le_bytes([self.0[2], self.0[3]]) as usize
    }

    const fn values_end(&self) -> usize {
        self.values_base() + self.values_len()
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct Entry([u8; 4]);

impl Entry {
    const fn key(&self) -> u16 {
        let key = u16::from_le_bytes([self.0[0], self.0[1]]);
        key & !VARIABLE_LEN_FLAG
    }

    const fn offset(&self) -> usize {
        u16::from_le_bytes([self.0[2], self.0[3]]) as usize
    }

    const fn is_variable_len(&self) -> bool {
        let key = u16::from_le_bytes([self.0[0], self.0[1]]);
        (key & VARIABLE_LEN_FLAG) != 0
    }

    const fn set(&mut self, key: u16, offset: u16, variable_len: bool) {
        let flag = if variable_len { VARIABLE_LEN_FLAG } else { 0 };
        let key = (key | flag).to_le_bytes();
        let offset = offset.to_le_bytes();
        self.0 = [key[0], key[1], offset[0], offset[1]];
    }
}

/// A read-only view over a serialized [`ClientAttTable`].
///
/// The view borrows the raw table format directly: a little-endian entry count, a little-endian value byte length, a
/// sorted index of 4-byte entries, and the value bytes. Unlike [`ClientAttTable`], the borrowed bytes may come from
/// arbitrary storage and do not need the owning table's alignment. Use [`try_from_raw()`](Self::try_from_raw) to
/// validate the buffer before reading values.
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
        if data.len() < HEADER_SIZE {
            return Err(Error::InvalidValue);
        }

        let map = Self { buf: data };

        if map.header().values_end() > data.len() {
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
                || offset > map.header().values_len()
            {
                return Err(Error::InvalidValue);
            }
        }

        // Validate variable length attributes
        for i in 0..map.header().att_count() {
            if map.value_end(i) < map.value_start(i) || map.value_len(i) > map.value_capacity(i) {
                return Err(Error::InvalidValue);
            }
        }

        Ok(map)
    }

    const fn header(&self) -> Header {
        Header([self.buf[0], self.buf[1], self.buf[2], self.buf[3]])
    }

    fn index(&self) -> &[Entry] {
        let header = self.header();
        let chunks = self.buf[HEADER_SIZE..header.values_base()].as_chunks::<ENTRY_SIZE>().0;
        // SAFETY: ClientAttTableEntry is repr(transparent) over [u8; ENTRY_SIZE], so it has the same size and
        // alignment as [u8; ENTRY_SIZE]. Every ENTRY_SIZE-byte chunk is therefore aligned and valid for reads as a
        // ClientAttTableEntry.
        unsafe { core::slice::from_raw_parts(chunks.as_ptr().cast::<Entry>(), chunks.len()) }
    }

    fn raw_value_start(&self, i: usize) -> usize {
        let header = self.header();
        let entry = self.index()[i];
        entry.offset() + header.values_base()
    }

    fn value_start(&self, i: usize) -> usize {
        let header = self.header();
        let entry = self.index()[i];
        let start = entry.offset() + header.values_base();
        if entry.is_variable_len() {
            start + 2
        } else {
            start
        }
    }

    fn value_end(&self, i: usize) -> usize {
        let header = self.header();
        self.index()
            .get(i + 1)
            .map(Entry::offset)
            .unwrap_or(header.values_len())
            + header.values_base()
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
        self.index().binary_search_by_key(&key, Entry::key).ok()
    }

    /// Returns a reference to the value associated with the given attribute handle, or `None` if not found.
    pub fn get(&self, key: u16) -> Option<&'a [u8]> {
        if key >= VARIABLE_LEN_FLAG {
            None
        } else {
            let i = self.find(key)?;
            Some(&self.buf[self.value_start(i)..][..self.value_len(i)])
        }
    }

    /// Returns the raw byte representation of the map, suitable for serialization or storage.
    pub fn raw(&self) -> &'a [u8] {
        let header = self.header();
        &self.buf[..header.values_end()]
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
    /// Adds an entry with the given attribute handle and value size.
    ///
    /// # Panics
    ///
    /// Panics if `key` is not greater than the previously pushed keys.
    pub fn push(&mut self, key: u16, mut value_len: u16, variable_len: bool) {
        assert!(value_len <= 512, "Bluetooth attributes must be at most 512 bytes");
        assert!(key > 0, "Bluetooth handles must be greater than 0");
        assert!(key <= 0x7fff, "Handle values above 0x7fff are reserved");

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
        self.set_values_len(self.values_len);

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
    pub fn build(self) -> ClientAttTable {
        let end = self.end();
        if end > CLIENT_ATT_TABLE_SIZE {
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

    fn set_values_len(&mut self, len: u16) {
        self.buf[2..4].copy_from_slice(&len.to_le_bytes())
    }

    const fn index_mut(&mut self) -> &mut [Entry] {
        let end = self.att_count() * ENTRY_SIZE;
        let (_, slice) = self.buf.split_at_mut(HEADER_SIZE);
        let (slice, _) = slice.split_at_mut(end);
        let chunks = slice.as_chunks_mut::<ENTRY_SIZE>().0;
        // SAFETY: ClientAttTableEntry is repr(transparent) over [u8; ENTRY_SIZE], so it has the same size and
        // alignment as [u8; ENTRY_SIZE]. The mutable chunks come from the table's uniquely borrowed buffer, so the
        // returned entries are uniquely borrowed for the same lifetime.
        unsafe { core::slice::from_raw_parts_mut(chunks.as_mut_ptr() as *mut _, chunks.len()) }
    }

    const fn values_base(&self) -> usize {
        HEADER_SIZE + self.att_count() * ENTRY_SIZE
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

#[cfg(test)]
mod tests {
    use super::{ClientAttTable, ClientAttTableView};
    use crate::att::AttErrorCode;

    fn assert_invalid(data: &[u8]) {
        assert!(ClientAttTableView::try_from_raw(data).is_err());
    }

    #[test]
    fn raw_view_uses_declared_values_len_and_ignores_trailing_storage() {
        #[rustfmt::skip]
        let data = [
            2, 0, 5, 0,
            1, 0, 0, 0,
            2, 0x80, 2, 0,
            0xaa, 0xbb, 1, 0, 0xcc,
            0xdd, 0xee,
        ];

        let view = ClientAttTableView::try_from_raw(&data).unwrap();

        assert_eq!(view.raw(), &data[..17]);
        assert_eq!(view.get(1), Some([0xaa, 0xbb].as_slice()));
        assert_eq!(view.get(2), Some([0xcc].as_slice()));
    }

    #[test]
    fn raw_view_rejects_malformed_table_boundaries_and_index() {
        // values_len promises two bytes, but only one is present.
        assert_invalid(&[1, 0, 2, 0, 1, 0, 0, 0, 0]);

        // att_count places the index beyond the provided buffer.
        assert_invalid(&[2, 0, 0, 0, 1, 0, 0, 0]);

        // Keys must be strictly ascending after masking off the variable-length flag.
        #[rustfmt::skip]
        let duplicate_key_after_masking = [
            2, 0, 2, 0,
            1, 0, 0, 0,
            1, 0x80, 1, 0,
            0, 0,
        ];
        assert_invalid(&duplicate_key_after_masking);

        // Offsets must be monotonically increasing and remain within values_len.
        #[rustfmt::skip]
        let decreasing_offset = [
            2, 0, 4, 0,
            1, 0, 2, 0,
            2, 0, 1, 0,
            0, 0, 0, 0,
        ];
        assert_invalid(&decreasing_offset);

        #[rustfmt::skip]
        let offset_past_values_len = [
            1, 0, 1, 0,
            1, 0, 2, 0,
            0,
        ];
        assert_invalid(&offset_past_values_len);
    }

    #[test]
    fn raw_view_rejects_variable_length_exceeding_encoded_capacity() {
        #[rustfmt::skip]
        let data = [
            2, 0, 8, 0,
            1, 0x80, 0, 0,
            2, 0, 6, 0,
            5, 0, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];

        assert_invalid(&data);
    }

    #[test]
    fn variable_length_writes_append_overwrite_truncate_and_preserve_capacity() {
        let mut builder = ClientAttTable::builder();
        builder.push(1, 4, true);
        let mut table = builder.build();

        assert_eq!(table.get(1), Some([].as_slice()));
        assert_eq!(table.write(1, 1, &[0xaa]), Err(AttErrorCode::INVALID_OFFSET));

        table.write(1, 0, &[1, 2]).unwrap();
        table.write(1, 2, &[3, 4]).unwrap();
        assert_eq!(table.get(1), Some([1, 2, 3, 4].as_slice()));
        assert_eq!(
            table.write(1, 4, &[5]),
            Err(AttErrorCode::INVALID_ATTRIBUTE_VALUE_LENGTH)
        );

        table.write(1, 1, &[9]).unwrap();
        assert_eq!(table.get(1), Some([1, 9].as_slice()));

        table.write(1, 2, &[7, 8]).unwrap();
        assert_eq!(table.get(1), Some([1, 9, 7, 8].as_slice()));
    }

    #[test]
    fn set_values_copies_matching_keys_truncates_to_capacity_and_zeros_missing_keys() {
        let mut src_builder = ClientAttTable::builder();
        src_builder.push(1, 2, false);
        src_builder.push(2, 5, true);
        src_builder.push(4, 1, false);
        let mut src = src_builder.build();
        src.write(1, 0, &[0x11, 0x22]).unwrap();
        src.write(2, 0, &[0x33, 0x44, 0x55, 0x66, 0x77]).unwrap();
        src.write(4, 0, &[0x88]).unwrap();

        let mut dst_builder = ClientAttTable::builder();
        dst_builder.push(1, 4, false);
        dst_builder.push(2, 3, true);
        dst_builder.push(3, 2, false);
        let mut dst = dst_builder.build();
        dst.write(1, 0, &[0xaa, 0xaa, 0xaa, 0xaa]).unwrap();
        dst.write(2, 0, &[0xbb, 0xbb]).unwrap();
        dst.write(3, 0, &[0xcc, 0xcc]).unwrap();

        dst.set_values(&src.view());

        assert_eq!(dst.get(1), Some([0x11, 0x22, 0, 0].as_slice()));
        assert_eq!(dst.get(2), Some([0x33, 0x44, 0x55].as_slice()));
        assert_eq!(dst.get(3), Some([0, 0].as_slice()));
        assert_eq!(dst.get(4), None);
    }

    #[test]
    fn clear_zeroes_value_region_without_changing_table_shape() {
        let mut builder = ClientAttTable::builder();
        builder.push(1, 2, false);
        builder.push(2, 3, true);
        let mut table = builder.build();
        table.write(1, 0, &[0xaa, 0xbb]).unwrap();
        table.write(2, 0, &[0xcc, 0xdd]).unwrap();
        let raw_len = table.raw().len();
        let mut header_and_index = [0; 12];
        header_and_index.copy_from_slice(&table.raw()[..12]);

        table.clear();

        assert_eq!(table.raw().len(), raw_len);
        assert_eq!(&table.raw()[..12], header_and_index.as_slice());
        assert_eq!(table.get(1), Some([0, 0].as_slice()));
        assert_eq!(table.get(2), Some([].as_slice()));
        assert_eq!(&table.raw()[12..], &[0, 0, 0, 0, 0, 0, 0]);
    }
}
