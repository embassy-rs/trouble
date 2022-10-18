//! Utilities for decoding from and encoding into bytes.
//!
//! This module defines zero-copy (de)serialization traits, [`ToBytes`] and [`FromBytes`], as well
//! as the helper structs [`ByteWriter`] and [`ByteReader`], which wrap a `&mut [u8]` or `&[u8]`
//! and offer useful utilities to read and write values.
//!
//! All types that end up getting transmitted over the air will want to implement [`ToBytes`] and
//! [`FromBytes`]. This includes the raw PDUs sent and received on advertising and data channels,
//! as well as messages used by a high-level protocol transferred over L2CAP.
//!
//! Also defined in this module is the [`BytesOr`] type, which can be used to store objects and
//! slices of objects either as a direct reference or as a `&[u8]` that is lazily decoded.
//!
//! [`ToBytes`]: trait.ToBytes.html
//! [`FromBytes`]: trait.FromBytes.html
//! [`ByteWriter`]: struct.ByteWriter.html
//! [`ByteReader`]: struct.ByteReader.html
//! [`BytesOr`]: struct.BytesOr.html

use zerocopy::LayoutVerified;

use crate::Error;
use core::marker::PhantomData;
use core::{cmp, fmt, iter, mem};

/// Reference to a `T`, or to a byte slice that can be decoded as a `T`.
///
/// # Motivation
///
/// Many packets can contain dynamically-sized lists of objects. These packets all need to implement
/// [`ToBytes`] and [`FromBytes`]. For [`FromBytes`], it is impossible to go from `&[u8]` to `&[T]`.
///
/// A workaround is to just store the `&[u8]` and decode `T`s only when necessary. However, this
/// isn't very type-safe and also makes it difficult to create the type when you have a list of
/// `T`s, but can't easily get a `&[u8]` (such as when creating a packet to be sent out). You'd have
/// to define your own byte buffer and serialize the `T`s into it, which is problematic due to the
/// potentially unknown size requirement and lifetime management.
///
/// A workaround around the workaround would be to use 2 types for the same packet: One storing a
/// `&[u8]` and implementing [`FromBytes`] which can only do *deserialization*, and one storing a
/// `&[T]` and implementing [`ToBytes`], which can only do *serialization*. This has the obvious
/// drawback of essentially duplicating all packet definitions.
///
/// Rubble's solution for this is `BytesOr`: It can store either an `&[u8]` or a `&T` (where `T`
/// might be a slice), and always implements [`ToBytes`] and [`FromBytes`] if `T` does. Methods
/// allowing access to the stored `T` (or the elements in the `&[T]` slice) will either directly
/// return the value, or decode it using its [`FromBytes`] implementation.
///
/// When encoding a `T`, [`BytesOr::from_ref`] can be used to store a `&T` in a `BytesOr`, which can
/// then be turned into bytes via [`ToBytes`]. When decoding data, [`FromBytes`] can be used to
/// create a `BytesOr` from bytes.
///
/// This type can also be used in structures when storing a `T` directly is not desirable due to
/// size concerns: It could be inside a rarely-encountered variant or would blow up the total size
/// of the containing enum). The size of `BytesOr` is currently 2 `usize`s plus a discriminant byte,
/// but could potentially be (unsafely) reduced further, should that be required.
///
/// [`ToBytes`]: trait.ToBytes.html
/// [`FromBytes`]: trait.FromBytes.html
/// [`BytesOr::from_ref`]: #method.from_ref
pub struct BytesOr<'a, T: ?Sized>(Inner<'a, T>);

impl<'a, T: ?Sized> From<&'a T> for BytesOr<'a, T> {
    fn from(r: &'a T) -> Self {
        BytesOr(Inner::Or(r))
    }
}

enum Inner<'a, T: ?Sized> {
    Bytes(&'a [u8]),
    Or(&'a T),
}

impl<'a, T: ?Sized> Clone for Inner<'a, T> {
    fn clone(&self) -> Self {
        match self {
            Inner::Bytes(b) => Inner::Bytes(b),
            Inner::Or(t) => Inner::Or(t),
        }
    }
}

impl<'a, T: ?Sized> Clone for BytesOr<'a, T> {
    fn clone(&self) -> Self {
        BytesOr(self.0)
    }
}

impl<'a, T: ?Sized> Copy for BytesOr<'a, T> {}
impl<'a, T: ?Sized> Copy for Inner<'a, T> {}

impl<'a, T: fmt::Debug + FromBytes<'a> + Copy> fmt::Debug for BytesOr<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.read().fmt(f)
    }
}

impl<'a, T: fmt::Debug + FromBytes<'a> + Copy> fmt::Debug for BytesOr<'a, [T]> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<'a, T: ?Sized> BytesOr<'a, T> {
    /// Creates a `BytesOr` that holds on to a `T` via reference.
    ///
    /// For creating a `BytesOr` that references a byte slice, the [`FromBytes`] impl(s) can be
    /// used.
    ///
    /// [`FromBytes`]: trait.FromBytes.html
    pub fn from_ref(value: &'a T) -> Self {
        BytesOr(Inner::Or(value))
    }
}

/// Creates a `BytesOr` that stores bytes that can be decoded to a `T`.
///
/// This will check that `bytes` can indeed be decoded as a `T` using its [`FromBytes`]
/// implementation, and returns an error if not.
///
/// The [`ByteReader`] will be advanced to point past the decoded `T` if the conversion succeeds.
///
/// [`FromBytes`]: trait.FromBytes.html
/// [`ByteReader`]: struct.ByteReader.html
impl<'a, T: FromBytes<'a>> FromBytes<'a> for BytesOr<'a, T> {
    fn from_bytes(bytes: &mut ByteReader<'a>) -> Result<Self, Error> {
        let raw = bytes.as_raw_bytes();
        T::from_bytes(bytes)?;
        let used = raw.len() - bytes.bytes_left();

        Ok(BytesOr(Inner::Bytes(&raw[..used])))
    }
}

/// Creates a `BytesOr` that stores bytes that can be decoded to a sequence of `T`s.
///
/// This will check that `bytes` can indeed be decoded as a sequence of `T`s, and returns an error
/// if not. Note that this will read *as many `T`s as possible* until the [`ByteReader`] is at its
/// end of input. Any trailing data after the list of `T`s will result in an error.
///
/// The [`ByteReader`] will be advanced to point past the decoded list of `T`s if the conversion
/// succeeds. In that case, it will be at EOF and no more data can be read.
///
/// [`ByteReader`]: struct.ByteReader.html
impl<'a, T: FromBytes<'a>> FromBytes<'a> for BytesOr<'a, [T]> {
    fn from_bytes(bytes: &mut ByteReader<'a>) -> Result<Self, Error> {
        let raw = bytes.as_raw_bytes();
        while !bytes.is_empty() {
            T::from_bytes(bytes)?;
        }

        Ok(BytesOr(Inner::Bytes(raw)))
    }
}

impl<'a, T: ToBytes + ?Sized> ToBytes for BytesOr<'a, T> {
    fn to_bytes(&self, buffer: &mut ByteWriter<'_>) -> Result<(), Error> {
        match self.0 {
            Inner::Bytes(b) => buffer.write_slice(b),
            Inner::Or(t) => t.to_bytes(buffer),
        }
    }
}

impl<'a, T: Copy + FromBytes<'a>> BytesOr<'a, T> {
    /// Reads the `T`, possibly by parsing the stored bytes.
    ///
    /// If `self` already stores a reference to a `T`, the `T` will just be copied out. If `self`
    /// stores a byte slice, the `T` will be parsed using its [`FromBytes`] implementation.
    ///
    /// [`FromBytes`]: trait.FromBytes.html
    pub fn read(&self) -> T {
        match self.0 {
            Inner::Bytes(b) => {
                let mut bytes = ByteReader::new(b);
                let t = T::from_bytes(&mut bytes).unwrap();
                assert!(bytes.is_empty());
                t
            }
            Inner::Or(t) => *t,
        }
    }
}

impl<'a, T: Copy + FromBytes<'a>> BytesOr<'a, T> {
    /// Returns an iterator over all `T`s stored in `self` (which is just one `T` in this case).
    ///
    /// This method exists to mirror its twin implemented for `BytesOr<'a, [T]>`.
    pub fn iter(&self) -> impl Iterator<Item = T> + 'a {
        iter::once(self.read())
    }
}

impl<'a, T: Copy + FromBytes<'a>> BytesOr<'a, [T]> {
    /// Returns an iterator over all `T`s stored in `self`.
    ///
    /// The iterator will copy or decode `T`s out of `self`.
    pub fn iter(&self) -> impl Iterator<Item = T> + 'a {
        IterBytesOr { inner: *self }
    }
}

/// An iterator over values stored in a `BytesOr`.
struct IterBytesOr<'a, T> {
    inner: BytesOr<'a, [T]>,
}

impl<'a, T: Copy + FromBytes<'a>> Iterator for IterBytesOr<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner.0 {
            Inner::Bytes(b) => {
                if b.is_empty() {
                    None
                } else {
                    // Read a `T` and overwrite our `b` with the left-over data
                    let mut reader = ByteReader::new(*b);
                    let t = T::from_bytes(&mut reader).unwrap();
                    *b = reader.into_rest();
                    Some(t)
                }
            }
            Inner::Or(slice) => {
                let (first, rest) = slice.split_first()?;
                *slice = rest;
                Some(*first)
            }
        }
    }
}

/// Wrapper around a byte slice that can be used to encode data into bytes.
///
/// All `write_*` methods on this type will return `Error::Eof` when the underlying buffer slice is
/// full.
pub struct ByteWriter<'a>(&'a mut [u8]);

impl<'a> ByteWriter<'a> {
    /// Creates a writer that will write to `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        ByteWriter(buf)
    }

    /// Consumes `self` and returns the part of the contained buffer that has not yet been written
    /// to.
    pub fn into_rest(self) -> &'a mut [u8] {
        self.0
    }

    /// Returns the raw buffer this `ByteWriter` would write to.
    ///
    /// Combined with `skip`, this method allows advanced operations on the underlying byte buffer.
    pub fn rest(&mut self) -> &mut [u8] {
        self.0
    }

    /// Skips the given number of bytes in the output data without writing anything there.
    ///
    /// This is a potentially dangerous operation that should only be used when necessary (eg. when
    /// the skipped data will be filled in by other code). If the skipped bytes are *not* written,
    /// they will probably contain garbage data from an earlier use of the underlying buffer.
    pub fn skip(&mut self, bytes: usize) -> Result<(), Error> {
        if self.space_left() < bytes {
            Err(Error::Eof)
        } else {
            let this = mem::replace(&mut self.0, &mut []);
            self.0 = &mut this[bytes..];
            Ok(())
        }
    }

    /// Creates and returns another `ByteWriter` that can write to the next `len` Bytes in the
    /// buffer.
    ///
    /// `self` will be modified to point after the split-off bytes.
    ///
    /// Note that if the created `ByteWriter` is not used, the bytes will contain whatever contents
    /// they had before creating `self` (ie. most likely garbage data left over from earlier use).
    /// If you are really sure you want that, `skip` is a more explicit way of accomplishing that.
    #[must_use = "data from ByteWriter will contain garbage if not used (use skip() if this is intended)"]
    pub fn split_off(&mut self, len: usize) -> Result<Self, Error> {
        if self.space_left() < len {
            Err(Error::Eof)
        } else {
            let this = mem::replace(&mut self.0, &mut []);
            let (head, tail) = this.split_at_mut(len);
            self.0 = tail;
            Ok(ByteWriter::new(head))
        }
    }

    /// Splits off the next byte in the buffer.
    ///
    /// The writer will be advanced to point to the rest of the underlying buffer.
    ///
    /// This allows filling in the value of the byte later, after writing more data.
    ///
    /// For a similar, but more flexible operation, see [`split_off`].
    ///
    /// [`split_off`]: #method.split_off
    pub fn split_next_mut(&mut self) -> Option<&'a mut u8> {
        let this = mem::replace(&mut self.0, &mut []);
        // Slight contortion to please the borrow checker:
        if this.is_empty() {
            self.0 = this;
            None
        } else {
            let (first, rest) = this.split_first_mut().unwrap();
            self.0 = rest;
            Some(first)
        }
    }

    /// Returns the number of bytes that can be written to `self` until it is full.
    pub fn space_left(&self) -> usize {
        self.0.len()
    }

    /// Writes all bytes from `other` to `self`.
    ///
    /// Returns `Error::Eof` when `self` does not have enough space left to fit `other`. In that
    /// case, `self` will not be modified.
    pub fn write_slice(&mut self, other: &[u8]) -> Result<(), Error> {
        if self.space_left() < other.len() {
            Err(Error::Eof)
        } else {
            self.0[..other.len()].copy_from_slice(other);
            let this = mem::replace(&mut self.0, &mut []);
            self.0 = &mut this[other.len()..];
            Ok(())
        }
    }

    /// Writes as many bytes as can fit from `other` into `self`.
    ///
    /// Returns the number of bytes written.
    pub fn write_slice_truncate(&mut self, other: &[u8]) -> usize {
        let num = cmp::min(self.space_left(), other.len());
        let other = &other[..num];
        self.write_slice(other).unwrap();
        num
    }

    /// Writes a single byte to `self`.
    ///
    /// Returns `Error::Eof` when no space is left.
    pub fn write_u8(&mut self, byte: u8) -> Result<(), Error> {
        let first = self.split_next_mut().ok_or(Error::Eof)?;
        *first = byte;
        Ok(())
    }

    /// Writes a `u16` to `self`, using Little Endian byte order.
    ///
    /// If `self` does not have enough space left, an error will be returned and no bytes will be
    /// written to `self`.
    pub fn write_u16_le(&mut self, value: u16) -> Result<(), Error> {
        self.write_slice(&value.to_le_bytes())
    }

    /// Writes a `u32` to `self`, using Little Endian byte order.
    ///
    /// If `self` does not have enough space left, an error will be returned and no bytes will be
    /// written to `self`.
    pub fn write_u32_le(&mut self, value: u32) -> Result<(), Error> {
        self.write_slice(&value.to_le_bytes())
    }

    /// Writes a `u64` to `self`, using Little Endian byte order.
    ///
    /// If `self` does not have enough space left, an error will be returned and no bytes will be
    /// written to `self`.
    pub fn write_u64_le(&mut self, value: u64) -> Result<(), Error> {
        self.write_slice(&value.to_le_bytes())
    }

    /// Writes a value to the stream by transmuting it to bytes.
    pub fn write_obj<T: zerocopy::AsBytes>(&mut self, obj: &T) -> Result<(), Error> {
        self.write_slice(obj.as_bytes())
    }
}

/// Allows reading values from a borrowed byte slice.
pub struct ByteReader<'a>(&'a [u8]);

impl<'a> ByteReader<'a> {
    /// Creates a new `ByteReader` that will read from the given byte slice.
    pub fn new(bytes: &'a [u8]) -> Self {
        ByteReader(bytes)
    }

    /// Returns a reference to the raw bytes in `self`, without advancing `self` or reading any
    /// data.
    pub fn as_raw_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Consumes `self` and returns the part of the contained buffer that has not yet been read
    /// from.
    pub fn into_rest(self) -> &'a [u8] {
        self.0
    }

    /// Skips the given number of bytes in the input data without inspecting them.
    ///
    /// This is a potentially dangerous operation that should only be used when the bytes really do
    /// not matter.
    pub fn skip(&mut self, bytes: usize) -> Result<(), Error> {
        if self.bytes_left() < bytes {
            Err(Error::Eof)
        } else {
            self.0 = &self.0[bytes..];
            Ok(())
        }
    }

    /// Creates and returns another `ByteReader` that will read from the next `len` Bytes in the
    /// buffer.
    ///
    /// `self` will be modified to point after the split-off bytes, and will continue reading from
    /// there.
    ///
    /// Note that if the created `ByteReader` is not used, the bytes will be ignored. If you are
    /// really sure you want that, `skip` is a more explicit way of accomplishing that.
    #[must_use = "data from ByteReader will be ignored if not used (use skip() if this is intended)"]
    pub fn split_off(&mut self, len: usize) -> Result<Self, Error> {
        if self.bytes_left() < len {
            Err(Error::Eof)
        } else {
            let (head, tail) = (&self.0[..len], &self.0[len..]);
            self.0 = tail;
            Ok(ByteReader::new(head))
        }
    }

    /// Returns the number of bytes that can still be read from `self`.
    pub fn bytes_left(&self) -> usize {
        self.0.len()
    }

    /// Returns whether `self` is at the end of the underlying buffer (EOF).
    ///
    /// If this returns `true`, no data can be read from `self` anymore.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Reads a `zerocopy`-supported object from the stream by transmuting an appropriate number of
    /// bytes.
    pub fn read_obj<T: zerocopy::FromBytes + zerocopy::Unaligned>(
        &mut self,
    ) -> Result<&'a T, Error> {
        let (obj, rest): (LayoutVerified<&'a [u8], T>, _) =
            zerocopy::LayoutVerified::new_unaligned_from_prefix(self.0).ok_or(Error::Eof)?;
        self.0 = rest;
        Ok(obj.into_ref())
    }

    /// Reads a byte slice of length `len` from `self`.
    ///
    /// If `self` contains less than `len` bytes, `Error::Eof` will be returned and `self` will not
    /// be modified.
    pub fn read_slice(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if self.bytes_left() < len {
            Err(Error::Eof)
        } else {
            let slice = &self.0[..len];
            self.0 = &self.0[len..];
            Ok(slice)
        }
    }

    /// Reads a byte-array-like type `S` from `self`.
    ///
    /// `S` must implement `Default` and `AsMut<[u8]>`, which allows using small arrays up to 32
    /// bytes as well as datastructures from `alloc` (eg. `Box<[u8]>` or `Vec<u8>`).
    pub fn read_array<S>(&mut self) -> Result<S, Error>
    where
        S: Default + AsMut<[u8]>,
    {
        let mut buf = S::default();
        let slice = buf.as_mut();
        if self.bytes_left() < slice.len() {
            return Err(Error::Eof);
        }

        slice.copy_from_slice(&self.0[..slice.len()]);
        self.0 = &self.0[slice.len()..];
        Ok(buf)
    }

    /// Reads the remaining bytes from `self`.
    pub fn read_rest(&mut self) -> &'a [u8] {
        let rest = self.0;
        self.0 = &[];
        rest
    }

    /// Reads a single byte from `self`.
    ///
    /// Returns `Error::Eof` when `self` is empty.
    pub fn read_u8(&mut self) -> Result<u8, Error> {
        Ok(self.read_array::<[u8; 1]>()?[0])
    }

    /// Reads a `u16` from `self`, using Little Endian byte order.
    pub fn read_u16_le(&mut self) -> Result<u16, Error> {
        let arr = self.read_array::<[u8; 2]>()?;
        Ok(u16::from_le_bytes(arr))
    }

    /// Reads a `u32` from `self`, using Little Endian byte order.
    pub fn read_u32_le(&mut self) -> Result<u32, Error> {
        let arr = self.read_array::<[u8; 4]>()?;
        Ok(u32::from_le_bytes(arr))
    }

    /// Reads a `u64` from `self`, using Little Endian byte order.
    pub fn read_u64_le(&mut self) -> Result<u64, Error> {
        let arr = self.read_array::<[u8; 8]>()?;
        Ok(u64::from_le_bytes(arr))
    }
}

/// Trait for encoding a value into a byte buffer.
pub trait ToBytes {
    /// Converts `self` to bytes and writes them into `writer`, advancing `writer` to point past the
    /// encoded value.
    ///
    /// If `writer` does not contain enough space, an error will be returned and the state of the
    /// buffer is unspecified (eg. `self` may be partially written into `writer`).
    fn to_bytes(&self, writer: &mut ByteWriter<'_>) -> Result<(), Error>;
}

/// Trait for decoding values from a byte slice.
pub trait FromBytes<'a>: Sized {
    /// Decode a `Self` from a byte slice, advancing `bytes` to point past the data that was read.
    ///
    /// If `bytes` contains data not valid for the target type, or contains an insufficient number
    /// of bytes, an error will be returned and the state of `bytes` is unspecified (it can point to
    /// arbitrary data).
    fn from_bytes(bytes: &mut ByteReader<'a>) -> Result<Self, Error>;
}

impl<T: ToBytes> ToBytes for [T] {
    fn to_bytes(&self, writer: &mut ByteWriter<'_>) -> Result<(), Error> {
        for t in self {
            t.to_bytes(writer)?;
        }
        Ok(())
    }
}

impl<'a> ToBytes for &'a [u8] {
    fn to_bytes(&self, writer: &mut ByteWriter<'_>) -> Result<(), Error> {
        writer.write_slice(*self)
    }
}

impl<'a> FromBytes<'a> for &'a [u8] {
    fn from_bytes(bytes: &mut ByteReader<'a>) -> Result<Self, Error> {
        Ok(bytes.read_rest())
    }
}

impl<'a> FromBytes<'a> for u8 {
    fn from_bytes(bytes: &mut ByteReader<'a>) -> Result<Self, Error> {
        bytes.read_u8()
    }
}

/// A zerocopy-compatible field of type `T`, but represented as `PRIM`.
#[derive(zerocopy::FromBytes, zerocopy::Unaligned)]
#[repr(transparent)]
pub struct Field<PRIM: zerocopy::FromBytes, T> {
    prim: PRIM,
    _p: PhantomData<T>,
}

impl<PRIM: zerocopy::FromBytes + Copy, T> Copy for Field<PRIM, T> {}

impl<PRIM: zerocopy::FromBytes + Clone, T> Clone for Field<PRIM, T> {
    fn clone(&self) -> Self {
        Self {
            prim: self.prim.clone(),
            _p: PhantomData,
        }
    }
}

impl<PRIM, T> Field<PRIM, T>
where
    PRIM: zerocopy::FromBytes + Copy,
    T: RawRepr<PRIM>,
{
    pub fn new(raw: PRIM) -> Self {
        Self {
            prim: raw,
            _p: PhantomData,
        }
    }

    pub fn raw(&self) -> &PRIM {
        &self.prim
    }

    /// Extracts the typed representation of `self`.
    pub fn value(&self) -> T {
        T::from_raw(self.prim)
    }
}

/// The debug representation is that of `T`.
impl<PRIM, T> fmt::Debug for Field<PRIM, T>
where
    PRIM: zerocopy::FromBytes + Copy,
    T: RawRepr<PRIM> + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value().fmt(f)
    }
}

impl<PRIM, T> defmt::Format for Field<PRIM, T>
where
    PRIM: zerocopy::FromBytes + Copy,
    T: RawRepr<PRIM> + defmt::Format,
{
    fn format(&self, f: defmt::Formatter<'_>) {
        self.value().format(f);
    }
}

/// Indicates that a type can be cheaply converted from and to a raw representation of type `T`.
///
/// This is meant to be used with [`Field`], and allows representing types as their raw contents in
/// memory, while allowing ergonomic conversion to their typed representation.
pub trait RawRepr<T> {
    fn from_raw(raw: T) -> Self;
    fn as_raw(&self) -> T;
}
