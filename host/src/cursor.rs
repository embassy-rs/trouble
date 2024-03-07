//! Module for cursors over a byte slice.
//!

use crate::codec::{Decode, Encode, Error};

// Not a byte writer. It is just a cursor to track where a byte slice is being written.
pub struct WriteCursor<'d> {
    pos: usize,
    data: &'d mut [u8],
}

impl<'d> WriteCursor<'d> {
    pub fn new(data: &'d mut [u8]) -> Self {
        Self { pos: 0, data }
    }

    pub fn reset(&mut self) {
        self.pos = 0;
    }

    pub fn truncate(&mut self, npos: usize) {
        self.pos = self.pos.min(npos);
    }

    // Split into two cursors
    pub fn split(&mut self, nbytes: usize) -> Result<(WriteCursor<'_>, WriteCursor<'_>), Error> {
        if self.available() < nbytes {
            Err(Error::InsufficientSpace)
        } else {
            let (first, second) = self.data.split_at_mut(nbytes);
            Ok((
                WriteCursor { data: first, pos: 0 },
                WriteCursor { pos: 0, data: second },
            ))
        }
    }

    /// Append byte slice
    pub fn append(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.available() < data.len() {
            Err(Error::InsufficientSpace)
        } else {
            self.data[self.pos..self.pos + data.len()].copy_from_slice(data);
            self.pos += data.len();
            Ok(())
        }
    }

    /// Write fixed sized type
    pub fn write<E: Encode>(&mut self, data: E) -> Result<(), Error> {
        if self.available() < data.size() {
            Err(Error::InsufficientSpace)
        } else {
            data.encode(&mut self.data[self.pos..self.pos + data.size()])?;
            self.pos += data.size();
            Ok(())
        }
    }

    pub fn write_ref<E: Encode>(&mut self, data: &E) -> Result<(), Error> {
        if self.available() < data.size() {
            Err(Error::InsufficientSpace)
        } else {
            data.encode(&mut self.data[self.pos..self.pos + data.size()])?;
            self.pos += data.size();
            Ok(())
        }
    }

    // Reserve a spot for a slice of data and return it
    pub fn write_buf<'m>(&'m mut self) -> SliceWriter<'m, 'd> {
        SliceWriter { writer: self }
    }

    pub fn available(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn finish(self) -> &'d mut [u8] {
        &mut self.data[..self.pos]
    }
}

pub struct SliceWriter<'m, 'd> {
    writer: &'m mut WriteCursor<'d>,
}

impl<'m, 'd> SliceWriter<'m, 'd> {
    pub fn finish(self, len: usize) -> Result<(), Error> {
        if self.writer.available() < len {
            Err(Error::InsufficientSpace)
        } else {
            self.writer.pos += len;
            Ok(())
        }
    }
}

impl<'m, 'd> AsRef<[u8]> for SliceWriter<'m, 'd> {
    fn as_ref(&self) -> &[u8] {
        &self.writer.data[self.writer.pos..]
    }
}

impl<'m, 'd> AsMut<[u8]> for SliceWriter<'m, 'd> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.writer.data[self.writer.pos..]
    }
}

// Not a byte reader. It is just a cursor to track where a byte slice is being written.
pub struct ReadCursor<'d> {
    pos: usize,
    data: &'d [u8],
}

impl<'d> ReadCursor<'d> {
    pub fn new(data: &'d [u8]) -> Self {
        Self { pos: 0, data }
    }

    pub fn read<T: Decode>(&mut self) -> Result<T, Error> {
        let src = &self.data[self.pos..];
        let val = T::decode(src)?;
        self.pos += val.size();
        Ok(val)
    }

    pub fn slice(&mut self, nbytes: usize) -> Result<&[u8], Error> {
        if self.available() < nbytes {
            Err(Error::InsufficientSpace)
        } else {
            let src = &self.data[self.pos..self.pos + nbytes];
            self.pos += nbytes;
            Ok(src)
        }
    }

    pub fn available(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn remaining(self) -> &'d [u8] {
        &self.data[self.pos..]
    }

    pub fn consume(self, nbytes: usize) -> Result<&'d [u8], Error> {
        if self.available() < nbytes {
            Err(Error::InsufficientSpace)
        } else {
            Ok(&self.data[self.pos..self.pos + nbytes])
        }
    }

    pub fn reset(&mut self) {
        self.pos = 0;
    }
}
