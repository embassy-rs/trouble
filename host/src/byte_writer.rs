use crate::att::Uuid;

pub struct ByteWriter<'d> {
    buf: &'d mut [u8],
    pos: usize,
}

impl<'d> ByteWriter<'d> {
    pub fn new(buf: &'d mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn available(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn get(&mut self, offset: usize) -> u8 {
        self.buf[offset]
    }

    pub fn set(&mut self, offset: usize, value: u8) {
        self.buf[offset] = value;
    }

    pub fn reserve(&mut self, n: usize) {
        self.pos += n;
    }

    pub fn write_u8(&mut self, val: u8) {
        self.buf[self.pos] = val;
        self.pos += 1;
    }

    pub fn write_u16_le(&mut self, val: u16) {
        let b = val.to_le_bytes();
        self.append(&b);
    }

    pub fn write_u16_be(&mut self, val: u16) {
        let b = val.to_be_bytes();
        self.append(&b);
    }

    pub fn write_u32_le(&mut self, val: u32) {
        let b = val.to_le_bytes();
        self.append(&b);
    }

    pub fn write_u64_le(&mut self, val: u64) {
        let b = val.to_le_bytes();
        self.append(&b);
    }

    pub fn slice(&mut self, n: usize) -> &mut [u8] {
        let s = &mut self.buf[self.pos..self.pos + n];
        self.pos += n;
        s
    }

    pub fn prepare<'m>(&'m mut self) -> SliceWriter<'m, 'd> {
        SliceWriter { writer: self }
    }

    pub fn append(&mut self, data: &[u8]) {
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
    }

    pub fn append_uuid(&mut self, uuid: &Uuid) {
        match uuid {
            Uuid::Uuid16(_) => {
                let slice = self.slice(2);
                uuid.bytes(slice);
            }
            Uuid::Uuid128(value) => {
                let slice = self.slice(value.len());
                uuid.bytes(slice);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn truncate(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub fn done(self) -> &'d mut [u8] {
        &mut self.buf[..self.pos]
    }
}

pub struct SliceWriter<'m, 'd> {
    writer: &'m mut ByteWriter<'d>,
}

impl<'m, 'd> SliceWriter<'m, 'd> {
    pub fn commit(self, len: usize) {
        self.writer.pos += len;
    }
}

impl<'m, 'd> AsRef<[u8]> for SliceWriter<'m, 'd> {
    fn as_ref(&self) -> &[u8] {
        &self.writer.buf[self.writer.pos..]
    }
}

impl<'m, 'd> AsMut<[u8]> for SliceWriter<'m, 'd> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.writer.buf[self.writer.pos..]
    }
}
