pub struct ByteWriter<'d> {
    buf: &'d mut [u8],
    pos: usize,
}

impl<'d> ByteWriter<'d> {
    pub fn new(buf: &'d mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn write_u8(&mut self, val: u8) {
        self.buf[self.pos] = val;
        self.pos += 1;
    }

    pub fn write_u16_le(&mut self, val: u16) {
        let b = val.to_le_bytes();
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

    pub fn append(&mut self, data: &[u8]) {
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
    }

    pub fn len(&self) -> usize {
        self.pos
    }
}
