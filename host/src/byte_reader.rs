pub struct ByteReader<'d> {
    buf: &'d [u8],
    pos: usize,
}

impl<'d> ByteReader<'d> {
    pub fn new(buf: &'d [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn read_u8(&mut self) -> u8 {
        assert!(self.pos < self.buf.len());
        let b = self.buf[self.pos];
        self.pos += 1;
        b
    }

    pub fn read_u16_le(&mut self) -> u16 {
        let b = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        b
    }

    pub fn read_u32_le(&mut self) -> u32 {
        let b = u32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        b
    }

    pub fn read_u64_le(&mut self) -> u64 {
        let b = u64::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
            self.buf[self.pos + 4],
            self.buf[self.pos + 5],
            self.buf[self.pos + 6],
            self.buf[self.pos + 7],
        ]);
        self.pos += 8;
        b
    }

    pub fn consume(self) -> &'d [u8] {
        &self.buf[self.pos..]
    }

    pub fn read_slice(&mut self, n: usize) -> &'d [u8] {
        let data = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        data
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }
}
