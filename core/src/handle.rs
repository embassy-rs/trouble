use serde::{Serialize, Serializer};

#[derive(Copy, Clone, Debug)]
pub struct InvalidHandle;

#[derive(Copy, Clone)]
pub struct Handle {
    handle: u16,
}

impl Serialize for Handle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_u16(self.handle)
    }
}

impl Handle {
    pub fn new(handle: u16) -> Result<Self, InvalidHandle> {
        if handle > 0x0EFF {
            return Err(InvalidHandle);
        }
        Ok( Self {
            handle
        })
    }
}