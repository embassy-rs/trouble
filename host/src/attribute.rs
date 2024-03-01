use core::{fmt, mem::size_of, slice};

use crate::att::AttErrorCode;
pub use crate::att::Uuid;
use crate::byte_writer::ByteWriter;

pub const GENERIC_ACCESS_SERVICE_UUID16: Uuid = Uuid::Uuid16(0x1800u16.to_le_bytes());
pub const CHARACTERISTIC_DEVICE_NAME_UUID16: Uuid = Uuid::Uuid16(0x2A00u16.to_le_bytes());
pub const CHARACTERISTIC_APPEARANCE_UUID16: Uuid = Uuid::Uuid16(0x2A03u16.to_le_bytes());

pub const GENERIC_ATTRIBUTE_SERVICE_UUID16: Uuid = Uuid::Uuid16(0x1801u16.to_le_bytes());

pub const PRIMARY_SERVICE_UUID16: Uuid = Uuid::Uuid16(0x2800u16.to_le_bytes());
pub const CHARACTERISTIC_UUID16: Uuid = Uuid::Uuid16(0x2803u16.to_le_bytes());
pub const GENERIC_ATTRIBUTE_UUID16: Uuid = Uuid::Uuid16(0x1801u16.to_le_bytes());

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum CharacteristicProp {
    Broadcast = 0x01,
    Read = 0x02,
    WriteWithoutResponse = 0x04,
    Write = 0x08,
    Notify = 0x10,
    Indicate = 0x20,
    AuthenticatedWrite = 0x40,
    Extended = 0x80,
}

pub trait AttData {
    fn readable(&self) -> bool {
        false
    }

    fn read(&mut self, _offset: usize, _data: &mut [u8]) -> Result<usize, AttErrorCode> {
        Ok(0)
    }

    fn writable(&self) -> bool {
        false
    }

    fn write(&mut self, _offset: usize, _data: &[u8]) -> Result<(), AttErrorCode> {
        Ok(())
    }
}

impl<const N: usize> AttData for [u8; N] {
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        if offset > N {
            return Ok(0);
        }
        let len = data.len().min(N - offset);
        if len > 0 {
            data[..len].copy_from_slice(&self[offset..offset + len]);
        }
        Ok(len)
    }
}

impl<'a, const N: usize> AttData for &'a [u8; N] {
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        if offset > N {
            return Ok(0);
        }
        let len = data.len().min(N - offset);
        if len > 0 {
            data[..len].copy_from_slice(&self[offset..offset + len]);
        }
        Ok(len)
    }
}

impl<'a, const N: usize> AttData for &'a mut [u8; N] {
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        if offset > N {
            return Ok(0);
        }
        let len = data.len().min(N - offset);
        if len > 0 {
            data[..len].copy_from_slice(&self[offset..offset + len]);
        }
        Ok(len)
    }

    fn writable(&self) -> bool {
        true
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        if offset > N {
            return Ok(());
        }
        let len = data.len().min(N - offset);
        if len > 0 {
            self[offset..offset + len].copy_from_slice(&data[..len]);
        }
        Ok(())
    }
}

impl<'a> AttData for &'a [u8] {
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        let len = self.len();
        if offset > len {
            return Ok(0);
        }
        let len = data.len().min(len - offset);
        data[..len].copy_from_slice(&self[offset..offset + len]);
        Ok(len)
    }
}

impl<'a> AttData for &'a mut [u8] {
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        let len = self.len();
        if offset > len {
            return Ok(0);
        }
        let len = data.len().min(len - offset);
        data[..len].copy_from_slice(&self[offset..offset + len]);
        Ok(len)
    }

    fn writable(&self) -> bool {
        true
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        let len = self.len();
        if offset > len {
            return Ok(());
        }
        let len = data.len().min(len - offset);
        self[offset..offset + len].copy_from_slice(&data[..len]);
        Ok(())
    }
}

impl<'a, T: Sized + 'static> AttData for &'a (T,) {
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        if offset > size_of::<T>() {
            return Ok(0);
        }
        let len = data.len().min(size_of::<T>() - offset);
        if len > 0 {
            let slice = unsafe { slice::from_raw_parts(&self.0 as *const T as *const u8, size_of::<T>()) };
            // TODO: Handle big endian case
            data[..len].copy_from_slice(&slice[offset..offset + len]);
        }
        Ok(len)
    }
}

impl AttData for Uuid {
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        let val = self.as_raw();
        if offset > val.len() {
            return Ok(0);
        }
        let len = data.len().min(val.len() - offset);
        if len > 0 {
            data[..len].copy_from_slice(&val[offset..offset + len]);
        }
        Ok(len)
    }
}

impl<'a, T: Sized + 'static> AttData for &'a mut (T,) {
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        if offset > size_of::<T>() {
            return Ok(0);
        }
        let len = data.len().min(size_of::<T>() - offset);
        if len > 0 {
            let slice = unsafe { slice::from_raw_parts(&self.0 as *const T as *const u8, size_of::<T>()) };
            // TODO: Handle big endian case
            data[..len].copy_from_slice(&slice[offset..offset + len]);
        }
        Ok(len)
    }

    fn writable(&self) -> bool {
        true
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        if offset > size_of::<T>() {
            return Ok(());
        }
        let len = data.len().min(size_of::<T>() - offset);
        if len > 0 {
            let slice = unsafe { slice::from_raw_parts_mut(&mut self.0 as *mut T as *mut u8, size_of::<T>()) };
            // TODO: Handle big endian case
            slice[offset..offset + len].copy_from_slice(&data[..len]);
        }
        Ok(())
    }
}

trait IntoResult<T> {
    fn into_result(self) -> Result<T, AttErrorCode>;
}

impl<T> IntoResult<T> for T {
    fn into_result(self) -> Result<T, AttErrorCode> {
        Ok(self)
    }
}

impl<T> IntoResult<T> for Result<T, AttErrorCode> {
    fn into_result(self) -> Result<T, AttErrorCode> {
        self
    }
}

impl<T, R> AttData for (R, ())
where
    T: IntoResult<usize>,
    R: FnMut(usize, &mut [u8]) -> T,
{
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        self.0(offset, data).into_result()
    }
}

impl<U, W> AttData for ((), W)
where
    U: IntoResult<()>,
    W: FnMut(usize, &[u8]) -> U,
{
    fn writable(&self) -> bool {
        true
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        self.1(offset, data).into_result()
    }
}

impl<T, U, R, W> AttData for (R, W)
where
    T: IntoResult<usize>,
    U: IntoResult<()>,
    R: FnMut(usize, &mut [u8]) -> T,
    W: FnMut(usize, &[u8]) -> U,
{
    fn readable(&self) -> bool {
        true
    }

    fn read(&mut self, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        self.0(offset, data).into_result()
    }

    fn writable(&self) -> bool {
        true
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        self.1(offset, data).into_result()
    }
}

pub const ATT_READABLE: u8 = 0x02;
pub const ATT_WRITEABLE: u8 = 0x08;

pub struct Attribute<'a> {
    pub uuid: Uuid,
    pub handle: u16,
    pub last_handle_in_group: u16,
    pub data: AttributeData<'a>,
}
pub enum AttributeData<'d> {
    Service(Uuid),
    Ref(&'d mut dyn AttData),
    Slice(&'static [u8]),
    CharDeclaration(u8, u16, Uuid),
}

impl<'d> AttributeData<'d> {
    pub fn readable(&self) -> bool {
        match self {
            Self::Ref(d) => d.readable(),
            Self::Slice(_) => true,
            Self::CharDeclaration(_, _, _) => true,
            Self::Service(_) => true,
        }
    }

    pub fn read(&mut self, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        match self {
            Self::Ref(d) => d.read(offset, data),
            Self::Slice(val) => {
                if offset > val.len() {
                    return Ok(0);
                }
                let len = data.len().min(val.len() - offset);
                if len > 0 {
                    data[..len].copy_from_slice(&val[offset..offset + len]);
                }
                Ok(len)
            }
            Self::Service(uuid) => {
                let val = uuid.as_raw();
                if offset > val.len() {
                    return Ok(0);
                }
                let len = data.len().min(val.len() - offset);
                if len > 0 {
                    data[..len].copy_from_slice(&val[offset..offset + len]);
                }
                Ok(len)
            }
            Self::CharDeclaration(props, handle, uuid) => {
                let val = uuid.as_raw();
                if offset > val.len() + 3 {
                    return Ok(0);
                }
                let mut w = ByteWriter::new(data);
                if offset == 0 {
                    w.write_u8(*props);
                    w.write_u16_le(*handle);
                } else if offset == 1 {
                    w.write_u16_le(*handle);
                } else if offset == 2 {
                    w.write_u8(handle.to_le_bytes()[1]);
                }

                let to_write = w.available().min(val.len());

                if to_write > 0 {
                    w.append(&val[..to_write]);
                }
                Ok(w.len())
            }
        }
    }

    pub fn writable(&self) -> bool {
        match self {
            Self::Ref(d) => d.writable(),
            Self::Slice(_) => false,
            Self::CharDeclaration(_, _, _) => false,
            Self::Service(_) => false,
        }
    }

    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        match self {
            Self::Ref(d) => d.write(offset, data),
            Self::Slice(_) => Err(AttErrorCode::WriteNotPermitted),
            Self::CharDeclaration(_, _, _) => Err(AttErrorCode::WriteNotPermitted),
            Self::Service(_) => Err(AttErrorCode::WriteNotPermitted),
        }
    }
}

impl<'a> fmt::Debug for Attribute<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attribute")
            .field("uuid", &self.uuid)
            .field("handle", &self.handle)
            .field("last_handle_in_group", &self.last_handle_in_group)
            .field("readable", &self.data.readable())
            .field("writable", &self.data.writable())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for Attribute<'a> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "{}", defmt::Debug2Format(self))
    }
}

impl<'a> Attribute<'a> {
    pub fn new(uuid: Uuid, data: AttributeData<'a>) -> Attribute<'a> {
        Attribute {
            uuid,
            handle: 0,
            data,
            last_handle_in_group: 0xffff,
        }
    }

    /*
    pub(crate) fn value(&mut self) -> Result<Data, AttErrorCode> {
        let mut data = Data::default();
        if self.data.readable() {
            let len = self.data.read(0, data.as_slice_mut())?;
            data.append_len(len);
        }
        Ok(data)
    }*/
}

use heapless::Vec;
pub struct AttributesBuilder<'a, const N: usize> {
    attributes: Vec<Attribute<'a>, N>,
    handle: u16,
}

impl<'a, const N: usize> AttributesBuilder<'a, N> {
    pub fn new() -> Self {
        let mut me = Self {
            attributes: Vec::new(),
            handle: 1,
        };
        me.push(
            PRIMARY_SERVICE_UUID16,
            AttributeData::Service(GENERIC_ACCESS_SERVICE_UUID16),
        );
        me.push(CHARACTERISTIC_DEVICE_NAME_UUID16, AttributeData::Slice(b"Trouble"));
        me.push(CHARACTERISTIC_APPEARANCE_UUID16, AttributeData::Slice(&[0x02, 0x00]));
        me.finish_group();
        me
    }

    fn finish_group(&mut self) {
        for att in self.attributes.iter_mut() {
            if att.last_handle_in_group == 0 {
                att.last_handle_in_group = self.handle;
                info!("Assiging last handle {:x}", att.last_handle_in_group);
            }
        }
        // Jump to next 0x10 aligned handle
        info!("Bumping handle from {:x}", self.handle);
        self.handle = self.handle + (0x10 - (self.handle % 0x10));
        info!("Next {:x}", self.handle);
    }

    pub fn push(&mut self, uuid: Uuid, data: AttributeData<'a>) {
        self.attributes
            .push(Attribute {
                uuid,
                handle: self.handle,
                data,
                last_handle_in_group: 0,
            })
            .unwrap();
        self.handle += 1;
    }

    pub fn build(self) -> Vec<Attribute<'a>, N> {
        self.attributes
    }
}

pub struct ServiceBuilder<'a, 'b, const N: usize> {
    attributes: &'b mut AttributesBuilder<'a, N>,
}

impl<'a, 'b, const N: usize> ServiceBuilder<'a, 'b, N> {
    pub fn new(attributes: &'b mut AttributesBuilder<'a, N>, uuid: Uuid) -> Self {
        attributes.push(PRIMARY_SERVICE_UUID16, AttributeData::Service(uuid));
        Self { attributes }
    }

    pub fn add_characteristic(self, uuid: Uuid, props: &[CharacteristicProp], value: &'a mut impl AttData) -> Self {
        let mut prop = 0u8;
        for p in props {
            prop |= *p as u8
        }
        self.attributes.push(
            CHARACTERISTIC_UUID16,
            AttributeData::CharDeclaration(prop, self.attributes.handle + 1, uuid),
        );

        self.attributes.push(uuid, AttributeData::Ref(value));
        self
    }

    pub fn done(self) {
        self.attributes.finish_group();
    }
}
