use core::{fmt, mem::size_of, slice};

use crate::{
    att::{AttErrorCode, Uuid},
    Data,
};

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
    pub data: &'a mut dyn AttData,
    pub last_handle_in_group: u16,
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

impl<'a> Attribute<'a> {
    pub fn new(uuid: Uuid, data: &'a mut impl AttData) -> Attribute<'a> {
        Attribute {
            uuid,
            handle: 0,
            data,
            last_handle_in_group: 0,
        }
    }

    pub(crate) fn value(&mut self) -> Result<Data, AttErrorCode> {
        let mut data = Data::default();
        if self.data.readable() {
            let len = self.data.read(0, data.as_slice_mut())?;
            data.append_len(len);
        }
        Ok(data)
    }
}
