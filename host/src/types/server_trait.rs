use crate::{
    prelude::{Characteristic, Connection},
    BleHostError, Error,
};
use bt_hci::controller::Controller;

pub trait GattServerInterface {
    type ControllerError;
    fn get<F: FnMut(&[u8]) -> T, T>(&self, handle: Characteristic, f: F) -> Result<T, Error>;

    fn set(&self, handle: Characteristic, input: &[u8]) -> Result<(), Error>;

    async fn notify(
        &self,
        handle: Characteristic,
        connection: &Connection<'_>,
        value: &[u8],
    ) -> Result<(), BleHostError<Self::ControllerError>>;
}
