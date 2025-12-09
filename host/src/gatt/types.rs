/// Represents a table of attributes that is read or written
pub trait AttributeTable {
    /// Error returned when reading or writing attributes;
    type Error;

    type Iterator: Iterator<Item = Self::Attribute>;
    type Attribute: Attribute;

    fn iter(&self) -> Self::Iterator;

    async fn read_attribute(&self, handle: u16, offset: u16, output: &mut [u8]) -> Result<usize, Self::Error>;
    async fn write_attribute(&self, handle: u16, offset: u16, input: &[u8]) -> Result<(), Self::Error>;
}

pub trait Attribute {
    fn handle(&self) -> u16;
}

pub trait ClientState {
    /// Error returned when updating client state.
    type Error;

    /// Signal connection established to a peer.
    fn connect(&self, peer: &Identity) -> Result<(), Error>;

    /// Signal disconnection from peer.
    fn disconnect(&self, peer: &Identity) -> Result<(), Error>;

    /// Signal that peer has subscribed/unsubscribed for notifications for attribute handle.
    fn set_notify(&self, peer: &Identity, handle: u16, enable: bool);

    /// Signal that peer has subscribed/unsubscribed for indications for attribute handle.
    fn set_indicate(&self, peer: &Identity, handle: u16, enable: bool);

    /// Query whether or not a peer is subscribed to notifications for a handle
    fn should_notify(&self, peer: &Identity, handle: u16) -> bool;

    /// Query whether or not a peer is subscribed to indications for a handle
    fn should_indicate(&self, peer: &Identity, handle: u16) -> bool;
}
