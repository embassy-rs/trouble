/// Size of L2CAP packets
#[cfg(not(any(feature = "esp32c2", feature = "esp32c6", feature = "esp32h2")))]
pub const L2CAP_MTU: usize = 128;
// Some esp chips only accept an MTU >= 255
#[cfg(any(feature = "esp32c2", feature = "esp32c6", feature = "esp32h2"))]
pub const L2CAP_MTU: usize = 255;
