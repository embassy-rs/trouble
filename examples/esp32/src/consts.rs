/// Size of L2CAP packets
///
/// 'esp-hal' likely has a bug, causing _some_ ESP32 chips to give "Invalid HCI Command Parameters" BLE errors at launch,
/// if the L2CAP MTU is set low enough.
///
/// The error producing ranges go:
///   - ESP32-C6: x..<255             // examples with 128, 251 would fail
///   - ESP32-C2: RANGE NOT KNOWN     // not having the hardware
///   - ESP32-H2: RANGE NOT KNOWN     // not having the hardware
///   - ESP32, -C3, -S2: claimed not to be affected [1]
///       [1]: https://github.com/embassy-rs/trouble/pull/236#issuecomment-2586457641
///
///   - ESP32-S3: 251 (presumably x..<255), see [2]:
///       [2]: https://matrix.to/#/#esp-rs:matrix.org/$ZzC-QWHocidnEXtn5vAxcsGnUDLTnk4NGf9Cr7kVrjo
///
/// Playing safe by using '255' (that works for all)
pub const L2CAP_MTU: usize = 255;