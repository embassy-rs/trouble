use trouble_host::prelude::*;

#[gatt_service(uuid = "0x180f")]
struct HeartRateService {
   #[characteristic(uuid = "0x2A37", read, notify)]
//    #[descriptor(uuid = "0x2902", value = "heart rate in bpm")]
   rate: f32,
   #[characteristic(uuid = "0x2A38", read)]
//    #[descriptor(uuid = "0x2902", value = "body sensor location")]
   location: f32,
   #[characteristic(uuid = "0x2A39", write)]
//    #[descriptor(uuid = "0x2902", value = "heart rate control point")]
   control: u8,
   #[characteristic(uuid = "0x2A63", read, notify)]
//    #[descriptor(uuid = "0x2902", value = "energy expended")]
   energy_expended: u16,
}