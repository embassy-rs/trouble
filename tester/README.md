# TrouBLE Tester

TrouBLE Tester is a Bluetooth Test Protocol (BTP) implementation for automated
conformance testing of the TrouBLE Bluetooth host using the Bluetooth SIG's
Profile Tuning Suite (PTS) via [auto-pts](https://github.com/intel/auto-pts).

## Supported BTP Services

| Service | Status |
|---------|--------|
| Core (ID 0) | Fully implemented |
| GAP (ID 1) | Mostly implemented |
| GATT (ID 2) | Server and client operations |
| L2CAP (ID 3) | Protocol parsing only (handlers stubbed) |
