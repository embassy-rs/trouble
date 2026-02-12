# Known issues (in RC libraries)

## `p256` and/or `elliptic-curve` does not build

See [https://github.com/RustCrypto/elliptic-curves/issues/1590](https://github.com/RustCrypto/elliptic-curves/issues/1590).

## ESP32 security samples do not run

The `esp-hal` library supports `rand_core` 0.6 and 0.9. We'd need it to support 0.10.

Adding this to `esp-hal` wouldn't be a big effort. Can be done as a PR but likely it'll just get there anyhow, once `rand_core` 0.10 proceeds down the RC aile.

