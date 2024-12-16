//! Compile-time configuration.
//!
//! `trouble` has some configuration settings that are set at compile time.
//!
//! They can be set in two ways:
//!
//! - Via Cargo features: enable a feature like `<name>-<value>`. `name` must be in lowercase and
//!   use dashes instead of underscores. For example. `l2cap-rx-queue-size-4`. Only a selection of values
//!   is available, check `Cargo.toml` for the list.
//! - Via environment variables at build time: set the variable named `TROUBLE_HOST_<value>`. For example
//!   `TROUBLE_HOST_L2CAP_RX_QUEUE_SIZE=1 cargo build`. You can also set them in the `[env]` section of `.cargo/config.toml`.
//!   Any value can be set, unlike with Cargo features.
//!
//! Environment variables take precedence over Cargo features. If two Cargo features are enabled for the same setting
//! with different values, compilation fails.
//!
//! ## Compatibility warning
//!
//! Changing ANY of these configuration settings changes the on-disk format of the database. If you change
//! them, you won't be able to read databases written with a different configuration.
//!
//! Currently, mounting doesn't check the on-disk database uses the same configuration. Mounting a database
//! with a different configuration might succeed and then cause fun errors later, perhaps very rarely.
//! Always remember to format your flash device every time you change them.

mod raw {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}

/// Connection event queue size
///
/// This is the connection event queue size for every connection.
///
/// Default: 2.
pub const CONNECTION_EVENT_QUEUE_SIZE: usize = raw::CONNECTION_EVENT_QUEUE_SIZE;

// ======== L2CAP parameters
//
/// L2CAP TX queue size
///
/// This is the tx queue size for l2cap packets not sent directly in HCI (i.e. attributes).
///
/// If the controller does not support tx buffering, increasing this value will allow
/// a higher throughput between the controller and host.
///
/// Default: 1.
pub const L2CAP_TX_QUEUE_SIZE: usize = raw::L2CAP_TX_QUEUE_SIZE;

/// L2CAP RX queue size
///
/// This is the rx queue size of every l2cap channel. Every channel have to be able
/// to buffer at least 1 packet, but if the controller already does buffering this
/// may be sufficient.
///
/// If the controller does not support rx buffering, increasing this value will allow
/// a higher throughput between the controller and host.
///
/// Default: 1.
pub const L2CAP_RX_QUEUE_SIZE: usize = raw::L2CAP_RX_QUEUE_SIZE;

/// L2CAP RX packet pool size
///
/// This is the rx packet pool size of every l2cap channel. There has to be at least
/// 1 packet that can be allocated, but the pool is shared among different channels.
///
/// If the rx queue size is adjusted, consider adjusting the rx packet pool size as well,
/// taking the number of channels and per-channel queue size into account.
///
/// Ensuring fair access to the pool is done configuring the QoS policy when creating
/// the host resources.
///
/// Default: 1.
pub const L2CAP_RX_PACKET_POOL_SIZE: usize = raw::L2CAP_RX_PACKET_POOL_SIZE;

/// GATT packet pool size.
///
/// Default: 8.
pub const GATT_PACKET_POOL_SIZE: usize = raw::GATT_PACKET_POOL_SIZE;

/// GATT notification max subscribers
///
/// Default: 1.
pub const GATT_CLIENT_NOTIFICATION_MAX_SUBSCRIBERS: usize = raw::GATT_CLIENT_NOTIFICATION_MAX_SUBSCRIBERS;

/// GATT notification queue size.
///
/// Default: 1.
pub const GATT_CLIENT_NOTIFICATION_QUEUE_SIZE: usize = raw::GATT_CLIENT_NOTIFICATION_QUEUE_SIZE;
