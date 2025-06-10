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
/// Default: 8.
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
/// Default: 8.
pub const L2CAP_RX_QUEUE_SIZE: usize = raw::L2CAP_RX_QUEUE_SIZE;

/// L2CAP default packet pool size
///
/// This is the default packet pool size of all l2cap channels. There has to be at least
/// 1 packet that can be allocated, but the pool is shared among different channels.
///
/// Default: 16.
pub const DEFAULT_PACKET_POOL_SIZE: usize = raw::DEFAULT_PACKET_POOL_SIZE;

/// L2CAP default packet pool mtu
///
/// This is the default packet pool mtu for all l2cap channels.
///
/// Default: 251.
pub const DEFAULT_PACKET_POOL_MTU: usize = raw::DEFAULT_PACKET_POOL_MTU;

/// Default: 1.
pub const GATT_CLIENT_NOTIFICATION_MAX_SUBSCRIBERS: usize = raw::GATT_CLIENT_NOTIFICATION_MAX_SUBSCRIBERS;

/// GATT notification queue size.
///
/// Default: 1.
pub const GATT_CLIENT_NOTIFICATION_QUEUE_SIZE: usize = raw::GATT_CLIENT_NOTIFICATION_QUEUE_SIZE;
