//#![cfg_attr(not(test), no_std)]
#![feature(type_alias_impl_trait)]
#![feature(generic_associated_types)]
#![feature(associated_type_defaults)]
#![allow(dead_code)]
#![allow(clippy::await_holding_refcell_ref)]
#![feature(async_closure)]

pub mod command;
pub mod event;
pub mod status;
pub mod handle;
pub mod rssi;
pub mod ogf;