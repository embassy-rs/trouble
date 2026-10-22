//! Native H4 sockets and cooperative discrete-time execution.
//!
//! This crate supplies the process-wide Embassy time driver. Do not enable
//! `embassy-time/std`, `wasm`, or `mock-driver` in the same binary.
//! Application futures run on one thread, without Tokio or an I/O worker.

#![cfg(unix)]
#![warn(missing_docs)]

pub mod babblesim;
mod executor;
mod time;
pub mod unix;

pub use executor::{Clock, Executor};

#[cfg(test)]
mod tests;
