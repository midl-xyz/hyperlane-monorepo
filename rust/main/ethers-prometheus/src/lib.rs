//! A prometheus middleware to collect metrics.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used, clippy::panic)]
#![deny(clippy::arithmetic_side_effects)]

/// Ethers contract bindings generated from `./abis` by `build.rs`.
///
/// Important: These bindings are generated into `OUT_DIR` so `cargo fmt` and other
/// tooling does not require generated source files to exist in the working tree.
pub mod contracts {
    include!(concat!(env!("OUT_DIR"), "/contracts/mod.rs"));
}

pub mod json_rpc_client;
pub mod middleware;
