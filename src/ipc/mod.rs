//! .

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub mod bind;
pub mod client;

pub(super) fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}
