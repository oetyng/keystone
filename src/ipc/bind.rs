//! .

use std::{io, net::SocketAddr};
use tokio::net::TcpListener;

/// Try binding to preferred port. If it fails, fallback to OS-assigned port (0).
pub async fn to(port: u16) -> io::Result<(TcpListener, SocketAddr)> {
    let addr = super::localhost(port);
    let listener = match TcpListener::bind(addr).await {
        Ok(tcp) => tcp,
        Err(_) => TcpListener::bind(super::localhost(0)).await?,
    };
    let addr = listener.local_addr()?;
    Ok((listener, addr))
}
