//! .

use std::{net::SocketAddr, process, time::Duration};
use tokio::{net::TcpStream, time::timeout};

pub async fn connect(port: u16) -> TcpStream {
    let addr = super::localhost(port);
    match try_connect(addr).await {
        Some(s) => s,
        None => {
            eprintln!("Failed to connect to service at {addr}.\nIs it running?");
            process::exit(1);
        }
    }
}

async fn try_connect(addr: SocketAddr) -> Option<TcpStream> {
    let duration = Duration::from_millis(300);
    match timeout(duration, TcpStream::connect(&addr)).await {
        Ok(stream) => stream.ok(),
        Err(_) => timeout(duration, TcpStream::connect(addr)).await.ok()?.ok(),
    }
}
