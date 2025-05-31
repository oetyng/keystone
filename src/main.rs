//! .

mod app;
mod cli;
mod daemon;
mod e2e;
mod error;
mod import;
mod ipc;
mod key_store;
mod protocol;

use cli::Cli;
use error::AppResult as Result;
use key_store::KeyStore;
use protocol::Request;

use clap::Parser;
use std::process;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let port = cli.port;

    let (request, output_target) = cli::parse_cmd(&cli.command)?;

    if let Request::Start = request {
        start_daemon(port).await;
        return Ok(());
    }

    let response = app::send(request, port).await;

    if let Err(e) = cli::render(response, cli.json, &output_target) {
        eprintln!("{e}");
        process::exit(1);
    }

    Ok(())
}

async fn start_daemon(port: u16) {
    match daemon::try_bind(port).await {
        Ok((tcp, addr)) => {
            println!("Daemon started on: {addr}");
            daemon::run(tcp, KeyStore::new()).await;
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
