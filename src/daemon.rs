//! .

use crate::{
    KeyStore,
    error::{AppError as Error, AppResult as Result},
    ipc::bind,
    protocol::{Request, Response, receive_msg, send_msg},
};

use std::{net::SocketAddr, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    select, task,
};
use tokio_util::sync::CancellationToken;

pub(crate) async fn try_bind(port: u16) -> Result<(TcpListener, SocketAddr)> {
    get_tcp(port).await
}

pub(crate) async fn run(tcp: TcpListener, store: KeyStore) {
    let store = Arc::new(store);
    let loop_ctrl = CancellationToken::new();
    loop {
        let res = select! {
            res = tcp.accept() => res,
            _ = loop_ctrl.cancelled() => {
                break;
            }
        };

        match res {
            Ok((stream, _)) => {
                let store_c = store.clone();
                let loop_ctrl_c = loop_ctrl.clone();
                task::spawn(async move {
                    handle_msg(stream, store_c, loop_ctrl_c).await;
                });
            }
            Err(e) => {
                eprintln!("Accept error: {e}");
            }
        }
    }
}

async fn handle_msg(stream: TcpStream, store: Arc<KeyStore>, loop_ctrl: CancellationToken) {
    let (mut reader, mut writer) = stream.into_split();
    match receive_msg(&mut reader).await {
        Ok(req) => match handle_request(req, store).await {
            HandlerResult::Respond(resp) => {
                let _ = send_msg(&mut writer, &resp).await;
            }
            HandlerResult::Shutdown => {
                let _ = send_msg(&mut writer, &Response::ShuttingDown).await;
                loop_ctrl.cancel();
            }
        },
        Err(e) => {
            let _ = send_msg(
                &mut writer,
                &Response::Error(format!("Decode error: {}", e)),
            )
            .await;
        }
    }
}

enum HandlerResult {
    Respond(Response),
    Shutdown,
}

async fn handle_request(req: Request, keys: Arc<KeyStore>) -> HandlerResult {
    match req {
        Request::Start => HandlerResult::Respond(Response::Error(
            "Invalid request: Can only run one instance at a time.".to_string(),
        )),
        Request::List => {
            let names = keys.names();
            HandlerResult::Respond(Response::KeyNames(names))
        }
        Request::PublicKey { name } => match keys.public_key(name) {
            Ok(pk) => HandlerResult::Respond(Response::PublicKey(pk)),
            Err(e) => HandlerResult::Respond(Response::Error(format!("{e}"))),
        },
        Request::PublicKeyOnPath { name, path } => match keys.public_key_on_path(name, path) {
            Ok(pk) => HandlerResult::Respond(Response::PublicKey(pk)),
            Err(e) => HandlerResult::Respond(Response::Error(format!("{e}"))),
        },
        Request::StoreEVM { name, evm_sk_hex } => match keys.store_evm(name, evm_sk_hex) {
            Ok(()) => HandlerResult::Respond(Response::KeyAdded),
            Err(e) => HandlerResult::Respond(Response::Error(format!("{e}"))),
        },
        Request::StoreBLS { name, bls_sk_hex } => match keys.store_bls(name, bls_sk_hex) {
            Ok(()) => HandlerResult::Respond(Response::KeyAdded),
            Err(e) => HandlerResult::Respond(Response::Error(format!("{e}"))),
        },
        Request::Remove(name) => match keys.remove(name) {
            Ok(()) => HandlerResult::Respond(Response::KeyRemoved),
            Err(e) => HandlerResult::Respond(Response::Error(format!("{e}"))),
        },
        Request::StoreDerived {
            from_name,
            to_name,
            path,
        } => match keys.store_derived(from_name, to_name, path) {
            Ok(()) => HandlerResult::Respond(Response::KeyAdded),
            Err(e) => HandlerResult::Respond(Response::Error(format!("{e}"))),
        },
        Request::Sign { with_name, payload } => match keys.sign(with_name, payload) {
            Ok(sig) => HandlerResult::Respond(Response::Signature(sig)),
            Err(e) => HandlerResult::Respond(Response::Error(format!("{e}"))),
        },
        Request::SignOnPath {
            from_name,
            path,
            payload,
        } => match keys.sign_on_path(from_name, path, payload) {
            Ok(sig) => HandlerResult::Respond(Response::Signature(sig)),
            Err(e) => HandlerResult::Respond(Response::Error(format!("{e}"))),
        },
        Request::Verify {
            with_name,
            signature,
            payload,
        } => {
            let sig = match parse_signature(&signature) {
                Ok(s) => s,
                Err(e) => return HandlerResult::Respond(Response::Error(e.to_string())),
            };
            match keys.verify(with_name, &sig, payload) {
                Ok(true) => HandlerResult::Respond(Response::ValidSignature),
                Ok(false) => {
                    HandlerResult::Respond(Response::Error("Signature verification failed".into()))
                }
                Err(e) => HandlerResult::Respond(Response::Error(e.to_string())),
            }
        }
        Request::VerifyOnPath {
            from_name,
            path,
            signature,
            payload,
        } => {
            let sig = match parse_signature(&signature) {
                Ok(s) => s,
                Err(e) => return HandlerResult::Respond(Response::Error(e.to_string())),
            };
            match keys.verify_on_path(from_name, path, &sig, payload) {
                Ok(true) => HandlerResult::Respond(Response::ValidSignature),
                Ok(false) => {
                    HandlerResult::Respond(Response::Error("Signature verification failed".into()))
                }
                Err(e) => HandlerResult::Respond(Response::Error(e.to_string())),
            }
        }
        Request::Shutdown => HandlerResult::Shutdown,
    }
}

async fn get_tcp(port: u16) -> Result<(TcpListener, SocketAddr)> {
    bind::to(port)
        .await
        .map_err(|_| Error::DaemonAlreadyRunning(port))
}

fn parse_signature(bytes: &[u8]) -> Result<bls::Signature> {
    if bytes.len() != 96 {
        return Err(Error::InvalidSignature(format!(
            "Expected 96 bytes, got {}",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 96];
    arr.copy_from_slice(bytes);

    bls::Signature::from_bytes(arr)
        .map_err(|e| Error::InvalidSignature(format!("From bytes failed: {e}")))
}
