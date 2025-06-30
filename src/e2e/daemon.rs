//! .

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use std::net::SocketAddr;
    use tokio::{net::TcpListener, task::JoinHandle};

    use crate::{
        KeyStore, app, daemon,
        e2e::{gen_name, gen_path, random_32b_bls_hex},
        protocol::{Request, Response},
    };

    #[tokio::test]
    async fn add_key_ack() {
        let _ = add_rand_key();
    }

    #[tokio::test]
    async fn added_key_exists() {
        let name = gen_name();
        let key = random_32b_bls_hex();
        let (addr, _handle) = add_key(name.clone(), key).await;
        assert_exists(name, addr.port()).await;
    }

    #[tokio::test]
    async fn sign_and_verify() {
        let name = gen_name();
        let bls_sk_hex = random_32b_bls_hex();
        let (addr, daemon) = add_key(name.clone(), bls_sk_hex).await;

        let message = b"hello world".to_vec();

        // Sign message
        let response = app::send(
            Request::Sign {
                with_name: name.clone(),
                payload: Bytes::from(message.to_vec()),
            },
            addr.port(),
        )
        .await;

        println!("{response:?}");
        let signature = match response {
            Response::Signature(sig) => sig,
            _ => panic!("Expected signature"),
        };

        // Verify
        let response = app::send(
            Request::Verify {
                with_name: name.clone(),
                payload: Bytes::from(message.to_vec()),
                signature: Bytes::from(signature.to_bytes().to_vec()),
            },
            addr.port(),
        )
        .await;

        assert!(matches!(response, Response::ValidSignature));

        drop(daemon);
    }

    #[tokio::test]
    async fn test_sign_on_path() {
        let name = gen_name();
        let bls_sk_hex = random_32b_bls_hex();
        let (addr, daemon) = add_key(name.clone(), bls_sk_hex).await;

        let message = b"hello world".to_vec();
        let path = gen_path();

        // Sign message
        let response = app::send(
            Request::SignOnPath {
                from_name: name.clone(),
                path: path.clone(),
                payload: Bytes::from(message.to_vec()),
            },
            addr.port(),
        )
        .await;

        println!("{response:?}");
        let signature = match response {
            Response::Signature(sig) => sig,
            _ => panic!("Expected signature"),
        };

        // Verify
        let response = app::send(
            Request::VerifyOnPath {
                from_name: name.clone(),
                path: path.clone(),
                payload: Bytes::from(message.to_vec()),
                signature: Bytes::from(signature.to_bytes().to_vec()),
            },
            addr.port(),
        )
        .await;

        assert!(matches!(response, Response::ValidSignature));

        drop(daemon);
    }

    async fn add_rand_key() -> (SocketAddr, JoinHandle<()>) {
        add_key(gen_name(), random_32b_bls_hex()).await
    }

    async fn add_key(name: String, bls_sk_hex: String) -> (SocketAddr, JoinHandle<()>) {
        let (addr, _handle) = spawn_test_daemon().await;
        let request = Request::StoreBLS { name, bls_sk_hex };
        let response = app::send(request, addr.port()).await;
        assert!(matches!(response, Response::KeyAdded));
        (addr, _handle)
    }

    async fn assert_exists(name: String, port: u16) {
        let request = Request::List;
        let response = app::send(request, port).await;
        assert!(matches!(response, Response::KeyNames(_)));
        match response {
            Response::KeyNames(names) => {
                assert!(names.contains(&name));
            }
            _ => (),
        }
    }

    async fn spawn_test_daemon() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let keystore = KeyStore::new();
        let handle = tokio::spawn(async move {
            run_daemon_on(listener, keystore).await;
        });
        (addr, handle)
    }

    async fn run_daemon_on(listener: TcpListener, keystore: KeyStore) {
        daemon::run(listener, keystore).await;
    }
}
