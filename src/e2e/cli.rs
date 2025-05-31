//! .

#[cfg(test)]
mod tests {
    use assert_cmd::Command;
    use base64::{Engine, engine::general_purpose::STANDARD as base64};
    use once_cell::sync::Lazy;
    use predicates::prelude::*;
    use std::{process::Child, sync::Mutex, thread, time::Duration};
    use tempfile::tempdir;

    use crate::{
        e2e::{name_from, random_32b_hex},
        protocol::DEFAULT_PORT,
    };

    static DAEMON: Lazy<Mutex<Option<Child>>> = Lazy::new(|| Mutex::new(None));

    fn setup() -> TestEnv {
        // TestEnv::new(DaemonMode::Shared(DEFAULT_PORT))
        TestEnv::new(DaemonMode::Isolated)
    }

    #[test]
    fn test_evm_add_list_remove_key() {
        let env = setup();
        let evm_key = &random_32b_hex();
        let name = "my_evm";

        // Add key
        env.cmd()
            .args(&["add-evm-key", "--name", name, "--hex", evm_key])
            .assert()
            .success();

        let list_key_cmd_success = cmd_success(&["list-keys", "--json"], &env);
        println!("Cmd list-keys succeeded: {list_key_cmd_success}");

        // List keys
        let output = env
            .cmd()
            .args(&["list-keys", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        assert!(exists(name, &output), "Key does not exist!");

        // Remove key
        env.cmd()
            .args(&["remove-key", "--name", name])
            .assert()
            .success();

        // Verify removed
        let output = env
            .cmd()
            .args(&["list-keys", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        assert!(exists(name, &output), "Key does not exist!");
    }

    #[test]
    fn test_bls_add_list_remove_key() {
        let env = setup();
        let key = bls::SecretKey::random();
        let key_hex = key.to_hex();
        let name = "my_bls";

        // Add key
        env.cmd()
            .args(&["add-bls-key", "--name", name, "--hex", &key_hex])
            .assert()
            .success();

        let list_key_cmd_success = cmd_success(&["list-keys", "--json"], &env);

        // List keys
        let output = env
            .cmd()
            .args(&["list-keys", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        assert!(exists(name, &output), "Key does not exist!");

        // Remove key
        env.cmd()
            .args(&["remove-key", "--name", name])
            .assert()
            .success();

        // Verify removed
        let output = env
            .cmd()
            .args(&["list-keys", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        assert!(exists(name, &output), "Key does not exist!");
    }

    #[test]
    fn test_get_public_key() {
        let env = setup();
        let dir = tempdir().unwrap();
        let pubkey_path = dir.path().join("pubkey.hex");

        let evm_key = &random_32b_hex();

        // Add key
        env.cmd()
            .args(&["add-evm-key", "--name", "testpk", "--hex", evm_key])
            .assert()
            .success();

        // Export public key
        env.cmd()
            .args(&["get-public-key", "--name", "testpk", "--out"])
            .arg(&pubkey_path)
            .args(&["--output", "hex"])
            .assert()
            .success();

        let contents = std::fs::read_to_string(&pubkey_path).unwrap();
        assert!(contents.trim().len() > 0);
    }

    #[test]
    fn test_get_public_key_on_path() {
        let env = setup();
        let dir = tempdir().unwrap();
        let pubkey_path = dir.path().join("derived_pubkey.hex");

        let evm_key = &random_32b_hex();

        // Add root key
        env.cmd()
            .args(&["add-evm-key", "--name", "root", "--hex", evm_key])
            .assert()
            .success();

        // Export derived public key
        env.cmd()
            .args(&[
                "get-public-key-on-path",
                "--name",
                "root",
                "--path",
                "a",
                "--path",
                "b",
                "--out",
            ])
            .arg(&pubkey_path)
            .args(&["--output", "hex"])
            .assert()
            .success();

        let contents = std::fs::read_to_string(&pubkey_path).unwrap();
        assert!(contents.trim().len() > 0);
    }

    #[test]
    fn test_sign_and_verify() {
        let env = setup();
        let dir = tempdir().unwrap();

        let evm_key = &random_32b_hex();
        let message = "deadbeef";
        let msg_path = dir.path().join("msg.bin");
        let sig_path = dir.path().join("sig.bin");

        std::fs::write(&msg_path, hex::decode(message).unwrap()).unwrap();

        env.cmd()
            .args(&["add-evm-key", "--name", "signer", "--hex", evm_key])
            .assert()
            .success();

        env.cmd()
            .args(&["sign", "--name", "signer", "--file"])
            .arg(&msg_path)
            .args(&["--out"])
            .arg(&sig_path)
            .assert()
            .success();

        env.cmd()
            .args(&["verify", "--name", "signer", "--file"])
            .arg(&msg_path)
            .args(&["--signature-file"])
            .arg(&sig_path)
            .assert()
            .success();
    }

    #[test]
    fn test_derive_key_and_use() {
        let env = setup();
        let evm_key = &random_32b_hex();

        // Store root key
        env.cmd()
            .args(&["add-evm-key", "--name", "root", "--hex", evm_key])
            .assert()
            .success();

        // Derive subkey
        env.cmd()
            .args(&[
                "derive-key",
                "--from-name",
                "root",
                "--path",
                "a",
                "--path",
                "b",
                "--to-name",
                "child",
            ])
            .assert()
            .success();

        // Verify child key exists
        let output = env
            .cmd()
            .args(&["list-keys", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert!(json.as_array().unwrap().iter().any(|v| v == "child"));
    }

    #[test]
    fn test_sign_on_path() {
        let env = setup();
        let dir = tempdir().unwrap();

        let evm_key = &random_32b_hex();
        let message = "cafebabe";
        let msg_path = dir.path().join("msg.bin");
        let sig_path = dir.path().join("sig.bin");

        std::fs::write(&msg_path, hex::decode(message).unwrap()).unwrap();

        // Store root key
        env.cmd()
            .args(&["add-evm-key", "--name", "root", "--hex", evm_key])
            .assert()
            .success();

        // Sign on path
        env.cmd()
            .args(&[
                "sign-on-path",
                "--name",
                "root",
                "--path",
                "a",
                "--path",
                "b",
                "--file",
            ])
            .arg(&msg_path)
            .args(&["--out"])
            .arg(&sig_path)
            .assert()
            .success();

        // Check that output was created and is non-empty
        let sig = std::fs::read(&sig_path).unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_verify_on_path() {
        let env = setup();
        let dir = tempdir().unwrap();

        let evm_key = &random_32b_hex();
        let message = "cafebabe";
        let msg_path = dir.path().join("msg.bin");
        let sig_path = dir.path().join("sig.bin");

        std::fs::write(&msg_path, hex::decode(message).unwrap()).unwrap();

        // Add root key
        env.cmd()
            .args(&["add-evm-key", "--name", "root", "--hex", evm_key])
            .assert()
            .success();

        // Sign on path
        env.cmd()
            .args(&[
                "sign-on-path",
                "--name",
                "root",
                "--path",
                "a",
                "--path",
                "b",
                "--file",
            ])
            .arg(&msg_path)
            .args(&["--out"])
            .arg(&sig_path)
            .assert()
            .success();

        // Verify on path
        env.cmd()
            .args(&[
                "verify-on-path",
                "--name",
                "root",
                "--path",
                "a",
                "--path",
                "b",
                "--file",
            ])
            .arg(&msg_path)
            .args(&["--signature-file"])
            .arg(&sig_path)
            .assert()
            .success();
    }

    #[test]
    fn test_sign_with_stdin_input() {
        let env = setup();

        let evm_key = &random_32b_hex();
        let input_msg = b"from-stdin";

        // Add key
        env.cmd()
            .args(&["add-evm-key", "--name", "stdin-key", "--hex", evm_key])
            .assert()
            .success();

        // Sign message via stdin
        let assert = env
            .cmd()
            .args(&["sign", "--name", "stdin-key", "--stdin"])
            .write_stdin(input_msg)
            .assert()
            .success();

        let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
        assert!(!stdout.trim().is_empty());
    }

    #[test]
    fn test_verify_with_signature_hex_and_base64() {
        let env = setup();
        let dir = tempdir().unwrap();
        let msg_path = dir.path().join("msg.bin");

        let evm_key = &random_32b_hex();
        let message = b"sig-source-test";

        std::fs::write(&msg_path, message).unwrap();

        // Add key
        env.cmd()
            .args(&["add-evm-key", "--name", "source-test", "--hex", evm_key])
            .assert()
            .success();

        // // Sign
        // let output = env.cmd()
        //     .args(&["sign", "--name", "source-test", "--file"])
        //     .arg(&msg_path)
        //     .args(&["--output", "base64"])
        //     .assert()
        //     .success()
        //     .get_output()
        //     .stdout
        //     .clone();

        // let sig_base64 = String::from_utf8(output.clone())
        //     .unwrap()
        //     .trim()
        //     .to_string();
        // let sig_hex = hex::encode(base64.decode(&sig_base64).unwrap());

        // // Verify via base64
        // env.cmd()
        //     .args(&["verify", "--name", "source-test", "--file"])
        //     .arg(&msg_path)
        //     .args(&["--signature-base64", &sig_base64])
        //     .assert()
        //     .success();

        // // Verify via hex
        // env.cmd()
        //     .args(&["verify", "--name", "source-test", "--file"])
        //     .arg(&msg_path)
        //     .args(&["--signature-hex", &sig_hex])
        //     .assert()
        //     .success();
    }

    #[test]
    fn test_sign_output_formats_raw_and_hex() {
        let env = setup();
        let dir = tempdir().unwrap();
        let msg_path = dir.path().join("raw_msg.bin");
        let out_path = dir.path().join("sig_output.bin");

        let evm_key = random_32b_hex();
        let name = name_from(evm_key.clone());
        std::fs::write(&msg_path, b"encoding-test").unwrap();

        // Add key
        env.cmd()
            .args(&["add-evm-key", "--name", &name, "--hex", &evm_key])
            .assert()
            .success();

        // Sign with raw output
        env.cmd()
            .args(&["sign", "--name", &name, "--file"])
            .arg(&msg_path)
            .args(&[
                "--out",
                out_path.to_str().unwrap(),
                "--raw-out",
                "--output",
                "hex",
            ])
            .assert()
            .success();

        let output = std::fs::read(&out_path).unwrap();
        assert!(!output.is_empty());

        // Confirm it is valid hex
        let decoded = hex::decode(&output).expect("not valid hex");
        assert_eq!(decoded.len(), 96);
    }

    // Negative Logic

    #[test]
    fn test_sign_with_unknown_key_fails() {
        let env = setup();
        let dir = tempdir().unwrap();
        let msg_path = dir.path().join("msg.bin");

        std::fs::write(&msg_path, b"hello").unwrap();

        let assert = env
            .cmd()
            .args(&["sign", "--name", "nonexistent", "--file"])
            .arg(&msg_path)
            .assert()
            .failure();

        assert.stderr(predicate::str::contains("not found").or(predicate::str::contains("Error")));
    }

    #[test]
    fn test_verify_with_invalid_signature_fails() {
        let env = setup();
        let dir = tempdir().unwrap();
        let msg_path = dir.path().join("msg.bin");
        let sig_path = dir.path().join("sig_invalid.bin");

        let evm_key = &random_32b_hex();

        std::fs::write(&msg_path, b"test message").unwrap();
        std::fs::write(&sig_path, vec![0u8; 96]).unwrap(); // invalid 96-byte signature

        // Add key
        env.cmd()
            .args(&["add-evm-key", "--name", "verify-fail", "--hex", evm_key])
            .assert()
            .success();

        // Attempt to verify
        env.cmd()
            .args(&["verify", "--name", "verify-fail", "--file"])
            .arg(&msg_path)
            .args(&["--signature-file"])
            .arg(&sig_path)
            .assert()
            .failure()
            .stderr(predicate::str::contains("Error: Invalid signature"));
    }

    #[test]
    fn test_derive_to_existing_key_name_fails() {
        let env = setup();

        let evm_key = &random_32b_hex();

        // Add root and child key with same name
        env.cmd()
            .args(&["add-evm-key", "--name", "dup", "--hex", evm_key])
            .assert()
            .success();

        // Attempt to derive into the same name
        env.cmd()
            .args(&[
                "derive-key",
                "--from-name",
                "dup",
                "--path",
                "conflict",
                "--to-name",
                "dup",
            ])
            .assert()
            .failure()
            .stderr(
                predicate::str::contains("already exists").or(predicate::str::contains("exists")),
            );
    }

    #[test]
    fn test_get_public_key_unknown_key_fails() {
        let env = setup();
        let dir = tempdir().unwrap();
        let pubkey_path = dir.path().join("pubkey_unknown.hex");

        env.cmd()
            .args(&["get-public-key", "--name", "no-such-key", "--out"])
            .arg(&pubkey_path)
            .args(&["--output", "hex"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("not found").or(predicate::str::contains("unknown")));
    }

    #[test]
    fn test_remove_unknown_key_fails() {
        let env = setup();

        env.cmd()
            .args(&["remove-key", "--name", "ghost"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("not found").or(predicate::str::contains("missing")));
    }

    // Bad input

    #[test]
    fn test_sign_with_invalid_hex_input_fails() {
        let env = setup();

        let evm_key = &random_32b_hex();

        // Add valid key
        env.cmd()
            .args(&["add-evm-key", "--name", "malformed", "--hex", evm_key])
            .assert()
            .success();

        // Try signing with invalid hex
        env.cmd()
            .args(&[
                "sign",
                "--name",
                "malformed",
                "--hex",
                "zzzzzz", // Invalid hex
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "Error: Parse(InvalidHexInput(InvalidHexCharacter { c: 'z'",
            ));
    }

    #[test]
    fn test_verify_with_invalid_base64_signature_fails() {
        let env = setup();

        let dir = tempdir().unwrap();
        let msg_path = dir.path().join("msg.txt");
        std::fs::write(&msg_path, b"hello").unwrap();
        let evm_key = &random_32b_hex();

        // Add a valid key
        env.cmd()
            .args(&["add-evm-key", "--name", "invalid-b64", "--hex", evm_key])
            .assert()
            .success();

        // Try to verify using malformed base64
        env.cmd()
            .args(&["verify", "--name", "invalid-b64", "--file"])
            .arg(&msg_path)
            .args(&["--signature-base64", "not@@@base64"])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "Error: Parse(InvalidBase64Input(InvalidByte(3, 64)))",
            ));
    }

    #[test]
    fn test_derive_with_empty_path_fails() {
        let env = setup();

        let evm_key = &random_32b_hex();

        // Add base key
        env.cmd()
            .args(&["add-evm-key", "--name", "base", "--hex", evm_key])
            .assert()
            .success();

        // Attempt to derive without any path
        env.cmd()
            .args(&[
                "derive-key",
                "--from-name",
                "base",
                "--to-name",
                "child-empty",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("path").or(predicate::str::contains("empty")));
    }

    // Automatically shut down daemon at end of test suite
    #[cfg(test)]
    mod teardown {
        use super::*;
        #[test]
        fn shutdown_at_end() {
            let env = setup();
            shutdown_daemon(&env);

            // Wait a moment and try a command, which should now fail
            thread::sleep(Duration::from_millis(500));

            let result = env
                .cmd()
                .arg("list-keys")
                .arg("--json")
                .output()
                .expect("Failed to run command");

            assert!(!result.status.success());
        }
    }

    /// Controls whether a shared daemon is reused or a new one is started per test.
    enum DaemonMode {
        Shared(u16),
        Isolated,
    }

    struct TestEnv {
        port: u16,
        daemon: Option<Child>,
    }

    impl TestEnv {
        pub fn new(mode: DaemonMode) -> Self {
            match mode {
                DaemonMode::Shared(port) => {
                    start_daemon_once(port);
                    Self { port, daemon: None }
                }
                DaemonMode::Isolated => {
                    let port = free_port();
                    let daemon = start_new_daemon_0(port);
                    Self {
                        port,
                        daemon: Some(daemon),
                    }
                }
            }
        }

        pub fn cmd(&self) -> Command {
            let mut cmd = Command::cargo_bin("auth").unwrap();
            cmd.args(&["--port", &self.port.to_string()]);
            cmd
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            if let Some(child) = &mut self.daemon {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn start_daemon_once(port: u16) {
        let mut guard = DAEMON.lock().unwrap();
        if guard.is_none() {
            ensure_auth_built();
            let child = start_new_daemon_0(port);
            *guard = Some(child);
        }
    }

    fn start_new_daemon_1(port: u16) -> Child {
        use assert_cmd::cargo::CommandCargoExt;
        use std::net::TcpStream;
        use std::process::Stdio;
        use std::thread;
        use std::time::Duration;
        use std::time::Instant;

        const TIMEOUT_MS: u128 = 2000;

        let child = std::process::Command::cargo_bin("auth")
            .unwrap()
            .arg("--port")
            .arg(port.to_string())
            .arg("start")
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to start daemon");

        // Wait for open port
        let start = Instant::now();
        loop {
            match TcpStream::connect(("127.0.0.1", port)) {
                Ok(_) => break,
                Err(_) => {
                    if start.elapsed().as_millis() > TIMEOUT_MS {
                        panic!("Daemon did not bind to port {port} within {TIMEOUT_MS} ms");
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }

        child
    }

    fn start_new_daemon_0(port: u16) -> Child {
        use assert_cmd::cargo::CommandCargoExt;
        use std::net::TcpStream;
        use std::thread;
        use std::time::Duration;
        use std::time::Instant;

        let child = std::process::Command::cargo_bin("auth")
            .unwrap()
            .arg("--port")
            .arg(port.to_string())
            .arg("start")
            .spawn()
            .expect("failed to start daemon");
        // Give the daemon time to bind to the port
        thread::sleep(Duration::from_millis(500));

        const TIMEOUT_MS: u128 = 2000;

        // Wait for open port
        let start = Instant::now();
        loop {
            match TcpStream::connect(("127.0.0.1", port)) {
                Ok(_) => break,
                Err(_) => {
                    if start.elapsed().as_millis() > TIMEOUT_MS {
                        panic!("Daemon did not bind to port {port} within {TIMEOUT_MS} ms");
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }

        child
    }
    fn ensure_auth_built() {
        let bin_path = get_bin_path();
        if !bin_path.exists() {
            println!("Building to: {bin_path:?}");
            let status = std::process::Command::new("cargo")
                .args(["build", "--bin", "auth"])
                .status()
                .expect("Failed to build binary");
            assert!(status.success(), "Build failed");
            assert!(bin_path.exists(), "Binary not found: {bin_path:?}");
        }
    }

    #[cfg(windows)]
    const BIN_NAME: &str = "auth.exe";
    #[cfg(not(windows))]
    const BIN_NAME: &str = "auth";

    fn get_bin_path() -> std::path::PathBuf {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        while path
            .file_name()
            .map(|n| n != "autonomi-extra")
            .unwrap_or(false)
        {
            path.pop();
        }

        path.push("target");
        path.push("debug");
        path.push(BIN_NAME);
        path
    }

    fn shutdown_daemon(env: &TestEnv) {
        let _ = env.cmd().arg("shutdown").assert().success();
        let mut guard = DAEMON.lock().unwrap();
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
        }
    }

    fn free_port() -> u16 {
        use std::net::TcpListener;
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn cmd_success(args: &[&str], env: &TestEnv) -> bool {
        let cmd = env.cmd().args(args).output().expect("Failed to run auth");
        eprintln!("stdout:\n{}", String::from_utf8_lossy(&cmd.stdout));
        eprintln!("stderr:\n{}", String::from_utf8_lossy(&cmd.stderr));
        cmd.status.success()
    }

    fn exists(name: &str, stdout: &Vec<u8>) -> bool {
        eprintln!("RAW stout OUTPUT:\n{}", String::from_utf8_lossy(stdout));
        let decoded = base64.decode(stdout).expect("Failed to decode base64");
        eprintln!(
            "BASE64 DECODED stout OUTPUT:\n{}",
            String::from_utf8_lossy(&decoded)
        );
        let json: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        let exists = json.as_array().unwrap().iter().any(|v| v == name);
        exists
    }
}
