//! .

use super::models::{OutputFormat, OutputTarget};

use crate::{
    cli::{
        error::{ParseError as Error, ParseResult as Result},
        models::{Command, InputSource, SignatureSource},
    },
    protocol::Request,
};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as base64;
use bytes::Bytes;
use std::fs;

pub(crate) fn parse_cmd(cmd: &Command) -> Result<(Request, OutputTarget)> {
    let request = map_cmd(cmd)?;
    let output = output_target(cmd);
    Ok((request, output))
}

fn map_cmd(cmd: &Command) -> Result<Request> {
    match cmd {
        Command::Start => Ok(Request::Start),
        Command::Shutdown => Ok(Request::Shutdown),
        Command::ListKeys { .. } => Ok(Request::List),
        Command::AddEvmKey { name, hex } => Ok(Request::StoreEVM {
            name: name.clone(),
            evm_sk_hex: hex.clone(),
        }),
        Command::AddBlsKey { name, hex } => Ok(Request::StoreBLS {
            name: name.clone(),
            bls_sk_hex: hex.clone(),
        }),
        Command::RemoveKey { name } => Ok(Request::Remove(name.clone())),
        Command::GetPublicKey { name, .. } => Ok(Request::PublicKey { name: name.clone() }),
        Command::GetPublicKeyOnPath { name, path, .. } => Ok(Request::PublicKeyOnPath {
            name: name.clone(),
            path: path.clone(),
        }),
        Command::DeriveKey {
            from_name,
            path,
            to_name,
        } => Ok(Request::StoreDerived {
            from_name: from_name.clone(),
            path: path.clone(),
            to_name: to_name.clone(),
        }),
        Command::Sign { name, input, .. } => {
            let payload = resolve_payload(input)?;
            Ok(Request::Sign {
                with_name: name.clone(),
                payload: Bytes::from(payload),
            })
        }
        Command::SignOnPath {
            name, path, input, ..
        } => {
            let payload = resolve_payload(input)?;
            Ok(Request::SignOnPath {
                from_name: name.clone(),
                path: path.clone(),
                payload: Bytes::from(payload),
            })
        }
        Command::Verify {
            name,
            input,
            signature,
            ..
        } => {
            let msg = resolve_payload(input)?;
            let sig = resolve_signature(signature)?;
            Ok(Request::Verify {
                with_name: name.clone(),
                signature: Bytes::from(sig),
                payload: Bytes::from(msg),
            })
        }
        Command::VerifyOnPath {
            name,
            path,
            input,
            signature,
            ..
        } => {
            let msg = resolve_payload(input)?;
            let sig = resolve_signature(signature)?;
            Ok(Request::VerifyOnPath {
                from_name: name.clone(),
                path: path.clone(),
                signature: Bytes::from(sig),
                payload: Bytes::from(msg),
            })
        }
    }
}

fn resolve_payload(input: &InputSource) -> Result<Vec<u8>> {
    match (&input.file, &input.hex, input.stdin) {
        (Some(path), None, false) => fs::read(path).map_err(Error::CouldNotReadPath),
        (None, Some(hex), false) => hex::decode(hex).map_err(Error::InvalidHexInput),
        (None, None, true) => {
            use std::io::Read;
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| Error::StdIn(format!("Failed to read stdin: {e}")))?;
            Ok(buf)
        }
        _ => Err(Error::InvalidInputSource(
            "Invalid input source; exactly one must be set".into(),
        )),
    }
}

fn resolve_signature(sig: &SignatureSource) -> Result<Vec<u8>> {
    match (
        &sig.signature_file,
        &sig.signature_hex,
        &sig.signature_base64,
    ) {
        (Some(path), None, None) => fs::read(path).map_err(Error::CouldNotReadPath),
        (None, Some(h), None) => hex::decode(h).map_err(Error::InvalidHexInput),
        (None, None, Some(b)) => base64.decode(b).map_err(Error::InvalidBase64Input),
        _ => Err(Error::InvalidInputSource(
            "Invalid signature input; exactly one must be set".into(),
        )),
    }
}

fn output_target(cmd: &Command) -> OutputTarget {
    match cmd.clone() {
        Command::ListKeys { output } => output,
        Command::GetPublicKey { output, .. } => output,
        Command::GetPublicKeyOnPath { output, .. } => output,
        Command::Sign { output, .. } => output,
        Command::SignOnPath { output, .. } => output,
        Command::Verify { output, .. } => output,
        Command::VerifyOnPath { output, .. } => output,
        _ => OutputTarget {
            out: None,
            stdout: true,
            raw_out: false,
            output: OutputFormat::Base64,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{
        error::ParseError,
        models::{Command, InputSource, OutputFormat, OutputTarget, SignatureSource},
    };
    use crate::protocol::Request;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as base64;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn start_command_request_start() {
        let cmd = Command::Start;
        let (req, out) = parse_cmd(&cmd).expect("parse should succeed");
        assert!(matches!(req, Request::Start));
        assert_eq!(out.stdout, true);
        assert_eq!(out.output, OutputFormat::Base64);
        assert_eq!(out.raw_out, false);
        assert_eq!(out.out, None);
    }

    #[test]
    fn shutdown_command_request_shutdown() {
        let cmd = Command::Shutdown;
        let (req, out) = parse_cmd(&cmd).expect("parse should succeed");
        assert!(matches!(req, Request::Shutdown));
        assert_eq!(out.stdout, true);
        assert_eq!(out.output, OutputFormat::Base64);
        assert_eq!(out.raw_out, false);
        assert_eq!(out.out, None);
    }

    #[test]
    fn listkeys_request_list_with_outputtarget() {
        let output_target = OutputTarget {
            out: Some("some_output.txt".into()),
            stdout: false,
            raw_out: true,
            output: OutputFormat::Hex,
        };
        let cmd = Command::ListKeys {
            output: output_target.clone(),
        };
        let (req, out) = parse_cmd(&cmd).expect("parse should succeed");
        assert!(matches!(req, Request::List));
        assert_eq!(out.out, Some("some_output.txt".into()));
        assert_eq!(out.stdout, false);
        assert_eq!(out.raw_out, true);
        assert_eq!(out.output, OutputFormat::Hex);
    }

    #[test]
    fn addevmkey_request_storeevm_name_hex() {
        let cmd = Command::AddEvmKey {
            name: "evm_key".into(),
            hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        };
        let (req, out) = parse_cmd(&cmd).expect("parse should succeed");
        assert!(matches!(
            req,
            Request::StoreEVM { ref name, ref evm_sk_hex }
            if name == "evm_key" && evm_sk_hex.starts_with("0123")
        ));
        assert_eq!(out.stdout, true);
        assert_eq!(out.output, OutputFormat::Base64);
    }

    #[test]
    fn removekey_request_removename() {
        let cmd = Command::RemoveKey {
            name: "delete_me".into(),
        };
        let (req, out) = parse_cmd(&cmd).expect("parse should succeed");
        assert!(matches!(req, Request::Remove(ref n) if n == "delete_me"));
        assert_eq!(out.stdout, true);
        assert_eq!(out.output, OutputFormat::Base64);
    }

    #[test]
    fn getpublickey_request_publickey_with_outputtarget() {
        let output_target = OutputTarget {
            out: None,
            stdout: true,
            raw_out: false,
            output: OutputFormat::Base64,
        };
        let cmd = Command::GetPublicKey {
            name: "pub_key".into(),
            output: output_target.clone(),
        };
        let (req, out) = parse_cmd(&cmd).expect("parse should succeed");
        assert!(matches!(req, Request::PublicKey { ref name } if name == "pub_key"));
        assert_eq!(out.stdout, true);
        assert_eq!(out.output, OutputFormat::Base64);
    }

    #[test]
    fn getpublickeyonpath_request_publickeyonpath_with_outputtarget_and_path() {
        let output_target = OutputTarget {
            out: Some("pubkey_out.txt".into()),
            stdout: false,
            raw_out: true,
            output: OutputFormat::Hex,
        };
        let cmd = Command::GetPublicKeyOnPath {
            name: "parent".into(),
            path: vec!["child".into(), "leaf".into()],
            output: output_target.clone(),
        };
        let (req, out) = parse_cmd(&cmd).expect("parse should succeed");
        assert!(
            matches!(req, Request::PublicKeyOnPath { ref name, ref path }
                if name == "parent" && path == &vec!["child".to_string(), "leaf".into()]
            )
        );
        assert_eq!(out, output_target);
    }

    #[test]
    fn derivekey_request_derive_from_name_path_to_name() {
        let cmd = Command::DeriveKey {
            from_name: "master".into(),
            path: vec!["scope1".into(), "scope2".into()],
            to_name: "derived".into(),
        };
        let (req, out) = parse_cmd(&cmd).expect("parse should succeed");
        assert!(
            matches!(req, Request::StoreDerived { ref from_name, ref path, ref to_name }
                if from_name == "master"
                && path == &vec!["scope1".to_string(), "scope2".into()]
                && to_name == "derived"
            )
        );
        assert_eq!(out.stdout, true);
        assert_eq!(out.output, OutputFormat::Base64);
    }

    #[test]
    fn signonpath_with_hex_input() {
        let cmd = Command::SignOnPath {
            name: "parent_key".into(),
            path: vec!["level1".into(), "leaf".into()],
            input: InputSource {
                file: None,
                hex: Some("746573745f64617461".into()), // "test_data"
                stdin: false,
            },
            output: OutputTarget {
                out: Some("sig.txt".into()),
                stdout: false,
                raw_out: true,
                output: OutputFormat::Hex,
            },
        };

        let (req, out) = parse_cmd(&cmd).expect("parse should succeed");
        match req {
            Request::SignOnPath {
                from_name,
                path,
                payload,
            } => {
                assert_eq!(from_name, "parent_key");
                assert_eq!(path, vec!["level1", "leaf"]);
                assert_eq!(payload, Bytes::from_static(b"test_data"));
            }
            _ => panic!("Expected Request::SignOnPath"),
        }
        assert_eq!(out.out, Some("sig.txt".into()));
        assert_eq!(out.output, OutputFormat::Hex);
    }

    #[test]
    fn signonpath_with_multiple_inputs_error() {
        let cmd = Command::SignOnPath {
            name: "conflict_path".into(),
            path: vec!["scope".into()],
            input: InputSource {
                file: Some("a.txt".into()),
                hex: Some("deadbeef".into()),
                stdin: false,
            },
            output: OutputTarget {
                out: None,
                stdout: true,
                raw_out: false,
                output: OutputFormat::Hex,
            },
        };

        let err = parse_cmd(&cmd).unwrap_err();
        assert!(matches!(err, ParseError::InvalidInputSource(_)));
    }

    #[test]
    fn verify_with_hex_sig() {
        let cmd = Command::Verify {
            name: "verifier".into(),
            input: InputSource {
                file: None,
                hex: Some("746573745f64617461".into()), // "test_data"
                stdin: false,
            },
            signature: SignatureSource {
                signature_file: None,
                signature_hex: Some("cafebabe".into()),
                signature_base64: None,
            },
            output: OutputTarget {
                out: None,
                stdout: true,
                raw_out: false,
                output: OutputFormat::Base64,
            },
        };

        let (req, out) = parse_cmd(&cmd).expect("parse should succeed");
        match req {
            Request::Verify {
                with_name,
                payload,
                signature,
            } => {
                assert_eq!(with_name, "verifier");
                assert_eq!(payload, Bytes::from_static(b"test_data"));
                assert_eq!(signature, Bytes::from(vec![0xca, 0xfe, 0xba, 0xbe]));
            }
            _ => panic!("Expected Request::Verify"),
        }
        assert_eq!(out.output, OutputFormat::Base64);
    }

    #[test]
    fn verify_with_base64_sig() {
        let cmd = Command::Verify {
            name: "verifier".into(),
            input: InputSource {
                file: None,
                hex: Some("746573745f64617461".into()), // "test_data"
                stdin: false,
            },
            signature: SignatureSource {
                signature_file: None,
                signature_hex: None,
                signature_base64: Some("yv66vgo=".into()), // base64 for cafeba
            },
            output: OutputTarget {
                out: Some("sig_out.txt".into()),
                stdout: false,
                raw_out: true,
                output: OutputFormat::Hex,
            },
        };

        let (req, out) = parse_cmd(&cmd).expect("parse should succeed");
        match req {
            Request::Verify {
                with_name,
                payload,
                signature,
            } => {
                assert_eq!(with_name, "verifier");
                assert_eq!(payload, Bytes::from_static(b"test_data"));
                assert_eq!(signature, Bytes::from(base64.decode("yv66vgo=").unwrap()));
            }
            _ => panic!("Expected Request::Verify"),
        }
        assert_eq!(out.out, Some("sig_out.txt".into()));
        assert_eq!(out.output, OutputFormat::Hex);
    }

    #[test]
    fn verify_with_file_sig() {
        let mut sig_file = NamedTempFile::new().unwrap();
        sig_file.write_all(&[0xca, 0xfe, 0xba, 0xbe]).unwrap();
        let sig_path = sig_file.path().to_path_buf();

        let cmd = Command::Verify {
            name: "verifier_file".into(),
            input: InputSource {
                file: None,
                hex: Some("746573745f64617461".into()), // "test_data"
                stdin: false,
            },
            signature: SignatureSource {
                signature_file: Some(sig_path),
                signature_hex: None,
                signature_base64: None,
            },
            output: OutputTarget {
                out: None,
                stdout: true,
                raw_out: false,
                output: OutputFormat::Base64,
            },
        };

        let (req, _) = parse_cmd(&cmd).expect("parse should succeed");
        match req {
            Request::Verify {
                with_name,
                payload,
                signature,
            } => {
                assert_eq!(with_name, "verifier_file");
                assert_eq!(payload, Bytes::from_static(b"test_data"));
                assert_eq!(signature, Bytes::from(vec![0xca, 0xfe, 0xba, 0xbe]));
            }
            _ => panic!("Expected Request::Verify"),
        }
    }

    #[test]
    fn verifyonpath_with_hex_sig() {
        let cmd = Command::VerifyOnPath {
            name: "path_verifier".into(),
            path: vec!["level1".into()],
            input: InputSource {
                file: None,
                hex: Some("746573745f64617461".into()), // "test_data"
                stdin: false,
            },
            signature: SignatureSource {
                signature_file: None,
                signature_hex: Some("cafebabe".into()),
                signature_base64: None,
            },
            output: OutputTarget {
                out: Some("verify_out.txt".into()),
                stdout: false,
                raw_out: true,
                output: OutputFormat::Hex,
            },
        };

        let (req, out) = parse_cmd(&cmd).expect("parse should succeed");
        match req {
            Request::VerifyOnPath {
                from_name,
                path,
                payload,
                signature,
            } => {
                assert_eq!(from_name, "path_verifier");
                assert_eq!(path, vec!["level1"]);
                assert_eq!(payload, Bytes::from_static(b"test_data"));
                assert_eq!(signature, Bytes::from(vec![0xca, 0xfe, 0xba, 0xbe]));
            }
            _ => panic!("Expected Request::VerifyOnPath"),
        }
        assert_eq!(out.out, Some("verify_out.txt".into()));
        assert_eq!(out.output, OutputFormat::Hex);
    }

    #[test]
    fn verifyonpath_with_base64_sig() {
        let cmd = Command::VerifyOnPath {
            name: "base64_path".into(),
            path: vec!["scope1".into(), "scope2".into()],
            input: InputSource {
                file: None,
                hex: Some("746573745f64617461".into()), // "test_data"
                stdin: false,
            },
            signature: SignatureSource {
                signature_file: None,
                signature_hex: None,
                signature_base64: Some("yv66vgo=".into()), // base64 for cafeba
            },
            output: OutputTarget {
                out: None,
                stdout: true,
                raw_out: false,
                output: OutputFormat::Base64,
            },
        };

        let (req, out) = parse_cmd(&cmd).expect("parse should succeed");
        match req {
            Request::VerifyOnPath {
                from_name,
                path,
                payload,
                signature,
            } => {
                assert_eq!(from_name, "base64_path");
                assert_eq!(path, vec!["scope1", "scope2"]);
                assert_eq!(payload, Bytes::from_static(b"test_data"));
                assert_eq!(signature, Bytes::from(base64.decode("yv66vgo=").unwrap()));
            }
            _ => panic!("Expected Request::VerifyOnPath"),
        }
        assert_eq!(out.output, OutputFormat::Base64);
    }

    #[test]
    fn resolve_payload_with_only_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        write!(tmp, "file_payload").unwrap();
        let path = tmp.path().to_path_buf();

        let input = InputSource {
            file: Some(path.clone()),
            hex: None,
            stdin: false,
        };

        let result = resolve_payload(&input).unwrap();
        assert_eq!(result, b"file_payload");
    }

    #[test]
    fn resolve_payload_with_only_hex() {
        let input = InputSource {
            file: None,
            hex: Some("746573745f64617461".into()), // "test_data"
            stdin: false,
        };

        let result = resolve_payload(&input).unwrap();
        assert_eq!(result, b"test_data");
    }

    #[test]
    fn resolve_payload_with_only_stdin() {}

    #[test]
    fn resolve_payload_with_multiple_inputs_error() {
        let input = InputSource {
            file: Some("some.txt".into()),
            hex: Some("deadbeef".into()),
            stdin: false,
        };

        let err = resolve_payload(&input).unwrap_err();
        assert!(matches!(err, ParseError::InvalidInputSource(_)));
    }

    #[test]
    fn resolve_signature_with_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&[0xca, 0xfe, 0xba, 0xbe]).unwrap();
        let path = tmp.path().to_path_buf();

        let sig = SignatureSource {
            signature_file: Some(path),
            signature_hex: None,
            signature_base64: None,
        };

        let result = resolve_signature(&sig).unwrap();
        assert_eq!(result, vec![0xca, 0xfe, 0xba, 0xbe]);
    }

    #[test]
    fn resolve_signature_with_hex() {
        let sig = SignatureSource {
            signature_file: None,
            signature_hex: Some("cafebabe".into()),
            signature_base64: None,
        };

        let result = resolve_signature(&sig).unwrap();
        assert_eq!(result, vec![0xca, 0xfe, 0xba, 0xbe]);
    }

    #[test]
    fn resolve_signature_with_base64() {
        let sig = SignatureSource {
            signature_file: None,
            signature_hex: None,
            signature_base64: Some("yv66vgo=".into()), // base64 for cafeba
        };

        let result = resolve_signature(&sig).unwrap();
        assert_eq!(result, base64.decode("yv66vgo=").unwrap());
    }

    #[test]
    fn resolve_signature_with_multiple_inputs_error() {
        let sig = SignatureSource {
            signature_file: Some("sigfile".into()),
            signature_hex: Some("cafebabe".into()),
            signature_base64: None,
        };

        let err = resolve_signature(&sig).unwrap_err();
        assert!(matches!(err, ParseError::InvalidInputSource(_)));
    }

    #[test]
    fn addevmkey_returns_default_outputtarget() {
        let cmd = Command::AddEvmKey {
            name: "evmkey".into(),
            hex: "deadbeef".into(),
        };
        let (_, out) = parse_cmd(&cmd).expect("parse should succeed");

        assert_eq!(out.out, None);
        assert_eq!(out.stdout, true);
        assert_eq!(out.raw_out, false);
        assert_eq!(out.output, OutputFormat::Base64);
    }

    #[test]
    fn start_returns_default_outputtarget() {
        let cmd = Command::Start;
        let (_, out) = parse_cmd(&cmd).expect("parse should succeed");

        assert_eq!(out.out, None);
        assert_eq!(out.stdout, true);
        assert_eq!(out.raw_out, false);
        assert_eq!(out.output, OutputFormat::Base64);
    }
}
