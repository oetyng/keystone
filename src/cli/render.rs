//! .

use crate::{
    cli::models::{OutputFormat, OutputTarget},
    protocol::Response,
};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as base64;
use std::io::Write;

pub fn render(
    response: Response,
    as_json: bool,
    output_target: &OutputTarget,
) -> Result<(), String> {
    match response {
        Response::KeyAdded => render_status("key added", as_json, output_target),
        Response::KeyRemoved => render_status("key removed", as_json, output_target),
        Response::ValidSignature => render_status("signature verified", as_json, output_target),
        Response::ShuttingDown => render_status("shutting down", as_json, output_target),
        Response::Error(msg) => {
            if as_json {
                let json = serde_json::to_vec_pretty(&serde_json::json!({ "error": msg }))
                    .map_err(|e| format!("JSON serialization failed: {e}"))?;
                write_output(&json, output_target, true)?;
            } else {
                eprintln!("Error: {}", msg);
            }
            Err("Daemon returned error".into())
        }
        Response::KeyNames(names) => {
            if as_json {
                let json = serde_json::to_vec_pretty(&names)
                    .map_err(|e| format!("JSON serialization failed: {e}"))?;
                write_output(&json, output_target, true)
            } else {
                for name in names {
                    println!("{name}");
                }
                Ok(())
            }
        }
        Response::PublicKey(pk) => {
            let bytes = pk.to_bytes(); // 48-byte G1
            write_output(&bytes, output_target, true)
        }
        Response::Signature(sig) => {
            let bytes = sig.to_bytes(); // 96-byte G2
            write_output(&bytes, output_target, true)
        }
    }
}

fn render_status(message: &str, as_json: bool, output_target: &OutputTarget) -> Result<(), String> {
    if as_json {
        let json = serde_json::to_vec_pretty(&serde_json::json!({ "status": message }))
            .map_err(|e| format!("JSON serialization failed: {e}"))?;
        write_output(&json, output_target, true)
    } else {
        println!("✔ {}", message);
        Ok(())
    }
}

fn write_output(
    data: &[u8],
    output_target: &OutputTarget,
    force_stdout: bool, // can be used for CLI overrides
) -> Result<(), String> {
    let encoded: Vec<u8> = match (output_target.raw_out, output_target.output) {
        (true, _) => data.to_vec(),
        (false, OutputFormat::Base64) => base64.encode(data).into_bytes(),
        (false, OutputFormat::Hex) => hex::encode(data).into_bytes(),
    };

    if let Some(path) = &output_target.out {
        std::fs::write(path, &encoded).map_err(|e| format!("Failed to write output: {e}"))?;
    }

    if force_stdout || output_target.stdout || output_target.out.is_none() {
        if output_target.raw_out {
            std::io::stdout()
                .write_all(&encoded)
                .map_err(|e| format!("Failed to write to stdout: {e}"))?;
        } else {
            println!("{}", String::from_utf8_lossy(&encoded));
        }
    }

    Ok(())
}
