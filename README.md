
# 🔐 One Auth DEMO: Keystore

### Overview

**For developers**  
A CLI-invocable binary for managing long-term secret keys and exposing scoped, stateless signing operations.

**For users**  
A single key manager that lets you log in to any supported app — without ever revealing your password or root key.

---

### Status

> This tool is near-functional and will be completed for use by applications.
> It can serve as a reference design for third-party application key management.
> It is intended **for demo use only** and not production.

---

## ✨ Features

- Stores a single EVM or BLS private key securely
- Derives application-specific subkeys via deterministic path
- Supports signing and verification over TCP
- CLI tool and daemon in a single binary
- Outputs raw, hex, or base64 formats
- Structured JSON output for programmatic integration

---

### ✅ CLI Coverage Summary

| Category        | Status        |
|-----------------|---------------|
| 🧠 Daemon       | ✅ Start / Shutdown tested |
| 🔐 Keys         | ✅ Add / Remove / List / BLS supported |
| 🌱 Derivation   | ✅ Path-based, key conflict, pubkey export |
| ✍️ Signing      | ✅ All inputs (`file`, `hex`, `stdin`) and encodings |
| 🔍 Verification | ✅ All signature types + invalid cases |
| 📤 Output       | ✅ `--out`, `--raw-out`, `--stdout`, `--json` |
| 🔁 Full E2E     | ✅ Cross-validated via actual CLI runs |

> Farily full suite of functional tests validating key store usage in real-world CLI flows.

---

## 📁 Example Flow: Signing

```bash
# Step 1: Add a key
auth add-evm-key \
  --name root \
  --hex <64-char-hex>

# Step 2: Sign message
auth sign \
  --name root \
  --hex deadbeef \
  --out sig.bin \
  --output base64

# Step 3: Verify signature
auth verify \
  --name root \
  --hex deadbeef \
  --signature-file sig.bin
```

---

## 🚀 Quick Start

### Start the background daemon

```bash
# Start the service
auth start
````

This will bind a local TCP socket and keep the process running.
Use `&` or a supervisor to run it in the background.

---

### Add a private key

Supports both EVM and BLS key formats

```bash
# Add an EVM key
auth add-evm-key \
  --name mykey \
  --hex deadbeefcafebabe...
```

```bash
# Add a BLS key
auth add-bls-key \
  --name myblskey \
  --hex deadbeefcafebabe...
```

### Remove a private key

```bash
# Remove a key
auth remove-key \
  --name oldkey
```

---

### List keys

```bash
# List all keys, print to stdout in base64 format
auth list-keys
```

```bash
# List keys and write output to file in hex format
auth list-keys \
  --out keys.txt \
  --output hex
```

Outputs all stored key names.

---

### Get public key

```bash
# Get public key and print to stdout as base64
auth get-public-key \
  --name mykey \
  --stdout
```

```bash
# Get public key and write to file as hex
auth get-public-key \
  --name root \
  --out pubkey.hex \
  --output hex
```

---

### Get public key on path

```bash
# Get public key on a derivation path and write to file
auth get-public-key-on-path \
  --name rootkey \
  --path myapp user123 \
  --out pubkey.txt
```

Does not store the derived key, or any intermediary derived keys.

---

### Derive a scoped subkey

```bash
# Derive a new key from an existing one using provided derivation path
auth derive-key \
  --from-name root \
  --path myapp user123 \
  --to-name newkey
```

This creates a new BLS key deterministically derived from `root` and stores it under the user-given name.

---

### Sign a message

```bash
# Sign a file and write base64 signature to stdout
auth sign \
  --name mykey \
  --file ./data.bin \
  --stdout
```

```bash
# Sign hex-encoded input and write raw signature to file
auth sign \
  --name mykey \
  --hex deadbeef \
  --out sig.bin \
  --raw-out
```

```bash
auth sign \
  --hex deadbeef... \
  --out signature.bin \
  --output base64
```

Supports input from `--file`, `--hex`, or `--stdin`.
Outputs signature in raw, hex, or base64 format.

---

### Sign message on a path

```bash
# Sign on a derivation path using stdin input
auth sign-on-path \
  --name rootkey \
  --path module1 user456 \
  --stdin \
  --stdout
```

Does not store the derived key, or any intermediary derived keys.

---

### Verify a signature

```bash
# Verify a signature from file using input file
auth verify \
  --name mykey \
  --file ./data.txt \
  --signature-file ./sig.txt
```

```bash
# Verify hex input against hex signature
auth verify \
  --name mykey \
  --hex deadbeef \
  --signature-hex a1b2c3...
```

Verifies the signature using the public key derived from the stored key.

---

### Verify signature on path

```bash
# Verify base64 signature on a derived key path
auth verify-on-path \
  --name rootkey \
  --path auth user789 \
  --file ./msg.txt \
  --signature-base64 MEUCIQ...
```

Verifies the signature using the public key on the derivation path starting with the stored key.

Does not store the derived key, or any intermediary derived keys.

---

### JSON

```bash
# Add global JSON flag to any command
auth list-keys --json
```

---

## 🧪 Output Options

All signing-related commands support:

* `--out <path>`: Write to file
* `--stdout`: Force output to stdout
* `--raw-out`: Output raw bytes
* `--output [hex|base64]`: Encoding format
* `--json`: Emit structured JSON (for machines)

---

## 📦 Installation

Requires Rust toolchain. To build:

```bash
cargo build --release
cp target/release/auth /usr/local/bin/auth
```

---

## 🔐 Security Model

* Only the root key is stored persistently.
* Derived subkeys are created on-the-fly and never stored unless explicitly requested.
* The signing API prevents key export — only signatures are returned.

---

## 💡 Tip

You can use `auth start &` to launch the daemon in the background.

---
---

# 🧱 Architecture & Protocol

This section documents the internal design, request/response protocol, daemon architecture, and integration model for advanced users and developers.

---

## 📦 Overview

The system is a **single-binary architecture** with two operational roles:

- **CLI mode**: Used to issue commands and send requests
- **Daemon mode** (`auth start`): A long-running TCP service that performs all sensitive operations

All stateful key material is held only in the daemon's memory.  
All other components interact via structured TCP messages.

---

## 🔌 Request/Response Protocol

The CLI serializes structured `Request` enums, and receives structured `Response` enums.

### ✅ Request enum (simplified)

```rust
pub enum Request {
    Start,
    Shutdown,
    List,
    StoreEVM { name: String, evm_sk_hex: String },
    StoreBLS { name: String, bls_sk_hex: String },
    Remove(String),
    PublicKey(String),
    PublicKeyOnPath { name: String, path: Vec<String> },
    Derive { from_name: String, to_name: String, path: Vec<String> },
    Sign { with_name: String, payload: Bytes },
    SignOnPath { with_name: String, path: Vec<String>, payload: Bytes },
    Verify { with_name: String, signature: Bytes, payload: Bytes },
    VerifyOnPath { with_name: String, path: Vec<String>, signature: Bytes, payload: Bytes },
}
````

All payloads are binary-safe (`Bytes`), not string-encoded.

---

### ✅ Response enum

```rust
pub enum Response {
    Ack,
    KeyNames(Vec<String>),
    PublicKey(PublicKey),
    Signature(Signature),
    Error(String),
}
```

Use the `--json` flag to serialize responses as structured JSON.

---

## 🧰 Daemon Lifecycle

### `auth start`:

* Attempts to bind to a fixed TCP port
* Runs `daemon::run()` in the foreground
* Handles one connection at a time (or use `tokio` concurrency if configured)

### Shutdown

```bash
auth shutdown
```

Triggers graceful shutdown. All state is in-memory; no persistence is performed.

---

## 🔐 KeyStore Model

* Root key is stored in memory
* Derived keys are computed on-demand and discarded
* `store_derived` explicitly persists a derived key by name

### API contracts

* All cryptographic types are parsed inside the daemon (`Signature`, `SecretKey`)
* CLI handles decoding hex/base64 into `Vec<u8>`
* TCP layer transmits compact `Bytes`, not serialized hex

---

## 📤 Output Design

All output-capable commands support:

* `--out` → write to file
* `--stdout` → force print
* `--raw-out` → binary
* `--output` → hex / base64
* `--json` → emit structured JSON envelope

This allows the CLI to be called safely from any external tool or scripting environment.

---

## 📁 Example Flow: Signing

```bash
# Step 1: Add a key
auth add-evm-key \
  --name root \
  --hex <64-char-hex>

# Step 2: Sign message
auth sign \
  --name root \
  --hex deadbeef \
  --out sig.bin \
  --output base64

# Step 3: Verify signature
auth verify \
  --name root \
  --hex deadbeef \
  --signature-file sig.bin
```

---

## API

### Add

```bash
auth add-evm-key --name <NAME> --hex <HEX>
```

```bash
auth add-bls-key --name <NAME> --hex <HEX>
```

---

### Remove

```bash
auth remove-key --name <NAME>
```

---

### List keys

```bash
auth list-keys \
  [--out <FILE>] \
  [--stdout] \
  [--raw-out] \
  [--output <base64|hex>]
```

---

### Get public key

```bash
auth get-public-key \
  --name <NAME> \
  [--out <FILE>] \
  [--stdout] \
  [--raw-out] \
  [--output <base64|hex>]
```

---

### Get public key on path

```bash
auth get-public-key-on-path \
  --name <NAME> \
  --path <P1> [--path <P2> ...] \
  [--out <FILE>] \
  [--stdout] \
  [--raw-out] \
  [--output <base64|hex>]
```

---

### Derive a scoped subkey

```bash
auth derive-key \
  --from-name <NAME> \
  --path <P1> [--path <P2> ...] \
  --to-name <NAME>
```

---

### Sign a message

```bash
auth sign --name <NAME> (--file <FILE> | --hex <HEX> | --stdin)
         [--out <FILE>] [--stdout] [--raw-out] [--output <base64|hex>]
```

---

### Sign message on a path

```bash
auth sign-on-path --name <NAME> --path <P1> [--path <P2> ...]
                 (--file <FILE> | --hex <HEX> | --stdin)
                 [--out <FILE>] [--stdout] [--raw-out] [--output <base64|hex>]
```

---

### Verify a signature

```bash
auth verify --name <NAME>
           (--file <FILE> | --hex <HEX> | --stdin)
           (--signature-file <FILE> | --signature-hex <HEX> | --signature-base64 <B64>)
           [--out <FILE>] [--stdout] [--raw-out] [--output <base64|hex>]
```

---

### Verify signature on path

```bash
auth verify-on-path --name <NAME> --path <P1> [--path <P2> ...]
                   (--file <FILE> | --hex <HEX> | --stdin)
                   (--signature-file <FILE> | --signature-hex <HEX> | --signature-base64 <B64>)
                   [--out <FILE>] [--stdout] [--raw-out] [--output <base64|hex>]
```

---

### JSON

```bash
# Add global JSON flag to any command
auth list-keys --json
```

---

## 🧩 Integration

* Embed CLI via subprocess or `Command::new("auth")`
* Use `--json` + `--out` for machine-safe responses
* Never embed private key in your application — use the daemon's `sign` and `derive` instead

---

## 🔐 Trust Model

* The daemon is the root of trust
* All other components are stateless and unprivileged
* Compromise of the daemon memory leaks root key — derivations offer **scoping**, not isolation

---

## 🔄 Future Plans

* Optional CRDT-style key graph with version tracking
* Secure memory fencing (e.g. `zeroize`)
* Pluggable backends (E.g. Autonomi network)
* Sign EVM transaction

---

# Test Coverage

## 🧪 Test Coverage Overview – `KeyStore`

Coverage of the core functionalities of the `KeyStore` implementation:

### ✅ Covered Functional Areas

| Feature Category           | Description                                                             | Covered |
|----------------------------|-------------------------------------------------------------------------|:-------:|
| **BLS Key Storage**        | Store valid keys, detect duplicates, handle invalid input               |   ✅    |
| **EVM Key Storage**        | Store EVM keys, handle invalid hex                                      |   ✅    |
| **Derived Keys**           | Create from BLS base keys, validate overwrite and missing base errors   |   ✅    |
| **Key Removal**            | Remove existing keys, handle non-existent removal                       |   ✅    |
| **Key Derivation**         | Valid path derivation, empty path handling, missing key errors          |   ✅    |
| **Signing**                | BLS signing, path-based signing, incorrect payload check                |   ✅    |
| **Verification**           | Normal/path-based, negative cases for mismatch, wrong key, etc.         |   ✅    |
| **Public Key Access**      | Retrieval, path-based retrieval, negative cases                         |   ✅    |
| **Internal Key Access**    | Direct `get()`, error for non-existent keys                             |   ✅    |
| **Listing Keys**           | Return all key names                                                    |   ✅    |
| **Concurrency safety**     | Partial test of parallel access and thread-safety guarantees            |   🟡    |

### 📉 Missing / Not Explicitly Covered

| Area                        | Notes                                                                 | Covered |
|-----------------------------|-----------------------------------------------------------------------|:-------:|
| Concurrency safety          | Insufficient tests for parallel access or thread-safety guarantees    |   🟡    |
| Persistence / I/O           | Not tested (assumes in-memory store)                                  |   🟡    |
| Performance boundaries      | No benchmarks or stress tests                                         |   ❌    |
| Serialization formats       | Not tested or mentioned                                               |   ❌    |
| Edge-case path semantics    | No tests for edge path characters, reserved names, etc.               |   ❌    |

---


## ✅ Test Coverage Overview - `parse_cmd` and Supporting Logic

This test suite provides validation of the CLI-to-request conversion layer (`parse_cmd`) and its auxiliary data resolution logic. It tests correctness of:

- Command-to-Request mapping
- Input parsing (from file, hex, or base64)
- Signature decoding
- Output formatting behavior
- Error handling for invalid combinations

### 🔍 Coverage Breakdown

| Area | Description | Covered Tests |
|------|-------------|---------------|
| **Core Command Mapping** | Ensures that every CLI subcommand correctly maps to the expected `Request` variant | `start_command_request_start`, `shutdown_command_request_shutdown`, `listkeys_request_list_with_outputtarget`, `addevmkey_request_storeevm_name_hex`, `removekey_request_removename`, `getpublickey_request_publickey_with_outputtarget`, `getpublickeyonpath_request_publickeyonpath_with_outputtarget_and_path`, `derivekey_request_derive_from_name_path_to_name` |
| **Payload Resolution** | Verifies that input payloads are correctly parsed from file, hex, or stdin (with invalid combinations rejected) | `resolve_payload_with_only_file`, `resolve_payload_with_only_hex`, `resolve_payload_with_only_stdin`, `resolve_payload_with_multiple_inputs_error` |
| **Signature Resolution** | Validates decoding of signature data from file, hex, or base64 and rejects multiple input fields | `resolve_signature_with_file`, `resolve_signature_with_hex`, `resolve_signature_with_base64`, `resolve_signature_with_multiple_inputs_error` |
| **Signing and Verification Commands** | Full request validation for signing and verification logic, including scoping and payload correctness | `signonpath_with_hex_input`, `verify_with_hex_sig`, `verify_with_base64_sig`, `verify_with_file_sig`, `verifyonpath_with_hex_sig`, `verifyonpath_with_base64_sig` |
| **Input Conflict Errors** | Explicit tests for invalid `InputSource` and `SignatureSource` combinations triggering expected errors | `signonpath_with_multiple_inputs_error`, `resolve_payload_with_multiple_inputs_error`, `resolve_signature_with_multiple_inputs_error` |
| **Output Behavior** | Ensures that default and custom `OutputTarget` values are correctly handled across all commands | `addevmkey_returns_default_outputtarget`, `start_returns_default_outputtarget`, `listkeys_request_list_with_outputtarget`, `verify_with_base64_sig`, `verifyonpath_with_hex_sig` |

---

## ✅ CLI Behavior Coverage (E2E Verified)

### 🧠 Daemon Lifecycle
| Command        | Behavior Tested                          |
|---------------|-------------------------------------------|
| `start`       | Launches background daemon                |
| `shutdown`    | Terminates daemon gracefully              |
| Post-shutdown | All commands fail as expected afterward   |

---

### 🔐 Key Management

| Command         | Scenarios Tested                                   |
|-----------------|-----------------------------------------------------|
| `add-evm-key`   | Valid key, malformed hex, duplicate name rejected   |
| `add-bls-key`   | Valid BLS key inserted and confirmed via listing    |
| `remove-key`    | Valid removal, error on unknown key                 |
| `list-keys`     | Checked before and after modifications, JSON parsed |

---

### 🌱 Key Derivation

| Command                | Scenarios Tested                                     |
|------------------------|-----------------------------------------------------|
| `derive-key`           | Valid multi-step path, conflict on `to-name`, empty path error |
| `get-public-key`       | Valid export, error on unknown key                  |
| `get-public-key-on-path` | Derived public key export validated                 |

---

### ✍️ Signing

| Command        | Input Types          | Output Formats Tested                         |
|----------------|----------------------|-----------------------------------------------|
| `sign`         | `--file`, `--hex`, `--stdin` | `--out`, `--raw-out`, `--output hex/base64` |
| `sign-on-path` | Path-based signing    | Valid output file verified                    |

---

### ✅ Verification

| Command          | Signature Input Types         | Error Cases Covered                        |
|------------------|-------------------------------|---------------------------------------------|
| `verify`         | `--signature-file`, `--hex`, `--base64` | Wrong key, invalid sig, malformed encoding |
| `verify-on-path` | Path-based public key used    | Confirmed success                          |

---

### 📤 Output Handling

| Flag             | Status                                                   |
|------------------|----------------------------------------------------------|
| `--out`          | Verified for all output-bearing commands                 |
| `--stdout`       | Defaults confirmed via test harness behavior             |
| `--raw-out`      | Validated as binary, confirmed structure post-output     |
| `--output`       | Hex + Base64 output tested for correctness               |
| `--json`         | Structured response parsed and asserted for correctness  |

---

**Test Methodology:**  
- Executed via real CLI (`assert_cmd`)
- Daemon launched once and shared
- Each command exercised with isolated keys and temp files
- Errors asserted for malformed, missing, or conflicting inputs
