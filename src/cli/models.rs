//! .

use std::path::PathBuf;

#[derive(clap::Parser)]
#[command(name = "app")]
pub struct Cli {
    #[clap(long, default_value = "48522")]
    pub port: u16,
    #[clap(global = true, long)]
    pub json: bool,
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(clap::Args, Debug, Clone)]
pub struct InputSource {
    #[clap(long, conflicts_with_all = ["hex", "stdin"])]
    pub file: Option<PathBuf>,

    #[clap(long, conflicts_with_all = ["file", "stdin"])]
    pub hex: Option<String>,

    #[clap(long, conflicts_with_all = ["file", "hex"])]
    pub stdin: bool,
}

#[derive(clap::Args, Debug, Clone)]
pub struct SignatureSource {
    #[clap(
        long,
        required_unless_present_any = ["signature_hex", "signature_base64"],
        conflicts_with_all = ["signature_hex", "signature_base64"]
    )]
    pub signature_file: Option<PathBuf>,

    #[clap(
        long,
        required_unless_present_any = ["signature_file", "signature_base64"],
        conflicts_with_all = ["signature_file", "signature_base64"]
    )]
    pub signature_hex: Option<String>,

    #[clap(
        long,
        required_unless_present_any = ["signature_file", "signature_hex"],
        conflicts_with_all = ["signature_file", "signature_hex"]
    )]
    pub signature_base64: Option<String>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct OutputTarget {
    #[clap(long)]
    pub out: Option<PathBuf>,

    #[clap(long)]
    pub stdout: bool,

    #[clap(long)]
    pub raw_out: bool,

    #[clap(long, default_value = "base64")]
    pub output: OutputFormat,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Base64,
    Hex,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum Command {
    Start,
    Shutdown,
    ListKeys {
        #[clap(flatten)]
        output: OutputTarget,
    },
    AddEvmKey {
        #[clap(long)]
        name: String,

        #[clap(long)]
        hex: String,
    },
    AddBlsKey {
        #[clap(long)]
        name: String,

        #[clap(long)]
        hex: String,
    },
    RemoveKey {
        #[clap(long)]
        name: String,
    },
    GetPublicKey {
        #[clap(long)]
        name: String,

        #[clap(flatten)]
        output: OutputTarget,
    },
    GetPublicKeyOnPath {
        #[clap(long)]
        name: String,

        #[clap(long)]
        path: Vec<String>,

        #[clap(flatten)]
        output: OutputTarget,
    },
    DeriveKey {
        #[clap(long)]
        from_name: String,

        #[clap(long)]
        path: Vec<String>,

        #[clap(long)]
        to_name: String,
    },
    Sign {
        #[clap(long)]
        name: String,

        #[clap(flatten)]
        input: InputSource,

        #[clap(flatten)]
        output: OutputTarget,
    },
    SignOnPath {
        #[clap(long)]
        name: String,

        #[clap(long)]
        path: Vec<String>,

        #[clap(flatten)]
        input: InputSource,

        #[clap(flatten)]
        output: OutputTarget,
    },
    Verify {
        #[clap(long)]
        name: String,

        #[clap(flatten)]
        input: InputSource,

        #[clap(flatten)]
        signature: SignatureSource,

        #[clap(flatten)]
        output: OutputTarget,
    },
    VerifyOnPath {
        #[clap(long)]
        name: String,

        #[clap(long)]
        path: Vec<String>,

        #[clap(flatten)]
        input: InputSource,

        #[clap(flatten)]
        signature: SignatureSource,

        #[clap(flatten)]
        output: OutputTarget,
    },
}
