//! .

mod error;
mod models;
mod render;
mod resolve;

pub(crate) use error::ParseError;
pub(crate) use models::Cli;
pub(crate) use render::render;
pub(crate) use resolve::parse_cmd;
