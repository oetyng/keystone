//! .

use crate::{
    ipc::client,
    protocol::{Request, Response, receive_msg, send_msg},
};

use std::process;

pub(crate) async fn send(request: Request, port: u16) -> Response {
    let mut stream = client::connect(port).await;
    let (reader, writer) = stream.split();

    if let Err(e) = send_msg(writer, &request).await {
        eprintln!("Failed to send request: {e}");
        process::exit(1);
    }

    let response: Response = match receive_msg(reader).await {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("Failed to receive response: {e}");
            process::exit(1);
        }
    };

    response
}
