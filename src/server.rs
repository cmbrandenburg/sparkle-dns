//! Defines components for running a DNS server.
//!
//! The `server` module currently provides a barebones server implementation:
//!
//! * Support for UDP only.
//! * No support for AXFR.
//! * No support for recursion.

use {WireDecoder, WireEncoder, WireMessage, std, wire};
use std::net::UdpSocket;
use std::sync::Arc;

// TODO: Replace println statements with rigorous logging.

/// Specifies an error that occurred while receiving a request and sending its
/// response.
#[derive(Debug)]
pub enum ServerError {
    Io { inner: std::io::Error, what: String },
}

impl std::error::Error for ServerError {
    fn description(&self) -> &str {
        match self {
            &ServerError::Io { ref what, .. } => what,
        }
    }
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        let d = (self as &std::error::Error).description();
        match self {
            &ServerError::Io { ref inner, .. } => write!(f, "{}: {}", d, inner),
        }
    }
}

/// Handles server events—e.g., by doing a DNS lookup to respond to a DNS
/// request.
///
/// Applications implement the `Handler` trait.
///
pub trait Handler {
    type Error: std::error::Error;
    fn handle_query<'a>(&self,
                        query: &WireMessage,
                        encoder: WireEncoder<'a, wire::marker::Response, wire::marker::AnswerSection>)
                        -> WireEncoder<'a, wire::marker::Response, wire::marker::Done>;
}

/// Manages all networking of a DNS server.
#[derive(Debug)]
pub struct Server<'a, H: 'a + Handler> {
    socket: Arc<UdpSocket>,
    handler: &'a H,
}

impl<'a, H: Handler> Server<'a, H> {
    pub fn new(h: &'a H) -> Result<Self, ServerError> {
        // TODO: Support options for binding to other ports.
        let addr = "0.0.0.0:53";
        let socket = UdpSocket::bind(addr).map_err(|e| {
                ServerError::Io {
                    inner: e,
                    what: format!("Failed to bind UDP socket to {}", addr),
                }
            })?;
        Ok(Server {
            socket: Arc::new(socket),
            handler: h,
        })
    }

    pub fn serve(self) -> Result<(), ServerError> {
        const MAX_UDP_MESSAGE_LEN: usize = 512;
        let mut ibuffer: [u8; MAX_UDP_MESSAGE_LEN] = [0; MAX_UDP_MESSAGE_LEN];
        // println!("Server is listening");
        loop {
            let (recv_len, peer_addr) = self.socket
                .recv_from(&mut ibuffer)
                .map_err(|e| {
                    ServerError::Io {
                        inner: e,
                        what: String::from("Failed to receive from UDP socket"),
                    }
                })?;
            let ipayload = &ibuffer[..recv_len];

            let mut decoder = WireDecoder::new(ipayload);
            let request = match decoder.decode_message() {
                Ok(x) => x,
                Err(e) => {
                    println!("Received invalid message: {}", e);
                    continue;
                }
            };

            // println!("Received message: {:?}", request);

            let mut obuffer: [u8; MAX_UDP_MESSAGE_LEN] = [0; MAX_UDP_MESSAGE_LEN];
            let encoder = match WireEncoder::new_response(&mut obuffer[..], &request) {
                Ok(x) => x,
                Err(_) => continue, // TODO: Should send a SERVFAIL or FORMERR here, probably.
            };

            let encoder = self.handler.handle_query(&request, encoder);
            let opayload = encoder.as_bytes();

            match self.socket.send_to(opayload, peer_addr) {
                Ok(send_len) => {
                    if send_len != opayload.len() {
                        println!("Sent unexpected number of bytes on UDP socket: Expected to send {}, actually sent \
                                  {}",
                                 opayload.len(),
                                 send_len);
                    }
                }
                Err(e) => {
                    println!("Failed to send on UDP socket: {}", e);
                }
            }
        }
    }
}
