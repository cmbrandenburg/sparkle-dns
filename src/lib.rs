//! Sparkle is a DNS server framework, useful for writing DNS server
//! applications that do dynamic per-request processing.

mod format;
mod serial;
mod wire;
pub mod server;

pub use format::{Class, Format, Name, QClass, QType, Question, RData, ResourceRecord, Type, class, qclass, qtype,
                 type_};
pub use serial::SerialNumber;
pub use wire::{WireDecoder, WireEncoder, WireFormat, WireLabelIter, WireMessage, WireName};

/// Encodes a DNS response message to an external buffer, starting with the
/// answers section.
pub type WireResponseEncoder<'a> = WireEncoder<'a, wire::marker::Response, wire::marker::AnswerSection>;

/// Returns a reference to an external buffer containing a completely encoded
/// DNS response message.
pub type WireResponseEncoderDone<'a> = WireEncoder<'a, wire::marker::Response, wire::marker::Done>;
