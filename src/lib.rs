//! Sparkle is a DNS server framework, useful for writing DNS server
//! applications that do dynamic per-request processing.

mod buf_name;
mod class;
mod error;
mod format;
mod name;
mod serial;
mod testing;
mod text;
mod ttl;
mod typ;
mod wire;

pub mod server;

pub use buf_name::BufName;
pub use class::{QClass, RClass, qclass, rclass};
pub use error::Error;
pub use format::{Format, Question, RData, ResourceRecord};
pub use name::Name;
pub use serial::Serial;
pub use text::TextName;
pub use ttl::Ttl;
pub use typ::{QType, RType, qtype, rtype};
pub use wire::{WireDecoder, WireEncoder, WireFormat, WireLabelIter, WireMessage, WireName};

/// Encodes a DNS response message to an external buffer, starting with the
/// answers section.
pub type WireResponseEncoder<'a> = WireEncoder<'a, wire::marker::Response, wire::marker::AnswerSection>;

/// Returns a reference to an external buffer containing a completely encoded
/// DNS response message.
pub type WireResponseEncoderDone<'a> = WireEncoder<'a, wire::marker::Response, wire::marker::Done>;
