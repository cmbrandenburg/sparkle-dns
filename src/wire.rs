// This module defines types for working with the DNS protocol on the
// wire--i.e., encoding and decoding DNS messages.
//
// The overarching design goal is for message-encoding and -decoding to do zero
// heap memory allocations. The purpose of this goal is run-time efficiency.
//
// Internally, there are many `unsafe` blocks to make this work. Why? The short
// answer is that in many cases Rust's safety checks are redundant because we're
// working with trusted memory and we can disable the checks for improved
// speed and size.
//
// Here's a longer explanation, starting first with decoding.
//
// We decode messages without allocating any heap memory, and one consequence is
// that decoding is generally two-pass:
//
// 1. The first pass checks the message's validity and returns offsets to
//    important parts within the message buffer. This pass operates on
//    *untrusted* data.
//
// 2. The second pass takes both a valid message and the offsets into it and
//    returns useful values, such as record types and domain names. This pass
//    operates on *trusted* data--i.e., can be `unsafe`.
//
// Note, none of the `unsafe` interfaces leak out through public interfaces in
// this module--i.e., all unsafety is well contained. Callers using this module
// can use these types knowing that they'll always get either valid data or a
// proper error--and never a memory error.
//
// Encoding is similar to decoding. Encoding works by writing message data to an
// external buffer. In some cases we are guaranteed that the buffer is big
// enough (because we previously checked the buffer's length). In these cases,
// we can use `unsafe` to do an unchecked write to the buffer.

use {Format, Name, QClass, QType, Question, RClass, RData, RType, ResourceRecord, Serial, Ttl, format, rclass, rtype,
     std};
use format::MAX_NAME_LENGTH;

/// Specifies the DNS on-the-wire protocol format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireFormat;

impl<'a> Format<'a> for WireFormat {
    type Name = WireName<'a>;
    type RawOctets = &'a [u8];
}

/// Encapsulates a DNS message domain name in an external buffer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireName<'a> {
    decoder: TrustedDecoder<'a>,
}

impl<'a> Name<'a> for WireName<'a> {
    type LabelIter = WireLabelIter<'a>;
    fn labels(&'a self) -> Self::LabelIter {
        WireLabelIter {
            decoder: self.decoder.clone(),
            done: false,
        }
    }
}

impl<'a> std::fmt::Display for WireName<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        self.labels()
            .fold(String::new(), |mut a, b| {
                a.push_str(b);
                if !b.is_empty() {
                    a.push('.');
                }
                a
            })
            .fmt(f)
    }
}

#[derive(Clone, Debug)]
pub struct WireLabelIter<'a> {
    decoder: TrustedDecoder<'a>,
    done: bool,
}

impl<'a> Iterator for WireLabelIter<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            None
        } else {
            match unsafe { self.decoder.decode_label_unchecked() } {
                Some(x) => Some(x),
                None => {
                    self.done = true;
                    Some("")
                }
            }
        }
    }
}

/// Encapsulates a DNS message in an external buffer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireMessage<'a> {
    id: u16,
    flags: u16,
    question_section: QuestionSection<'a>,
    answer_section: ResourceRecordSection<'a>,
    authority_section: ResourceRecordSection<'a>,
    additional_section: ResourceRecordSection<'a>,
}

impl<'a> WireMessage<'a> {
    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn recursion_desired(&self) -> bool {
        0 != self.flags & RD_MASK
    }

    pub fn questions(&self) -> std::iter::Take<QuestionIter<'a>> {
        self.question_section.questions()
    }

    pub fn answers(&self) -> std::iter::Take<ResourceRecordIter<'a>> {
        self.answer_section.resource_records()
    }

    pub fn authorities(&self) -> std::iter::Take<ResourceRecordIter<'a>> {
        self.authority_section.resource_records()
    }

    pub fn additionals(&self) -> std::iter::Take<ResourceRecordIter<'a>> {
        self.additional_section.resource_records()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QuestionSection<'a> {
    count: u16,
    decoder: TrustedDecoder<'a>,
}

impl<'a> QuestionSection<'a> {
    pub fn questions(&self) -> std::iter::Take<QuestionIter<'a>> {
        QuestionIter { decoder: self.decoder.clone() }.take(self.count as usize)
    }
}

#[derive(Clone, Debug)]
pub struct QuestionIter<'a> {
    decoder: TrustedDecoder<'a>,
}

impl<'a> Iterator for QuestionIter<'a> {
    type Item = Question<'a, WireFormat>;
    fn next(&mut self) -> Option<Self::Item> {
        Some(unsafe { self.decoder.decode_question_unchecked() })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResourceRecordSection<'a> {
    count: u16,
    decoder: TrustedDecoder<'a>,
}

impl<'a> ResourceRecordSection<'a> {
    pub fn resource_records(&self) -> std::iter::Take<ResourceRecordIter<'a>> {
        ResourceRecordIter { decoder: self.decoder.clone() }.take(self.count as usize)
    }
}

#[derive(Clone, Debug)]
pub struct ResourceRecordIter<'a> {
    decoder: TrustedDecoder<'a>,
}

impl<'a> Iterator for ResourceRecordIter<'a> {
    type Item = ResourceRecord<'a, WireFormat>;
    fn next(&mut self) -> Option<Self::Item> {
        Some(unsafe { self.decoder.decode_resource_record_unchecked() })
    }
}

const QR_MASK: u16 = 0b_1000_0000_0000_0000; // 0 for query, 1 for response
// const AA_MASK: u16 = 0b_0000_0100_0000_0000; // authoritative answer
const TC_MASK: u16 = 0b_0000_0010_0000_0000; // truncation
const RD_MASK: u16 = 0b_0000_0001_0000_0000; // recursion desired?
// const RA_MASK: u16 = 0b_0000_0000_1000_0000; // recursion available?
// const Z_MASK: u16 = 0b_0000_0000_0111_0000; // reserved for future use

// const OPCODE_MASK: u16 = 0b_0111_1000_0000_0000;
pub mod opcode {
    // pub const QUERY: u16 = 0b_0000_0000_0000_0000; // standard query
    // pub const IQUERY: u16 = 0b_0000_1000_0000_0000; // inverse query
    // pub const STATUS: u16 = 0b_0001_0000_0000_0000; // server status request
}

// const RCODE_MASK: u16 = 0b_0000_0000_0000_1111;
pub mod rcode {
    // pub const NOERROR: u16 = 0b_0000_0000_0000_0000; // no error
    // pub const FORMERR: u16 = 0b_0000_0000_0000_0001; // format error
    // pub const SERVFAIL: u16 = 0b_0000_0000_0000_0010; // server failure
    // pub const NXDOMAIN: u16 = 0b_0000_0000_0000_0011; // name error
    // pub const NOTIMP: u16 = 0b_0000_0000_0000_0100; // not implemented
    // pub const REFUSED: u16 = 0b_0000_0000_0000_0101; // refused
}

/// Defines marker types—should not be used directly.
pub mod marker {
    pub trait QueryOrResponse {}

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Query;
    impl QueryOrResponse for Query {}

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Response;
    impl QueryOrResponse for Response {}

    pub trait EncoderState {}

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct QuestionSection;
    impl EncoderState for QuestionSection {}

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct AnswerSection;
    impl EncoderState for AnswerSection {}

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct AuthoritySection;
    impl EncoderState for AuthoritySection {}

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct AdditionalSection;
    impl EncoderState for AdditionalSection {}

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Done;
    impl EncoderState for Done {}
}

/// Specifies an error that occurred while encoding a DNS message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncoderError;

impl std::error::Error for EncoderError {
    fn description(&self) -> &str {
        "Buffer is too small to contain message--message truncated"
    }
}

impl std::fmt::Display for EncoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        let d = (self as &std::error::Error).description();
        d.fmt(f)
    }
}

/// Writes a DNS message to an external buffer.
///
/// `WireEncoder` guards against buffer overflow. If the external buffer is too
/// small to contain all content, then the encoder sets the message's TC
/// (truncation) flag and elides questions and/or resource records such that the
/// DNS message is valid and fits within the buffer.
///
#[derive(Debug, Eq, PartialEq)]
pub struct WireEncoder<'a, Q: marker::QueryOrResponse, S: marker::EncoderState> {
    _phantom: std::marker::PhantomData<(Q, S)>,
    buffer: &'a mut [u8],
    cursor: usize,
}

impl<'a, Q: marker::QueryOrResponse, S: marker::EncoderState> WireEncoder<'a, Q, S> {
    fn new(buffer: &'a mut [u8]) -> Result<Self, EncoderError> {
        const HEADER_LEN: usize = 12;
        if buffer.len() < HEADER_LEN {
            return Err(EncoderError);
        }

        // Zero-out all bytes in the header.
        for i in 0..HEADER_LEN {
            buffer[i] = 0;
        }

        Ok(WireEncoder {
               _phantom: std::marker::PhantomData,
               buffer: buffer,
               cursor: HEADER_LEN,
           })
    }

    unsafe fn read_u16_at_unchecked(&self, index: usize) -> u16 {
        debug_assert!(index + 2 <= self.buffer.len());
        let hi = (*self.buffer.get_unchecked(index + 0) as u16) << 8;
        let lo = (*self.buffer.get_unchecked(index + 1) as u16) << 0;
        hi | lo
    }

    unsafe fn write_u16_at_unchecked(&mut self, index: usize, v: u16) {
        debug_assert!(index + 2 <= self.buffer.len());
        *self.buffer.get_unchecked_mut(index + 0) = (v >> 8) as u8;
        *self.buffer.get_unchecked_mut(index + 1) = (v >> 0) as u8;
    }

    fn encode_id(&mut self, id: u16) {
        unsafe { self.write_u16_at_unchecked(0, id) };
    }

    fn encode_flags(&mut self, mask: u16, flags: u16) {
        debug_assert_eq!(flags | mask, mask);
        unsafe {
            let bits = self.read_u16_at_unchecked(2) & !mask | flags;
            self.write_u16_at_unchecked(2, bits);
        }
    }

    fn encode_octets_at(&mut self, cursor: &mut usize, octets: &[u8]) -> Result<(), EncoderError> {
        if *cursor + octets.len() > self.buffer.len() {
            self.encode_flags(TC_MASK, TC_MASK);
            Err(EncoderError)
        } else {
            (&mut self.buffer[*cursor..*cursor + octets.len()]).copy_from_slice(octets);
            *cursor += octets.len();
            Ok(())
        }
    }

    fn encode_u8_at(&mut self, cursor: &mut usize, v: u8) -> Result<(), EncoderError> {
        self.buffer
            .get_mut(*cursor)
            .and_then(|x| {
                          *x = v;
                          *cursor += 1;
                          Some(())
                      })
            .or_else(|| {
                         self.encode_flags(TC_MASK, TC_MASK);
                         None
                     })
            .map(|_| ())
            .ok_or(EncoderError)
    }

    fn encode_u16_at(&mut self, cursor: &mut usize, v: u16) -> Result<(), EncoderError> {
        let mut w = *cursor;
        self.encode_u8_at(&mut w, (v >> 8) as u8)?;
        self.encode_u8_at(&mut w, (v >> 0) as u8)?;
        *cursor = w;
        Ok(())
    }

    fn encode_u32_at(&mut self, cursor: &mut usize, v: u32) -> Result<(), EncoderError> {
        let mut w = *cursor;
        self.encode_u16_at(&mut w, (v >> 16) as u16)?;
        self.encode_u16_at(&mut w, (v >> 0) as u16)?;
        *cursor = w;
        Ok(())
    }

    fn encode_rclass_at(&mut self, cursor: &mut usize, rclass: RClass) -> Result<(), EncoderError> {
        self.encode_u16_at(cursor, rclass.0)
    }

    fn encode_qclass_at(&mut self, cursor: &mut usize, qclass: QClass) -> Result<(), EncoderError> {
        self.encode_u16_at(cursor, qclass.0)
    }

    fn encode_rtype_at(&mut self, cursor: &mut usize, rtype: RType) -> Result<(), EncoderError> {
        self.encode_u16_at(cursor, rtype.0)
    }

    fn encode_qtype_at(&mut self, cursor: &mut usize, qtype: QType) -> Result<(), EncoderError> {
        self.encode_u16_at(cursor, qtype.0)
    }

    fn encode_name_at<'b, N: Name<'b>>(&mut self, cursor: &mut usize, name: &'b N) -> Result<(), EncoderError> {
        // TODO: Compress the name, if possible.
        let mut w = *cursor;
        for label in name.labels() {
            debug_assert!(label.len() < 64);
            self.encode_u8_at(&mut w, label.len() as u8)?;
            self.encode_octets_at(&mut w, label.as_bytes())?;
        }
        *cursor = w;
        Ok(())
    }

    fn encode_question_at<'b, F: Format<'b>>(&mut self,
                                             cursor: &mut usize,
                                             q: &'b Question<'b, F>)
                                             -> Result<(), EncoderError> {
        let mut w = *cursor;
        self.encode_name_at(&mut w, q.qname())?;
        self.encode_qtype_at(&mut w, q.qtype())?;
        self.encode_qclass_at(&mut w, q.qclass())?;
        *cursor = w;
        Ok(())
    }

    fn encode_rdlength_and_rdata_at<'b, F: Format<'b>>(&mut self,
                                                       cursor: &mut usize,
                                                       rdata: &'b RData<'b, F>)
                                                       -> Result<(), EncoderError> {
        let mut w = *cursor + 2; // leave room for RDLENGTH
        match rdata {
            &RData::A { ref address } => self.encode_octets_at(&mut w, &address.octets()[..])?,
            &RData::CName { ref cname } => self.encode_name_at(&mut w, cname)?,
            &RData::NS { ref nsdname } => self.encode_name_at(&mut w, nsdname)?,
            &RData::SOA {
                ref mname,
                ref rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                self.encode_name_at(&mut w, mname)?;
                self.encode_name_at(&mut w, rname)?;
                self.encode_u32_at(&mut w, u32::from(serial))?;
                self.encode_u32_at(&mut w, refresh.as_u32())?;
                self.encode_u32_at(&mut w, retry.as_u32())?;
                self.encode_u32_at(&mut w, expire.as_u32())?;
                self.encode_u32_at(&mut w, minimum.as_u32())?;
            }
            &RData::Other { ref octets } => self.encode_octets_at(&mut w, octets.as_ref())?,
        }
        let rdlength = w - (*cursor + 2);
        debug_assert!(rdlength <= 0xffff);
        unsafe { self.write_u16_at_unchecked(*cursor, rdlength as u16) }
        *cursor = w;
        Ok(())
    }

    fn encode_resource_record_at<'b, F: Format<'b>>(&mut self,
                                                    cursor: &mut usize,
                                                    r: &'b ResourceRecord<'b, F>)
                                                    -> Result<(), EncoderError> {
        let mut w = *cursor;
        self.encode_name_at(&mut w, r.name())?;
        self.encode_rtype_at(&mut w, r.rtype())?;
        self.encode_rclass_at(&mut w, r.rclass())?;
        self.encode_u32_at(&mut w, r.ttl().as_u32())?;
        self.encode_rdlength_and_rdata_at(&mut w, r.rdata())?;
        *cursor = w;
        Ok(())
    }
}

impl<'a, Q: marker::QueryOrResponse> WireEncoder<'a, Q, marker::QuestionSection> {
    /// Transitions the encoder into a state for encoding answers.
    pub fn finalize_questions(self) -> WireEncoder<'a, Q, marker::AnswerSection> {
        WireEncoder {
            _phantom: std::marker::PhantomData,
            buffer: self.buffer,
            cursor: self.cursor,
        }
    }

    pub fn encode_question<'b, F: Format<'b>>(&mut self, q: &'b Question<'b, F>) -> Result<(), EncoderError> {
        let mut cursor = self.cursor;
        self.encode_question_at(&mut cursor, q)?;
        self.cursor = cursor;
        unsafe {
            let qdcount = self.read_u16_at_unchecked(4) + 1;
            self.write_u16_at_unchecked(4, qdcount);
        }
        Ok(())
    }
}

impl<'a> WireEncoder<'a, marker::Query, marker::QuestionSection> {
    pub fn new_query(buffer: &'a mut [u8], id: u16) -> Result<Self, EncoderError> {
        let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(buffer)?;
        e.encode_id(id);
        // QR flag is zero to indicate we're a query
        Ok(e)
    }
}

impl<'a> WireEncoder<'a, marker::Response, marker::AnswerSection> {
    /// Constructs an encoder for encoding a response message.
    ///
    /// The target response is initialized such that:
    ///
    /// * Its **ID** field is copied from the request.
    /// * Its **QR** bit is set.
    /// * Its **RD** bit is copied from the request.
    /// * Its question section is copied verbatim from the request.
    ///
    /// If the request contains multiple questions, then the response will also
    /// contain multiple questions.
    ///
    pub fn new_response(buffer: &'a mut [u8], request: &WireMessage) -> Result<Self, EncoderError> {
        let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(buffer)?;

        e.encode_id(request.id()); // copied from request
        e.encode_flags(QR_MASK, QR_MASK); // yes, we're a response
        let bit = if request.recursion_desired() { RD_MASK } else { 0 };
        e.encode_flags(RD_MASK, bit); // copied from request

        // TODO: The subsequent `for` loop is a workaround for a lifetime error.
        // Here's the loop I want to use:
        //
        // for q in request.questions() {
        //     e.encode_question(&q);
        // }
        //
        // I don't understand why this causes a lifetime error. I've asked a
        // StackOverflow question about it here:
        //
        // http://stackoverflow.com/q/41337021/1094609

        for q in request.questions() {
            let mut w = e.cursor;
            e.encode_name_at(&mut w, q.qname())?;
            e.encode_qtype_at(&mut w, q.qtype())?;
            e.encode_qclass_at(&mut w, q.qclass())?;
            e.cursor = w;
            unsafe {
                let qdcount = e.read_u16_at_unchecked(4) + 1;
                e.write_u16_at_unchecked(4, qdcount);
            }
        }

        Ok(e.finalize_questions()) // prevent caller from fiddling with question section
    }

    pub fn finalize_answers(self) -> WireEncoder<'a, marker::Response, marker::AuthoritySection> {
        WireEncoder {
            _phantom: std::marker::PhantomData,
            buffer: self.buffer,
            cursor: self.cursor,
        }
    }

    pub fn encode_answer<'b, F: Format<'b>>(&mut self, r: &'b ResourceRecord<'b, F>) -> Result<(), EncoderError> {
        let mut cursor = self.cursor;
        self.encode_resource_record_at(&mut cursor, r)?;
        self.cursor = cursor;
        unsafe {
            let ancount = self.read_u16_at_unchecked(6) + 1;
            self.write_u16_at_unchecked(6, ancount);
        }
        Ok(())
    }
}

impl<'a> WireEncoder<'a, marker::Response, marker::AuthoritySection> {
    pub fn finalize_authorities(self) -> WireEncoder<'a, marker::Response, marker::AdditionalSection> {
        WireEncoder {
            _phantom: std::marker::PhantomData,
            buffer: self.buffer,
            cursor: self.cursor,
        }
    }

    pub fn encode_authority<'b, F: Format<'b>>(&mut self, r: &'b ResourceRecord<'b, F>) -> Result<(), EncoderError> {
        let mut cursor = self.cursor;
        self.encode_resource_record_at(&mut cursor, r)?;
        self.cursor = cursor;
        unsafe {
            let nscount = self.read_u16_at_unchecked(8) + 1;
            self.write_u16_at_unchecked(8, nscount);
        }
        Ok(())
    }
}

impl<'a> WireEncoder<'a, marker::Response, marker::AdditionalSection> {
    pub fn finalize_additionals(self) -> WireEncoder<'a, marker::Response, marker::Done> {
        WireEncoder {
            _phantom: std::marker::PhantomData,
            buffer: self.buffer,
            cursor: self.cursor,
        }
    }

    pub fn encode_additional<'b, F: Format<'b>>(&mut self, r: &'b ResourceRecord<'b, F>) -> Result<(), EncoderError> {
        let mut cursor = self.cursor;
        self.encode_resource_record_at(&mut cursor, r)?;
        self.cursor = cursor;
        unsafe {
            let arcount = self.read_u16_at_unchecked(10) + 1;
            self.write_u16_at_unchecked(10, arcount);
        }
        Ok(())
    }
}

impl<'a, Q: marker::QueryOrResponse> WireEncoder<'a, Q, marker::Done> {
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.cursor]
    }
}

/// Specifies an error that occurred while decoding a DNS message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecoderError {
    /// **RDATA** content does not match **RDLENGTH**.
    BadRdlength,

    /// Domain name compression results in an infinite name.
    InfiniteName,

    /// Domain name label length uses reserved bits.
    InvalidLabelLength,

    /// Domain name contains one or more invalid characters.
    InvalidLabel,

    /// Domain name is too long.
    NameTooLong,

    /// Domain name compression offset is out of range.
    NameOffsetOutOfRange,

    /// Message ends unexpectedly.
    UnexpectedEof,

    /// Message contains extra octets.
    UnexpectedOctets,
}

impl std::error::Error for DecoderError {
    fn description(&self) -> &str {
        match self {
            &DecoderError::BadRdlength => "RDATA content does not match RDLENGTH",
            &DecoderError::InfiniteName => "Domain name compression results in an infinite name",
            &DecoderError::InvalidLabelLength => "Domain name label field is invalid",
            &DecoderError::InvalidLabel => "Domain name contains one or more invalid labels",
            &DecoderError::NameTooLong => "Domain name is too long",
            &DecoderError::NameOffsetOutOfRange => "Domain name compression offset is out of range",
            &DecoderError::UnexpectedEof => "Message ends unexpectedly",
            &DecoderError::UnexpectedOctets => "Message contains extra octets",
        }
    }
}

impl std::fmt::Display for DecoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        let d = (self as &std::error::Error).description();
        d.fmt(f)
    }
}

/// Reads an untrusted DNS message from an external buffer while providing
/// error-checking.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireDecoder<'a> {
    buffer: &'a [u8],
    cursor: usize,
}

impl<'a> WireDecoder<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        WireDecoder {
            buffer: buffer,
            cursor: 0,
        }
    }

    #[cfg(test)]
    fn with_cursor_offset(&self, n: usize) -> Self {
        WireDecoder {
            cursor: self.cursor + n,
            ..*self
        }
    }

    unsafe fn as_trusted(&self) -> TrustedDecoder<'a> {
        TrustedDecoder {
            cursor: self.cursor,
            ..TrustedDecoder::new(self.buffer)
        }
    }

    fn decode_u8(&mut self) -> Result<u8, DecoderError> {
        match self.buffer.get(self.cursor) {
            None => Err(DecoderError::UnexpectedEof),
            Some(x) => {
                self.cursor += std::mem::size_of::<u8>();
                Ok(*x)
            }
        }
    }

    fn decode_u16(&mut self) -> Result<u16, DecoderError> {
        let mut w = self.clone();
        let hi = (w.decode_u8()? as u16) << 8;
        let lo = (w.decode_u8()? as u16) << 0;
        *self = w;
        Ok(hi | lo)
    }

    fn decode_u32(&mut self) -> Result<u32, DecoderError> {
        let mut w = self.clone();
        let hi = (w.decode_u16()? as u32) << 16;
        let lo = w.decode_u16()? as u32;
        *self = w;
        Ok(hi | lo)
    }

    fn decode_octets(&mut self, n: usize) -> Result<&'a [u8], DecoderError> {
        if self.cursor + n > self.buffer.len() {
            return Err(DecoderError::UnexpectedEof);
        }
        let x = &self.buffer[self.cursor..self.cursor + n];
        self.cursor += n;
        Ok(x)
    }

    fn decode_rclass(&mut self) -> Result<RClass, DecoderError> {
        Ok(RClass(self.decode_u16()?))
    }

    fn decode_qclass(&mut self) -> Result<QClass, DecoderError> {
        Ok(QClass(self.decode_u16()?))
    }

    fn decode_rtype(&mut self) -> Result<RType, DecoderError> {
        Ok(RType(self.decode_u16()?))
    }

    fn decode_qtype(&mut self) -> Result<QType, DecoderError> {
        Ok(QType(self.decode_u16()?))
    }

    fn decode_name(&mut self) -> Result<WireName<'a>, DecoderError> {

        // When we're done (successfully) decoding the name, our cursor must
        // point to the next field in the message. This position *isn't* the
        // same as where we stop decoding. Why? Because *name compression* might
        // cause us to jump around and finish decoding at a prior position in
        // the message.

        let mut end_of_name = 0;
        let mut compressed = false;

        // If an error occurs, then we must not have mutated our decoder's
        // state. To make this easier, we use a temporary decoder and mutate its
        // state instead.

        let mut w = self.clone();

        // An invalid DNS message could contain an infinite cycle of DNS labels.
        // To guard against this, we place an upper bound on the number of
        // labels. Otherwise, we would loop endlessly.

        const MAX_LABELS: usize = (MAX_NAME_LENGTH - 1) / 2;
        let mut total_len = 0;

        // Ok, all set. Now do the decoding.

        for _ in 0..(MAX_LABELS + 1) {
            let len = w.decode_u8()?;
            if !compressed {
                end_of_name = w.cursor;
            }
            match len & 0b_1100_0000 {
                0b_1100_0000 => {
                    compressed = true;
                    let offset = (len & 0b_0011_1111) as usize;

                    // According to RFC 1035, section 4.1.4, it's illegal to jump
                    // *forward* in a message:
                    //
                    // > In this scheme, an entire domain name or a list of labels
                    // at the end of a domain name is replaced with a pointer to a
                    // **prior** occurance of the same name. <
                    //
                    // (emphasis ours)

                    if offset >= w.cursor {
                        return Err(DecoderError::NameOffsetOutOfRange);
                    }

                    w.cursor = offset;
                }
                0b_0000_0000 => {
                    let len = len as usize;
                    total_len += len + 1;
                    if 0 == len {

                        // The reason we check the length now, at the end, and
                        // not when the length calculation is performed, is so
                        // that we can report separate errors for "too long" and
                        // "infinite cycle" without keeping a list of previous
                        // cursor values.

                        if total_len > MAX_NAME_LENGTH {
                            return Err(DecoderError::NameTooLong);
                        }

                        let name = WireName { decoder: unsafe { self.as_trusted() } };
                        self.cursor = end_of_name; // no error -> now safe to mutate
                        return Ok(name);
                    }
                    let label = w.decode_octets(len)?;
                    if !format::is_hostname_valid(label) {
                        return Err(DecoderError::InvalidLabel);
                    }
                }
                _ => {
                    // Other bit combinations are reserved for future use, as
                    // according to RFC 1035, section 4.1.4.
                    return Err(DecoderError::InvalidLabelLength);
                }
            }
        }

        Err(DecoderError::InfiniteName)

    }

    fn decode_rdata(&mut self, c: RClass, t: RType, rdlength: u16) -> Result<RData<'a, WireFormat>, DecoderError> {

        let mut w = self.clone();
        let rdata = match (c, t) {
            (rclass::IN, rtype::A) => RData::A { address: std::net::Ipv4Addr::from(w.decode_u32()?) },
            (_, rtype::CNAME) => RData::CName { cname: w.decode_name()? },
            (_, rtype::NS) => RData::NS { nsdname: w.decode_name()? },
            (_, rtype::SOA) => RData::SOA {
                mname: w.decode_name()?,
                rname: w.decode_name()?,
                serial: Serial(w.decode_u32()?),
                refresh: Ttl(w.decode_u32()?),
                retry: Ttl(w.decode_u32()?),
                expire: Ttl(w.decode_u32()?),
                minimum: Ttl(w.decode_u32()?),
            },
            (_, _) => RData::Other { octets: w.decode_octets(rdlength as usize)? },
        };

        // Check that the rdlength matches the number of bytes we actually
        // decoded.
        debug_assert!(self.cursor <= w.cursor);
        if rdlength as usize != w.cursor - self.cursor {
            return Err(DecoderError::BadRdlength);
        }

        *self = w; // no error -> now safe to mutate (move cursor)
        Ok(rdata)
    }

    fn decode_resource_record_section(&mut self, count: u16) -> Result<ResourceRecordSection<'a>, DecoderError> {

        // Validate all resource records and move the cursor.

        let mut w = self.clone();
        for _ in 0..count {
            w.decode_name()?;
            let t = w.decode_rtype()?;
            let c = w.decode_rclass()?;
            w.decode_u32()?;
            let rdlength = w.decode_u16()?;
            w.decode_rdata(c, t, rdlength)?;
        }

        // Ok, all resource records are valid.

        let r = ResourceRecordSection {
            count: count,
            decoder: unsafe { self.as_trusted() },
        };

        *self = w; // no error -> now safe to mutate (move cursor)
        Ok(r)
    }

    fn decode_question_section(&mut self, count: u16) -> Result<QuestionSection<'a>, DecoderError> {

        // Validate all questions and move the cursor.

        let mut w = self.clone();
        for _ in 0..count {
            w.decode_name()?;
            w.decode_qtype()?;
            w.decode_qclass()?;
        }

        // Ok, all questions are valid.

        let q = QuestionSection {
            count: count,
            decoder: unsafe { self.as_trusted() },
        };

        *self = w; // no error -> now safe to mutate (move cursor)
        Ok(q)
    }

    pub fn decode_message(&mut self) -> Result<WireMessage<'a>, DecoderError> {

        let mut w = self.clone();

        let id = w.decode_u16()?;
        let flags = w.decode_u16()?;
        let qdcount = w.decode_u16()?;
        let ancount = w.decode_u16()?;
        let nscount = w.decode_u16()?;
        let arcount = w.decode_u16()?;

        let question_section = w.decode_question_section(qdcount)?;
        let answer_section = w.decode_resource_record_section(ancount)?;
        let authority_section = w.decode_resource_record_section(nscount)?;
        let additional_section = w.decode_resource_record_section(arcount)?;

        if w.cursor != self.buffer.len() {
            return Err(DecoderError::UnexpectedOctets);
        }

        *self = w; // no error -> now safe to mutate (move cursor)

        Ok(WireMessage {
               id: id,
               flags: flags,
               question_section: question_section,
               answer_section: answer_section,
               authority_section: authority_section,
               additional_section: additional_section,
           })
    }
}

/// Decodes trusted DNS messages without providing error-checking.
///
/// An `TrustedDecoder` is literally unsafe and must only be used to decoded
/// trusted DNS messages—i.e., messages that have already been decoded without
/// error.
///
#[derive(Clone, Debug, Eq, PartialEq)]
struct TrustedDecoder<'a> {
    // Because the message is trusted, we don't need to keep track of the
    // message's length, which would otherwise be used only for error-checking.
    // By using a pointer (*const u8) instead of a slice (&'a [u8]), we save a
    // little memory by eliding the slice's length.
    buffer: *const u8,
    cursor: usize,

    // We explicitly track the lifetime so that maybe the compiler will save us
    // from doing something stupid.
    _phantom: std::marker::PhantomData<&'a ()>,

    // When debugging, add the slice's length back in. This allows us to do
    // some debug-only error-checking.
    #[cfg(debug_assertions)]
    size: usize,
}

impl<'a> TrustedDecoder<'a> {
    #[cfg(not(debug_assertions))]
    pub unsafe fn new(buffer: &'a [u8]) -> Self {
        TrustedDecoder {
            _phantom: std::marker::PhantomData,
            buffer: buffer.as_ptr(),
            cursor: 0,
        }
    }

    #[cfg(debug_assertions)]
    pub unsafe fn new(buffer: &'a [u8]) -> Self {
        TrustedDecoder {
            _phantom: std::marker::PhantomData,
            buffer: buffer.as_ptr(),
            cursor: 0,
            size: buffer.len(),
        }
    }

    #[cfg(test)]
    fn with_cursor_offset(&self, n: usize) -> Self {
        TrustedDecoder {
            cursor: self.cursor + n,
            ..*self
        }
    }

    #[cfg(not(debug_assertions))]
    fn size(&self) -> usize {
        0 // dummy value, never used
    }

    #[cfg(debug_assertions)]
    fn size(&self) -> usize {
        self.size
    }

    pub unsafe fn decode_u8_unchecked(&mut self) -> u8 {
        debug_assert!(self.cursor + std::mem::size_of::<u8>() <= self.size());
        let x = *self.buffer.offset(self.cursor as isize);
        self.cursor += std::mem::size_of::<u8>();
        x
    }

    pub unsafe fn decode_u16_unchecked(&mut self) -> u16 {
        let hi = (self.decode_u8_unchecked() as u16) << 8;
        let lo = (self.decode_u8_unchecked() as u16) << 0;
        hi | lo
    }

    pub unsafe fn decode_u32_unchecked(&mut self) -> u32 {
        let hi = (self.decode_u16_unchecked() as u32) << 16;
        let lo = (self.decode_u16_unchecked() as u32) << 0;
        hi | lo
    }

    pub unsafe fn decode_octets_unchecked(&mut self, n: usize) -> &'a [u8] {
        debug_assert!(self.cursor + n <= self.size());
        let x = std::slice::from_raw_parts(self.buffer.offset(self.cursor as isize), n);
        self.cursor += n;
        x
    }

    pub unsafe fn decode_rclass_unchecked(&mut self) -> RClass {
        RClass(self.decode_u16_unchecked())
    }

    pub unsafe fn decode_qclass_unchecked(&mut self) -> QClass {
        QClass(self.decode_u16_unchecked())
    }

    pub unsafe fn decode_rtype_unchecked(&mut self) -> RType {
        RType(self.decode_u16_unchecked())
    }

    pub unsafe fn decode_qtype_unchecked(&mut self) -> QType {
        QType(self.decode_u16_unchecked())
    }

    pub unsafe fn decode_label_unchecked(&mut self) -> Option<&'a str> {
        loop {
            let len = self.decode_u8_unchecked();
            if 0b_1100_0000 == len & 0b_1100_0000 {
                let offset = (len & 0b_0011_1111) as usize;
                self.cursor = offset;
            } else {
                debug_assert_eq!(len & 0b_1100_0000, 0b_0000_0000);
                return match len as usize {
                           0 => None,
                           len @ _ => Some(std::str::from_utf8_unchecked(self.decode_octets_unchecked(len))),
                       };
            }
        }
    }

    pub unsafe fn decode_name_unchecked(&mut self) -> WireName<'a> {

        // Because the name is valid and we don't need to check for any errors,
        // we needn't traverse the whole name. Instead, we need only find the
        // first byte of the field immediately following the name and set the
        // decoder's cursor to point to that byte. I.e., we stop traversing as
        // soon as we reach either (1) the end of the name or (2) the first
        // compressed label.

        let name = WireName { decoder: self.clone() };

        loop {
            let len = self.decode_u8_unchecked();
            if 0b_1100_0000 == len & 0b_1100_0000 {
                return name; // the remainder of the name is compressed
            } else {
                debug_assert_eq!(len & 0b_1100_0000, 0b_0000_0000);
                if 0 == len {
                    return name; // end of name
                }
                self.cursor += len as usize;
            }
        }
    }

    pub unsafe fn decode_rdata_unchecked(&mut self, c: RClass, t: RType, rdlength: u16) -> RData<'a, WireFormat> {
        match (c, t) {
            (rclass::IN, rtype::A) => RData::A { address: std::net::Ipv4Addr::from(self.decode_u32_unchecked()) },
            (_, rtype::CNAME) => RData::CName { cname: self.decode_name_unchecked() },
            (_, rtype::NS) => RData::NS { nsdname: self.decode_name_unchecked() },
            (_, rtype::SOA) => RData::SOA {
                mname: self.decode_name_unchecked(),
                rname: self.decode_name_unchecked(),
                serial: Serial(self.decode_u32_unchecked()),
                refresh: Ttl(self.decode_u32_unchecked()),
                retry: Ttl(self.decode_u32_unchecked()),
                expire: Ttl(self.decode_u32_unchecked()),
                minimum: Ttl(self.decode_u32_unchecked()),
            },
            _ => RData::Other { octets: self.decode_octets_unchecked(rdlength as usize) },
        }
    }

    pub unsafe fn decode_resource_record_unchecked(&mut self) -> ResourceRecord<'a, WireFormat> {
        let name = self.decode_name_unchecked();
        let rtype = self.decode_rtype_unchecked();
        let rclass = self.decode_rclass_unchecked();
        let ttl = Ttl(self.decode_u32_unchecked());
        let rdlength = self.decode_u16_unchecked();
        let rdata = self.decode_rdata_unchecked(rclass, rtype, rdlength);
        ResourceRecord::new(name, rtype, rclass, ttl, rdata)
    }

    pub unsafe fn decode_question_unchecked(&mut self) -> Question<'a, WireFormat> {
        Question::new(self.decode_name_unchecked(),
                      self.decode_qtype_unchecked(),
                      self.decode_qclass_unchecked())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{QuestionSection, ResourceRecordSection, TrustedDecoder};
    use {Format, Name, Question, RClass, RData, RType, ResourceRecord, Serial, Ttl, qclass, qtype, rclass, rtype, std};
    use format::MAX_NAME_LENGTH;
    use std::str::FromStr;

    struct TestFormat;

    impl<'a> Format<'a> for TestFormat {
        type Name = TestName;
        type RawOctets = Vec<u8>;
    }

    struct TestName(Vec<String>);

    impl TestName {
        fn new<S: Into<String>>(s: S) -> Self {
            let mut s = s.into();
            if !s.ends_with('.') {
                s.push('.');
            }
            TestName(s.split('.').map(|x| String::from(x)).collect())
        }
    }

    impl<'a> Name<'a> for TestName {
        type LabelIter = TestLabelIter<'a>;
        fn labels(&'a self) -> Self::LabelIter {
            TestLabelIter { inner: self.0.iter() }
        }
    }

    impl std::fmt::Display for TestName {
        fn fmt(&self, _f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
            unreachable!();
        }
    }

    struct TestLabelIter<'a> {
        inner: std::slice::Iter<'a, String>,
    }

    impl<'a> Iterator for TestLabelIter<'a> {
        type Item = &'a str;
        fn next(&mut self) -> Option<Self::Item> {
            match self.inner.next() {
                None => None,
                Some(x) => Some(&x),
            }
        }
    }

    #[test]
    fn wire_name_display() {
        let mut d = WireDecoder::new(b"\x03foo\x03bar\x00");
        let n = d.decode_name().unwrap();
        let got = format!("{}", n);
        let expected = "foo.bar.";
        assert_eq!(got, expected);
    }

    #[test]
    fn new_encoder_clears_header_bytes() {
        let mut b: [u8; 12] = [0xff; 12];
        WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b, expected);
    }

    #[test]
    fn new_encoder_nok() {
        let mut b: [u8; 11] = [0xff; 11];
        let got = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b);
        let expected = Err(EncoderError);
        assert_eq!(got, expected);
    }

    #[test]
    fn encoder_read_write_u16_at_unchecked() {
        let mut b: [u8; 12] = [0; 12];
        let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
        let got = unsafe { e.read_u16_at_unchecked(3) };
        let expected = 0x0000;
        assert_eq!(got, expected);

        unsafe { e.write_u16_at_unchecked(3, 0x1234) };
        let expected = b"\x00\x00\x00\x12\
                         \x34\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(e.buffer, expected);

        let got = unsafe { e.read_u16_at_unchecked(3) };
        let expected = 0x1234;
        assert_eq!(got, expected);
    }

    #[test]
    fn encoder_id() {
        let mut b: [u8; 12] = [0; 12];
        {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            e.encode_id(0x1234);
        }
        let expected = b"\x12\x34\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b, expected);
    }

    #[test]
    fn encoder_flags_set_all() {
        let mut b: [u8; 12] = [0; 12];
        {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            e.encode_flags(0xffff, 0xffff);
        }
        let expected = b"\x00\x00\xff\xff\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b, expected);
    }

    #[test]
    fn encoder_flags_clear_all() {
        let mut b: [u8; 12] = [0; 12];
        {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            unsafe { e.write_u16_at_unchecked(2, 0xffff) }
            e.encode_flags(0xffff, 0xffff);
        }
        let expected = b"\x00\x00\xff\xff\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b, expected);
    }

    #[test]
    fn encoder_flags_set_and_clear_some() {
        let mut b: [u8; 12] = [0; 12];
        {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            unsafe { e.write_u16_at_unchecked(2, 0x0950) }
            e.encode_flags(0x0ff0, 0x0590);
        }
        let expected = b"\x00\x00\x05\x90\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b, expected);
    }

    #[test]
    fn encoder_octets_at_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_octets_at(&mut cursor, b"foo");
            let expected = Ok(());
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                              foo";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_octets_at_nok() {
        let mut b: [u8; 14] = [0; 14];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_octets_at(&mut cursor, b"foo");
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_u8_at_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_u8_at(&mut cursor, 0x12);
            let expected = Ok(());
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x12";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_u8_at_nok() {
        let mut b: [u8; 12] = [0; 12];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_u8_at(&mut cursor, 0x12);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_u16_at_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_u16_at(&mut cursor, 0x1234);
            let expected = Ok(());
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x12\x34";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_u16_at_nok() {
        let mut b: [u8; 13] = [0; 13];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_u16_at(&mut cursor, 0x1234);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_u32_at_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_u32_at(&mut cursor, 0x12345678);
            let expected = Ok(());
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x12\x34\x56\x78";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_u32_at_nok() {
        let mut b: [u8; 15] = [0; 15];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_u32_at(&mut cursor, 0x12345678);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_rclass_at_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_rclass_at(&mut cursor, rclass::IN);
            let expected = Ok(());
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x01";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_rclass_at_nok() {
        let mut b: [u8; 13] = [0; 13];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_rclass_at(&mut cursor, rclass::IN);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_qclass_at_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_qclass_at(&mut cursor, qclass::ANY);
            let expected = Ok(());
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\xff";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_qclass_at_nok() {
        let mut b: [u8; 13] = [0; 13];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_qclass_at(&mut cursor, qclass::ANY);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_rtype_at_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_rtype_at(&mut cursor, rtype::CNAME);
            let expected = Ok(());
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x05";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_rtype_at_nok() {
        let mut b: [u8; 13] = [0; 13];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_rtype_at(&mut cursor, rtype::CNAME);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_qtype_at_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_qtype_at(&mut cursor, qtype::ANY);
            let expected = Ok(());
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\xff";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_qtype_at_nok() {
        let mut b: [u8; 13] = [0; 13];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_qtype_at(&mut cursor, qtype::ANY);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_name_at_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_name_at(&mut cursor, &TestName::new("foo.bar."));
            let expected = Ok(());
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x03foo\
                         \x03bar\
                         \x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_name_at_nok() {
        let mut b: [u8; 20] = [0; 20];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::QuestionSection>::new(&mut b).unwrap();
            let mut cursor = 12;
            let got = e.encode_name_at(&mut cursor, &TestName::new("foo.bar."));
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_question_at_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(&mut b).unwrap();
            let r = Question::<TestFormat>::new(TestName::new("foo."), qtype::ANY, qclass::ANY);
            let mut cursor = 12;
            let got = e.encode_question_at(&mut cursor, &r);
            let expected = Ok(());
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x03foo\x00\
                         \x00\xff\
                         \x00\xff";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_question_at_nok() {
        let mut b: [u8; 20] = [0; 20];
        let len = {
            let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(&mut b).unwrap();
            let r = Question::<TestFormat>::new(TestName::new("foo."), qtype::ANY, qclass::ANY);
            let mut cursor = 12;
            let got = e.encode_question_at(&mut cursor, &r);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_question_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(&mut b).unwrap();
            let q = Question::<TestFormat>::new(TestName::new("foo."), qtype::ANY, qclass::ANY);
            let got = e.encode_question(&q);
            let expected = Ok(());
            assert_eq!(got, expected);
            assert_eq!(e.cursor, 12 + 9); // next byte after question
            e.cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x01\x00\x00\
                         \x00\x00\x00\x00\
                         \x03foo\x00\
                         \x00\xff\
                         \x00\xff";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_question_nok() {
        let mut b: [u8; 20] = [0; 20];
        let len = {
            let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(&mut b).unwrap();
            let q = Question::<TestFormat>::new(TestName::new("foo."), qtype::ANY, qclass::IN);
            let got = e.encode_question(&q);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            e.cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_rdlength_and_rdata_at_a_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(&mut b).unwrap();
            let rdata: RData<TestFormat> = RData::A { address: std::net::Ipv4Addr::from_str("1.2.3.4").unwrap() };
            let mut cursor = 12;
            let got = e.encode_rdlength_and_rdata_at(&mut cursor, &rdata);
            let expected = Ok(());
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x04\x01\x02\
                         \x03\x04";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_rdlength_and_rdata_at_a_nok() {
        let mut b: [u8; 17] = [0; 17];
        let len = {
            let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(&mut b).unwrap();
            let rdata: RData<TestFormat> = RData::A { address: std::net::Ipv4Addr::from_str("1.2.3.4").unwrap() };
            let mut cursor = 12;
            let got = e.encode_rdlength_and_rdata_at(&mut cursor, &rdata);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_rdlength_and_rdata_at_cname_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(&mut b).unwrap();
            let rdata: RData<TestFormat> = RData::CName { cname: TestName::new("foo.") };
            let mut cursor = 12;
            let got = e.encode_rdlength_and_rdata_at(&mut cursor, &rdata);
            let expected = Ok(());
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x05\x03foo\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_rdlength_and_rdata_at_cname_nok() {
        let mut b: [u8; 16] = [0; 16];
        let len = {
            let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(&mut b).unwrap();
            let rdata: RData<TestFormat> = RData::CName { cname: TestName::new("foo.") };
            let mut cursor = 12;
            let got = e.encode_rdlength_and_rdata_at(&mut cursor, &rdata);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_rdlength_and_rdata_at_ns_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(&mut b).unwrap();
            let rdata: RData<TestFormat> = RData::NS { nsdname: TestName::new("foo.") };
            let mut cursor = 12;
            let got = e.encode_rdlength_and_rdata_at(&mut cursor, &rdata);
            let expected = Ok(());
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x05\x03foo\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_rdlength_and_rdata_at_ns_nok() {
        let mut b: [u8; 16] = [0; 16];
        let len = {
            let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(&mut b).unwrap();
            let rdata: RData<TestFormat> = RData::NS { nsdname: TestName::new("foo.") };
            let mut cursor = 12;
            let got = e.encode_rdlength_and_rdata_at(&mut cursor, &rdata);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_rdlength_and_rdata_at_soa_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(&mut b).unwrap();
            let rdata: RData<TestFormat> = RData::SOA {
                mname: TestName::new("foo."),
                rname: TestName::new("bar."),
                serial: Serial(0x01020304),
                refresh: Ttl(0x5060708),
                retry: Ttl(0x090a0b0c),
                expire: Ttl(0x0d0e0f10),
                minimum: Ttl(0x11121314),
            };
            let mut cursor = 12;
            let got = e.encode_rdlength_and_rdata_at(&mut cursor, &rdata);
            let expected = Ok(());
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x1e\
                         \x03foo\x00\
                         \x03bar\x00\
                         \x01\x02\x03\x04\
                         \x05\x06\x07\x08\
                         \x09\x0a\x0b\x0c\
                         \x0d\x0e\x0f\x10\
                         \x11\x12\x13\x14";
        assert_eq!(&b[..len], &expected[..]);
    }

    #[test]
    fn encoder_rdlength_and_rdata_at_soa_nok() {
        let mut b: [u8; 43] = [0; 43];
        let len = {
            let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(&mut b).unwrap();
            let rdata: RData<TestFormat> = RData::SOA {
                mname: TestName::new("foo."),
                rname: TestName::new("bar."),
                serial: Serial(0x01020304),
                refresh: Ttl(0x5060708),
                retry: Ttl(0x090a0b0c),
                expire: Ttl(0x0d0e0f10),
                minimum: Ttl(0x11121314),
            };
            let mut cursor = 12;
            let got = e.encode_rdlength_and_rdata_at(&mut cursor, &rdata);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_rdlength_and_rdata_at_other_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(&mut b).unwrap();
            let rdata: RData<TestFormat> = RData::Other { octets: b"foo".to_vec() };
            let mut cursor = 12;
            let got = e.encode_rdlength_and_rdata_at(&mut cursor, &rdata);
            let expected = Ok(());
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x03\
                         foo";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_rdlength_and_rdata_at_other_nok() {
        let mut b: [u8; 16] = [0; 16];
        let len = {
            let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(&mut b).unwrap();
            let rdata: RData<TestFormat> = RData::Other { octets: b"foo".to_vec() };
            let mut cursor = 12;
            let got = e.encode_rdlength_and_rdata_at(&mut cursor, &rdata);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_resource_record_at_ok() {
        let mut b: [u8; 512] = [0; 512];
        let len = {
            let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(&mut b).unwrap();
            let r = ResourceRecord::<TestFormat>::new(TestName::new("foo."),
                                                      rtype::CNAME,
                                                      rclass::IN,
                                                      Ttl(1000),
                                                      RData::CName { cname: TestName::new("bar.") });
            let mut cursor = 12;
            let got = e.encode_resource_record_at(&mut cursor, &r);
            let expected = Ok(());
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x03foo\x00\
                         \x00\x05\
                         \x00\x01\
                         \x00\x00\x03\xe8\
                         \x00\x05\
                         \x03bar\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_resource_record_at_nok() {
        let mut b: [u8; 31] = [0; 31];
        let len = {
            let mut e = WireEncoder::<marker::Query, marker::QuestionSection>::new(&mut b).unwrap();
            let r = ResourceRecord::<TestFormat>::new(TestName::new("foo."),
                                                      rtype::CNAME,
                                                      rclass::IN,
                                                      Ttl(1000),
                                                      RData::CName { cname: TestName::new("bar.") });
            let mut cursor = 12;
            let got = e.encode_resource_record_at(&mut cursor, &r);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_new_response() {

        let request_buffer = b"\x12\x34\x01\x00\
                               \x00\x02\x00\x00\
                               \x00\x00\x00\x00\
                               \x03foo\x00\x00\x01\x00\x01\
                               \x03bar\x00\x00\x01\x00\x01";
        let mut decoder = WireDecoder::new(request_buffer);
        let request = decoder.decode_message().unwrap();

        let mut b: [u8; 512] = [0xff; 512];
        let len = {
            let e = WireEncoder::new_response(&mut b, &request).unwrap();
            e.cursor
        };
        let expected = b"\x12\x34\x81\x00\
                         \x00\x02\x00\x00\
                         \x00\x00\x00\x00\
                         \x03foo\x00\x00\x01\x00\x01\
                         \x03bar\x00\x00\x01\x00\x01";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_answer_ok() {
        let mut b: [u8; 512] = [0xff; 512];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::AnswerSection>::new(&mut b).unwrap();
            let r = ResourceRecord::<TestFormat>::new(TestName::new("foo."),
                                                      rtype::CNAME,
                                                      rclass::IN,
                                                      Ttl(1000),
                                                      RData::CName { cname: TestName::new("bar.") });
            let got = e.encode_answer(&r);
            let expected = Ok(());
            assert_eq!(got, expected);
            e.cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x01\
                         \x00\x00\x00\x00\
                         \x03foo\x00\
                         \x00\x05\
                         \x00\x01\
                         \x00\x00\x03\xe8\
                         \x00\x05\
                         \x03bar\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_answer_nok() {
        let mut b: [u8; 31] = [0xff; 31];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::AnswerSection>::new(&mut b).unwrap();
            let r = ResourceRecord::<TestFormat>::new(TestName::new("foo."),
                                                      rtype::CNAME,
                                                      rclass::IN,
                                                      Ttl(1000),
                                                      RData::CName { cname: TestName::new("bar.") });
            let got = e.encode_answer(&r);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            e.cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_authority_ok() {
        let mut b: [u8; 512] = [0xff; 512];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::AuthoritySection>::new(&mut b).unwrap();
            let r = ResourceRecord::<TestFormat>::new(TestName::new("foo."),
                                                      rtype::NS,
                                                      rclass::IN,
                                                      Ttl(1000),
                                                      RData::NS { nsdname: TestName::new("bar.") });
            let got = e.encode_authority(&r);
            let expected = Ok(());
            assert_eq!(got, expected);
            e.cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x01\x00\x00\
                         \x03foo\x00\
                         \x00\x02\
                         \x00\x01\
                         \x00\x00\x03\xe8\
                         \x00\x05\
                         \x03bar\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_authority_nok() {
        let mut b: [u8; 31] = [0xff; 31];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::AuthoritySection>::new(&mut b).unwrap();
            let r = ResourceRecord::<TestFormat>::new(TestName::new("foo."),
                                                      rtype::NS,
                                                      rclass::IN,
                                                      Ttl(1000),
                                                      RData::NS { nsdname: TestName::new("bar.") });
            let got = e.encode_authority(&r);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            e.cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_additional_ok() {
        let mut b: [u8; 512] = [0xff; 512];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::AdditionalSection>::new(&mut b).unwrap();
            let r = ResourceRecord::<TestFormat>::new(TestName::new("foo."),
                                                      rtype::A,
                                                      rclass::IN,
                                                      Ttl(1000),
                                                      RData::A {
                                                          address: std::net::Ipv4Addr::from_str("1.2.3.4").unwrap(),
                                                      });
            let got = e.encode_additional(&r);
            let expected = Ok(());
            assert_eq!(got, expected);
            e.cursor
        };
        let expected = b"\x00\x00\x00\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x01\
                         \x03foo\x00\
                         \x00\x01\
                         \x00\x01\
                         \x00\x00\x03\xe8\
                         \x00\x04\
                         \x01\x02\x03\x04";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn encoder_additional_nok() {
        let mut b: [u8; 30] = [0xff; 30];
        let len = {
            let mut e = WireEncoder::<marker::Response, marker::AdditionalSection>::new(&mut b).unwrap();
            let r = ResourceRecord::<TestFormat>::new(TestName::new("foo."),
                                                      rtype::A,
                                                      rclass::IN,
                                                      Ttl(1000),
                                                      RData::A {
                                                          address: std::net::Ipv4Addr::from_str("1.2.3.4").unwrap(),
                                                      });
            let got = e.encode_additional(&r);
            let expected = Err(EncoderError);
            assert_eq!(got, expected);
            e.cursor
        };
        let expected = b"\x00\x00\x02\x00\
                         \x00\x00\x00\x00\
                         \x00\x00\x00\x00";
        assert_eq!(&b[..len], expected);
    }

    #[test]
    fn untrusted_decoder_u8_ok() {
        let mut d = WireDecoder::new(b"\x00\x12").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_u8();
        let expected = Ok(18);
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(std::mem::size_of::<u8>()));
    }

    #[test]
    fn untrusted_decoder_u8_nok_truncated() {
        let mut d = WireDecoder::new(b"");
        let o = d.clone();
        let got = d.decode_u8();
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_u16_ok() {
        let mut d = WireDecoder::new(b"\x00\x02\x05").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_u16();
        let expected = Ok(517);
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(std::mem::size_of::<u16>()));
    }

    #[test]
    fn untrusted_decoder_u16_nok_truncated() {
        let mut d = WireDecoder::new(b"\x00");
        let o = d.clone();
        let got = d.decode_u16();
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_u32_ok() {
        let mut d = WireDecoder::new(b"\x00\x12\x34\x56\x78").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_u32();
        let expected = Ok(0x12345678);
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(std::mem::size_of::<u32>()));
    }

    #[test]
    fn untrusted_decoder_u32_nok_truncated() {
        let mut d = WireDecoder::new(b"\x00\x00\x00");
        let o = d.clone();
        let got = d.decode_u32();
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_octets_ok_empty() {
        let mut d = WireDecoder::new(b"\x00").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_octets(0);
        let expected = Ok(&b""[..]);
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(0));
    }

    #[test]
    fn untrusted_decoder_octets_ok_nonempty() {
        let mut d = WireDecoder::new(b"\x00\x01\x02\x03").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_octets(3);
        let expected = Ok(&b"\x01\x02\x03"[..]);
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(3));
    }

    #[test]
    fn untrusted_decoder_octets_nok_truncated() {
        let mut d = WireDecoder::new(b"\x00\x00\x00");
        let o = d.clone();
        let got = d.decode_octets(4);
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_rclass_ok() {
        let mut d = WireDecoder::new(b"\x00\x00\x01").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rclass();
        let expected = Ok(rclass::IN);
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(std::mem::size_of::<u16>()));
    }

    #[test]
    fn untrusted_decoder_rclass_nok_truncated() {
        let mut d = WireDecoder::new(b"\x00");
        let o = d.clone();
        let got = d.decode_rclass();
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_qclass_ok() {
        let mut d = WireDecoder::new(b"\x00\x00\xff").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_qclass();
        let expected = Ok(qclass::ANY);
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(std::mem::size_of::<u16>()));
    }

    #[test]
    fn untrusted_decoder_qclass_nok_truncated() {
        let mut d = WireDecoder::new(b"\x00");
        let o = d.clone();
        let got = d.decode_qclass();
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_rtype_ok() {
        let mut d = WireDecoder::new(b"\x00\x00\x05").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rtype();
        let expected = Ok(rtype::CNAME);
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(std::mem::size_of::<u16>()));
    }

    #[test]
    fn untrusted_decoder_rtype_nok_truncated() {
        let mut d = WireDecoder::new(b"\x00");
        let o = d.clone();
        let got = d.decode_rtype();
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_qtype_ok() {
        let mut d = WireDecoder::new(b"\x00\x00\xff").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_qtype();
        let expected = Ok(qtype::ANY);
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(std::mem::size_of::<u16>()));
    }

    #[test]
    fn untrusted_decoder_qtype_nok_truncated() {
        let mut d = WireDecoder::new(b"\x00");
        let o = d.clone();
        let got = d.decode_qtype();
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_name_ok_empty() {
        let mut d = WireDecoder::new(b"\x00\x00").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_name();
        let expected = Ok(WireName { decoder: unsafe { o.as_trusted() } });
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(1));
    }

    #[test]
    fn untrusted_decoder_name_ok_uncompressed() {
        let mut d = WireDecoder::new(b"\x00\
                                          \x03foo\
                                          \x03bar\
                                          \x00")
                .with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_name();
        let expected = Ok(WireName { decoder: unsafe { o.as_trusted() } });
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(9));
    }

    #[test]
    fn untrusted_decoder_name_ok_compressed() {
        let mut d = WireDecoder::new(b"\x00\
                                          \x03qux\
                                          \x00\
                                          \x03bar\
                                          \xc1\
                                          \x03foo\
                                          \xc6")
                .with_cursor_offset(11);
        let o = d.clone();
        let got = d.decode_name();
        let expected = Ok(WireName { decoder: unsafe { o.as_trusted() } });
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(5));
    }

    #[test]
    fn untrusted_decoder_name_nok_label_offset_jumps_forward() {
        let mut d = WireDecoder::new(b"\x03foo\
                                          \xc5\
                                          \x03bar
                                          \x00");
        let o = d.clone();
        let got = d.decode_name();
        let expected = Err(DecoderError::NameOffsetOutOfRange);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_name_nok_label_offset_jumps_out_of_message() {
        let mut d = WireDecoder::new(b"\x03foo\
                                          \xc5");
        let o = d.clone();
        let got = d.decode_name();
        let expected = Err(DecoderError::NameOffsetOutOfRange);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_name_nok_label_length_is_truncated() {
        let mut d = WireDecoder::new(b"");
        let o = d.clone();
        let got = d.decode_name();
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_name_nok_label_is_truncated() {
        let mut d = WireDecoder::new(b"\x03fo");
        let o = d.clone();
        let got = d.decode_name();
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_name_nok_label_is_invalid() {
        let mut d = WireDecoder::new(b"\x01-\x00"); // names cannot start with a hyphen
        let o = d.clone();
        let got = d.decode_name();
        let expected = Err(DecoderError::InvalidLabel);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_name_nok_label_length_uses_reserved_bits() {
        // The reserved bits are 0x80 and 0x40 (high bits).

        let mut d = WireDecoder::new(b"\x43foo\x00");
        let o = d.clone();
        let got = d.decode_name();
        let expected = Err(DecoderError::InvalidLabelLength);
        assert_eq!(got, expected);
        assert_eq!(d, o);

        let mut d = WireDecoder::new(b"\x83foo\x00");
        let o = d.clone();
        let got = d.decode_name();
        let expected = Err(DecoderError::InvalidLabelLength);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_name_nok_name_is_infinite_cycle() {
        let mut d = WireDecoder::new(b"\x03foo\xc0");
        let o = d.clone();
        let got = d.decode_name();
        let expected = Err(DecoderError::InfiniteName);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_name_nok_name_is_too_long() {

        fn make_name(length: usize) -> Vec<u8> {
            debug_assert!(3 <= length);
            let mut v = Vec::new();
            for _ in 0..((length - 3) / 2) {
                v.push(1);
                v.push(b'x');
            }
            let remainder = 2 - (length % 2);
            v.push(remainder as u8);
            for _ in 0..remainder {
                v.push(b'x');
            }
            v.push(0);
            debug_assert_eq!(v.len(), length);
            v
        }

        // Check that we're in conformance with RFC 1035.
        assert_eq!(MAX_NAME_LENGTH, 255);

        let name_max = make_name(MAX_NAME_LENGTH);
        let mut d = WireDecoder::new(&name_max);
        let o = d.clone();
        let got = d.decode_name();
        let expected = Ok(WireName { decoder: unsafe { o.as_trusted() } });
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(MAX_NAME_LENGTH));

        let name_too_big = make_name(MAX_NAME_LENGTH + 1);
        let mut d = WireDecoder::new(&name_too_big);
        let o = d.clone();
        let got = d.decode_name();
        let expected = Err(DecoderError::NameTooLong);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_question_section_ok_empty() {
        let mut d = WireDecoder::new(b"\x00\
                                            \x03foo\x00\x00\x05\x00\x01\
                                            \x03bar\x00\x00\x05\x00\x01")
                .with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_question_section(2);
        let expected = Ok(QuestionSection {
                              count: 2,
                              decoder: unsafe { o.clone().as_trusted() },
                          });
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(18));
    }

    #[test]
    fn untrusted_decoder_question_section_nok_bad_qname() {
        let mut d = WireDecoder::new(b"\x01-\x00\x00\x05\x00\x01");
        let o = d.clone();
        let got = d.decode_question_section(1);
        let expected = Err(DecoderError::InvalidLabel);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_question_section_nok_truncated_qtype() {
        let mut d = WireDecoder::new(b"\x03foo\x00\x00");
        let o = d.clone();
        let got = d.decode_question_section(1);
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_question_section_nok_truncated_qclass() {
        let mut d = WireDecoder::new(b"\x03foo\x00\x00\x05\x00");
        let o = d.clone();
        let got = d.decode_question_section(1);
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_question_section_nok_too_few_questions() {
        let mut d = WireDecoder::new(b"\x03foo\x00\x00\x05\x00\x01");
        let o = d.clone();
        let got = d.decode_question_section(2);
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_rdata_other_ok() {
        let mut d = WireDecoder::new(b"\x00\x01\x02\x03").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rdata(RClass(255), RType(255), 3);
        let expected = Ok(RData::Other { octets: &b"\x01\x02\x03"[..] });
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(3));
    }

    #[test]
    fn untrusted_decoder_rdata_other_nok_truncated() {
        let mut d = WireDecoder::new(b"\x00\x01\x02\x03").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rdata(RClass(255), RType(255), 4);
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_rdata_a_ok() {
        let mut d = WireDecoder::new(b"\x00\x01\x02\x03\x04").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rdata(rclass::IN, rtype::A, 4);
        let expected = Ok(RData::A { address: std::net::Ipv4Addr::from_str("1.2.3.4").unwrap() });
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(4));
    }

    #[test]
    fn untrusted_decoder_rdata_a_nok_address_truncated() {
        let mut d = WireDecoder::new(b"\x00\x0a\x00\x00").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rdata(rclass::IN, rtype::A, 4);
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_rdata_a_nok_bad_rdlength() {
        let mut d = WireDecoder::new(b"\x00\x0a\x00\x00\x01").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rdata(rclass::IN, rtype::A, 3);
        let expected = Err(DecoderError::BadRdlength);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_rdata_cname_ok() {
        let mut d = WireDecoder::new(b"\x00\x03foo\x00").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rdata(rclass::IN, rtype::CNAME, 5);
        let expected = Ok(RData::CName { cname: WireName { decoder: unsafe { o.as_trusted() } } });
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(5));
    }

    #[test]
    fn untrusted_decoder_rdata_cname_nok_cname_truncated() {
        let mut d = WireDecoder::new(b"\x00\x03foo").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rdata(rclass::IN, rtype::CNAME, 4);
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_rdata_cname_nok_bad_rdlength() {
        let mut d = WireDecoder::new(b"\x00\x03foo\x00").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rdata(rclass::IN, rtype::CNAME, 4);
        let expected = Err(DecoderError::BadRdlength);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_rdata_ns_ok() {
        let mut d = WireDecoder::new(b"\x00\x03foo\x00").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rdata(rclass::IN, rtype::NS, 5);
        let expected = Ok(RData::NS { nsdname: WireName { decoder: unsafe { o.as_trusted() } } });
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(5));
    }

    #[test]
    fn untrusted_decoder_rdata_ns_nok_nsdname_truncated() {
        let mut d = WireDecoder::new(b"\x00\x03foo").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rdata(rclass::IN, rtype::NS, 4);
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_rdata_ns_nok_bad_rdlength() {
        let mut d = WireDecoder::new(b"\x00\x03foo\x00").with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rdata(rclass::IN, rtype::NS, 4);
        let expected = Err(DecoderError::BadRdlength);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_rdata_soa_ok() {
        let mut d = WireDecoder::new(b"\x00\
                                       \x03foo\x00\
                                       \x03bar\x00\
                                       \x01\x02\x03\x04\
                                       \x05\x06\x07\x08\
                                       \x09\x0a\x0b\x0c\
                                       \x0d\x0e\x0f\x10\
                                       \x11\x12\x13\x14")
                .with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rdata(rclass::IN, rtype::SOA, 30);
        let expected = Ok(RData::SOA {
                              mname: WireName { decoder: unsafe { o.as_trusted() } },
                              rname: WireName { decoder: unsafe { o.with_cursor_offset(5).as_trusted() } },
                              serial: Serial(0x01020304),
                              refresh: Ttl(0x05060708),
                              retry: Ttl(0x090a0b0c),
                              expire: Ttl(0x0d0e0f10),
                              minimum: Ttl(0x11121314),
                          });
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(30));
    }

    #[test]
    fn untrusted_decoder_rdata_soa_nok_bad_mname() {
        let mut d = WireDecoder::new(b"\x00\
                                       \x03---\x00\
                                       \x03bar\x00\
                                       \x01\x02\x03\x04\
                                       \x05\x06\x07\x08\
                                       \x09\x0a\x0b\x0c\
                                       \x0d\x0e\x0f\x10\
                                       \x11\x12\x13\x14")
                .with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rdata(rclass::IN, rtype::SOA, 30);
        let expected = Err(DecoderError::InvalidLabel);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_rdata_soa_nok_bad_rname() {
        let mut d = WireDecoder::new(b"\x00\
                                       \x03foo\x00\
                                       \x03---\x00\
                                       \x01\x02\x03\x04\
                                       \x05\x06\x07\x08\
                                       \x09\x0a\x0b\x0c\
                                       \x0d\x0e\x0f\x10\
                                       \x11\x12\x13\x14")
                .with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rdata(rclass::IN, rtype::SOA, 30);
        let expected = Err(DecoderError::InvalidLabel);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_rdata_soa_nok_integer_fields_truncated() {
        let mut d = WireDecoder::new(b"\x00\
                                       \x03foo\x00\
                                       \x03bar\x00\
                                       \x01\x02\x03\x04\
                                       \x05\x06\x07\x08\
                                       \x09\x0a\x0b\x0c\
                                       \x0d\x0e\x0f\x10\
                                       \x11\x12\x13")
                .with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rdata(rclass::IN, rtype::SOA, 29);
        let expected = Err(DecoderError::UnexpectedEof);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_rdata_soa_nok_bad_rdlength() {
        let mut d = WireDecoder::new(b"\x00\
                                       \x03foo\x00\
                                       \x03bar\x00\
                                       \x01\x02\x03\x04\
                                       \x05\x06\x07\x08\
                                       \x09\x0a\x0b\x0c\
                                       \x0d\x0e\x0f\x10\
                                       \x11\x12\x13\x14")
                .with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_rdata(rclass::IN, rtype::SOA, 29);
        let expected = Err(DecoderError::BadRdlength);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn untrusted_decoder_resource_record_section_ok() {
        let mut d = WireDecoder::new(b"\x00\
                                         \x03foo\x00\
                                         \x00\x05\
                                         \x00\x01\
                                         \x00\x00\x03\xe8\
                                         \x00\x05\
                                         \x03bar\x00\
                                         \x03qux\x00\
                                         \x00\x05\
                                         \x00\x01\
                                         \x00\x00\x03\xe8\
                                         \x00\x05\
                                         \x03baz\x00")
                .with_cursor_offset(1);
        let o = d.clone();
        let got = d.decode_resource_record_section(2);
        let expected = Ok(ResourceRecordSection {
                              count: 2,
                              decoder: unsafe { o.as_trusted() },
                          });
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(40));
    }

    #[test]
    fn untrusted_decoder_message_ok() {
        let b = b"\x00\
                  \x12\x34\x81\x80\
                  \x00\x01\x00\x02\
                  \x00\x00\x00\x00\
                  \x03foo\x00\
                  \x00\x01\
                  \x00\x01\
                  \x03foo\x00\
                  \x00\x01\
                  \x00\x01\
                  \x00\x00\x03\xe8\
                  \x00\x04\
                  \x01\x02\x03\x04\
                  \x03foo\x00\
                  \x00\x01\
                  \x00\x01\
                  \x00\x00\x03\xe8\
                  \x00\x04\
                  \x05\x06\x07\x08";
        let mut d = WireDecoder::new(b).with_cursor_offset(1);
        d.cursor = 1;
        let o = d.clone();
        let got = d.decode_message();
        let expected = Ok(WireMessage {
                              id: 0x1234,
                              flags: 0x8180,
                              question_section: QuestionSection {
                                  count: 1,
                                  decoder: unsafe { o.with_cursor_offset(12).as_trusted() },
                              },
                              answer_section: ResourceRecordSection {
                                  count: 2,
                                  decoder: unsafe { o.with_cursor_offset(21).as_trusted() },
                              },
                              authority_section: ResourceRecordSection {
                                  count: 0,
                                  decoder: unsafe { o.with_cursor_offset(59).as_trusted() },
                              },
                              additional_section: ResourceRecordSection {
                                  count: 0,
                                  decoder: unsafe { o.with_cursor_offset(59).as_trusted() },
                              },
                          });
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(59));
    }

    #[test]
    fn untrusted_decoder_message_nok_unexpected_octets() {
        let b = b"\x00\
                  \x12\x34\x81\x80\
                  \x00\x01\x00\x02\
                  \x00\x00\x00\x00\
                  \x03foo\x00\
                  \x00\x01\
                  \x00\x01\
                  \x03foo\x00\
                  \x00\x01\
                  \x00\x01\
                  \x00\x00\x03\xe8\
                  \x00\x04\
                  \x01\x02\x03\x04\
                  \x03foo\x00\
                  \x00\x01\
                  \x00\x01\
                  \x00\x00\x03\xe8\
                  \x00\x04\
                  \x05\x06\x07\x08
                  extra octets here";
        let mut d = WireDecoder::new(b).with_cursor_offset(1);
        d.cursor = 1;
        let o = d.clone();
        let got = d.decode_message();
        let expected = Err(DecoderError::UnexpectedOctets);
        assert_eq!(got, expected);
        assert_eq!(d, o);
    }

    #[test]
    fn trusted_decoder_u8() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x12") }.with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_u8_unchecked() };
        let expected = 18;
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(std::mem::size_of::<u8>()));
    }

    #[test]
    fn trusted_decoder_u16() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x02\x05") }.with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_u16_unchecked() };
        let expected = 517;
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(std::mem::size_of::<u16>()));
    }

    #[test]
    fn trusted_decoder_u32() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x12\x34\x56\x78") }.with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_u32_unchecked() };
        let expected = 0x12345678;
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(std::mem::size_of::<u32>()));
    }

    #[test]
    fn trusted_decoder_octets_empty() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00") }.with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_octets_unchecked(0) };
        let expected = &b""[..];
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(0));
    }

    #[test]
    fn trusted_decoder_octets_nonempty() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x01\x02\x03") }.with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_octets_unchecked(3) };
        let expected = &b"\x01\x02\x03"[..];
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(3));
    }

    #[test]
    fn trusted_decoder_rclass() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x00\x01") }.with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_rclass_unchecked() };
        let expected = rclass::IN;
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(std::mem::size_of::<u16>()));
    }

    #[test]
    fn trusted_decoder_qclass() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x00\xff") }.with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_qclass_unchecked() };
        let expected = qclass::ANY;
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(std::mem::size_of::<u16>()));
    }

    #[test]
    fn trusted_decoder_rtype() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x00\x05") }.with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_rtype_unchecked() };
        let expected = rtype::CNAME;
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(std::mem::size_of::<u16>()));
    }

    #[test]
    fn trusted_decoder_qtype() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x00\xff") }.with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_qtype_unchecked() };
        let expected = qtype::ANY;
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(std::mem::size_of::<u16>()));
    }

    #[test]
    fn trusted_decoder_label_end() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x00") }.with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_label_unchecked() };
        let expected = None;
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(1));
    }

    #[test]
    fn trusted_decoder_label_uncompressed() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x03foo") }.with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_label_unchecked() };
        let expected = Some("foo");
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(4));
    }

    #[test]
    fn trusted_decoder_label_compressed() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x03foo\x00\xc1") }.with_cursor_offset(6);
        let o = d.clone();
        let got = unsafe { d.decode_label_unchecked() };
        let expected = Some("foo");
        assert_eq!(got, expected);
        assert_eq!(d, TrustedDecoder { cursor: 5, ..o });
    }

    #[test]
    fn trusted_decoder_name_empty() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x00") }.with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_name_unchecked() };
        let expected = WireName { decoder: o.clone() };
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(1));
    }

    #[test]
    fn trusted_decoder_name_uncompressed() {
        let mut d = unsafe {
                TrustedDecoder::new(b"\x00\
                                      \x03foo\
                                      \x03bar\
                                      \x00")
            }
            .with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_name_unchecked() };
        let expected = WireName { decoder: o.clone() };
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(9));
    }

    #[test]
    fn trusted_decoder_name_compressed() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x03foo\x00\xc1") }.with_cursor_offset(6);
        let o = d.clone();
        let got = unsafe { d.decode_name_unchecked() };
        let expected = WireName { decoder: o.clone() };
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(1));
    }

    #[test]
    fn trusted_decoder_rdata_other() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x01\x02\x03") }.with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_rdata_unchecked(RClass(255), RType(255), 3) };
        let expected = RData::Other { octets: &b"\x01\x02\x03"[..] };
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(3));
    }

    #[test]
    fn trusted_decoder_rdata_a() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x01\x02\x03\x04") }.with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_rdata_unchecked(rclass::IN, rtype::A, 4) };
        let expected = RData::A { address: std::net::Ipv4Addr::from_str("1.2.3.4").unwrap() };
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(4));
    }

    #[test]
    fn trusted_decoder_rdata_cname() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x03foo\x00") }.with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_rdata_unchecked(rclass::IN, rtype::CNAME, 5) };
        let expected = RData::CName { cname: WireName { decoder: o.clone() } };
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(5));
    }

    #[test]
    fn trusted_decoder_rdata_ns() {
        let mut d = unsafe { TrustedDecoder::new(b"\x00\x03foo\x00") }.with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_rdata_unchecked(rclass::IN, rtype::NS, 5) };
        let expected = RData::NS { nsdname: WireName { decoder: o.clone() } };
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(5));
    }

    #[test]
    fn trusted_decoder_question() {
        let mut d = unsafe {
                TrustedDecoder::new(b"\x00\
                                      \x03foo\x00\x00\x05\x00\x01")
            }
            .with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_question_unchecked() };
        let expected = Question::new(WireName { decoder: o.clone() }, qtype::CNAME, qclass::IN);
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(9));
    }

    #[test]
    fn trusted_decoder_rdata_soa() {
        let mut d = unsafe {
                TrustedDecoder::new(b"\x00\
                                      \x03foo\x00\
                                      \x03bar\x00\
                                      \x01\x02\x03\x04\
                                      \x05\x06\x07\x08\
                                      \x09\x0a\x0b\x0c\
                                      \x0d\x0e\x0f\x10\
                                      \x11\x12\x13\x14")
            }
            .with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_rdata_unchecked(rclass::IN, rtype::SOA, 30) };
        let expected = RData::SOA {
            mname: WireName { decoder: o.clone() },
            rname: WireName { decoder: o.clone().with_cursor_offset(5) },
            serial: Serial(0x01020304),
            refresh: Ttl(0x05060708),
            retry: Ttl(0x090a0b0c),
            expire: Ttl(0x0d0e0f10),
            minimum: Ttl(0x11121314),
        };
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(30));
    }

    #[test]
    fn trusted_decoder_resource_record() {
        let mut d = unsafe {
                TrustedDecoder::new(b"\x00\
                                      \x03foo\x00\
                                      \x00\x05\
                                      \x00\x01\
                                      \x00\x00\x03\xe8\
                                      \x00\x05\
                                      \x03bar\x00")
            }
            .with_cursor_offset(1);
        let o = d.clone();
        let got = unsafe { d.decode_resource_record_unchecked() };
        let expected =
            ResourceRecord::new(WireName { decoder: o.clone() },
                                rtype::CNAME,
                                rclass::IN,
                                Ttl(1000),
                                RData::CName { cname: WireName { decoder: o.clone().with_cursor_offset(15) } });
        assert_eq!(got, expected);
        assert_eq!(d, o.with_cursor_offset(20));
    }
}
