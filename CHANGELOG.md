# Sparkle-DNS Change Log

## v0.0.2 (2017-01-15)

Breaking changes:

* Changed `WireEncoder` methods to now return `Result<_, EncoderError>`
  instead of `Result<_, ()>` ([#6][issue_6]).
* Changed zone serial number type from `u32` to new `SerialNumber` type
  ([#1](issue_1)). The new type enforces a partial ordering using
  sequence space arithmetic.
* Changed time value type from `u32` to new `Ttl` type ([#3](issue_3)).

Additional changes:

* Added derived implementations (e.g., `Debug`) to `WireEncoder`-related
  types.
* Resolved all compile-time warnings ([#2][issue_2]).

## v0.0.1 (2016-12-26)

This is the first release. It provides minimal support for running a DNS
server.

* Handles UDP request messages on port 53.
* Provides basic support for decoding request messages and encoding
  response messages, with support for a small number of resource record
  types (A, CNAME, NS, and SOA) and the IN class.

[issue_1]: https://github.com/cmbrandenburg/sparkle-dns/issues/1
[issue_2]: https://github.com/cmbrandenburg/sparkle-dns/issues/2
[issue_3]: https://github.com/cmbrandenburg/sparkle-dns/issues/3
[issue_6]: https://github.com/cmbrandenburg/sparkle-dns/issues/6
