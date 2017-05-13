# Sparkle-DNS Change Log

## v0.0.3 (unreleased)

New:

* The API exports a new `TextName` type to represent the textual,
  human-readable representation of domain names (e.g., "example.com").

Breaking changes:

* The iterator returned from the `Name::labels` trait method now yields
  the empty string as the last item if the name is fully qualified
  ([#11][issue_11]). Previously, the iterator made no distinction
  between fully qualified domain names and relative domain names.

Fixes:

* Hostname validation now conforms with RFCs 1035 and 1123
  ([#12][issue_12] and [#13][issue_13]). Previously, validation (1)
  disallowed hostnames to begin with a decimal digit (0-9), nor (2) did
  it check that labels are no more than 63 octets, nor (3) did it check
  that domain names are at most 255 octets.

## v0.0.2 (2017-01-15)

Breaking changes:

* The `WireEncoder` methods now return `Result<_, EncoderError>`
  instead of `Result<_, ()>` ([#6][issue_6]).
* The zone serial number type changed from a plain `u32` to a new
  `SerialNumber` type ([#1](issue_1)). The new type enforces a partial
  ordering using sequence space arithmetic.
* The time value type changed from a plain `u32` to new `Ttl` type
  ([#3](issue_3)).

Additional changes:

* The `WireEncoder`-related types now have derived implementations
  (e.g., `Debug`).
* All compile-time warnings have been resolved ([#2][issue_2]).

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
[issue_11]: https://github.com/cmbrandenburg/sparkle-dns/issues/11
[issue_12]: https://github.com/cmbrandenburg/sparkle-dns/issues/12
[issue_13]: https://github.com/cmbrandenburg/sparkle-dns/issues/13
