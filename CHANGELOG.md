# Sparkle-DNS Change Log

## v0.0.2 (unreleased)

No changes yet!

## v0.0.1 (2016-12-26)

This is the first release. It provides minimal support for running a DNS
server.

* Handles UDP request messages on port 53.
* Provides basic support for decoding request messages and encoding
  response messages, with support for a small number of resource record
  types (A, CNAME, NS, and SOA) and the IN class.
