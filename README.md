# Sparkle-DNS

Sparkle-DNS is a DNS server framework, written in Rust.

Basically, the `sparkle` crate is a library that aims to be useful for
people who're writing high-performance DNS servers capable of doing
powerful dynamic handling of DNS request messages. This is unlike a
traditional DNS server, which is (1) an executable and (2) statically
configured, even if updated frequently.

Sparkle-DNS is a side project while I work on the DNS team for a CDN.
It's very much a work-in-progress and currently very immature.
