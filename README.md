# Sparkle-DNS

Sparkle-DNS is a DNS library, written in Rust.

Sparkle is a **research project** and is as yet not currently suitable
or useful for production code.

What is Sparkle? Here's an analogy: Sparkle is to DNS as
[Hyper][hyper_github] is to HTTP. Anyway, that's my goal.

In other words, I aim for Sparkle to be a low-level, high-performance
DNS library that allows applications to embed DNS functionality with a
high degree of control and flexibility.

My motivating use case for Sparkle is to write a custom DNS server that
implements a lot of per-request handling logic—e.g., traffic
engineering, i.e., the DNS server responding with different DNS records
according to real-time configuration changes on the server. The
application would implement this custom logic in a DNS request
handler—similar to how a web application using Hyper implements its
custom logic in an HTTP request handler.

Sparkle-DNS is a side project while I work on the DNS team for a CDN.

If you have comments or questions, please [email me][feedback_email].

[feedback_email]: mailto:c.m.brandenburg@gmail.com
[hyper_github]: https://github.com/hyperium/hyper
