# Sparkle-DNS

Sparkle is a **DNS server library** written in Rust. It aims to be
useful for writing custom DNS edge servers capable of powerful dynamic
request handling—i.e., traffic engineering. It can also serve as the
foundation for writing a traditional static DNS server.

Sparkle is a side project while I work on the DNS team of a CDN. My
motive for creating Sparkle stems from my experience maintaining a
[PowerDNS](https://www.powerdns.com/) backend and dealing with the
PowerDNS architecture's limitations for doing per-request processing.

## Basic design

Sparkle handles the vanilla DNS responsibilities, thereby freeing the
application to focus on its per-request secret sauce.

Here's what Sparkle does:

* Manages sockets by sending and receiving DNS messages.
* Parses incoming DNS messages and formats outgoing DNS messages.
* Parses and formats well known configuration formats, e.g., zone
  files.
* Provides data structures for caching responses.

The application is then responsible for the following:

* Loading its zone configuration(s).
* Taking questions in a request and generating resource records for the
  response.

The application has complete leeway how it generates the response's
resource records—e.g., scaling up more server-side IP addresses for
popular content or sending traffic to a different geographic region to
handle unusual loads. 

In short, Sparkle does the humdrum work of low-level DNS, and the
application does the fun dynamic stuff.
