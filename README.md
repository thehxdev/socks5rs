# Socks5rs
Socks5rs is a very minimal and simple socks5 protocol implementation based on [RFC1928](https://datatracker.ietf.org/doc/html/rfc1928)
and [tokio](https://tokio.rs/) async runtime (with `io-util` feature flag). This library is low-level and does not abstract IO operations
except tiny `io` module. Instead it operates on raw bytes and provides abstractions for working with Socks5 protocol itself to be used in
many situations and with any IO implementation (See [Sans I/O](https://sans-io.readthedocs.io/)).

## Examples
- [Socks5 server with support for `CONNECT` command](examples/server.rs)
