## Testing Authenticated Session-Sender and Session-Reflector Operation With The RESTful API

RFC 8762 says that "key management and the mechanisms to distribute the HMAC key
[for integrity protection of STAMP test packets] are outside the scope of this specification." Teaparty
implements these two functions using its RESTful API.

In particular, the `sessions` endpoint (see Teaparty's main [`README.md`](../README.md)) can be used
to specify an HMAC key for a Session-Sender by configuring a session instance on the reflector. The files
in this directory make it easy (easier?) to test Teaparty's authenticated operation.

### Files

`session_request.json` contains a properly formatted JSON object that can be `POST`ed to the `session` endpoint
of the Teaparty server to create a new session with 

| Parameter | Value |
| -- | -- |
| SSID | `5` |
| HMAC Key | `testing` |
| Source Port | `5001` |
| Destination Port | `862` |
| Source IP | `127.0.0.1` |
| Destination IP | `0.0.0.0` |

`session_request.curl` contains an invocation of `curl` that can be `source`d which will `POST`
the contents of `session_request.json` to the `session` endpoint of a Teaparty server running
on `127.0.0.1`.

`session_sender.tea` contains an invocation of Teaparty that will test whether a client can send
an authenticated STAMP test packet to the configured Reflector.

> Note: `source` the `session_request.curl` and `session_sender.tea` file from the root directory of this repository.

`ipv6_extension_header_test_packet` and `ipv6_extension_header_test_packet2` contain the raw bytes of a STAMP test packet with Tlv for Reflected IPv6 Extension Header Data. These files are suitable for use with the [ipv6toolkit](https://github.com/fgont/ipv6toolkit).
