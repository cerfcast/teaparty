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

## Testing Reflected IPv6 Extension Header Data

Testing requires a custom version of the awesome [ipv6toolkit](https://github.com/fgont/ipv6toolkit). Below, _should be reflected_ means that the contents of the IPv6 Extension Header should be copied into the TLV in the reflected STAMP packet _and_ it should be present in the IPv6 packet. All Reflected IPv6 Extension Header Data TLVs that are _not_ reflected should be marked as unrecognized.

### Getting The Tool

The _awesome_ [ipv6toolkit](https://github.com/fgont/ipv6toolkit) with the required customizations is available in `third_party/ipv6toolkit`. If you are on a UNIX-like system, then the normal `make` should get you a build:

```console
$ cd third_party/ipv6toolkit
$ make
```

If you have trouble building, refer to [`README.TXT`](../third_party/ipv6toolkit/README.TXT).

### Running The Tests

See [Files, below](#files-1) for a description on each of the test files. Included here are the commands for using those files and the expected outcome.

| Command | Included Extension Headers | Expected Result |
| -- | -- | -- |
| `./udp6 -s ::1 -d ::1 -a 862 -c 8 3 9 --data-file <path to ...>/testing_data/ipv6_extension_header_test_packet1` | 1. Hop-by-hop (length of 8, type 3 and `0x09` body)  | Extension headers (1) should be reflected |
| `./udp6 -s ::1 -d ::1 -a 862 -C 16 3 9 --data-file <path to ...>/testing_data/ipv6_extension_header_test_packet1` | 1. Destination (length of 16, type 3 and `0x09` body)  | Extension headers (1) should not be reflected (mismatched length) |
| `./udp6 -s ::1 -d ::1 -a 862 -c 8 3 9  -C 8 3 10 --data-file <path to ...>/testing_data/ipv6_extension_header_test_packet2` | 1. Hop-by-hop (length of 8, type 3 and `0x09` body)  | Extension headers (1) and (2) should be reflected |
| | 2. Destination (length of 8, type 3 and `0x0a` body)  | |
| `./udp6 -s ::1 -d ::1 -a 862 -c 8 3 9  -C 16 3 10 --data-file <path to ...>/testing_data/ipv6_extension_header_test_packet3` | 1. Hop-by-hop (length of 8, type 3 and `0x09` body)  | Extension headers (1) and (2) should be reflected |
| | 2. Destination (length of 16, type 3 and `0x0a` body)  | |
| `./udp6 -s ::1  -d ::1 -a 862 -c 8 3 9 -C 8 3 8 -C 8 3 11 --data-file <path to ...>/testing_data/ipv6_extension_header_test_packet4` | 1. Hop-by-hop (length of 8, type 3 and `0x09` body)  | Extension headers (1) and (3) should be reflected; (2) should be unrecognized (mismatched length) |
| | 2. Destination (length of 8, type 3 and `0x08` body)  | |
| | 3. Destination (length of 8, type 3 and `0x0b` body)  | |

### Files
| Name | Description |
| -- | -- |
| `ipv6_extension_header_test_packet1` | Extension Header Tlv requests reflection of an 8 byte IPv6 extension headers. |
| `ipv6_extension_header_test_packet2` | Extension Header Tlv requests reflection of two 8 byte IPv6 extension headers. |
| `ipv6_extension_header_test_packet3` | Extension Header Tlv requests reflection of two IPv6 extension headers (8 bytes and 16 bytes). |
| `ipv6_extension_header_test_packet4` | Extension Header Tlv requests reflection of three IPv6 extension headers (8 bytes, 2 bytes and 16 bytes). |
