## Teaparty

An open source implementation of the Simple Two-Way Active Measurement Protocol ([RFC 8762](https://datatracker.ietf.org/doc/html/rfc8762)). Most of the documentation here is Teaparty specific. However, see [STAMP Protocol](#stamp-protocol) for documentation about what is available in this repository that is useful for _anyone_ working with the STAMP protocol.


### Building

> Note well: Compilation has only been testing on Linux-based systems (specifically Fedora Core 39+). Your mileage may vary, and patches
are _definitely_ welcome!

After cloning the repository, make sure to initialize the git submodules:

```console
$ git submodule update --init --recursive
```

After that, it _should_ be as easy as 

```console
$ cargo build
```

### Running

`teaparty` has both a _reflector_ and a _sender_ mode. The _sender_ mode is developed/maintained for the purposes of testing interoperability. 

#### Reflector

Because the Reflector listens on a privileged port by default, it requires root privileges to run (see below for ways to customize the `teaparty` startup).

```console
$ sudo teaparty reflector
```

is the fastest way to get started. After that, take a look at the following start options documented using the `--help` CLI flag:

```console

Usage: teaparty reflector [OPTIONS]

Options:
      --stateless              Run teaparty in stateless mode.
      --heartbeat <HEARTBEAT>  Specify hearbeat message target and interval (in seconds) as [IP]@[Seconds]
      --link-layer             Run teaparty in link-layer mode.
  -h, --help                   Print help
```

Some TLVs (see below) need access to link-layer information about the test packet. Capturing such information is not possible using traditional BSD-socket-like methods.
When the Reflector runs in _link-layer mode_, it will listen for test packets by acting as a packet capturing system. While this feature will allow the Reflector to handle
more TLVs, it may also cause additional overhead.

**Monitoring**

By default, the Reflector will launch a RESTful API on the localhost on port 8080. It supports the following endpoints:

`/heartbeats`

Will return information about the configured heartbeat targets:

```console
$ curl http://127.0.0.1:8000/heartbeats
```

Sample output:
```JSON
[
  {
    "target": "8.8.8.8:8620",
    "interval": {
      "secs": 5,
      "nanos": 0
    }
  }
]
```

`/sessions`

Will return information about the currently active sessions:

```console
$ curl 127.0.0.1:8000/sessions
```

Sample output:
```JSON
[
  {
    "id": {
      "src": "0.0.0.0:862",
      "dst": "127.0.0.1:4567",
      "ssid": {
        "Ssid": 61183
      }
    },
    "data": {
      "sequence": 1,
      "last": {
        "secs_since_epoch": 1733193824,
        "nanos_since_epoch": 695132749
      }
    }
  },
  {
    "id": {
      "src": "0.0.0.0:862",
      "dst": "127.0.0.1:5001",
      "ssid": {
        "Ssid": 61183
      }
    },
    "data": {
      "sequence": 0,
      "last": {
        "secs_since_epoch": 1733193827,
        "nanos_since_epoch": 926120800
      }
    }
  }
]
```

More endpoints are planned. Endpoints that _control_ and not just monitor the Reflector are planned, too.

**Configuring**

`/session`

Will add a new active session, if possible. A request to create a new session (a _session request_) requires
- a source of test packets: `src_ip`: a string; `src_port`: a number
- a destination of test packets (i.e., the reflector): `src_ip`: a string; `src_port`: a number
- a key used for validating authenticated test packets: `key`: a string
- a session ID: `ssid`: a number

Upon `POST`ing a JSON object with the fields above, the server will respond with:

- 500: The session could not be created (most likely because a session with the requested parameters exists)
- 200: The sesion was created (and the body of the response will be the `POST`ed JSON for confirmation)

#### Sender

The Sender has a variety of options that are useful for testing implementations of a STAMP-compliant Reflector:

```console
Usage: teaparty sender [OPTIONS] [COMMAND]

Commands:
  tlvs  
  help  Print this message or the help of the given subcommand(s)

Options:
      --ssid <SSID>                    
      --malformed <MALFORMED>          Include a malformed Tlv in the test packet [possible values: bad-flags, bad-length]
      --ecn <ECN>                      Enable a non-default ECN for testing [possible values: not-ect, ect1, ect0, ce]
      --dscp <DSCP>                    Enable a non-default DSCP for testing [possible values: cs0, cs1, cs2, cs3, cs4, cs5, cs6, cs7, af11, af12, af13, af21, af22, af23, af31, af32, af33, af41, af42, af43, ef, voiceadmit]
      --ttl <TTL>                      Enable a non-default TTL for testing
      --src-port <SRC_PORT>            [default: 0]
      --authenticated <AUTHENTICATED>  
  -h, --help                           Print help
```

The `--src-port` option is useful for testing the statefulness of the Reflector. The `--malformed` option is useful
for testing the Reflector's error handling. The `--ecn` and `--dscp` will set the TOS fields of the IP packet of the test packet with the values specified.
-- useful for testing the Reflector's implementation of the TLVs related to quality of service. Omitting either of those options means that the test packet
will have neither DSCP nor ECN values set in the IP header. Setting the `--authenticated` flag will cause the sender to operate in
[Authenticated Mode](https://datatracker.ietf.org/doc/html/rfc8762#section-4-3) and use `<AUTHENTICATED>` as the key for generating the test packet's HMAC.

The `tlvs` subcommand will put TLVs into the test packet.

```console
Usage: teaparty sender tlvs [COMMAND]

Commands:
  dscp-ecn           
  time               
  destination-port   
  class-of-service   
  location           
  unrecognized       
  padding            
  access-report      
  history            
  followup           
  reflected-control  
  hmac
  bit-error-rate
  v6-extension-header-reflection  
  help               Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

| Name | TLV | Defaults/Notes |
| -- | -- | -- | 
| class-of-service | Class of Service | The DSCP value requested to be set in the reflected IP packet can be specified with the `--dscp`. By default, the requested value is `CS1`. |
| dscp-ecn | DSCP ECN | The values requested to be set in the reflected IP packet for the DSCP and ECN values can be specified with the `--dscp` and `--ecn` flags, respectively. By default, the requested values are `CS1` and `ECT0`, respectively. |
| time | Timestamp | All fields empty (see [RFC 8972](https://datatracker.ietf.org/doc/html/rfc8972))
| destination-port | Destination Port| 983 |
| location | Location | A Source IP Address sub-TLV |
| unrecognized | _Special_| Will include a TLV whose type is unrecognized |
| padding | Padding | Will pad out a STAMP packet with 64 bytes (by default); customize with the `-s` option |
| history | History | Will include a TLV that requests information about the previous _N_ reflected packets in the current session (defaults to 3; customize with `--length`) |
| reflected-control | Reflected Test Packet Control | Will include a TLV that manipulates the size, quantity and frequency of responses from the reflector (customize with `--reflected-length`, `--count` and `--interval`, respectively). |
| hmac | HMAC TLV | Will include a TLV that contains a HMAC (calculated using the key for authenticating the base STAMP packet [see `--authenticated`, above]) to verify integrity of TLV data. |
| bit-error-rate | Bit Error Rate and Bit Error Detection | Will include a TLV that can be used to (detect and) measure a path's bit error rate using a pattern of bytes spread over a given size (customize with `--pattern` and `--size`, respectively). |
| v6-extension-header-reflection | Reflected IPv6 Extension Header Data | There is no client functionality for this TLV (yet) |

_Example_:

```console
$ teaparty 127.0.0.1 sender  --dscp ef tlvs class-of-service 
```
will send a STAMP test packet to a Reflector running on localhost that contains a Class of Service TLV (with the requested value of the reflected packet's IP header`DSCP` field set to `CS1`) with the test IP packet's DSCP value set to `EF`.

It is possible to put more than one TLV into a test packet by separating multiple instances of the `tlvs` subcommand with the `--`.

_Example_:
```console
$ 127.0.0.1 sender --ecn ect1 --dscp af11 tlvs time -- dscp-ecn --ecn ect0 --dscp af21
```

will send a STAMP test packet to a Reflector running on localhost that contains a Timestamp TLV, a DSCP ECN TLV (requesting that the reflected IP packet's headers have DSCP and ECN fields set to `AF21` and `ECT0`, respectively), and with the test IP packet's ECN and DSCP values set to `ECT1` and `AF11`, respectively.

### Contributing

We would _love_ to have you contribute. We love contributors, big and small and everywhere in between. If you would like to learn more about how to work with us, just open an issue!

### Conformance Status

#### RFC 8762

| Feature | Supported |
| -- | -- |
| Unauthenticated STAMP messages (reflector) | &#9989;  |
| Unauthenticated STAMP messages (sender) | &#9989; |
| Authenticated STAMP messages (reflector) | &#9989;  |
| Authenticated STAMP messages (sender) | &#9989; |
| Stateful (reflector) | &#9989; |

#### RFC 8972

| TLV | Supported |
| -- | -- |
| Extra Padding (reflector) | &#10060; |
| Extra Padding (sender) | &#9989; |
| Location (reflector) |  &#9989;|
| Location (sender) | &#9989; |
| Timestamp (reflector) | &#9989; |
| Timestamp (sender) |  &#9989;  |
| Class of service (reflector) | &#9989; |
| Class of service (sender) |  &#9989; |
| Direct measurement (reflector) | &#10060; |
| Direct measurement (sender) | &#10060; |
| Access report (reflector) | &#9989; |
| Access report (sender) | &#9989; |
| Follow-up Telemetry (reflector) | &#9989; |
| Follow-up Telemetry (sender) | &#9989; |
| HMAC (reflector) | &#9989; |
| HMAC (sender) | &#9989; |


#### Yet-to-be-standardized TLVs

| TLV | Supported |
| -- | -- |
| DSCP ECN (reflector) | &#9989; |
| DSCP ECN (sender) | &#9989; |
| Heartbeat (reflector) | &#9989; |
| Heartbeat (sender) | &#10060; |
| Destination port (reflector) | &#9989; |
| Destination port (sender) | &#9989; |
| History (reflector) | &#9989; |
| History (sender) | &#9989; |
| Reflected Test Packet Control ([RFC](https://datatracker.ietf.org/doc/draft-ietf-ippm-asymmetrical-pkts/))| &#9989; (more testing required, but support starting in [48c274b](https://github.com/cerfcast/teaparty/commit/48c274ba935a00f4652aead5accd6156def3d6cb))|
| Bit Error Detection and Bit Error Rate ([RFC](https://datatracker.ietf.org/doc/draft-gandhi-ippm-stamp-ber/)) | &#9989; (more work required for complete implementation, but support starting in [592558a](https://github.com/cerfcast/teaparty/commit/592558a38dbcf9b273acb2a2fe8ab0d8f16d0709))[^bertlv] |
| Simple Two-Way Active Measurement Protocol (STAMP) Extensions for Reflecting STAMP Packet IP Headers ([RFC](https://www.ietf.org/archive/id/draft-ietf-ippm-stamp-ext-hdr-04.html)) | &#9989; (more work required for complete implementation, but support starting in [aa7cdb7](https://github.com/cerfcast/teaparty/commit/aa7cdb755da7d38213f2153f1a0859de5b8aa48a))[^headerreflect] |

[^bertlv]: Note: The BER TLV has been temporarily assigned `0x9` and `0xa` for TLV Type for the Count and Pattern, respectively. The implementation will be updated as the Draft changes.
[^headerreflect]: Note: The Reflected IPv6 Extension Header Data TLV has been temporarily assigned `0xb` for TLV Type. The implementation will be updated as the Draft changes.
### Testing

In addition to unit tests, there are tools for end-to-end tests in the `testing_data` directory. See [`testing_data/README.md`](./testing_data/README.md)
for more information.

### STAMP Protocol

There is early work on a YANG model for the configuration of a Session Sender and/or Reflector in the [`yang`](./yang/) directory. Start with [`yang/yang.md`](./yang/yang.md) if you are interested in contributing -- and, _yes_, we would _love_ it!

There is a Lua-based STAMP dissector for Wireshark in the [`wireshark`](./wireshark/) directory. There are usage instructions and other details for potential contributors in [`wireshark/README.md`](./wireshark/README.md). Again, we would _love_ contributors!