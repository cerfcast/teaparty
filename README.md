## Teaparty

An open source implementation of the Simple Two-Way Active Measurement Protocol ([RFC 8762](https://datatracker.ietf.org/doc/html/rfc8762)).

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

`teaparty` has both a _reflector_ and a _sender_ mode. The _reflector_ mode is the one that has been most tested. The _sender_ mode is developed/maintained for the purposes of testing interoperability. 

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
  -h, --help                   Print help
```

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

The Sender has a variety of options, but they are mostly for the purposes of testing the Reflector:

```console
Usage: teaparty sender [OPTIONS] [COMMAND]

Commands:
  tlvs  
  help  Print this message or the help of the given subcommand(s)

Options:
      --ssid <SSID>                    
      --malformed <MALFORMED>          Include a malformed Tlv in the test packet [possible values: bad-flags, bad-length]
      --ecn                            Enable a non-default ECN for testing (ECT0)
      --dscp                           Enable a non-default DSCP for testing (EF)
      --src-port <SRC_PORT>            [default: 0]
      --authenticated <AUTHENTICATED>  
  -h, --help                           Print help
```

The `--src-port` option is useful for testing the statefulness of the Reflector. The `--malformed` option is useful
for testing the Reflector's error handling. The `--ecn` and `--dscp` will set the TOS fields of the IP packet of the test packet (with the values [ECT0](https://www.juniper.net/documentation/us/en/software/junos/cos/topics/concept/cos-qfx-series-explicit-congestion-notification-understanding.html#understanding-cos-explicit-congestion-notification__subsection_anp_p5j_w5b)
and [EF](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus1000/sw/4_0/qos/configuration/guide/nexus1000v_qos/qos_6dscp_val.pdf), respectively) -- useful for testing the Reflector's implementation of the TLVs related to quality of service. Setting the `--authenticated` flag will cause the sender to operate in [Authenticated Mode](https://datatracker.ietf.org/doc/html/rfc8762#section-4-3) and use `<AUTHENTICATED>` as the key for generating the test packet's HMAC.

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
  history           
  help              Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
``` 

| Name | TLV | Defaults/Notes |
| -- | -- | -- | 
| class-of-service | Class of Service | When used with `--dscp` option, `DSCP1` field contains EF. Otherwise, `DSCP1` field contains CS0. |
| dscp-ecn | DSCP ECN | When used with `--dscp` option, `DSCP1` field contains EF. Otherwise, `DSCP1` field contains CS0. When used with `--ecn` option, `ECN1` field contains ECT0. Otherwise, `ECN1` field contains Not-ECT. | |
| time | Timestamp | All fields empty (see [RFC 8972](https://datatracker.ietf.org/doc/html/rfc8972))
| destination-port | Destination Port| 983 |
| location | Location | A Source IP Address sub-TLV |
| unrecognized | _Special_| Will include a TLV whose type is unrecognized |
| padding | Padding | Will pad out a STAMP packet with 64 bytes (by default); customize with the `-s` option |
| history | History | Will include a TLV that requests information about the previous _N_ reflected packets in the current session (defaults to 3; customize with `--length`) |



It is possible to put more than one TLV into a test packet by separating multiple instances of the `tlvs` subcommand with the `--`.

_Example_:

```console
$ teaparty 127.0.0.1 sender  --dscp tlvs class-of-service 
```
will send a STAMP test packet to a Reflector running on localhost that contains a Class of Service TLV (with the `DSCP1` field set to EF) with the IP packet's DSCP value set to EF.

```console
$ 127.0.0.1 sender --ecn --dscp tlvs time -- dscp-ecn  -- class-of-service 
```
will send a STAMP test packet to a Reflector running on localhost that contains a Timestamp TLV, a DSCP ECN TLV (with the the `DSCP1` and `ECN1` fields set to EF and ECT0, respectively), a Class of Service TLV (with the `DSCP1` field set to EF) and with the IP packet's ECN and DSCP values set to ECT0 and EF, respectively.

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
| Access report (reflector) | &#10060; |
| Access report (sender) | &#10060; |
| Follow-up Telemetry (reflector) | &#10060; |
| Follow-up Telemetry (sender) | &#10060; |
| HMAC (reflector) | &#10060; |
| HMAC (sender) | &#10060; |


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