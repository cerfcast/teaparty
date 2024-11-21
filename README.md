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

`teaparty` has both a _client_ and a _server_ mode. The _server_ mode is the one that has been most tested. The _client_ mode is developed/maintained for the purposes of testing interoperability. 

#### Server

Because the server listens on a privileged port by default, the server requires root privileges to run (see below for ways to customize the `teaparty` startup).

```console
$ sudo ./target/<mode>/teaparty server
```

is the fastest way to get started. After that, take a look at the following start options documented using the `--help` CLI flag:

```console

Usage: teaparty server [OPTIONS]

Options:
      --stateless              Run teaparty in stateless mode.
      --heartbeat <HEARTBEAT>  Specify hearbeat message target and interval (in seconds) as [IP]@[Seconds]
  -h, --help                   Print help
```

#### Client

`TODO`

### Contributing

We would _love_ to have you contribute. We love contributors, big and small and everywhere in between. If you would like to learn more about how to work with us, just open an issue!

### Conformance Status

#### RFC 8762

| Feature | Supported |
| -- | -- |
| Unauthenticated STAMP messages (reflector) | &#9989;  |
| Unauthenticated STAMP messages (sender) | &#9989; |
| Authenticated STAMP messages (reflector) | &#10060; |
| Authenticated STAMP messages (sender) | &#10060; |
| Stateful (reflector) | &#9989; |

#### RFC 8972

| TLV | Supported |
| -- | -- |
| Extra Padding (reflector) | &#10060; |
| Extra Padding (sender) | &#9989; |
| Location (reflector) | &#10060; |
| Location (sender) | &#10060; |
| Timestamp (reflector) | &#9989; |
| Timestamp (sender) |  &#9989;  |
| Class of service (reflector) | &#10060; |
| Class of service (sender) | &#10060; |
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
| Destination port (sender) | &#10060; |