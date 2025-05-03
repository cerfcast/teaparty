# STAMP Configuration Parameters YANG Model 

## Using ...

The actual YANG is in [ietf-stamp.yang](./ietf-stamp.yang). [`pyang`](https://github.com/mbj4668/pyang) will validate whether the model conforms to [IETF specifications](https://datatracker.ietf.org/doc/rfc8407/):

```console
pyang --ietf --lint <  ietf-stamp.yang
```

`pyang` offers some cool options for visualizing the model. For instance, `pyang` will generate HTML:

```console
pyang --ietf --lint -f jstree <  ietf-stamp.yang > ietf-stamp.html
```

To install `pyang`, use `pip` (installing in a virtual environment makes things much easier, of course):

```console
$ pip install pyang
```

**Note:** You may need to install `setuptools` if you get an error about `pkg_resources`.

## Model

### Description

All types are from set of core types in [YANG](https://datatracker.ietf.org/doc/rfc6020/) or the [Common Yang Data Types](https://datatracker.ietf.org/doc/rfc6021/).

Some additional types specific to this model are defined herein (see [Custom Data Types](#custom-data-types)).

In the description of the model, any item without a default is _mandatory_ in a configuration. If a default is given and the configuration does not contain a value for that configuration item, the default is used.

### Custom Data Types

```YANG
  typedef timestamp {
    description
      "Format of timestamp fields in STAMP packet.";
    type enumeration {
      enum ntp {
        description
          "NTP format";
      }
      enum ptpv2 {
        description
          "PTPv2 format";
      }
    }
    default ntp;
  }
```

### Model

| Name | Description | Type | Default | Restrictions | Mandatory? | Teaparty Support? |
| -- | -- | -- | -- | -- | -- | -- |
| Reflector Port Number | The port number on which a STAMP reflector listens for test packets from a STAMP Session Sender. | port-number | 862 | Must be from User Ports or Dynamic Ports as defined in [RFC6335](https://www.rfc-editor.org/info/rfc6335). | No | Yes |
| Timestamp Format | The format of the timestamp fields in STAMP packets. | timestamp | `ntp` | N/A | No | No |