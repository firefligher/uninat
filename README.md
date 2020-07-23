# UniNAT

UniNAT has been developed to map IPv4 subnets transparently. Initially, it was
created for a VPN, but it may also be useful in other situations.

## Why?

If you create a VPN on ISO/OSI Layer III (IPv4), you need to ensure that your
VPN-subnet does not collide with any other subnet that your clients are
connected to, otherwise they will not be able to access at least one of both.

Probably, there are multiple approaches to solve this issue, but here is mine:
I moved the responsibility for choosing the correct subnet from the
gateway-side to the client-side. Now, the client is responsible for determining
one [private-use](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
subnet that is not occupied yet and may be used for the VPN.

Now, there is just one little problem left: How do I manage all of these
different subnets and how do I ensure that all clients think that they are in
the same subnet?

One solution is the extensive usage of iptable-rules, but actually I do not
want to mess up my firewall with thousands of entries. Hence, I decided to
develop this tiny little utility that only requires two iptable-entries.

## How?

The VPN-gateway also chooses a subnet for the VPN. The address information of
all incoming packets will be translated/normalized to this subnet at iptable's
PREROUTING step. Then, the Linux kernel will route the packet to the right
network interface. At POSTROUTING, the normalized IPv4 address information will
be translated to the subnet of the destination host.

This mechanism makes the whole subnet translation transparent to all
participants. It is required that all subnets of all clients and the gateway
have the same size.

The whole application is running in userland and relies on iptable's
NFQUEUE-target. You may use iptable's `--queue-balance` parameter to split up
the load on multiple instances of UniNAT.

## Interface

### Command-line

The following command-line parameters are available and may be used when
launching another UniNAT-process.

| Parameter                         | Shortcut                    | Description                                                                                               |
|:---------------------------------:|:---------------------------:|:----------------------------------------------------------------------------------------------------------|
| `--table-file <path>`             | `-t<path>`                  | *Required.* Specifies the path to the table file.                                                         |
| `--queue <number>`                | `-q<number>`                | *Required.* Specifies the iptables NFQUEUE number.                                                        |
| `--mode {PREROUTING|POSTROUTING}` | `-m{PREROUTING|POSTROUTING} | *Required.* Whether the NAT is performed by the source (PREROUTING) or destination (POSTROUTING) address. |
| `--verbose`                       | `-v`                        | Increases the number of details that will be logged to the output (decreases performance).                |

### Signals

At the moment, `SIGUSR1` will trigger reloading the configuration from the
specified table file.

### Table file

The table file specifies the actual mapping that the *UniNAT* process applies
on the handled packets. Each line must contain exactly two IPv4 addresses, each
ending with its CIDR-suffix.

```
10.0.0.0/8      192.168.255.0/24
172.16.0.0/12   192.168.255.0/24
192.168.0.0/16  192.168.255.0/24
```

TODO: Expand
