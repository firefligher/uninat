# UniNAT

UniNAT has been developed to map IPv4 subnets transparently. Initially, it was
created for a VPN, but it may also be useful in other situations.

## Why?

If you create a VPN on ISO/OSI Layer III (IPv4), you need to ensure that your
VPN-subnet does not collide with any other subnet that your clients are
connected to, otherwise they will not be able to access at least one of both.

Probably, there are multiple approaches to solve this issue, but here is mine:
I moved the responsibility for choosing the correct subnet from the
gateway-side to the client-side. Now, the client is responsible to determine
one [private-use](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
subnet that is not occupied yet and may be used for the VPN.

Now, there is just one little problem left: How do I manage all of these
different subnets and how do I ensure that all clients think that they are in
the same subnet?

One solution is the extensive usage of iptable-rules, but actually I do not
want to mess up my firewall with thousands of entries. Hence, I decided to
develop this tiny daemon that only requires two iptable-entries.

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

Since the subnet-decisions of the clients may change at runtime, UniNAT
provides an asynchronous interface for updating the internal mapping table. For
performance reasons it is based on shared memory and semaphores.
