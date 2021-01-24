# pling
A link-layer ping utility implemented with raw sockets (AF_PACKET, SOCK_RAW)

```
Usage: pling -h|--help
       pling -I|--interface <IFACE> -l|--listen
       pling -I|--interface <IFACE> [-c <CNT>] [-s <SIZE>] [-i <SECS>] [-r HOST] HOST [ HOST ... ]

Options:
  -I, --interface       The interface to send or receive on
  -l, --listen          listen-mode
  -c, --count CNT       Send only CNT pings
  -s, --size SIZE       Send SIZE data bytes in packets (default 56)
  -i, --interval SECS   Interval
  -r, --replyto HOST    The host address to reply to (default: source address)
```

pling utilizes its own, unoffical ether type (0x4304) which allows to test a link on a low level, without relying on a network protocol like IPv4/IPv6. No ARP or ICMPv6 Neighbor Discovery is necessary before sending the echo requests or echo replies.

To use pling, you start one pling instance in listen-mode (*--listen*). Then you can ping it by starting another pling instance on a different host with the MAC address(es) of the target host(s) sepecified.

## Examples:

pling can be used to test the unicast and multicast capabilities of a link individually.

### Unicast test:

Listener on veth0/02:11:22:33:44:55 :
```
$ pling --interface veth0 --listen
06:11:22:33:44:55 > 02:11:22:33:44:55, LLCMP, echo request, reply-to 06:11:22:33:44:55, id 0x69a7, seq 1, length 0(18)
06:11:22:33:44:55 > 02:11:22:33:44:55, LLCMP, echo request, reply-to 06:11:22:33:44:55, id 0x69a7, seq 2, length 0(18)
06:11:22:33:44:55 > 02:11:22:33:44:55, LLCMP, echo request, reply-to 06:11:22:33:44:55, id 0x69a7, seq 3, length 0(18)
```

Sender on veth1/06:11:22:33:44:55 :
```
$ pling --interface veth1 --count 3 02:11:22:33:44:55
0(18) bytes from 02:11:22:33:44:55 (via 02:11:22:33:44:55): pling_seq=1 time=0.268 ms
0(18) bytes from 02:11:22:33:44:55 (via 02:11:22:33:44:55): pling_seq=2 time=0.208 ms
0(18) bytes from 02:11:22:33:44:55 (via 02:11:22:33:44:55): pling_seq=3 time=0.221 ms
```

### Broadcast test:

The reply-to feature can be used to force the listener to reply to the broadcast address. That way the broadcast capabilities of an interface can be tested individually, without relying on unicast.

Listener on veth0/02:11:22:33:44:55 :
```
$ pling --listen --interface veth0
06:11:22:33:44:55 > 02:11:22:33:44:55, LLCMP, echo request, reply-to 06:11:22:33:44:55, id 0xdf2f, seq 1, length 0(18)
06:11:22:33:44:55 > 02:11:22:33:44:55, LLCMP, echo request, reply-to 06:11:22:33:44:55, id 0xdf2f, seq 2, length 0(18)
06:11:22:33:44:55 > 02:11:22:33:44:55, LLCMP, echo request, reply-to 06:11:22:33:44:55, id 0xdf2f, seq 3, length 0(18)
```

Sender on veth1/06:11:22:33:44:55 :
```
$ pling --interface vethy --count 3 --replyto 06:11:22:33:44:55  02:11:22:33:44:55
0(18) bytes from 02:11:22:33:44:55 (via 02:11:22:33:44:55): pling_seq=1 time=0.310 ms
0(18) bytes from 02:11:22:33:44:55 (via 02:11:22:33:44:55): pling_seq=2 time=0.171 ms
0(18) bytes from 02:11:22:33:44:55 (via 02:11:22:33:44:55): pling_seq=3 time=0.106 ms
```

## Packet format

**LLCMP - Link-layer Control Message Protocol**

The packet format is (mostly) analogical to ICMPv6, the Internet Control Message Protocol for IPv6. Currently an LLCMP Echo Request and an LLCMP Echo Reply is implemented in pling:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Ethernet Destination ...                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  ... Ethernet Destination     |       Ethernet Source ...     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 ... Ethernet Source                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      LLCMP Ethernet Type      |  Reserved1    |  Reserved2    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      LLCMP Payload Length     |  LLCMP Type   |  Reserved3    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      LLCMP Identifier         |  LLCMP Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     LLCMP Reply-To ...                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  ... LLCMP Reply-To           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

*Ethernet Destination:*
* 6 bytes MAC address of the receiver. All but 00:00:00:00:00:00 allowed.

*Ethernet Source:*
* 6 bytes MAC address of the sender. Only unicast MAC addresses allowed (least-significant bit of the first octet set to 0 and not 00:00:00:00:00:00).

*LLCMP Ethernet Type:*
* 0x4304 (network byte order / big-endian), unnofficial ethernet type.

*Reserved1:*
* Reserved, probably LLCMP hop limit later

*Reserved2:*
* Reserved, probably LLCMP traffic class for Quality-of-Service later

*LLCMP Payload Length:*
* Number of bytes beyond the LLCMP header. Typically "frame size - 14 bytes ethernet header - 16 bytes LLCMP header". (ToDo: maybe define LLCMP header size as 6 bytes, so excluding the Echo Request/Reply specific fields "Identifier", "Sequence Number" and "Reply-To"?)

*LLCMP Type:*
* Currently implemented/defined:
  * LLCMP Echo Request, 128
  * LLCMP Echo Reply, 129

*Reserved3:*
* Reserved, probably code/subtype or flags for a specific LLCMP Type later

*LLCMP Identifier:*
* Random, but fixed 2 bytes for a specific LLCMP Echo Request/Reply session

*LLCMP Sequence Number:*
* A 2 bytes, sequential number (network byte order / big-endian) for a specific LLCMP Echo Request/Reply exchange. Starts with 1 and is increased by one with every next Echo Request.

*LLCMP Reply-To:*
* 6 bytes MAC address. In an LLCMP Echo Request specifies the Ethernet Destination which the receiver should use in its LLCMP Echo Reply. In an LLCMP Echo Reply is equal to the Ethernet Source of the LLCMP Echo Reply. Can be used to detect Layer 2 source NATs / proxies, too.

## Operating System Compability

pling has been implemented and tested on Linux, specifically Debian with glibc and OpenWrt with musl. For other systems the getrandom systemcall and the ioctl calls probably need to be replaced. Also the _\_\_be16_ type is glibc/musl specific (but is useful to detect endianess issues during compile time).

## Future Ideas

In the future it would be useful to adopt further functionallity from IP/ICMP and add that capability to both pling and switch(-like) devices. The layer 2 mesh routing protocol B.A.T.M.A.N. Advanced for instance has its own ping/echo protocol with TTL and record-route capabilities to monitor its route selection. However it would be useful if a generic link-layer "ICMP" were established which also simple switches or switch-like devices were aware of.

* Destination unreachable: a switch(-like) device could return a message when it does not know where to further forward a frame
* Packet Too Big: a switch(-like) device could return a message with the MTU limit when it is unable to forward the frame on an interface/port because of a smaller MTU on the according outgoing interface/port
* hop limit: a hoplimit/"time-to-live" could be added which switch(-like) devices could decrement and evaluate
* record routes: Switch(-like) devices could insert their MAC address in the echo request/reply packets when forwarding the frame, which, together with a hop limit, would be very helpful to determine and debug a bridging loop
* Multicast Listener Discovery: A generic link-layer multicast sign-up protocol, analog to IGMP/MLD for IPv4/IPv6, to sign-up for any multicast MAC address; would be useful for non-IP protocols, like batman-adv, to avoid having to flood all its multicast/broadcast packets

Other ToDos:
* Gather and display some statistics when exiting
* Currently Echo Reply timeouts are equal equal to the interval. Implement higher/adjustable ones and maybe exit immediately when receiving a reply for the last sequence number, like ping does. (Or at least when pinging a unicast destination? For a multicast case it's actually quite useful to wait a bit longer for more replies.)
* Use ether-hosts file to translate names to MAC addresses? (similar to bat-hosts, search /etc/ether-hosts, then ~/ether-hosts and ./ether-hosts)
* Maybe add a 2 byte LLCMP tvlv\_len field?
* Maybe add a 1 byte LLCMP version field?
