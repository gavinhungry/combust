combust
=======
`combust` is an iptables/nftables-based firewall script with profiles.


Installation
------------
A pair of systemd service units, `combust.service` and `combust-nft.service`, as
well as OpenWrt-style init scripts, `combust.rc` and `combust-nft.rc`, are
provided.


Configuration
-------------
All configuration options are located in `/etc/combust/combust.conf`.  A
configuration profile may be used with either the iptables or the nftables
variant.

`ICMP_REPLY`: Set to `1` to enable ping replies.

`USE_IPV6`: Set to `1` to enable IPv6 support. If `0`, all IPv6 packets, both
inbound and outbound, are dropped.

`VPN_SERVER`: Set to `1` if the host is a VPN server. See also `IPV4_VPN` and
`IF[VPN]`.

`ROUTING`: Set to `1` if the host is a router.


#### IP Ranges
`IPV4_LAN`: Optional list of local IP ranges (in CIDR notation).

`IPV4_VPN`: VPN subnet address, ignored if `VPN_SERVER` is not enabled.


### Local Interfaces
`IF`: An array of group names to interfaces (or other group names).  For
example:

```sh
IF=(
  # [${GROUP_NAME}]="${INTERFACE1} [${INTERFACE2}] ..."
  [LAN]='eth0'
  [WLAN]='wlan0'
  [WAN]='LAN WLAN'
)
```

Here, the WAN interfaces (those with external internet access) are specified by
the LAN and WLAN group names (`eth0` and `wlan0` in this example).


### Local Ports
Lists of open ports are specified by protocol and the name of the interface(s).
For example:

```sh
# ${PROTOCOL}_${INTERFACE_GROUP}="${PORT1} [${PORT2}] ..."
TCP_WAN='22'
UDP_WLAN='2048'
```

The first line above opens TCP port 22 on the WAN interfaces (using the previous
example, this includes interfaces `eth0` and `wlan0`).

The second line opens UDP port 2048 only on the WLAN (`wlan0`) interface.

Rate limiting per-minute can be specified by including the limit after the port
number, seperated by a colon:

```sh
TCP_WAN='22:4'
```

This will limit connections to TCP port 22 on the WAN interfaces to 4 per
minute.  The burst-rate can also be specified here, after the per-minute rate:

```sh
TCP_WAN='22:4:8'
```

> **Note**: Burst-rate currently only works in the iptables version.


### Clients
Clients in a routing environment can be named for easy port-forwarding:

```sh
CLIENTS=(
  # [${CLIENT_NAME}]="${IP}"
  [LAPTOP]='172.168.1.1'
)
```

Then, to forward ports:

```sh
${PROTOCOL}_${CLIENT_NAME}="${PORT1} [${PORT2}] ..."
TCP_LAPTOP='10443'
```

The above line forwards TCP port 10443 from the router to the client named
LAPTOP.  To forward to a different port, delimit the source and destination with
a colon:

```sh
TCP_LAPTOP='10443:443'
```

LICENSE
-------
`combust` is released under the terms of the
[MIT license](http://tldrlegal.com/license/mit-license). See **LICENSE**.
