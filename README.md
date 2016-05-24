combust
=======
`combust` is an [nftables](http://netfilter.org/projects/nftables) firewall
script with profiles.

Configuration
-------------
All configuration options are located in `/etc/combust.conf`.

`ICMP_REPLY`: Set to `1` to enable ping replies.

`USE_IPV6`: Set to `1` to enable IPv6 support. If `0`, all IPv6 packets, both
inbound and outbound, are dropped.

`VPN_SERVER`: Set to `1` if the host is a VPN server. See also `IPV4_VPN` and
`IF[VPN]`.

`STRICT_LOOPBACK`: Set to `1` to only allow loopback connections directly to and
from the loopback interface.


#### IP Ranges
`IPV4_LAN`: Optional list of local IP ranges (in CIDR notation).

`IPV4_VPN`: VPN subnet address, ignored if `VPN_SERVER` is not enabled.


### Local Interfaces
`IF`: An array of group names to interfaces (or other group names). For example:

```sh
IF=(
  [LO]='lo'
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
minute.

License
-------
This software is released under the terms of the **MIT license**. See `LICENSE`.
