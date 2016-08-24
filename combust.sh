#!/bin/bash

set -o pipefail

NFT=/usr/bin/nft
IP=/usr/bin/ip

declare -A IF
source /etc/combust.conf

ERRORS=0
for PARM in "$@"; do
  case $PARM in
    '-d'|'--dry-run') DRYRUN=1 ;&
    '-v'|'--verbose') VERBOSE=1 ;;
    '-f'|'--flush') FLUSH=1 ;;
  esac
done

# ---[ FUNCTIONS ]--------------------------------------------------------------
pref() {
  [ ${!1:-0} -eq 1 ] && return
}

msg() {
  pref VERBOSE && echo -e "\n\e[0;33;40m$@\e[0m"
}

finish() {
  pref DRYRUN && msg 'This was a dry run, no changes have been applied'
  exit $ERRORS
}

nftraw() {
  pref VERBOSE && echo "nft $@"

  if ! pref DRYRUN; then
    $NFT $@ || let ERRORS++
  fi
}

nft() {
  FAMILY=$1; shift
  CMD=$1; shift
  SUBCMD=$1; shift

  nftraw $CMD $SUBCMD $FAMILY $@
}

nft4() {
  nft "ip" "$@"
}

nft6() {
  pref USE_IPV6 || return 0
  nft "ip6" "$@"
}

nft4chain() {
  nft4 add chain "$@"
}

nft6chain() {
  nft6 add chain "$@"
}

nftchain() {
  nft4chain "$@"
  nft6chain "$@"
}

nft4rule() {
  nft4 add rule "$@"
}

nft6rule() {
  nft6 add rule "$@"
}

nftrule() {
  nft4rule "$@"
  nft6rule "$@"
}

nftpolicy() {
  TABLE=$1
  CHAIN=$2
  POLICY=$3

  nft ip add rule $TABLE $CHAIN $POLICY

  pref USE_IPV6 || POLICY=drop
  nft ip6 add rule $TABLE $CHAIN $POLICY
}

_awksub_ip() {
  grep "\s${1}$" | awk '{sub(/\/.*/,"",$2); print $2}'
}

inet() {
  $IP -4 addr show $1 | grep '^\s*inet\s' | _awksub_ip $1
}

inet6() {
  $IP -6 addr show $1 | grep '^\s*inet6\s' | _awksub_ip $1
}

interfaces() {
  for I in ${IF[$1]}; do
    for IX in ${IF[$I]-$I}; do
      echo ${IF[$IX]-$IX}
    done
  done
}

# ---[ FLUSH ]------------------------------------------------------------------
msg 'Flushing existing rules'

nftraw flush ruleset

if pref FLUSH; then
  finish
fi

# input/output/forward chains on a filter table
nftraw -f /usr/share/nftables/ipv4-filter
nftraw -f /usr/share/nftables/ipv6-filter

if pref VPN_SERVER; then
  nftraw -f /usr/share/nftables/ipv4-nat
  nftraw -f /usr/share/nftables/ipv6-nat
fi

nftchain filter valid_src
nftchain filter valid_dst

# ---[ VALID ]------------------------------------------------------------------
msg 'External interface sources'
if [ -n "$IPV4_LAN" ]; then
  for RANGE in $IPV4_LAN; do
    nft4rule filter valid_src ip saddr $RANGE return
  done
fi

# RFC1918 private addresses - include in IPV4_LAN to allow
nft4rule filter valid_src ip saddr 10.0.0.0/8     drop
nft4rule filter valid_src ip saddr 172.16.0.0/12  drop
nft4rule filter valid_src ip saddr 192.168.0.0/16 drop

nft4rule filter valid_src ip saddr 127.0.0.0/8     drop
nft4rule filter valid_src ip saddr 169.254.0.0/16  drop
nft4rule filter valid_src ip saddr 0.0.0.0/8       drop
nft4rule filter valid_src ip saddr 255.255.255.255 drop
nft4rule filter valid_src ip saddr 192.168.0.0/16  drop

if [ -n "$IPV6_LAN" ]; then
  for RANGE in $IPV6_LAN; do
    nft6rule filter valid_src ip6 saddr $RANGE return
  done
fi

nft6rule filter valid_src ip6 saddr ::1/128 drop

msg 'External interface destinations'

if pref STRICT_LOOPBACK; then
  nft4rule filter valid_dst ip daddr 127.0.0.0/8 drop
  nft6rule filter valid_dst ip6 daddr ::1/128 drop
fi


# ---[ INPUT ]------------------------------------------------------------------
msg 'filter/input'

nftrule filter input ct state invalid drop
nftrule filter input ct state { related, established } accept

# loopback
if pref STRICT_LOOPBACK; then
  nft4rule filter input iifname ${IF[LO]} ip saddr 127.0.0.0/8 ip daddr 127.0.0.0/8 accept
  nft6rule filter input iifname ${IF[LO]} ip6 saddr ::1/128 ip6 daddr ::1/128 accept
else
  nft4rule filter input iifname ${IF[LO]} ip daddr 127.0.0.0/8 accept
  nft6rule filter input iifname ${IF[LO]} ip6 daddr ::1/128 accept
fi

msg 'filter/input: common attacks'
nftchain filter syn_flood
nftrule filter syn_flood limit rate 2/second return
nftrule filter syn_flood drop

for I in $(interfaces WAN); do
  nftrule filter input iifname $I tcp flags '& (syn|rst|ack) == (syn)' jump syn_flood

  nftrule filter input iifname $I ct state new tcp flags '& (syn) < (syn)' drop
  nftrule filter input iifname $I ct state new tcp flags '& (syn|rst) == (syn|rst)' drop
  nftrule filter input iifname $I ct state new tcp flags '& (fin|syn|rst|psh|ack|urg) == (fin|syn)' drop
  nftrule filter input iifname $I ct state new tcp flags '& (fin|syn|rst|psh|ack|urg) == (fin)' drop
  nftrule filter input iifname $I ct state new tcp flags '& (fin|syn|rst|psh|ack|urg) < (fin)' drop
  nftrule filter input iifname $I ct state new tcp flags '== (fin|syn|rst|psh|ack|urg)' drop
  nftrule filter input iifname $I ct state new tcp flags '& (fin|syn|rst|psh|ack|urg) == (fin|psh|urg)' drop
  nftrule filter input iifname $I ct state new tcp flags '& (fin|syn|rst|psh|ack|urg) == (fin|syn|psh|urg)' drop

  nftrule filter input iifname $I jump valid_src
done

msg 'filter/input: forwarded interfaces'
for I in $(interfaces FOR); do
  nftrule filter forward iifname $I accept
  nftrule filter forward oifname $I accept
done

msg 'filter/input: ICMP reply'
if pref ICMP_REPLY; then
  nft4rule filter input icmp   type echo-request limit rate 8/second accept
  nft6rule filter input icmpv6 type echo-request limit rate 8/second accept
fi

# IPv6
nft6rule filter input ip6 saddr fe80::/10 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept

msg 'filter/input: per-interface rules'
for IL in ${!IF[@]}; do
  for I in $(interfaces $IL); do
    for PROTO in TCP UDP; do
      PROTO_IL=${PROTO}_${IL}
      for PORT in ${!PROTO_IL}; do
        if [ $(echo $PORT | grep -c ':') -eq 1 ]; then
          DPORT=$(echo $PORT | cut -d':' -f1)
          LIMIT=$(echo $PORT | cut -d':' -f2)
          BURST=$(echo $PORT | cut -d':' -f3)
          for P in $(eval echo "$DPORT"); do

            nftrule filter input iifname $I ct state new ${PROTO,,} dport $P limit rate ${LIMIT:-8}/minute accept
          done
          continue
        fi
        for P in $(eval echo "$PORT"); do
          nftrule filter input iifname $I ${PROTO,,} dport $P accept
        done
      done
    done
  done
done


# ---[ OUTPUT ]-----------------------------------------------------------------
msg 'filter/output'

nftrule filter output ct state invalid drop

for I in $(interfaces WAN); do
  nftrule filter output oifname $I jump valid_dst
done


# ---[ FORWARD ]----------------------------------------------------------------
msg 'filter/forward'

nftrule filter forward ct state invalid drop

msg 'filter/forward: route forwarding'
if pref VPN_SERVER; then
  for I in $(interfaces WAN); do
    nft4rule filter forward iifname $I oifname ${IF[VPN]} ip daddr $IPV4_VPN ct state { related, established } accept
    nft4rule filter forward iifname ${IF[VPN]} oifname $I ip saddr $IPV4_VPN accept
  done
fi

msg 'filter/input: forwarded interfaces'
for I in $(interfaces FOR); do
    nftrule filter forward iifname $I accept
    nftrule filter forward oifname $I accept
done

# ---[ POSTROUTING ]------------------------------------------------------------
msg 'nat/postrouting'
for I in $(interfaces WAN); do
  if INET=$(inet $I); then
    if pref VPN_SERVER; then
      nft4rule nat postrouting oifname $I ip saddr $IPV4_VPN snat $INET
    fi
  fi
done

# ---[ POLICY ]-----------------------------------------------------------------
msg 'default chain policies'
nftpolicy filter input drop
nftpolicy filter output accept
nftpolicy filter forward drop

finish
