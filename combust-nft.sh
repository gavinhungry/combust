#!/bin/bash
#
# Name: combust-nft
# Auth: Gavin Lloyd <gavinhungry@gmail.com>
# Date: 06 Mar 2014 (last modified: 07 Mar 2014)
# Desc: nftables-based firewall script with simple profiles
#
# THIS SCRIPT IS INCOMPLETE
#

NFT=/usr/bin/nft

declare -A IF
declare -A CLIENTS

# FIXME: /etc/combust/combust.conf
source ./combust-nft.conf

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
  pref VERBOSE && echo -e "\n\033[1m$(basename $0)\033[0m: $@"
}

finish() {
  pref DRYRUN && msg 'This was a dry run, no changes have been applied'
  exit $ERRORS
}

nft() {
  FAMILY=$1; shift
  CMD=$1; shift
  SUBCMD=$1; shift

  pref VERBOSE && echo "nft $CMD $SUBCMD $FAMILY $@"

  if ! pref DRYRUN; then
    $NFT $CMD $SUBCMD $FAMILY $@ || let ERRORS++
  fi
}

nft4() {
  nft "ip" "$@"
}

nft6() {
  # FIXME
  # pref USE_IPV6 || return 0
  nft "ip6" "$@"
}

nft4chain() {
  nft4 add chain filter "$@"
}

nft6chain() {
  nft6 add chain filter "$@"
}

nftchain() {
  nft4chain "$@"
  nft6chain "$@"
}

nft4rule() {
  nft4 add rule filter "$@"
}

nft6rule() {
  nft6 add rule filter "$@"
}

nftrule() {
  nft4rule "$@"
  nft6rule "$@"
}

# ---[ FLUSH ]------------------------------------------------------------------
msg 'Flushing existing rules'

# https://twitter.com/gavinhungry/status/441743648611262464
for FAMILY in ip ip6 arp bridge; do
  TABLES=$($NFT list tables $FAMILY | grep "^table\s" | cut -d' ' -f2)

  for TABLE in $TABLES; do
    CHAINS=$($NFT list table $FAMILY $TABLE | grep "^\schain\s" | cut -d' ' -f2)

    for CHAIN in $CHAINS; do
      nft $FAMILY flush chain $TABLE $CHAIN
      nft $FAMILY delete chain $TABLE $CHAIN
    done

    nft $FAMILY flush table $TABLE
    nft $FAMILY delete table $TABLE
  done
done

if pref FLUSH; then
  finish
fi

# input/output/forward chains on a filter table
$NFT -f /etc/nftables/ipv4-filter
$NFT -f /etc/nftables/ipv6-filter

nftchain valid_src
nftchain valid_dst

# ---[ VALID ]------------------------------------------------------------------
msg 'External interface sources'
if [ ! -z "$IPV4_LAN" ]; then
  for RANGE in $IPV4_LAN; do
    nft4rule valid_src ip saddr $RANGE return
  done
fi

# RFC1918 private addresses - include in IPV4_LAN to allow
nft4rule valid_src ip saddr 10.0.0.0/8     drop
nft4rule valid_src ip saddr 172.16.0.0/12  drop
nft4rule valid_src ip saddr 192.168.0.0/16 drop

nft4rule valid_src ip saddr 127.0.0.0/8 drop
nft4rule valid_src ip saddr 169.254.0.0/16 drop
nft4rule valid_src ip saddr 0.0.0.0/8 drop
nft4rule valid_src ip saddr 255.255.255.255 drop
nft4rule valid_src ip saddr 192.168.0.0/16 drop

if [ ! -z "$IPV6_LAN" ]; then
  for RANGE in $IPV6_LAN; do
    nft6rule valid_src ip6 saddr $RANGE return
  done
fi

nft6rule valid_src ip6 saddr ::1/128 drop

msg 'External interface destinations'
nft4rule valid_dst ip daddr 127.0.0.0/8 drop
nft4rule valid_dst ip daddr 224.0.0.0/4 drop

nft6rule valid_dst ip6 daddr ::1/128 drop


# ---[ INPUT ]------------------------------------------------------------------
msg 'filter/input'

nftrule input ct state invalid drop
nftrule input ct state {related, established} accept

# loopback
nft4rule input iifname ${IF[LO]} ip saddr 127.0.0.0/8 ip daddr 127.0.0.0/8 accept
nft6rule input iifname ${IF[LO]} ip6 saddr ::1/128 ip6 daddr ::1/128 accept

msg 'filter/input: common attacks'
nftchain syn_flood
nftrule syn_flood limit rate 2/second accept # FIXME: burst of 4
nftrule syn_flood accept

for I in ${IF[WAN]}; do
  WAN=${IF[$I]-$I}

  nftrule input iifname $WAN tcp flags '& (syn|rst|ack) == (syn)' jump syn_flood

  nftrule input iifname $WAN ct state new tcp flags '& (syn) < (syn)' drop
  nftrule input iifname $WAN ct state new tcp flags '& (syn|rst) == (syn|rst)' drop
  nftrule input iifname $WAN ct state new tcp flags '& (fin|syn|rst|psh|ack|urg) == (fin|syn)' drop
  nftrule input iifname $WAN ct state new tcp flags '& (fin|syn|rst|psh|ack|urg) == (fin)' drop
  nftrule input iifname $WAN ct state new tcp flags '& (fin|syn|rst|psh|ack|urg) < (fin)' drop
  nftrule input iifname $WAN ct state new tcp flags '== (fin|syn|rst|psh|ack|urg)' drop
  nftrule input iifname $WAN ct state new tcp flags '& (fin|syn|rst|psh|ack|urg) == (fin|psh|urg)' drop
  nftrule input iifname $WAN ct state new tcp flags '& (fin|syn|rst|psh|ack|urg) == (fin|syn|psh|urg)' drop

  nftrule input iifname $WAN jump valid_src
done


# msg 'filter/INPUT: allowed LAN traffic'
# if pref ROUTING; then
#   ipt  -A INPUT -i ${IF[LAN]} -j ACCEPT
#   ipt6 -A INPUT -i ${IF[LAN]} -j ACCEPT
# fi

# # ICMP ping
# if pref ICMP_REPLY; then
#   ipt  -A INPUT -p icmp   --icmp-type   echo-request -m limit --limit 2/s --limit-burst 4 -j ACCEPT
#   ipt6 -A INPUT -p icmpv6 --icmpv6-type echo-request -m limit --limit 2/s --limit-burst 4 -j ACCEPT
# fi

# # IPv6
# ipt6 -A INPUT -p icmpv6 -m icmp6 -s fe80::/10 --icmpv6-type neighbour-solicitation  -j ACCEPT
# ipt6 -A INPUT -p icmpv6 -m icmp6 -s fe80::/10 --icmpv6-type neighbour-advertisement -j ACCEPT

# msg 'filter/INPUT: per-interface rules'
# for IL in ${!IF[@]}; do
#   for I in ${IF[$IL]}; do
#     for PROTO in TCP UDP; do
#       PROTO_IL=${PROTO}_${IL}
#       for PORT in ${!PROTO_IL}; do
#         if [ $(echo $PORT | grep -c ':') -eq 1 ]; then
#           DPORT=$(echo $PORT | cut -d':' -f1)
#           LIMIT=$(echo $PORT | cut -d':' -f2)
#           BURST=$(echo $PORT | cut -d':' -f3)
#           for P in $(eval echo "$DPORT"); do
#             ipt  -A INPUT -i ${IF[$I]-$I} -p ${PROTO,,} --dport $P -m conntrack --ctstate NEW -m limit --limit ${LIMIT:-8}/m --limit-burst ${BURST:-4} -j ACCEPT
#             ipt6 -A INPUT -i ${IF[$I]-$I} -p ${PROTO,,} --dport $P -m conntrack --ctstate NEW -m limit --limit ${LIMIT:-8}/m --limit-burst ${BURST:-4} -j ACCEPT
#           done
#           continue
#         fi
#         for P in $(eval echo "$PORT"); do
#           ipt  -A INPUT -i ${IF[$I]-$I} -p ${PROTO,,} --dport $P -j ACCEPT
#           ipt6 -A INPUT -i ${IF[$I]-$I} -p ${PROTO,,} --dport $P -j ACCEPT
#         done
#       done
#     done
#   done
# done

# nftrule input drop

# # ---[ OUTPUT ]-----------------------------------------------------------------
# msg 'filter/OUTPUT'

# ipt  -P OUTPUT ACCEPT
# ipt6 -P OUTPUT ACCEPT

# ipt  -A OUTPUT -m conntrack --ctstate INVALID -j DROP
# ipt6 -A OUTPUT -m conntrack --ctstate INVALID -j DROP

# for I in ${IF[WAN]}; do
#   ipt  -A OUTPUT -o ${IF[$I]-$I} -j valid_dst_ipv4
#   ipt6 -A OUTPUT -o ${IF[$I]-$I} -j valid_dst_ipv6
# done


# # ---[ FORWARD ]----------------------------------------------------------------
# msg 'filter/FORWARD'

# ipt  -P FORWARD DROP
# ipt6 -P FORWARD DROP

# ipt  -A FORWARD -m conntrack --ctstate INVALID -j DROP
# ipt6 -A FORWARD -m conntrack --ctstate INVALID -j DROP

# msg 'filter/FORWARD: route forwarding'
# if pref ROUTING; then
#   ipt  -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
#   ipt6 -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

#   ipt  -A FORWARD -i ${IF[LAN]} -o ${IF[LAN]} -j ACCEPT
#   ipt6 -A FORWARD -i ${IF[LAN]} -o ${IF[LAN]} -j ACCEPT

#   for I in ${IF[WAN]}; do
#     ipt  -A FORWARD -i ${IF[LAN]} -o ${IF[$I]-$I} -j ACCEPT
#     ipt6 -A FORWARD -i ${IF[LAN]} -o ${IF[$I]-$I} -j ACCEPT
#   done
# fi

# if pref VPN_SERVER; then
#   for I in ${IF[WAN]}; do
#     ipt  -A FORWARD -i ${IF[$I]-$I} -o ${IF[VPN]} -d $IPV4_VPN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
#     ipt  -A FORWARD -i ${IF[VPN]} -o ${IF[$I]-$I} -s $IPV4_VPN -j ACCEPT
#   done
# fi

# msg 'filter/FORWARD: client port forwards'
# for CLIENT in ${!CLIENTS[@]}; do
#   for PROTO in TCP UDP; do
#     PROTO_CLIENT=${PROTO}_${CLIENT}
#     for PORT in ${!PROTO_CLIENT}; do
#       FROM=$(echo $PORT | cut -d':' -f1)
#       DEST=$(echo $PORT | cut -d':' -f2)
#       HOST=${CLIENTS[$CLIENT]}
#       for I in ${IF[WAN]}; do
#         ipt -t nat -A PREROUTING -i ${IF[$I]-$I} -p ${PROTO,,} --dport $FROM -j DNAT --to-destination $HOST:$DEST
#         ipt        -A FORWARD    -i ${IF[$I]-$I} -p ${PROTO,,} --dport $DEST -d $HOST -j ACCEPT
#       done
#     done
#   done
# done


# # ---[ POSTROUTING ]------------------------------------------------------------
# msg 'nat/POSTROUTING'

# if pref VPN_SERVER; then
#   for I in ${IF[WAN]}; do
#     ipt -t nat -A POSTROUTING -o ${IF[$I]-$I} -s $IPV4_VPN -j MASQUERADE
#   done
# fi

# if pref ROUTING; then
#   for I in ${IF[WAN]}; do
#     ipt -t nat -A POSTROUTING -o ${IF[$I]-$I} -j MASQUERADE
#   done
# fi

# finish
