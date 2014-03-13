#!/bin/bash
#
# Name: combust
# Auth: Gavin Lloyd <gavinhungry@gmail.com>
# Date: 01 Jul 2006 (last modified: 13 Mar 2014)
# Desc: iptables-based firewall script with simple profiles
#

IPTABLES=/usr/bin/iptables
IP6TABLES=/usr/bin/ip6tables

declare -A IF
declare -A CLIENTS
source /etc/combust/combust.conf

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

ipt() {
  pref VERBOSE && echo "IPv4: $@"
  if ! pref DRYRUN; then
    $IPTABLES "$@" || let ERRORS++
  fi
}

ipt6() {
  pref USE_IPV6 || return 0
  ipt6_do "$@" || let ERRORS++
}

ipt6_do() {
  pref VERBOSE && echo "IPv6: $@"
  if ! pref DRYRUN; then
    $IP6TABLES "$@"
  fi
}


# ---[ FLUSH ]------------------------------------------------------------------
msg 'Flushing existing rules'

ipt -Z
ipt -F
ipt -X
ipt -t nat -F
ipt -t nat -X
ipt -t mangle -F
ipt -t mangle -X

ipt6 -Z
ipt6 -F
ipt6 -X

if pref FLUSH; then
  ipt -P INPUT ACCEPT
  ipt -P OUTPUT ACCEPT
  ipt -P FORWARD ACCEPT

  ipt6 -P INPUT ACCEPT
  ipt6 -P OUTPUT ACCEPT
  ipt6 -P FORWARD ACCEPT

  finish
fi

if ! pref USE_IPV6 && [ -x $IP6TABLES ]; then
  msg 'Not using IPv6'

  ipt6_do -Z
  ipt6_do -F
  ipt6_do -X
  ipt6_do -P INPUT DROP
  ipt6_do -P OUTPUT DROP
  ipt6_do -P FORWARD DROP
fi

ipt -N valid_src_ipv4
ipt -N valid_dst_ipv4

ipt6 -N valid_src_ipv6
ipt6 -N valid_dst_ipv6


# ---[ VALID ]------------------------------------------------------------------
msg 'External interface sources'
if [ ! -z "$IPV4_WAN" ]; then
  for RANGE in $IPV4_WAN; do
    ipt -A valid_src_ipv4 -s $RANGE -j RETURN
  done
fi

[ -z $RFC_1918_BITS ] && RFC_1918_BITS=0
[ $RFC_1918_BITS -ne 24 ] && ipt -A valid_src_ipv4 -s 10.0.0.0/8     -j DROP
[ $RFC_1918_BITS -ne 20 ] && ipt -A valid_src_ipv4 -s 172.16.0.0/12  -j DROP
[ $RFC_1918_BITS -ne 16 ] && ipt -A valid_src_ipv4 -s 192.168.0.0/16 -j DROP

ipt  -A valid_src_ipv4 -s 127.0.0.0/8     -j DROP
ipt  -A valid_src_ipv4 -s 169.254.0.0/16  -j DROP
ipt  -A valid_src_ipv4 -s 0.0.0.0/8       -j DROP
ipt  -A valid_src_ipv4 -s 224.0.0.0/4     -j DROP
ipt  -A valid_src_ipv4 -s 255.255.255.255 -j DROP
ipt6 -A valid_src_ipv6 -s ::1/128         -j DROP

msg 'External interface destinations'
if [ ! -z "$IPV6_WAN" ]; then
  for RANGE in $IPV6_WAN; do
    ipt6 -A valid_src_ipv6 -s $RANGE -j RETURN
  done
fi

ipt  -A valid_dst_ipv4 -d 127.0.0.0/8 -j DROP
ipt  -A valid_dst_ipv4 -d 224.0.0.0/4 -j DROP
ipt6 -A valid_dst_ipv6 -d ::1/128     -j DROP


# ---[ INPUT ]------------------------------------------------------------------
msg 'filter/INPUT'

ipt  -P INPUT DROP
ipt6 -P INPUT DROP

ipt  -A INPUT -m conntrack --ctstate INVALID -j DROP
ipt6 -A INPUT -m conntrack --ctstate INVALID -j DROP

ipt  -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ipt6 -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# loopback
ipt  -A INPUT -i ${IF[LO]} -s 127.0.0.0/8 -d 127.0.0.0/8 -j ACCEPT
ipt6 -A INPUT -i ${IF[LO]} -s ::1/128 -d ::1/128 -j ACCEPT

msg 'filter/INPUT: common attacks'
ipt  -N syn_flood_ipv4
ipt6 -N syn_flood_ipv6

ipt  -A syn_flood_ipv4 -p tcp --syn -m limit --limit 2/s --limit-burst 4 -j RETURN
ipt6 -A syn_flood_ipv6 -p tcp --syn -m limit --limit 2/s --limit-burst 4 -j RETURN

ipt  -A syn_flood_ipv4 -j DROP
ipt6 -A syn_flood_ipv6 -j DROP

for I in ${IF[WAN]}; do
  WAN=${IF[$I]-$I}

  ipt  -A INPUT -i $WAN -p tcp --syn -j syn_flood_ipv4
  ipt6 -A INPUT -i $WAN -p tcp --syn -j syn_flood_ipv6

  ipt  -A INPUT -i $WAN -p tcp -m conntrack --ctstate NEW ! --syn -j DROP
  ipt6 -A INPUT -i $WAN -p tcp -m conntrack --ctstate NEW ! --syn -j DROP

  ipt  -A INPUT -i $WAN -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
  ipt6 -A INPUT -i $WAN -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

  ipt  -A INPUT -i $WAN -p tcp --tcp-flags ALL SYN,FIN -j DROP
  ipt6 -A INPUT -i $WAN -p tcp --tcp-flags ALL SYN,FIN -j DROP

  ipt  -A INPUT -i $WAN -p tcp --tcp-flags ALL FIN -j DROP
  ipt6 -A INPUT -i $WAN -p tcp --tcp-flags ALL FIN -j DROP

  ipt  -A INPUT -i $WAN -p tcp --tcp-flags ALL NONE -j DROP
  ipt6 -A INPUT -i $WAN -p tcp --tcp-flags ALL NONE -j DROP

  ipt  -A INPUT -i $WAN -p tcp --tcp-flags ALL ALL -j DROP
  ipt6 -A INPUT -i $WAN -p tcp --tcp-flags ALL ALL -j DROP

  ipt  -A INPUT -i $WAN -p tcp --tcp-flags ALL URG,PSH,FIN -j DROP
  ipt6 -A INPUT -i $WAN -p tcp --tcp-flags ALL URG,PSH,FIN -j DROP

  ipt  -A INPUT -i $WAN -p tcp --tcp-flags ALL URG,PSH,SYN,FIN -j DROP
  ipt6 -A INPUT -i $WAN -p tcp --tcp-flags ALL URG,PSH,SYN,FIN -j DROP

  ipt  -A INPUT -i $WAN -j valid_src_ipv4
  ipt6 -A INPUT -i $WAN -j valid_src_ipv6
done

msg 'filter/INPUT: allowed LAN traffic'
if pref ROUTING; then
  ipt  -A INPUT -i ${IF[LAN]} -j ACCEPT
  ipt6 -A INPUT -i ${IF[LAN]} -j ACCEPT
fi

# ICMP ping
if pref ICMP_REPLY; then
  ipt  -A INPUT -p icmp   --icmp-type   echo-request -m limit --limit 2/s --limit-burst 4 -j ACCEPT
  ipt6 -A INPUT -p icmpv6 --icmpv6-type echo-request -m limit --limit 2/s --limit-burst 4 -j ACCEPT
fi

# IPv6
ipt6 -A INPUT -p icmpv6 -m icmp6 -s fe80::/10 --icmpv6-type neighbour-solicitation  -j ACCEPT
ipt6 -A INPUT -p icmpv6 -m icmp6 -s fe80::/10 --icmpv6-type neighbour-advertisement -j ACCEPT

msg 'filter/INPUT: per-interface rules'
for IL in ${!IF[@]}; do
  for I in ${IF[$IL]}; do
    for PROTO in TCP UDP; do
      PROTO_IL=${PROTO}_${IL}
      for PORT in ${!PROTO_IL}; do
        if [ $(echo $PORT | grep -c ':') -eq 1 ]; then
          DPORT=$(echo $PORT | cut -d':' -f1)
          LIMIT=$(echo $PORT | cut -d':' -f2)
          BURST=$(echo $PORT | cut -d':' -f3)
          for P in $(eval echo "$DPORT"); do
            ipt  -A INPUT -i ${IF[$I]-$I} -p ${PROTO,,} --dport $P -m conntrack --ctstate NEW -m limit --limit ${LIMIT:-8}/m --limit-burst ${BURST:-4} -j ACCEPT
            ipt6 -A INPUT -i ${IF[$I]-$I} -p ${PROTO,,} --dport $P -m conntrack --ctstate NEW -m limit --limit ${LIMIT:-8}/m --limit-burst ${BURST:-4} -j ACCEPT
          done
          continue
        fi
        for P in $(eval echo "$PORT"); do
          ipt  -A INPUT -i ${IF[$I]-$I} -p ${PROTO,,} --dport $P -j ACCEPT
          ipt6 -A INPUT -i ${IF[$I]-$I} -p ${PROTO,,} --dport $P -j ACCEPT
        done
      done
    done
  done
done


# ---[ OUTPUT ]-----------------------------------------------------------------
msg 'filter/OUTPUT'

ipt  -P OUTPUT ACCEPT
ipt6 -P OUTPUT ACCEPT

ipt  -A OUTPUT -m conntrack --ctstate INVALID -j DROP
ipt6 -A OUTPUT -m conntrack --ctstate INVALID -j DROP

for I in ${IF[WAN]}; do
  ipt  -A OUTPUT -o ${IF[$I]-$I} -j valid_dst_ipv4
  ipt6 -A OUTPUT -o ${IF[$I]-$I} -j valid_dst_ipv6
done


# ---[ FORWARD ]----------------------------------------------------------------
msg 'filter/FORWARD'

ipt  -P FORWARD DROP
ipt6 -P FORWARD DROP

ipt  -A FORWARD -m conntrack --ctstate INVALID -j DROP
ipt6 -A FORWARD -m conntrack --ctstate INVALID -j DROP

msg 'filter/FORWARD: route forwarding'
if pref ROUTING; then
  ipt  -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  ipt6 -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

  ipt  -A FORWARD -i ${IF[LAN]} -o ${IF[LAN]} -j ACCEPT
  ipt6 -A FORWARD -i ${IF[LAN]} -o ${IF[LAN]} -j ACCEPT

  for I in ${IF[WAN]}; do
    ipt  -A FORWARD -i ${IF[LAN]} -o ${IF[$I]-$I} -j ACCEPT
    ipt6 -A FORWARD -i ${IF[LAN]} -o ${IF[$I]-$I} -j ACCEPT
  done
fi

if pref VPN_SERVER; then
  for I in ${IF[WAN]}; do
    ipt  -A FORWARD -i ${IF[$I]-$I} -o ${IF[VPN]} -d $IPV4_VPN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ipt  -A FORWARD -i ${IF[VPN]} -o ${IF[$I]-$I} -s $IPV4_VPN -j ACCEPT
  done
fi

msg 'filter/FORWARD: client port forwards'
for CLIENT in ${!CLIENTS[@]}; do
  for PROTO in TCP UDP; do
    PROTO_CLIENT=${PROTO}_${CLIENT}
    for PORT in ${!PROTO_CLIENT}; do
      FROM=$(echo $PORT | cut -d':' -f1)
      DEST=$(echo $PORT | cut -d':' -f2)
      HOST=${CLIENTS[$CLIENT]}
      for I in ${IF[WAN]}; do
        ipt -t nat -A PREROUTING -i ${IF[$I]-$I} -p ${PROTO,,} --dport $FROM -j DNAT --to-destination $HOST:$DEST
        ipt        -A FORWARD    -i ${IF[$I]-$I} -p ${PROTO,,} --dport $DEST -d $HOST -j ACCEPT
      done
    done
  done
done


# ---[ POSTROUTING ]------------------------------------------------------------
msg 'nat/POSTROUTING'

if pref VPN_SERVER; then
  for I in ${IF[WAN]}; do
    ipt -t nat -A POSTROUTING -o ${IF[$I]-$I} -s $IPV4_VPN -j MASQUERADE
  done
fi

if pref ROUTING; then
  for I in ${IF[WAN]}; do
    ipt -t nat -A POSTROUTING -o ${IF[$I]-$I} -j MASQUERADE
  done
fi

finish
