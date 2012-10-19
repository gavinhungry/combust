#!/bin/bash
#
# Name: combust
# Auth: Gavin Lloyd <gavinhungry@gmail.com>
# Date: 01 Jul 2006 (last modified: 19 Oct 2012)
# Desc: iptables-based firewall script with simple profiles
#

declare -A IF
declare -A CLIENTS
source /etc/iptables/combust.conf

[ ${1-0} == '-v' ] && VERBOSE=1 || VERBOSE=0
[ ${1-0} == '-d' ] && DRYRUN=1 || DRYRUN=0

# ---[ FUNCTIONS ]--------------------------------------------------------------
msg() {
  [ $VERBOSE == 1 -o $DRYRUN == 1 ] && echo -e "\n\033[1m$(basename $0)\033[0m: $@"
}

ipt() {
  [ $VERBOSE == 1 -o $DRYRUN == 1 ] && echo "IPv4: $@"
  [ $DRYRUN == 0 ] && $IPTABLES "$@"
}

ipt6() {
  [ ${USE_IPV6-0} == 1 ] || return 0
  ipt6_do "$@"
}

ipt6_do() {
  [ $VERBOSE == 1 -o $DRYRUN == 1 ] && echo "IPv6: $@"
  [ $DRYRUN == 0 ] && $IP6TABLES "$@"
}


# ---[ FLUSH ]------------------------------------------------------------------
msg 'Flushing existing rules'

ipt -F
ipt -X
ipt -t nat -F
ipt -t nat -X
ipt -N valid_src_ipv4
ipt -N valid_dst_ipv4

ipt6 -F
ipt6 -X
ipt6 -N valid_src_ipv6
ipt6 -N valid_dst_ipv6

if [ ${USE_IPV6-0} == 0 -a -x $IP6TABLES ]; then
  msg 'Not using IPv6'

  ipt6_do -F
  ipt6_do -X
  ipt6_do -P INPUT DROP
  ipt6_do -P OUTPUT DROP
  ipt6_do -P FORWARD DROP
fi


# ---[ VALID ]------------------------------------------------------------------
msg 'External interface sources'
if [ ! -z "$IPV4_WAN" ]; then
  for RANGE in $IPV4_WAN; do
    ipt -A valid_src_ipv4 -s $RANGE -j RETURN
  done
fi

ipt  -A valid_src_ipv4 -s 127.0.0.0/8     -j DROP
ipt  -A valid_src_ipv4 -s 192.168.0.0/16  -j DROP
ipt  -A valid_src_ipv4 -s 172.16.0.0/12   -j DROP
ipt  -A valid_src_ipv4 -s 10.0.0.0/8      -j DROP
ipt  -A valid_src_ipv4 -s 169.254.0.0/16  -j DROP
ipt  -A valid_src_ipv4 -s 0.0.0.0/8       -j DROP
ipt  -A valid_src_ipv4 -s 224.0.0.0/4     -j DROP
ipt  -A valid_src_ipv4 -d 255.255.255.255 -j DROP
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

ipt  -A INPUT -m state --state INVALID -j DROP
ipt6 -A INPUT -m state --state INVALID -j DROP

ipt  -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
ipt6 -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# loopback
ipt  -A INPUT -i ${IF[LO]} -s 127.0.0.0/8 -d 127.0.0.0/8 -j ACCEPT
ipt6 -A INPUT -i ${IF[LO]} -s ::1/128 -d ::1/128 -j ACCEPT

msg 'filter/INPUT: common attacks'
for I in ${IF[WAN]}; do
  WAN=${IF[$I]-$I}

  ipt  -A INPUT -i $WAN -p tcp -m state --state NEW ! --syn -j DROP
  ipt6 -A INPUT -i $WAN -p tcp -m state --state NEW ! --syn -j DROP

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
if [ ${ROUTING-0} == 1 ]; then
  ipt  -A INPUT -i ${IF[LAN]} -j ACCEPT
  ipt6 -A INPUT -i ${IF[LAN]} -j ACCEPT
fi

# ICMP ping
if [ ${ICMP_REPLY-0} == 1 ]; then
  ipt  -A INPUT -p icmp   --icmp-type   echo-request -m limit --limit 8/sec -j ACCEPT
  ipt6 -A INPUT -p icmpv6 --icmpv6-type echo-request -m limit --limit 8/sec -j ACCEPT
elif [ ${ICMP_REPLY-0} == 'LAN' ]; then
  ipt  -A INPUT -i ${IF[LAN]} -p icmp   --icmp-type   echo-request -m limit --limit 8/sec -j ACCEPT
  ipt6 -A INPUT -i ${IF[LAN]} -p icmpv6 --icmpv6-type echo-request -m limit --limit 8/sec -j ACCEPT
fi

# IPv6
ipt6 -A INPUT -p icmpv6 -m icmp6 -s fe80::/10 --icmpv6-type neighbour-solicitation  -j ACCEPT
ipt6 -A INPUT -p icmpv6 -m icmp6 -s fe80::/10 --icmpv6-type neighbour-advertisement -j ACCEPT

msg 'filter/INPUT: per-interface rules'
for IL in ${!IF[@]}; do
  for I in ${IF[$IL]}; do
    for PROTO in TCP UDP; do
      for PORT in $(eval echo \$${PROTO}_${IL}); do
        ipt  -A INPUT -i ${IF[$I]-$I} -p ${PROTO,,} --dport $PORT -j ACCEPT
        ipt6 -A INPUT -i ${IF[$I]-$I} -p ${PROTO,,} --dport $PORT -j ACCEPT
      done
    done
  done
done


# ---[ OUTPUT ]-----------------------------------------------------------------
msg 'filter/OUTPUT'

ipt  -P OUTPUT ACCEPT
ipt6 -P OUTPUT ACCEPT

ipt  -A OUTPUT -m state --state INVALID -j DROP
ipt6 -A OUTPUT -m state --state INVALID -j DROP

for I in ${IF[WAN]}; do
  ipt  -A OUTPUT -o ${IF[$I]-$I} -j valid_dst_ipv4
  ipt6 -A OUTPUT -o ${IF[$I]-$I} -j valid_dst_ipv6
done


# ---[ FORWARD ]----------------------------------------------------------------
msg 'filter/FORWARD'

ipt  -P FORWARD DROP
ipt6 -P FORWARD DROP

ipt  -A FORWARD -m state --state INVALID -j DROP
ipt6 -A FORWARD -m state --state INVALID -j DROP

msg 'filter/FORWARD: route forwarding'
if [ ${ROUTING-0} == 1 ]; then
  ipt  -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
  ipt6 -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

  ipt  -A FORWARD -i ${IF[LAN]} -o ${IF[LAN]} -j ACCEPT
  ipt6 -A FORWARD -i ${IF[LAN]} -o ${IF[LAN]} -j ACCEPT

  for I in ${IF[WAN]}; do
    ipt  -A FORWARD -i ${IF[LAN]} -o ${IF[$I]-$I} -j ACCEPT
    ipt6 -A FORWARD -i ${IF[LAN]} -o ${IF[$I]-$I} -j ACCEPT
  done
fi

if [ ${VPN_SERVER-0} == 1 ]; then
  for I in ${IF[WAN]}; do
    ipt  -A FORWARD -i ${IF[$I]-$I} -o ${IF[VPN]} -d $IPV4_VPN -m state --state RELATED,ESTABLISHED -j ACCEPT
    ipt  -A FORWARD -i ${IF[VPN]} -o ${IF[$I]-$I} -s $IPV4_VPN -j ACCEPT
  done
fi

msg 'filter/FORWARD: client port forwards'
for CLIENT in ${!CLIENTS[@]}; do
  for PROTO in TCP UDP; do
    for PORT in $(eval echo \$${PROTO}_${CLIENT}); do
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

if [ ${VPN_SERVER-0} == 1 ]; then
  for I in ${IF[WAN]}; do
    ipt -t nat -A POSTROUTING -o ${IF[$I]-$I} -s $IPV4_VPN -j MASQUERADE
  done
fi

if [ ${ROUTING-0} == 1 ]; then
  for I in ${IF[WAN]}; do
    ipt -t nat -A POSTROUTING -o ${IF[$I]-$I} -j MASQUERADE
  done
fi


# ---[ CLEANUP ]----------------------------------------------------------------
[ $DRYRUN == 1 ] && msg 'This was a dry run, no changes have been applied'
