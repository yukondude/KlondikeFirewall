#!/bin/bash
################################################################################
# klondike-router
# A shell script to configure a stateful netfilter/iptables IPv4
# packet-filtering firewall routing firewall.
#-------------------------------------------------------------------------------
# chkconfig: 35 11 89
# description: Configuration rules for stateful packet-filter iptables firewall.
#-------------------------------------------------------------------------------
# This script must run after the main iptables rc script (assuming there is one)
# and should also run after the main networking rc script (usually
# /etc/init.d/networking). For safety's sake, the main iptables script should
# run before networking starts, and should set the default policy for all
# built-in chains to DROP.
#
# Replace all items marked "TODO" with your own network values. The existing
# rules assume a private class-C LAN, so you'll have to adjust as necessary.
# Of course, you'll also have to set up your own rules.
#
# LAN: Private network behind router.
# NET: Public network.
#
# The default setup (once proper IP addresses are in place) configures a routing
# firewall that forwards incoming HTTP, HTTPS, SMTP, and SSH traffic from NET to
# a server on the private LAN. The routing server also acts as a DNS proxy and
# NTP time server to clients on the LAN. The routing server may also initiate
# HTTP, RSYNC, and Passive FTP requests to the NET.
#-------------------------------------------------------------------------------
# By Dave Rogers
# yukon dude software <yukondude.com>
# Whitehorse, Yukon, Canada
#-------------------------------------------------------------------------------
# Copyright (c) 2002-2014 Dave Rogers
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------
# Inspired by:
# Netfilter by Paul "Rusty" Russell
#   [www.netfilter.org]
# Iptables Tutorial by Oskar Andreasson
#   [iptables-tutorial.frozentux.net/iptables-tutorial.html]
# Connection Tracking by James C. Stephens
#   [www.sns.ias.edu/~jns/wp/2006/01/24/iptables-how-does-it-work]
# Linux IP Masquerade HOWTO by David A. Ranch
#   [www.tldp.org/HOWTO/IP-Masquerade-HOWTO]
# Firewall Ruleset by vogt@hansenet.com
#   [link no longer valid]
# Redundant Internet Connections Using Linux by Seann Herdejurgen
#   [www.samag.com/documents/s=1824/sam0201h/0201h.htm]
# rc.firewall.iptables.dual version 1.2b3 by obsid@sentry.net
#   [www.sentry.net/~obsid/IPTables/rc.scripts.dir/current/rc.firewall.iptables.dual]
################################################################################

#-------------------------------------------------------------------------------
# Dependency Checks

# Bail if iptables isn't in the path.
if [ -z $(which iptables 2>/dev/null) ]; then
  echo -n "$0 is unable to load the firewall rules: "
  echo "the iptables utility is not in the path."
  exit 1
fi

#-------------------------------------------------------------------------------
# Network Interfaces

# TODO: Change interfaces.
IFACE_LAN="eth1" # LAN-facing interface
IFACE_NET="eth0" # NET-facing interface
IFACE_LOC="lo" # Loopback

#-------------------------------------------------------------------------------
# Host and Network IP Addresses

# TODO: Change LAN-facing addresses.
IPADDR_LAN="192.168.1.1/32" # LAN-facing NIC IP
IPNETW_LAN="192.168.1.0/24" # LAN-facing network
IPBCAST_LAN="192.168.1.255" # LAN-facing broadcast IP

# TODO: Change NET-facing addresses.
IPADDR_NET="199.247.1.1/32" # NET-facing NIC IP
IPNETW_NET="! ${IPNETW_LAN}" # NET-facing network (essentially, everything else)
IPBCAST_NET="199.247.1.255" # NET-facing broadcast IP

IPNETW_LOC="127.0.0.0/8"

#-------------------------------------------------------------------------------
# Private and Reserved Network IP Addresses

# TODO: Change if you don't use a private class-C LAN.
PRIVATE="10.0.0.0/8 172.16.0.0/12 224.0.0.0/4" # Impossible IPs.
PRIVATE_LAN="192.168.0.0/16" # Possible LAN-facing IPs.

# Addresses reserved by IANA (subject to change, so I just picked the outliers).
#   [http://www.iana.org/assignments/ipv4-address-space]
RESERVED="0.0.0.0/8 1.0.0.0/8 2.0.0.0/8 240.0.0.0/4"

#-------------------------------------------------------------------------------
# Known Remote Host IP Addresses

# TODO: Change DNS server addresses.
DNS_NET_1="10.11.12.13"
DNS_NET_2="10.11.12.13"

# TODO: Add any other fixed IPs of interest.

#-------------------------------------------------------------------------------
# Known IP Protocols (other than TCP, UDP, ICMP)

IPPROT_IGMP="2"

#-------------------------------------------------------------------------------
# ICMP Message Types

ICMP_PONG="0"
ICMP_UNREACHABLE="3"
ICMP_PING="8"
ICMP_TIME_EXCEEDED="11"
ICMP_TRACEROUTE="30"

#-------------------------------------------------------------------------------
# Known TCP and UDP Ports and Port Ranges

# TODO: Add/remove ports as necessary.
PORT_FTP="21"
PORT_FTP_CMD="21"
PORT_FTP_DATA="20"
PORT_SSH="22"
PORT_TELNET="23"
PORT_SMTP="25"
PORT_DNS="53"
PORT_HTTP="80"
PORT_POP="110"
PORT_AUTH="113"
PORT_NTP="123"
PORT_MSRPC="135"
PORT_MSNBNS="137"
PORT_MSNBDG="138"
PORT_MSNBSSN="139"
PORT_HTTPS="443"
PORT_MSDS="445"
PORT_RSYNC="873"
PORTS_TRACEROUTE="32769:65535"

#-------------------------------------------------------------------------------
# Internal Port-Forwarded Service Addresses

# TODO: Add/remove port-forwarded IPs as necessary.
HTTP_LAN="192.168.1.2"
HTTPS_LAN="192.168.1.2"
SMTP_LAN="192.168.1.2"
SSH_LAN="192.168.1.2"

#-------------------------------------------------------------------------------
# Privileged and Unprivileged Port Ranges

PORTS_PRIV="0:1023"
PORTS_UNPRIV="1024:65535"

#-------------------------------------------------------------------------------
# Log Levels for Target Chains

LOG_LEVEL_ATTACK="3"  # err
LOG_LEVEL_ILLEGAL="4" # warning
LOG_LEVEL_UNKNOWN="4" # warning
LOG_LEVEL_FLOOD="5"   # notice
LOG_LEVEL_SCAN="5"    # notice
LOG_LEVEL_WATCH="6"   # info

#-------------------------------------------------------------------------------
# Configure Kernel Networking Parameters
# See www.tldp.org/HOWTO/Adv-Routing-HOWTO-13.html for further explanation.

config_kernel() {
  # Load necessary kernel modules. Most are loaded automatically, but
  # ip_conntrack_ftp and ip_nat_ftp must be loaded explicitly to enable FTP
  # connection tracking, and FTP SNAT, respectively.
  modprobe ip_conntrack_ftp
  modprobe ip_nat_ftp

  # Set the maximum number of connections to track if not already > 4096.
  if [ -e /proc/sys/net/ipv4/ip_conntrack_max ]; then
    if [ $(cat /proc/sys/net/ipv4/ip_conntrack_max) -le 4096 ]; then
      echo "4096" > /proc/sys/net/ipv4/ip_conntrack_max
    fi
  fi

  # Set local port range for TCP/UDP connections.
  if [ -e /proc/sys/net/ipv4/ip_local_port_range ]; then
    echo -e "32768\t61000" > /proc/sys/net/ipv4/ip_local_port_range
  fi

  # Disable source-routed packets.
  if [ -e /proc/sys/net/ipv4/conf/all/accept_source_route ]; then
    for i in /proc/sys/net/ipv4/conf/*/accept_source_route; do
      echo "0" > $i;
    done
  fi

  # Enable reverse path filter to combat spoofing.
  if [ -e /proc/sys/net/ipv4/conf/all/rp_filter ]; then
    for i in /proc/sys/net/ipv4/conf/*/rp_filter; do
      echo "1" > $i;
    done
  fi

  # Don't reply to smurf ping broadcasts.
  if [ -e /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts ]; then
    echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
  fi

  # Log spoofed, source-routed, or redirect packets.
  if [ -e /proc/sys/net/ipv4/conf/all/log_martians ]; then
    echo "1" > /proc/sys/net/ipv4/conf/all/log_martians
  fi

  # Disable external ICMP redirects.
  if [ -e /proc/sys/net/ipv4/conf/$IFACE_NET/accept_redirects ]; then
    echo "0" > /proc/sys/net/ipv4/conf/$IFACE_NET/accept_redirects
  fi

  # Ignore ICMP responses to hosts misinterpreting broadcast traffic.
  if [ -e /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses ]; then
    echo "1" > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
  fi

  # Enable IP forwarding.
  if [ -e /proc/sys/net/ipv4/ip_forward ]; then
    echo "1" > /proc/sys/net/ipv4/ip_forward
  fi
}

#-------------------------------------------------------------------------------
# Remove All Chains and Rules

flush() {
  # Flush the rules from the built-in chains.
  iptables -F
  iptables -F -t nat
  iptables -F -t mangle

  # Drop any custom chains.
  iptables -X
  iptables -X -t nat
  iptables -X -t mangle
  
  # Zero the counters.
  iptables -Z
  iptables -Z -t nat
  iptables -Z -t mangle
}

#-------------------------------------------------------------------------------
# Set Policy for Built-in Chains
# Use DROP as the default policy unless specified otherwise.

set_policy() {
  iptables -P INPUT ${1:-DROP}
  iptables -P FORWARD ${1:-DROP}
  iptables -P OUTPUT ${1:-DROP}
}

#-------------------------------------------------------------------------------
# Install Target Chains
# All rules must jump to one of these target chains.

install_targets() {
  # Accept incoming packets. This chain exists primarily for accounting purposes.
  iptables -N TGT_ACCEPT_IN
  iptables -A TGT_ACCEPT_IN -j ACCEPT

  # Accept outgoing packets. This chain exists primarily for accounting purposes.
  iptables -N TGT_ACCEPT_OUT
  iptables -A TGT_ACCEPT_OUT -j ACCEPT

  # Drop incoming packets. This chain exists primarily for accounting purposes.
  iptables -N TGT_DROP_IN
  iptables -A TGT_DROP_IN -j DROP

  # Drop outgoing packets. This chain exists primarily for accounting purposes.
  iptables -N TGT_DROP_OUT
  iptables -A TGT_DROP_OUT -j DROP

  # Reject and reset incoming TCP packets. This is a "friendly" way to respond
  # to certain unwanted protocol probes such as AUTH (IDENTD).
  iptables -N TGT_TCP_REJECT_IN
  iptables -A TGT_TCP_REJECT_IN -p tcp -j REJECT --reject-with tcp-reset

  # Reject and reset outgoing TCP packets. This is a "friendly" way to respond
  # to certain unwanted protocol probes such as AUTH (IDENTD).
  iptables -N TGT_TCP_REJECT_OUT
  iptables -A TGT_TCP_REJECT_OUT -p tcp -j REJECT --reject-with tcp-reset

  # Log and drop malicious incoming packets that are known security exploits.
  iptables -N TGT_ATTACK_IN
  iptables -A TGT_ATTACK_IN -j LOG --log-level $LOG_LEVEL_ATTACK --log-prefix "FW_ATTACK_IN: "
  iptables -A TGT_ATTACK_IN -j TGT_DROP_IN

  # Log and drop malicious outgoing packets that are known security exploits.
  iptables -N TGT_ATTACK_OUT
  iptables -A TGT_ATTACK_OUT -j LOG --log-level $LOG_LEVEL_ATTACK --log-prefix "FW_ATTACK_OUT: "
  iptables -A TGT_ATTACK_OUT -j TGT_DROP_OUT

  # Discard annoying but otherwise innocuous incoming packets.
  iptables -N TGT_DISCARD_IN
  iptables -A TGT_DISCARD_IN -j TGT_DROP_IN

  # Discard annoying but otherwise innocuous incoming packets.
  iptables -N TGT_DISCARD_OUT
  iptables -A TGT_DISCARD_OUT -j TGT_DROP_OUT

  # Log and drop any suspected incoming flood attacks (more than 15 packets per
  # second with a maximum burst of 30 per second). Don't log more than 5
  # packets per minute so that the log doesn't fill up.
  iptables -N TGT_FLOOD_IN
  iptables -A TGT_FLOOD_IN -m limit --limit 15/s --limit-burst 30 -j RETURN
  iptables -A TGT_FLOOD_IN -m limit --limit 5/m -j LOG --log-level $LOG_LEVEL_FLOOD --log-prefix "FW_FLOOD_IN: "
  iptables -A TGT_FLOOD_IN -j TGT_DROP_IN

  # Log and drop malformed or impossible incoming packets.
  iptables -N TGT_ILLEGAL_IN
  iptables -A TGT_ILLEGAL_IN -j LOG --log-level $LOG_LEVEL_ILLEGAL --log-prefix "FW_ILLEGAL_IN: "
  iptables -A TGT_ILLEGAL_IN -j TGT_DROP_IN

  # Log and drop malformed or impossible outgoing packets.
  iptables -N TGT_ILLEGAL_OUT
  iptables -A TGT_ILLEGAL_OUT -j LOG --log-level $LOG_LEVEL_ILLEGAL --log-prefix "FW_ILLEGAL_OUT: "
  iptables -A TGT_ILLEGAL_OUT -j TGT_DROP_OUT

  # Log and drop packets that look like incoming scans. Don't log more than 5
  # packets per minute so that the log doesn't fill up.
  iptables -N TGT_SCAN_IN
  iptables -A TGT_SCAN_IN -m limit --limit 5/m -j LOG --log-level $LOG_LEVEL_SCAN --log-prefix "FW_SCAN_IN: "
  iptables -A TGT_SCAN_IN -j TGT_DROP_IN
  
  # Log and drop unknown incoming packets. Don't log more than 5 packets per
  # minute so that the log doesn't fill up.
  iptables -N TGT_UNKNOWN_IN
  iptables -A TGT_UNKNOWN_IN -m limit --limit 5/m -j LOG --log-level $LOG_LEVEL_UNKNOWN --log-prefix "FW_UNKNOWN_IN: "
  iptables -A TGT_UNKNOWN_IN -j TGT_DROP_IN

  # Log and drop unknown outgoing packets. Don't log more than 5 packets per
  # minute so that the log doesn't fill up.
  iptables -N TGT_UNKNOWN_OUT
  iptables -A TGT_UNKNOWN_OUT -m limit --limit 5/m -j LOG --log-level $LOG_LEVEL_UNKNOWN --log-prefix "FW_UNKNOWN_OUT: "
  iptables -A TGT_UNKNOWN_OUT -j TGT_DROP_OUT

  # Log and accept incoming packets that we want to keep an eye on.
  iptables -N TGT_WATCH_IN
  iptables -A TGT_WATCH_IN -j LOG --log-level $LOG_LEVEL_WATCH --log-prefix "FW_WATCH_IN: " --log-ip-options
  iptables -A TGT_WATCH_IN -j TGT_ACCEPT_IN

  # Log and accept outgoing packets that we want to keep an eye on.
  iptables -N TGT_WATCH_OUT
  iptables -A TGT_WATCH_OUT -j LOG --log-level $LOG_LEVEL_WATCH --log-prefix "FW_WATCH_OUT: " --log-ip-options
  iptables -A TGT_WATCH_OUT -j TGT_ACCEPT_OUT
}

#-------------------------------------------------------------------------------
# Install Local Loopback Interface Rules
# No restrictions on local loopback interface.

install_lo_in_out() {
  iptables -A INPUT -i $IFACE_LOC -j TGT_ACCEPT_IN
  iptables -A OUTPUT -o $IFACE_LOC -j TGT_ACCEPT_OUT
}

#-------------------------------------------------------------------------------
# Install BAD_TCP_ANY_IN Chain
# Filters out bad TCP segments originating from any connected network.

install_bad_tcp_any_in() {
  iptables -N BAD_TCP_ANY_IN
  iptables -A INPUT -p tcp -j BAD_TCP_ANY_IN
  
  # Be polite and deny inbound AUTH connections (usually from broken email
  # servers).
  iptables -A BAD_TCP_ANY_IN -p tcp --dport $PORT_AUTH -j TGT_TCP_REJECT_IN

  # Segments with illegal TCP flags.
  iptables -A BAD_TCP_ANY_IN -p tcp --tcp-option 64 -j TGT_ILLEGAL_IN
  iptables -A BAD_TCP_ANY_IN -p tcp --tcp-option 128 -j TGT_ILLEGAL_IN

  # Segments pretending to be part of an established connection.
  iptables -A BAD_TCP_ANY_IN -p tcp ! --syn -m state --state NEW -j TGT_ILLEGAL_IN
  
  # Segments with every flag bit set (XMAS tree packets).
  iptables -A BAD_TCP_ANY_IN -p tcp --tcp-flags ALL ALL -j TGT_ILLEGAL_IN
  
  # Segments with no flag bits set (NULL packets).
  iptables -A BAD_TCP_ANY_IN -p tcp --tcp-flags ALL NONE -j TGT_ILLEGAL_IN

  # SYN flood DoS attacks.
  iptables -A BAD_TCP_ANY_IN -p tcp --syn -j TGT_FLOOD_IN
  
  # Stealth scan. Treat like flood because a few at a time are valid.
  iptables -A BAD_TCP_ANY_IN -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j TGT_FLOOD_IN
  
  # XMAS scan, used by NMAP.
  iptables -A BAD_TCP_ANY_IN -p tcp --tcp-flags ALL FIN,URG,PSH -j TGT_SCAN_IN
  
  # SYN/RST scan.
  iptables -A BAD_TCP_ANY_IN -p tcp --tcp-flags SYN,RST SYN,RST -j TGT_SCAN_IN
  
  # SYN/FIN scan.
  iptables -A BAD_TCP_ANY_IN -p tcp --tcp-flags SYN,FIN SYN,FIN -j TGT_SCAN_IN

  # MyDoom backdoor scan.
  iptables -A BAD_TCP_ANY_IN -p tcp --dport 3127 -j TGT_SCAN_IN
}

#-------------------------------------------------------------------------------
# Install BAD_ANY_IN Chain
# Filters out bad traffic originating from any connected network.

install_bad_any_in() {
  iptables -N BAD_ANY_IN
  iptables -A INPUT -j BAD_ANY_IN
  
  # Ignore any Internet Group Management Protocol (IGMP) messages.
  iptables -A BAD_ANY_IN -p $IPPROT_IGMP -j TGT_DISCARD_IN
  
  # Invalid packet.
  iptables -A BAD_ANY_IN -m state --state INVALID -j TGT_ILLEGAL_IN
  
  # Packet fragments.
  iptables -A BAD_ANY_IN -f -j TGT_ILLEGAL_IN
  
  # Ping scan. Treat like flood because a few at a time are valid.
  iptables -A BAD_ANY_IN -p icmp --icmp-type $ICMP_PING -j TGT_FLOOD_IN

  # Packets pretending to be headed for the loopback interface.
  iptables -A BAD_ANY_IN -d $IPNETW_LOC -j TGT_ILLEGAL_IN
  
  # Packets pretending to be from a private network address.
  for NETW in $PRIVATE; do
    iptables -A BAD_ANY_IN -s $NETW -j TGT_ILLEGAL_IN
  done
  
  # Packets pretending to be from a reserved address.
  for NETW in $RESERVED; do
    iptables -A BAD_ANY_IN -s $NETW -j TGT_ILLEGAL_IN
  done
  
  # Packets with a source port of zero. Started showing up in May, 2003.
  iptables -A BAD_ANY_IN -p tcp --sport 0 -j TGT_ILLEGAL_IN
  iptables -A BAD_ANY_IN -p udp --sport 0 -j TGT_ILLEGAL_IN
  
  # Throw away MS SQL Server Slammer worm crap.
  iptables -A BAD_ANY_IN -p tcp --dport 1433 -j TGT_DISCARD_IN
  iptables -A BAD_ANY_IN -p udp --dport 1434 -j TGT_DISCARD_IN
}

#-------------------------------------------------------------------------------
# Install BAD_ANY_OUT Chain
# Filters out bad traffic destined for any connected network.

install_bad_any_out() {
  iptables -N BAD_ANY_OUT
  iptables -A OUTPUT -j BAD_ANY_OUT

  # Packets pretending to be part of an established connection.
  iptables -A BAD_ANY_OUT -p tcp ! --syn -m state --state NEW -j TGT_ILLEGAL_OUT

  # Prevent information leak described by Red Hat Advisory RHSA-2002:086-05.
  iptables -A BAD_ANY_OUT -p icmp -m state --state INVALID -j TGT_ILLEGAL_OUT

  # Packets heading for a private network address.
  for NETW in $PRIVATE; do
    iptables -A BAD_ANY_OUT -d $NETW -j TGT_ILLEGAL_OUT
  done

  # Packets heading for a reserved address.
  for NETW in $RESERVED; do
    iptables -A BAD_ANY_OUT -d $NETW -j TGT_ILLEGAL_OUT
  done
  
  # Packets with a source port of zero.
  iptables -A BAD_ANY_OUT -p tcp --sport 0 -j TGT_ILLEGAL_OUT
  iptables -A BAD_ANY_OUT -p udp --sport 0 -j TGT_ILLEGAL_OUT
}

#-------------------------------------------------------------------------------
# Install BAD_NET_IN Chain
# Filters out bad traffic originating from the public internet.

install_bad_net_in() {
  iptables -N BAD_NET_IN
  iptables -A INPUT -i $IFACE_NET -j BAD_NET_IN

  # Drop annoying MS worm traffic.
  iptables -A BAD_NET_IN -p udp --dport $PORT_MSNBNS -j TGT_DISCARD_IN
  iptables -A BAD_NET_IN -p tcp --dport $PORT_MSRPC -j TGT_DISCARD_IN
  iptables -A BAD_NET_IN -p tcp --dport $PORT_MSNBSSN -j TGT_DISCARD_IN

  # Broadcast packets.
  iptables -A BAD_NET_IN -d $IPBCAST_NET -j TGT_ATTACK_IN

  # Packets pretending to be from this address.
  iptables -A BAD_NET_IN -s $IPADDR_NET -j TGT_ILLEGAL_IN

  # Packets pretending to be from the LAN private network.
  iptables -A BAD_NET_IN -s $PRIVATE_LAN -j TGT_ILLEGAL_IN
}

#-------------------------------------------------------------------------------
# Install BAD_NET_OUT Chain
# Filters out bad traffic destined for the public internet.

install_bad_net_out() {
  iptables -N BAD_NET_OUT
  iptables -A OUTPUT -o $IFACE_NET -j BAD_NET_OUT

  # Broadcast packets.
  iptables -A BAD_NET_OUT -d $IPBCAST_NET -j TGT_ATTACK_OUT

  # Packets with spoofed source address.
  iptables -A BAD_NET_OUT -s ! $IPADDR_NET -j TGT_ILLEGAL_OUT

  # Packets heading for the LAN private network.
  iptables -A BAD_NET_OUT -d $PRIVATE_LAN -j TGT_ILLEGAL_OUT
}

#-------------------------------------------------------------------------------
# Install BAD_LAN_IN Chain
# Filters out bad traffic originating from the local private network.

install_bad_lan_in() {
  iptables -N BAD_LAN_IN
  iptables -A INPUT -i $IFACE_LAN -j BAD_LAN_IN

  # Ping broadcasts.
  iptables -A BAD_LAN_IN -d $IPBCAST_LAN -p icmp -j TGT_ATTACK_IN

  # Packets pretending to be from this address (that weren't actually broadcast
  # by this host).
  iptables -A BAD_LAN_IN -s $IPADDR_LAN -d ! $IPBCAST_LAN -j TGT_ILLEGAL_IN

  # Packets pretending to be from a network other than the LAN network.
  iptables -A BAD_LAN_IN -s ! $IPNETW_LAN -j TGT_ILLEGAL_IN
}

#-------------------------------------------------------------------------------
# Install BAD_LAN_OUT Chain
# Filters out bad traffic destined for the local private network.

install_bad_lan_out() {
  iptables -N BAD_LAN_OUT
  iptables -A OUTPUT -o $IFACE_LAN -j BAD_LAN_OUT

  # Ping broadcasts.
  iptables -A BAD_LAN_OUT -d $IPBCAST_LAN -p icmp -j TGT_ATTACK_OUT

  # Packets heading for a network other than the LAN network.
  iptables -A BAD_LAN_OUT -d ! $IPNETW_LAN -j TGT_ILLEGAL_OUT
}

#-------------------------------------------------------------------------------
# Install ICMP_ANY_IN Chain
# Selectively accepts ICMP messages originating from any connected network.

install_icmp_any_in() {
  iptables -N ICMP_ANY_IN
  iptables -A INPUT -p icmp -j ICMP_ANY_IN

  # Inbound ping (echo request) messages.
  iptables -A ICMP_ANY_IN -p icmp --icmp-type $ICMP_PING -m state --state NEW -j TGT_ACCEPT_IN

  # Inbound pong (echo reply) messages from previous outbound ping queries.
  iptables -A ICMP_ANY_IN -p icmp --icmp-type $ICMP_PONG -m state --state ESTABLISHED -j TGT_ACCEPT_IN

  # Inbound time exceeded messages from previous outbound queries
  # (e.g. traceroute).
  iptables -A ICMP_ANY_IN -p icmp --icmp-type $ICMP_TIME_EXCEEDED -m state --state RELATED -j TGT_ACCEPT_IN

  # Inbound unreachable messages from previous outbound queries.
  iptables -A ICMP_ANY_IN -p icmp --icmp-type $ICMP_UNREACHABLE -m state --state RELATED -j TGT_ACCEPT_IN
}

#-------------------------------------------------------------------------------
# Install ICMP_ANY_OUT Chain
# Selectively accepts ICMP messages destined for any connected network.

install_icmp_any_out() {
  iptables -N ICMP_ANY_OUT
  iptables -A OUTPUT -p icmp -j ICMP_ANY_OUT

  # Outbound ping (echo request) messages.
  iptables -A ICMP_ANY_OUT -p icmp --icmp-type $ICMP_PING -m state --state NEW -j TGT_ACCEPT_OUT

  # Outbound pong (echo reply) messages from previous inbound ping queries.
  iptables -A ICMP_ANY_OUT -p icmp --icmp-type $ICMP_PONG -m state --state ESTABLISHED -j TGT_ACCEPT_OUT

  # Outbound time exceeded messages from previous inbound queries
  # (e.g. traceroute).
  iptables -A ICMP_ANY_OUT -p icmp --icmp-type $ICMP_TIME_EXCEEDED -m state --state RELATED -j TGT_ACCEPT_OUT

  # Outbound unreachable messages from previous inbound queries.
  iptables -A ICMP_ANY_OUT -p icmp --icmp-type $ICMP_UNREACHABLE -m state --state RELATED -j TGT_ACCEPT_OUT
}

#-------------------------------------------------------------------------------
# Install TCP_LAN_IN Chain
# Selectively accepts TCP segments originating from the local private network.

install_tcp_lan_in() {
  iptables -N TCP_LAN_IN
  iptables -A INPUT -i $IFACE_LAN -p tcp -j TCP_LAN_IN

  # Inbound Secure SHell connections.
  iptables -A TCP_LAN_IN -p tcp --dport $PORT_SSH -m state --state NEW,ESTABLISHED -j TGT_ACCEPT_IN
}

#-------------------------------------------------------------------------------
# Install TCP_LAN_OUT Chain
# Selectively accepts TCP segments destined for the local private network.

install_tcp_lan_out() {
  iptables -N TCP_LAN_OUT
  iptables -A OUTPUT -o $IFACE_LAN -p tcp -j TCP_LAN_OUT

  # Inbound Secure SHell connections.
  iptables -A TCP_LAN_OUT -p tcp --sport $PORT_SSH -m state --state ESTABLISHED -j TGT_ACCEPT_OUT
}

#-------------------------------------------------------------------------------
# Install TCP_NET_IN Chain
# Selectively accepts TCP segments originating from the public internet.

install_tcp_net_in() {
  iptables -N TCP_NET_IN
  iptables -A INPUT -i $IFACE_NET -p tcp -j TCP_NET_IN

  # Outbound HTTP connections.
  iptables -A TCP_NET_IN -p tcp --sport $PORT_HTTP -m state --state ESTABLISHED -j TGT_ACCEPT_IN

  # Outbound RSYNC connections.
  iptables -A TCP_NET_IN -p tcp --sport $PORT_RSYNC -m state --state ESTABLISHED -j TGT_ACCEPT_IN

  # Outbound passive FTP connections.
  iptables -A TCP_NET_IN -p tcp --sport $PORT_FTP_CMD -m state --state ESTABLISHED -j TGT_ACCEPT_IN

  iptables -A TCP_NET_IN -p tcp --sport $PORTS_UNPRIV --dport $PORTS_UNPRIV -m state --state ESTABLISHED -j TGT_ACCEPT_IN
}

#-------------------------------------------------------------------------------
# Install TCP_NET_OUT Chain
# Selectively accepts TCP segments destined for the public internet.

install_tcp_net_out() {
  iptables -N TCP_NET_OUT
  iptables -A OUTPUT -o $IFACE_NET -p tcp -j TCP_NET_OUT

  # Outbound HTTP connections.
  iptables -A TCP_NET_OUT -p tcp --dport $PORT_HTTP -m state --state NEW,ESTABLISHED -j TGT_ACCEPT_OUT

  # Outbound RSYNC connections.
  iptables -A TCP_NET_OUT -p tcp --dport $PORT_RSYNC -m state --state NEW,ESTABLISHED -j TGT_ACCEPT_OUT

  # Outbound passive FTP connections.
  iptables -A TCP_NET_OUT -p tcp --dport $PORT_FTP_CMD -m state --state NEW,ESTABLISHED -j TGT_ACCEPT_OUT

  iptables -A TCP_NET_OUT -p tcp --dport $PORTS_UNPRIV --sport $PORTS_UNPRIV -m state --state ESTABLISHED,RELATED -j TGT_ACCEPT_OUT
}

#-------------------------------------------------------------------------------
# Install TCP_ANY_IN Chain
# Selectively accepts TCP segments originating from the any connected network.

install_tcp_any_in() {
  iptables -N TCP_ANY_IN
  iptables -A INPUT -p tcp -j TCP_ANY_IN

  # Ignore annoying MS domain service gunk.
  iptables -A TCP_ANY_IN -p tcp --dport $PORT_MSDS -j TGT_DISCARD_IN
}

#-------------------------------------------------------------------------------
# Install TCP_ANY_OUT Chain
# Selectively accepts TCP segments destined for the public internet.

install_tcp_any_out() {
  iptables -N TCP_ANY_OUT
  iptables -A OUTPUT -p tcp -j TCP_ANY_OUT

  # Ignore any attempts to contact DNS servers through TCP.
  iptables -A TCP_ANY_OUT -p tcp --dport $PORT_DNS -j TGT_DISCARD_OUT
}

#-------------------------------------------------------------------------------
# Install UDP_LAN_IN Chain
# Selectively accepts UDP segments originating from the local private network.

install_udp_lan_in() {
  iptables -N UDP_LAN_IN
  iptables -A INPUT -i $IFACE_LAN -p udp -j UDP_LAN_IN

  # Inbound DNS queries.
  iptables -A UDP_LAN_IN -p udp --dport $PORT_DNS -m state --state NEW,ESTABLISHED -j TGT_ACCEPT_IN

  # Inbound NTP queries.
  iptables -A UDP_LAN_IN -p udp --dport $PORT_NTP -m state --state NEW,ESTABLISHED -j TGT_ACCEPT_IN

  # Ignore broadcast traffic for Samba.
  iptables -A UDP_LAN_IN -p udp -m multiport --ports $PORT_MSNBNS,$PORT_MSNBDG -j TGT_DISCARD_IN
}

#-------------------------------------------------------------------------------
# Install UDP_LAN_OUT Chain
# Selectively accepts UDP datagrams destined for the local private network.

install_udp_lan_out() {
  iptables -N UDP_LAN_OUT
  iptables -A OUTPUT -o $IFACE_LAN -p udp -j UDP_LAN_OUT

  # Inbound DNS queries.
  iptables -A UDP_LAN_OUT -p udp --sport $PORT_DNS -m state --state ESTABLISHED -j TGT_ACCEPT_OUT

  # Inbound NTP queries.
  iptables -A UDP_LAN_OUT -p udp --sport $PORT_NTP -m state --state ESTABLISHED -j TGT_ACCEPT_OUT
}

#-------------------------------------------------------------------------------
# Install UDP_NET_IN Chain
# Selectively accepts UDP segments originating from the public internet.

install_udp_net_in() {
  iptables -N UDP_NET_IN
  iptables -A INPUT -i $IFACE_NET -p udp -j UDP_NET_IN

  # Outbound DNS queries to primary server.
  iptables -A UDP_NET_IN -s $DNS_NET_1 -p udp --sport $PORT_DNS -m state --state ESTABLISHED -j TGT_ACCEPT_IN

  # Outbound DNS queries to secondary server.
  iptables -A UDP_NET_IN -s $DNS_NET_2 -p udp --sport $PORT_DNS -m state --state ESTABLISHED -j TGT_ACCEPT_IN

  # Outbound NTP queries.
  iptables -A UDP_NET_IN -p udp --sport $PORT_NTP -m state --state ESTABLISHED -j TGT_ACCEPT_IN
}

#-------------------------------------------------------------------------------
# Install UDP_NET_OUT Chain
# Selectively accepts UDP datagrams destined for the public internet.

install_udp_net_out() {
  iptables -N UDP_NET_OUT
  iptables -A OUTPUT -o $IFACE_NET -p udp -j UDP_NET_OUT
  
  # Outbound DNS queries to primary server.
  iptables -A UDP_NET_OUT -d $DNS_NET_1 -p udp --dport $PORT_DNS -m state --state NEW,ESTABLISHED -j TGT_ACCEPT_OUT

  # Outbound DNS queries to secondary server.
  iptables -A UDP_NET_OUT -d $DNS_NET_2 -p udp --dport $PORT_DNS -m state --state NEW,ESTABLISHED -j TGT_ACCEPT_OUT

  # Outbound NTP queries.
  iptables -A UDP_NET_OUT -p udp --dport $PORT_NTP -m state --state NEW,ESTABLISHED -j TGT_ACCEPT_OUT

  # Outbound traceroute queries.
  iptables -A UDP_NET_OUT -p udp --dport $PORTS_TRACEROUTE -m state --state NEW -j TGT_ACCEPT_OUT
}

#-------------------------------------------------------------------------------
# Install FORWARD_IN Chain
# Filters out bad traffic, and selectively accepts forwarded connections,
# destined for the local private network.

install_forward_in() {
  iptables -N FORWARD_IN
  iptables -A FORWARD -i $IFACE_NET -o $IFACE_LAN -j FORWARD_IN

  # Inbound filter rules.
  iptables -A FORWARD_IN -p tcp -j BAD_TCP_ANY_IN
  iptables -A FORWARD_IN -j BAD_NET_IN
  iptables -A FORWARD_IN -j BAD_ANY_IN

  # Inbound established connections.
  iptables -A FORWARD_IN -m state --state ESTABLISHED,RELATED -j TGT_ACCEPT_IN

  # Inbound DNAT new connections.
  iptables -A FORWARD_IN -p tcp -d $HTTP_LAN --dport $PORT_HTTP -m state --state NEW -j TGT_ACCEPT_IN

  iptables -A FORWARD_IN -p tcp -d $HTTPS_LAN --dport $PORT_HTTPS -m state --state NEW -j TGT_ACCEPT_IN

  iptables -A FORWARD_IN -p tcp -d $SMTP_LAN --dport $PORT_SMTP -m state --state NEW -j TGT_ACCEPT_IN

  iptables -A FORWARD_IN -p tcp -d $SSH_LAN --dport $PORT_SSH -m state --state NEW -j TGT_ACCEPT_IN

  iptables -A FORWARD_IN -p tcp -d $PFTP_LAN --dport $PORT_FTP_CMD -m state --state NEW -j TGT_ACCEPT_IN

  # TODO: Delete once forwarding rules are figured out.
  iptables -A FORWARD_IN -j TGT_WATCH_IN
}

#-------------------------------------------------------------------------------
# Install FORWARD_OUT Chain
# Filters out bad traffic, and selectively accepts forwarded connections,
# destined for the public internet.

install_forward_out() {
  iptables -N FORWARD_OUT
  iptables -A FORWARD -i $IFACE_LAN -o $IFACE_NET -j FORWARD_OUT

  # Outbound filter rules.
  iptables -A FORWARD_OUT -p tcp -j BAD_TCP_ANY_IN
  iptables -A FORWARD_OUT -j BAD_LAN_IN
  iptables -A FORWARD_OUT -j BAD_ANY_IN

  # Outbound new or established connections.
  iptables -A FORWARD_OUT -m state --state NEW,ESTABLISHED -j TGT_ACCEPT_OUT
  
  # Catch the occasional TCP request that slips by the previous rule.
  iptables -A FORWARD_OUT -p tcp --syn -j TGT_ACCEPT_OUT

  # TODO: Delete once forwarding rules are figured out.
  iptables -A FORWARD_OUT -j TGT_WATCH_OUT
}

#-------------------------------------------------------------------------------
# Install SNAT Rules
# Handle SNAT (static IP masquerade) for the local private network hosts.

install_snat() {
  iptables -t nat -A POSTROUTING -o $IFACE_NET -s $IPNETW_LAN -j SNAT --to-source ${IPADDR_NET%/*}
}

#-------------------------------------------------------------------------------
# Install DNAT Rules
# Handle DNAT (inbound port forwarding) to local private network hosts.

install_dnat() {
  # Inbound SMTP connections.
  iptables -t nat -A PREROUTING -i $IFACE_NET -p tcp -d $IPADDR_NET --dport $PORT_SMTP -j DNAT --to-destination $SMTP_LAN:$PORT_SMTP

  # Inbound HTTP connections.
  iptables -t nat -A PREROUTING -i $IFACE_NET -p tcp -d $IPADDR_NET --dport $PORT_HTTP -j DNAT --to-destination $HTTP_LAN:$PORT_HTTP

  # Inbound HTTPS connections.
  iptables -t nat -A PREROUTING -i $IFACE_NET -p tcp -d $IPADDR_NET --dport $PORT_HTTPS -j DNAT --to-destination $HTTPS_LAN:$PORT_HTTPS

  # Inbound SSH connections.
  iptables -t nat -A PREROUTING -i $IFACE_NET -p tcp -d $IPADDR_NET --dport $PORT_SSH -j DNAT --to-destination $SSH_LAN:$PORT_SSH
}

#-------------------------------------------------------------------------------
# Install TOS Mangle Rules
# Configure Type of Service rules for mangle table:
#   Minimize-Delay       16 (0x10)
#   Maximize-Throughput   8 (0x08)
#   Maximize-Reliability  4 (0x04)
#   Minimize-Cost         2 (0x02)
#   Normal-Service        0 (0x00)
# Use with caution: Type of Service isn't widely implemented in routers and may
# actually cause problems.

install_mangle() {
  iptables -t mangle -N MANGLE_TOS

  # Maximize throughput.
  iptables -t mangle -A MANGLE_TOS -p tcp --dport $PORT_FTP_DATA -j TOS --set-tos 8
  iptables -t mangle -A MANGLE_TOS -p tcp --dport $PORT_HTTP -j TOS --set-tos 8
  iptables -t mangle -A MANGLE_TOS -p tcp --dport $PORT_HTTPS -j TOS --set-tos 8

  # Minimize delay.
  iptables -t mangle -A MANGLE_TOS -p tcp --dport $PORT_FTP_CMD -j TOS --set-tos 16
  iptables -t mangle -A MANGLE_TOS -p tcp --dport $PORT_SSH -j TOS --set-tos 16
  iptables -t mangle -A MANGLE_TOS -p tcp --dport $PORT_SMTP -j TOS --set-tos 16
  iptables -t mangle -A MANGLE_TOS -p tcp --dport $PORT_DNS -j TOS --set-tos 16

  # Install MANGLE_TOS on OUTPUT chain.
  iptables -t mangle -A OUTPUT -o $IFACE_NET -j MANGLE_TOS
  
  # Log and drop segments with no flag bits set (NULL packets).
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -m limit --limit 5/minute -j LOG --log-level $LOG_LEVEL_SCAN --log-prefix "FW_SCAN_MANGLE: " --log-tcp-options --log-ip-options
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
	
  # Install MANGLE_TOS on PREROUTING chain.
  iptables -t mangle -A PREROUTING -i $IFACE_LAN -j MANGLE_TOS
}

#-------------------------------------------------------------------------------
# Initialize Firewall

init_fw() {
  config_kernel
  flush
  set_policy ${1:-DROP}
}

#-------------------------------------------------------------------------------
# Install Firewall Rules

install_fw() {
  # Install the target chains.
  install_targets

  # Install local loopback interface rules.
  install_lo_in_out

  # Special case: filter TCP packets seperately.
  install_bad_tcp_any_in
  
  # Filter out bad packets: least to most specific.
  install_bad_any_in
  install_bad_any_out
  install_bad_net_in
  install_bad_net_out
  install_bad_lan_in
  install_bad_lan_out
  
  # Apply ICMP protocol rules: most to least specific.
  install_icmp_any_in
  install_icmp_any_out
  
  # Apply TCP protocol rules: most to least specific.
  install_tcp_lan_in
  install_tcp_lan_out
  install_tcp_net_in
  install_tcp_net_out
  install_tcp_any_in
  install_tcp_any_out
  
  # Apply UDP protocol rules: most to least specific.
  install_udp_lan_in
  install_udp_lan_out
  install_udp_net_in
  install_udp_net_out

  # Log anything that falls off the end.
  iptables -A INPUT -j TGT_UNKNOWN_IN
  iptables -A OUTPUT -j TGT_UNKNOWN_OUT

  # Apply forwarding rules.
  install_forward_in
  install_forward_out

  # Apply NAT rules.
  install_snat
  install_dnat
  
  # Apply mangle TOS rules. Enable only if you understand TOS better than I do.
  #install_mangle
}

#-------------------------------------------------------------------------------
# Interpret Command-line Parameters

case "$1" in
opensesame)
  # DANGER! DANGER! DANGER!
  # Initialize the firewall and set the default policy to ACCEPT, allowing all
  # traffic through unimpeded.
  init_fw ACCEPT
  ;;
start | restart)
  # start==restart since there's no daemon process to stop or signal.
  init_fw
  install_fw
  ;;
stop)
  # Initialize the firewall and set the default policy to DROP, effectively
  # stopping all traffic.
  init_fw
  ;;
*)
  echo $"Usage: $0 {start|stop|restart}"
  exit 1
esac

#-------------------------------------------------------------------------------
# All Done

exit 0

################################################################################
# EOF
################################################################################
