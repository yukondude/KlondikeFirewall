#!/bin/bash
################################################################################
# klondike-standalone
# A shell script to configure stateful packet-filter rules for a netfilter/
# iptables standalone firewall.
#-------------------------------------------------------------------------------
# chkconfig: 2345 11 89
# description: Configuration rules for stateful packet-filter iptables firewall.
#-------------------------------------------------------------------------------
# This script must run after the main iptables rc script (usually,
# /etc/rc.d/init.d/iptables) and should also run after the main networking rc
# script (usually /etc/rc.d/init.d/network). For safety's sake, the main
# iptables script should run before networking starts, and should set the
# default policy for all built-in chains to DROP.
#
# Replace all items marked "TODO" with your own network values. The existing
# rules assume a private class-C LAN, so you'll have to adjust as necessary.
# Of course, you'll also have to set up your own rules.
#
# The default setup (once proper IP addresses are in place) configures a
# standalone server firewall that permits local SSH, POP, CUPS, and Samba
# requests, and global HTTP, HTTPS, and SMTP requests. The server is also
# permitted to initiate HTTP, RSYNC, SMTP, NTP, and DNS requests to the outside.
#-------------------------------------------------------------------------------
# By Dave Rogers [thedude strudel yukondude full-stop com]
# yukon dude software [www.yukondude.com]
# Whitehorse, Yukon, Canada
#-------------------------------------------------------------------------------
# Copyright © 2002-2007 Dave Rogers
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
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
#-------------------------------------------------------------------------------
# $Id$
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
IFACE_NETW="eth0" # Network interface
IFACE_LOOP="lo" # Loopback

#-------------------------------------------------------------------------------
# Host and Network IP Addresses

# TODO: Change addresses.
IPADDR="192.168.1.1/32" # Server IP
IPNETW="192.168.1.0/24" # Network
IPBCAST="192.168.1.255" # Broadcast

IPLOOP="127.0.0.0/8" # Loopback

#-------------------------------------------------------------------------------
# Known Remote Host IP Addresses

# TODO: Change DNS server addresses.
DNS_IPADDR_1="199.247.235.6"
DNS_IPADDR_2="199.247.235.7"

# TODO: Add any other fixed IPs of interest.

#-------------------------------------------------------------------------------
# Private and Reserved Network IP Addresses

# TODO: Change if you don't use a private class-C LAN.
PRIVATE="10.0.0.0/8 172.16.0.0/12 224.0.0.0/4" # Impossible IPs.
PRIVATE_LAN="192.168.0.0/16" # Possible local network IPs.

# Addresses reserved by IANA (subject to change, so I just picked the outliers).
#   [http://www.iana.org/assignments/ipv4-address-space]
RESERVED="0.0.0.0/8 1.0.0.0/8 2.0.0.0/8 240.0.0.0/4"

################################################################################
# GLOBAL VARIABLES THAT SHOULDN'T NEED TO CHANGE
################################################################################

#-------------------------------------------------------------------------------
# Kernel Parameters

CONN_TRACK_MAX="4096"
LOCAL_PORT_MIN="32768"
LOCAL_PORT_MAX="61000"

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
# Common TCP and UDP Ports and Port Ranges

PORT_FTP_DATA="20"
PORT_FTP_CMD="21"
PORT_FTP="21"
PORT_SSH="22"
PORT_TELNET="23"
PORT_SMTP="25"
PORT_DNS="53"
PORT_HTTP="80"
PORT_POP="110"
PORT_AUTH="113"
PORT_NTP="123"
PORT_MSNBNS="137"
PORT_MSNBDG="138"
PORT_MSNBSSN="139"
PORT_HTTPS="443"
PORT_MSDS="445"
PORT_CUPS="631"
PORT_RSYNC="873"
PORT_SVNSERVE="3690"
PORT_WEBCACHE="8080"
PORTS_TRACEROUTE="32769:65535"

#-------------------------------------------------------------------------------
# Privileged and Unprivileged Port Ranges

PORTS_PRIV="0:1023"
PORTS_UNPRIV="1024:65535"

#-------------------------------------------------------------------------------
# Log Levels for Target Chains

LOG_LEVEL_PROBE="3"   # err
LOG_LEVEL_ILLEGAL="4" # warning
LOG_LEVEL_UNKNOWN="4" # warning
LOG_LEVEL_FLOOD="5"   # notice
LOG_LEVEL_SCAN="5"    # notice
LOG_LEVEL_WATCH="6"   # info

#-------------------------------------------------------------------------------
# Types of Service

TOS_MIN_DELAY="16"
TOS_MAX_THRU="8"
TOS_MAX_RELIABLE="4"
TOS_MIN_COST="2"
TOS_NORMAL="0"

################################################################################
# SCRIPT FUNCTIONS
################################################################################

#-------------------------------------------------------------------------------
# Configure Kernel Networking Parameters
# See www.tldp.org/HOWTO/Adv-Routing-HOWTO-13.html for further explanation.

config_kernel() {
  # Load necessary kernel modules. Most are loaded automatically, but
  # ip_conntrack_ftp must be loaded explicitly to enable FTP connection
  # tracking.
  modprobe ip_conntrack_ftp

  # Set the maximum number of connections to track.
  if [ -e /proc/sys/net/ipv4/ip_conntrack_max ]; then
    if [ $(cat /proc/sys/net/ipv4/ip_conntrack_max) -le "${CONN_TRACK_MAX}" ]; then
      echo "${CONN_TRACK_MAX}" > /proc/sys/net/ipv4/ip_conntrack_max
    fi
  fi

  # Set local port range for TCP/UDP connections.
  if [ -e /proc/sys/net/ipv4/ip_local_port_range ]; then
    echo -e "${LOCAL_PORT_MIN}\t${LOCAL_PORT_MAX}" > /proc/sys/net/ipv4/ip_local_port_range
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

  # Disable ICMP redirects.
  if [ -e /proc/sys/net/ipv4/conf/$IFACE_NETW/accept_redirects ]; then
    echo "0" > /proc/sys/net/ipv4/conf/$IFACE_NETW/accept_redirects
  fi

  # Ignore ICMP responses to hosts misinterpreting broadcast traffic.
  if [ -e /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses ]; then
    echo "1" > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
  fi

  # Disable IP forwarding.
  if [ -e /proc/sys/net/ipv4/ip_forward ]; then
    echo "0" > /proc/sys/net/ipv4/ip_forward
  fi
}

#-------------------------------------------------------------------------------
# Remove All Chains and Rules

flush() {
  # Flush the rules from the built-in chains.
  iptables -F -t filter
  iptables -F -t nat
  iptables -F -t mangle

  # Drop any custom chains.
  iptables -X -t filter
  iptables -X -t nat
  iptables -X -t mangle
  
  # Zero the counters.
  iptables -Z -t filter
  iptables -Z -t nat
  iptables -Z -t mangle
}

#-------------------------------------------------------------------------------
# Set Policy for Built-in Chains
# Use DROP as the default policy unless specified otherwise.

set_policy() {
  iptables -t filter -P INPUT ${1:-DROP}
  iptables -t filter -P FORWARD ${1:-DROP}
  iptables -t filter -P OUTPUT ${1:-DROP}
}

#-------------------------------------------------------------------------------
# Install Target Chains
# All rules must jump to one of these target chains.

install_targets() {
  # Accept packets. This chain exists primarily for accounting purposes.
  iptables -N TGT_ACCEPT
  iptables -A TGT_ACCEPT -j ACCEPT

  # Drop packets. This chain exists primarily for accounting purposes.
  iptables -N TGT_DROP
  iptables -A TGT_DROP -j DROP

  # Reject (and reset TCP) packets. This is a "friendly" way to respond to
  # certain unwanted protocol probes such as AUTH (IDENTD).
  iptables -N TGT_REJECT
  iptables -A TGT_REJECT -p tcp -j REJECT --reject-with tcp-reset
  iptables -A TGT_REJECT -j REJECT

  # Discard annoying but otherwise innocuous packets.
  iptables -N TGT_DISCARD
  iptables -A TGT_DISCARD -j TGT_DROP

  # Log and drop any suspected flood attacks (more than 15 packets per second
  # with a maximum burst of 30 per second). Don't log more than 5 packets per
  # minute so that the log doesn't fill up.
  iptables -N TGT_FLOOD
  iptables -A TGT_FLOOD -m limit --limit 15/s --limit-burst 30 -j RETURN
  iptables -A TGT_FLOOD -m limit --limit 5/m -j LOG --log-level $LOG_LEVEL_FLOOD --log-prefix "FW_FLOOD: "
  iptables -A TGT_FLOOD -j TGT_DROP

  # Log and drop malformed or impossible packets.
  iptables -N TGT_ILLEGAL
  iptables -A TGT_ILLEGAL -j LOG --log-level $LOG_LEVEL_ILLEGAL --log-prefix "FW_ILLEGAL: "
  iptables -A TGT_ILLEGAL -j TGT_DROP

  # Log and drop malicious packets that are associated with known security
  # exploits.
  iptables -N TGT_PROBE
  iptables -A TGT_PROBE -j LOG --log-level $LOG_LEVEL_PROBE --log-prefix "FW_PROBE: "
  iptables -A TGT_PROBE -j TGT_DROP

  # Log and drop packets that look like scans. Don't log more than 5 packets per
  # minute so that the log doesn't fill up.
  iptables -N TGT_SCAN
  iptables -A TGT_SCAN -m limit --limit 5/m -j LOG --log-level $LOG_LEVEL_SCAN --log-prefix "FW_SCAN: "
  iptables -A TGT_SCAN -j TGT_DROP
  
  # Log and drop unknown packets. Don't log more than 5 packets per minute so
  # that the log doesn't fill up.
  iptables -N TGT_UNKNOWN
  iptables -A TGT_UNKNOWN -m limit --limit 5/m -j LOG --log-level $LOG_LEVEL_UNKNOWN --log-prefix "FW_UNKNOWN: "
  iptables -A TGT_UNKNOWN -j TGT_DROP

  # Log and accept packets that we want to keep an eye on.
  iptables -N TGT_WATCH
  iptables -A TGT_WATCH -j LOG --log-level $LOG_LEVEL_WATCH --log-prefix "FW_WATCH: "
  iptables -A TGT_WATCH -j TGT_ACCEPT
}

#-------------------------------------------------------------------------------
# Install BAD_TCP_IN Chain
# Filters out bad TCP segments originating from any connected network.

install_bad_tcp_in() {
  iptables -N BAD_TCP_IN
  iptables -A INPUT -p tcp -j BAD_TCP_IN
  
  # Be polite and deny inbound AUTH connections (usually from broken email
  # servers).
  iptables -A BAD_TCP_IN -p tcp --dport $PORT_AUTH -j TGT_REJECT

  # Segments with illegal TCP flags.
  iptables -A BAD_TCP_IN -p tcp --tcp-option 64 -j TGT_ILLEGAL
  iptables -A BAD_TCP_IN -p tcp --tcp-option 128 -j TGT_ILLEGAL

  # Segments pretending to be part of an established connection.
  iptables -A BAD_TCP_IN -p tcp ! --syn -m state --state NEW -j TGT_ILLEGAL
  
  # Segments with every flag bit set (XMAS tree packets).
  iptables -A BAD_TCP_IN -p tcp --tcp-flags ALL ALL -j TGT_ILLEGAL
  
  # Segments with no flag bits set (NULL packets).
  iptables -A BAD_TCP_IN -p tcp --tcp-flags ALL NONE -j TGT_ILLEGAL

  # SYN flood DoS attacks.
  iptables -A BAD_TCP_IN -p tcp --syn -j TGT_FLOOD
  
  # Stealth scan. Treat like flood because a few at a time are valid.
  iptables -A BAD_TCP_IN -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j TGT_FLOOD
  
  # XMAS scan, used by NMAP.
  iptables -A BAD_TCP_IN -p tcp --tcp-flags ALL FIN,URG,PSH -j TGT_SCAN
  
  # SYN/RST scan.
  iptables -A BAD_TCP_IN -p tcp --tcp-flags SYN,RST SYN,RST -j TGT_SCAN
  
  # SYN/FIN scan.
  iptables -A BAD_TCP_IN -p tcp --tcp-flags SYN,FIN SYN,FIN -j TGT_SCAN

  # MyDoom backdoor scan.
  iptables -A BAD_TCP_IN -p tcp --dport 3127 -j TGT_SCAN
}

#-------------------------------------------------------------------------------
# Install BAD_ANY_IN Chain
# Filters out bad traffic originating from any connected network.

install_bad_any_in() {
  iptables -N BAD_ANY_IN
  iptables -A INPUT -j BAD_ANY_IN
  
  # Ignore any Internet Group Management Protocol (IGMP) messages.
  iptables -A BAD_ANY_IN -p $IPPROT_IGMP -j TGT_DISCARD
  
  # Invalid packet.
  iptables -A BAD_ANY_IN -m state --state INVALID -j TGT_ILLEGAL
  
  # Packet fragments.
  iptables -A BAD_ANY_IN -f -j TGT_ILLEGAL
  
  # Ping scan. Treat like flood because a few at a time are valid.
  iptables -A BAD_ANY_IN -p icmp --icmp-type $ICMP_PING -j TGT_FLOOD

  # Packets pretending to be headed for the loopback interface.
  iptables -A BAD_ANY_IN -d $IPLOOP -j TGT_ILLEGAL
  
  # Packets pretending to be from a private network address.
  for NETW in $PRIVATE; do
    iptables -A BAD_ANY_IN -s $NETW -j TGT_ILLEGAL
  done
  
  # Packets pretending to be from a reserved address.
  for NETW in $RESERVED; do
    iptables -A BAD_ANY_IN -s $NETW -j TGT_ILLEGAL
  done
  
  # Packets with a source port of zero. Started showing up in May, 2003.
  iptables -A BAD_ANY_IN -p tcp --sport 0 -j TGT_ILLEGAL
  iptables -A BAD_ANY_IN -p udp --sport 0 -j TGT_ILLEGAL
  
  # Throw away MS SQL Server Slammer worm crap.
  iptables -A BAD_ANY_IN -p tcp --dport 1433 -j TGT_DISCARD
  iptables -A BAD_ANY_IN -p udp --dport 1434 -j TGT_DISCARD
}

#-------------------------------------------------------------------------------
# Install BAD_ANY_OUT Chain
# Filters out bad traffic destined for any connected network.

install_bad_any_out() {
  iptables -N BAD_ANY_OUT
  iptables -A OUTPUT -j BAD_ANY_OUT

  # Packets pretending to be part of an established connection.
  iptables -A BAD_ANY_OUT -p tcp ! --syn -m state --state NEW -j TGT_ILLEGAL

  # Prevent information leak described by Red Hat Advisory RHSA-2002:086-05.
  iptables -A BAD_ANY_OUT -p icmp -m state --state INVALID -j TGT_ILLEGAL

  # Packets heading for a private network address.
  for NETW in $PRIVATE; do
    iptables -A BAD_ANY_OUT -d $NETW -j TGT_ILLEGAL
  done

  # Packets heading for a reserved address.
  for NETW in $RESERVED; do
    iptables -A BAD_ANY_OUT -d $NETW -j TGT_ILLEGAL
  done
  
  # Packets with a source port of zero.
  iptables -A BAD_ANY_OUT -p tcp --sport 0 -j TGT_ILLEGAL
  iptables -A BAD_ANY_OUT -p udp --sport 0 -j TGT_ILLEGAL
}

#-------------------------------------------------------------------------------
# Install ICMP_IN Chain
# Selectively accepts ICMP messages originating from any connected network.

install_icmp_in() {
  iptables -N ICMP_IN
  iptables -A INPUT -p icmp -j ICMP_IN

  # Inbound ping (echo request) messages.
  iptables -A ICMP_IN -p icmp --icmp-type $ICMP_PING -m state --state NEW -j TGT_ACCEPT

  # Inbound pong (echo reply) messages from previous outbound ping queries.
  iptables -A ICMP_IN -p icmp --icmp-type $ICMP_PONG -m state --state ESTABLISHED -j TGT_ACCEPT

  # Inbound time exceeded messages from previous outbound queries
  # (e.g. traceroute).
  iptables -A ICMP_IN -p icmp --icmp-type $ICMP_TIME_EXCEEDED -m state --state RELATED -j TGT_ACCEPT

  # Inbound unreachable messages from previous outbound queries.
  iptables -A ICMP_IN -p icmp --icmp-type $ICMP_UNREACHABLE -m state --state RELATED -j TGT_ACCEPT
}

#-------------------------------------------------------------------------------
# Install ICMP_OUT Chain
# Selectively accepts ICMP messages destined for any connected network.

install_icmp_out() {
  iptables -N ICMP_OUT
  iptables -A OUTPUT -p icmp -j ICMP_OUT

  # Outbound ping (echo request) messages.
  iptables -A ICMP_OUT -p icmp --icmp-type $ICMP_PING -m state --state NEW -j TGT_ACCEPT

  # Outbound pong (echo reply) messages from previous inbound ping queries.
  iptables -A ICMP_OUT -p icmp --icmp-type $ICMP_PONG -m state --state ESTABLISHED -j TGT_ACCEPT

  # Outbound time exceeded messages from previous inbound queries
  # (e.g. traceroute).
  iptables -A ICMP_OUT -p icmp --icmp-type $ICMP_TIME_EXCEEDED -m state --state RELATED -j TGT_ACCEPT

  # Outbound unreachable messages from previous inbound queries.
  iptables -A ICMP_OUT -p icmp --icmp-type $ICMP_UNREACHABLE -m state --state RELATED -j TGT_ACCEPT
}

#-------------------------------------------------------------------------------
# Install TCP_IN Chain
# Selectively accepts TCP segments originating from any connected network.

install_tcp_in() {
  iptables -N TCP_IN
  iptables -A INPUT -i $IFACE_NETW -p tcp -j TCP_IN

  # Inbound SSH connections from local network.
  iptables -A TCP_IN -p tcp -s $IPNETW --dport $PORT_SSH -m state --state NEW,ESTABLISHED -j TGT_ACCEPT

  # Inbound and outbound web connections.
  iptables -A TCP_IN -p tcp --dport $PORT_HTTP -m state --state NEW,ESTABLISHED -j TGT_ACCEPT
  iptables -A TCP_IN -p tcp --sport $PORT_HTTP -m state --state ESTABLISHED -j TGT_ACCEPT
  
  # Inbound secure web connections.
  iptables -A TCP_IN -p tcp --dport $PORT_HTTPS -m state --state NEW,ESTABLISHED -j TGT_ACCEPT

  # Inbound and outbound email connections.
  iptables -A TCP_IN -p tcp --dport $PORT_SMTP -m state --state NEW,ESTABLISHED -j TGT_ACCEPT
  iptables -A TCP_IN -p tcp --sport $PORT_SMTP -m state --state ESTABLISHED -j TGT_ACCEPT
  
  # Inbound POP3 connections from local network.
  iptables -A TCP_IN -p tcp -s $IPNETW --dport $PORT_POP -m state --state NEW,ESTABLISHED -j TGT_ACCEPT

  # Inbound printing connections from local network.
  iptables -A TCP_IN -p tcp -s $IPNETW --dport $PORT_CUPS -m state --state NEW,ESTABLISHED -j TGT_ACCEPT
  
  # Outbound RSYNC connections.
  iptables -A TCP_IN -p tcp --sport $PORT_RSYNC -m state --state ESTABLISHED -j TGT_ACCEPT

  # Inbound SAMBA connections from local network.
  iptables -A TCP_IN -p tcp -s $IPNETW --dport $PORT_MSNBSSN -m state --state NEW,ESTABLISHED -j TGT_ACCEPT
  iptables -A TCP_IN -p tcp -s $IPNETW --dport $PORT_MSDS -m state --state NEW,ESTABLISHED -j TGT_ACCEPT
}

#-------------------------------------------------------------------------------
# Install TCP_OUT Chain
# Selectively accepts TCP segments destined for any connected network.

install_tcp_out() {
  iptables -N TCP_OUT
  iptables -A OUTPUT -o $IFACE_NETW -p tcp -j TCP_OUT

  # Inbound SSH connections from local network.
  iptables -A TCP_OUT -p tcp -d $IPNETW --sport $PORT_SSH -m state --state ESTABLISHED -j TGT_ACCEPT

  # Inbound and outbound web connections.
  iptables -A TCP_OUT -p tcp --sport $PORT_HTTP -m state --state ESTABLISHED -j TGT_ACCEPT
  iptables -A TCP_OUT -p tcp --dport $PORT_HTTP -m state --state NEW,ESTABLISHED -j TGT_ACCEPT
  
  # Inbound secure web connections.
  iptables -A TCP_OUT -p tcp --sport $PORT_HTTPS -m state --state ESTABLISHED -j TGT_ACCEPT

  # Inbound and outbound email connections.
  iptables -A TCP_OUT -p tcp --sport $PORT_SMTP -m state --state ESTABLISHED -j TGT_ACCEPT
  iptables -A TCP_OUT -p tcp --dport $PORT_SMTP -m state --state NEW,ESTABLISHED -j TGT_ACCEPT
  
  # Inbound POP3 connections from LAN.
  iptables -A TCP_OUT -p tcp -d $IPNETW --sport $PORT_POP -m state --state ESTABLISHED -j TGT_ACCEPT

  # Reject outbound AUTH/IDENTD connections.
  iptables -A TCP_OUT -p tcp --dport $PORT_AUTH -j TGT_REJECT
  
  # Inbound printing connections from local network.
  iptables -A TCP_OUT -p tcp -d $IPNETW --sport $PORT_CUPS -m state --state ESTABLISHED -j TGT_ACCEPT

  # Outbound RSYNC connections.
  iptables -A TCP_OUT -p tcp --dport $PORT_RSYNC -m state --state NEW,ESTABLISHED -j TGT_ACCEPT

  # Inbound SAMBA connections from local network.
  iptables -A TCP_OUT -p tcp -d $IPNETW --sport $PORT_MSNBSSN -m state --state ESTABLISHED -j TGT_ACCEPT
  iptables -A TCP_OUT -p tcp -d $IPNETW --sport $PORT_MSDS -m state --state ESTABLISHED -j TGT_ACCEPT
}

#-------------------------------------------------------------------------------
# Install UDP_IN Chain
# Selectively accepts UDP segments originating from any connected network.

install_udp_in() {
  iptables -N UDP_IN
  iptables -A INPUT -i $IFACE_NETW -p udp -j UDP_IN

  # Inbound DNS queries from LAN.
  iptables -A UDP_IN -s $IPNETW -p udp --dport $PORT_DNS -m state --state NEW,ESTABLISHED -j TGT_ACCEPT

  # Outbound DNS queries to primary server.
  iptables -A UDP_IN -s $DNS_IPADDR_1 -p udp --sport $PORT_DNS -m state --state ESTABLISHED -j TGT_ACCEPT

  # Outbound DNS queries to secondary server.
  iptables -A UDP_IN -s $DNS_IPADDR_2 -p udp --sport $PORT_DNS -m state --state ESTABLISHED -j TGT_ACCEPT

  # Outbound NTP queries.
  iptables -A UDP_IN -p udp --sport $PORT_NTP -m state --state ESTABLISHED -j TGT_ACCEPT

  # NetBEUI broadcast traffic for Samba (source port == destination port).
  iptables -A UDP_IN -p udp -m multiport --ports $PORT_MSNBNS,$PORT_MSNBDG -j TGT_ACCEPT
}

#-------------------------------------------------------------------------------
# Install UDP_OUT Chain
# Selectively accepts UDP datagrams destined for any connected network.

install_udp_out() {
  iptables -N UDP_OUT
  iptables -A OUTPUT -o $IFACE_NETW -p udp -j UDP_OUT

  # Inbound DNS queries from LAN.
  iptables -A UDP_OUT -d $IPNETW -p udp --sport $PORT_DNS -m state --state ESTABLISHED -j TGT_ACCEPT

  # Outbound DNS queries to primary server.
  iptables -A UDP_OUT -d $DNS_IPADDR_1 -p udp --dport $PORT_DNS -m state --state NEW,ESTABLISHED -j TGT_ACCEPT

  # Outbound DNS queries to secondary server.
  iptables -A UDP_OUT -d $DNS_IPADDR_2 -p udp --dport $PORT_DNS -m state --state NEW,ESTABLISHED -j TGT_ACCEPT

  # Outbound NTP queries.
  iptables -A UDP_OUT -p udp --dport $PORT_NTP -m state --state NEW,ESTABLISHED -j TGT_ACCEPT

  # Outbound traceroute queries.
  iptables -A UDP_OUT -p udp --dport $PORTS_TRACEROUTE -m state --state NEW -j TGT_ACCEPT

  # NetBEUI broadcast traffic for Samba (source port == destination port).
  iptables -A UDP_OUT -p udp -m multiport --ports $PORT_MSNBNS,$PORT_MSNBDG -j TGT_ACCEPT
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

  # Allow all local loopback traffic.
  iptables -A INPUT -i $IFACE_LOOP -j TGT_ACCEPT
  iptables -A OUTPUT -o $IFACE_LOOP -j TGT_ACCEPT
 
  # Special case: filter TCP packets seperately.
  install_bad_tcp_in
  
  # Filter out bad packets: least to most specific.
  install_bad_any_in
  install_bad_any_out
  
  # Apply ICMP protocol rules.
  install_icmp_in
  install_icmp_out
  
  # Apply TCP protocol rules.
  install_tcp_in
  install_tcp_out
  
  # Apply UDP protocol rules.
  install_udp_in
  install_udp_out

  # Log anything that falls off the end.
  iptables -A INPUT -j TGT_UNKNOWN
  iptables -A OUTPUT -j TGT_UNKNOWN
}

################################################################################
# SCRIPT STATEMENTS
################################################################################

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
panic | stop)
  # Initialize the firewall and set the default policy to DROP, effectively
  # stopping all traffic.
  init_fw
  ;;
*)
  echo $"Usage: $0 {start|stop|restart|panic}"
  exit 1
esac

#-------------------------------------------------------------------------------
# All Done

exit 0

################################################################################
# EOF
################################################################################
