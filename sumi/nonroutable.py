#!/usr/bin/env python
# Created:20040201
# By Jeff Connelly

# $Id$

# non-routable (formerly bogus) networks dictionary

import socket
import struct

# source:  http://www.obfuscation.org/ipf/ipf-howto.html#TOC_40

nonroutable_net = [
"0.0.0.0/7", "2.0.0.0/8", "5.0.0.0/8", "10.0.0.0/8", "23.0.0.0/8", 
"27.0.0.0/8", "31.0.0.0/8", "70.0.0.0/7", "72.0.0.0/5", "83.0.0.0/8",
"84.0.0.0/6", "88.0.0.0/5", "96.0.0.0/3", "127.0.0.0/8", "128.0.0.0/16",
"128.66.0.0/16", "169.254.0.0/16", "172.16.0.0/12", "191.255.0.0/16",
"192.0.0.0/19", "192.0.48.0/20", "192.0.64.0/18", "192.0.128.0/17",
"192.168.0.0/16", "197.0.0.0/8", "201.0.0.0/8", "204.152.64.0/23",
"219.0.0.0/8", "220.0.0.0/6", "224.0.0.0/3" ]

def __init__():
    global nr_ranges
    nr_ranges = []
    # build a quick list of ranges to check.. 
    for net_cidr in nonroutable_net:
        (net, cidr) = net_cidr.split("/")
        cidr = int(cidr)
        (net_start, ) = struct.unpack(">L", socket.inet_aton(net))
        net_end = net_start |  \
            struct.unpack("<L", struct.pack(">L", \
            (0xffffffffL >> (32 - cidr) << (32 - cidr))))[0]
        nr_ranges.append([net_start, net_end, net_cidr])
        #print socket.inet_ntoa(struct.pack(">L", net_start)),cidr,"~",\
        #      socket.inet_ntoa(struct.pack(">L", net_end))

# Returns True if str_ip is a nonroutable src address (bogus src address)
# Note that it may still be a valid private address however
def is_nonroutable_ip(str_ip):
    (ip,) = struct.unpack(">L", socket.inet_aton(str_ip))
    for range in nr_ranges:
        (start, end, pattern) = range
        if ip >= start and ip <= end:
            #print str_ip,"failed",pattern
            return True
    return False

__init__()
#print is_nonroutable_ip("192.168.0.1")
 
