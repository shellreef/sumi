#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
#
# ping.py
# 
# ping.py uses the ICMP protocol's mandatory ECHO_REQUEST
# datagram to elicit an ICMP ECHO_RESPONSE from a
# host or gateway.
#
# Copyright (C) 23. Feb. 2004 - Lars Strand <lars strand at gnist org>
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
# TODO:
# - do not create socket inside 'while' (but if not: ipv6 won't work)
# - add ping from network/multicast
#
# Must be running as root, or write a suid-wrapper. Since newer *nix
# variants, the kernel ignores the set[ug]id flags on #! scripts for
# security reasons
#
# RFC792, echo/reply message
#
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Identifier          |        Sequence Number        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Data ...
# +-+-+-+-+-
#

# FIX - flush socket!!

import sys, os, struct, array, time, select, binascii, math, getopt, string
from socket import *

# total size of data (payload)
ICMP_DATA_STR = 56  

# initial values of header variables
ICMP_TYPE = 8
ICMP_TYPE_IP6 = 128
ICMP_CODE = 0
ICMP_CHECKSUM = 0
ICMP_ID = 0
ICMP_SEQ_NR = 0

########################## contruct a ping packet
def contruct(id, size, ipv6):
    """Constructs a icmp packet of variable size"""

    # size must be big enough to contain time sent
    if size < int(struct.calcsize("d")):
        usage("packetsize to small, must be at least %d" % int(struct.calcsize("d")))
        sys.exit(1)
    
    # contruct header
    if ipv6:
        header = struct.pack('BbHHh', ICMP_TYPE_IP6, ICMP_CODE, ICMP_CHECKSUM, ICMP_ID, ICMP_SEQ_NR+id)
    else:
        header = struct.pack('bbHHh', ICMP_TYPE, ICMP_CODE, ICMP_CHECKSUM, ICMP_ID, ICMP_SEQ_NR+id)

    # if size big enough
    load = "-- IF YOU ARE READING THIS YOU ARE A NERD! --"
    
    # space for time
    size -= struct.calcsize("d")

    # contruct payload based on size, may be omitted :)
    rest = ""
    if size > len(load):
        rest = load
        size -= len(load)

    # pad the rest of payload
    rest += size * "X"

    # pack
    data = struct.pack("d", time.time()) + rest
    packet = header + data          # ping packet without checksum
    checksum = in_cksum(packet)     # make checksum

    # contruct header with correct checksum
    if ipv6:
        header = struct.pack('BbHHh', ICMP_TYPE_IP6, ICMP_CODE, checksum, ICMP_ID, ICMP_SEQ_NR+id)
    else:
        header = struct.pack('bbHHh', ICMP_TYPE, ICMP_CODE, checksum, ICMP_ID, ICMP_SEQ_NR+id)
    packet = header + data          # ping packet *with* checksum

    return packet
### end contruct

########################## same as in_cksum found in ping.c on FreeBSD
def in_cksum(packet):
    """Generates a checksum of a (ICMP) packet.
    Based on ping.c on FreeBSD"""

    if len(packet) & 1:             # any data?
        packet = packet + '\0'      # make null 
    words = array.array('h', packet)# make a signed short array of packet 
    sum = 0

    for word in words:
        sum = sum + (word & 0xffff) # bitwise AND
    hi = sum >> 16                  # bitwise right-shift
    lo = sum & 0xffff               # bitwise AND
    sum = hi + lo
    sum = sum + (sum >> 16)
    
    return (~sum) & 0xffff          # bitwise invert + AND
### end in_cksum

########################## pingNode
def pingNode(alive=0, timeout=1.0, ipv6=0, number=sys.maxint, node=None, flood=0, size=ICMP_DATA_STR):
    """Pings a node based on input"""

    # if no node, exit
    if not node:
        usage("")
        sys.exit(1)

    # if not a valid host, exit
    if ipv6:
        if has_ipv6:
            try:
                info, port = getaddrinfo(node, None)
                host = info[4][0]
                # do not print ipv6 twice if ipv6 address given as node
                if host == node: 
                    noPrintIPv6adr = 1
            except:
                usage("cannot resolve %s: Unknow host" % node)
                sys.exit(1)
        else:
            usage("No support for IPv6 on this plattform")
            sys.exit(1)
    else:    # IPv4
        try:
            host = gethostbyname(node)
        except:
            usage("cannot resolve %s: Unknow host" % node)
            sys.exit(1)

    # trying to ping a network?
    if not ipv6:
        if int(string.split(host, ".")[-1]) == 0:
            usage("no support for network ping")
            sys.exit(1)

    # do some sanity check
    if number == 0:
        usage("invalid count of packets to transmit: '" + str(a)+ "'")
        sys.exit(1)
    if alive:
        number = 1

    # Send the ping(s)
    start = 1; min = 999; max = 0.0; avg = 0.0
    lost = 0; tsum = 0.0; tsumsq = 0.0

    # tell the user what we do
    if not alive:
        if ipv6:
            # do not print the ipv6 twice if ip adress given as node
            # (it can be to long in term window)
            if noPrintIPv6adr == 1:
                # add 40 (header) + 8 (icmp header) + payload
                print "PING "+str(node)+" : "+str(40+8+size)+" data bytes (40+8+"+str(size)+")"
            else:
                # add 40 (header) + 8 (icmp header) + payload
                print "PING "+str(node)+" ("+str(host)+"): "+str(40+8+size)+" data bytes (40+8+"+str(size)+")"
        else:
            # add 20 (header) + 8 (icmp header) + payload
            print "PING "+str(node)+" ("+str(host)+"): "+str(20+8+size)+" data bytes (20+8+"+str(size)+")"
        
    # trap ctrl-d and ctrl-c
    try:
        # send the number of ping packets as given
        while start <= number:
            lost += 1                             # in case user hit ctrl-c
            packet = contruct(start, size, ipv6)  # make a ping packet

            # create the IPv6/IPv4 socket
            # 
            if ipv6:
                # can not create a raw socket if not root or setuid to root
                try:
                    pingSocket = socket(AF_INET6, SOCK_RAW, getprotobyname("ipv6-icmp"))
                except error, e:
                    print "socket error: %s" % e
                    print "You must be root (uses raw sockets)" % os.path.basename(sys.argv[0])
                    sys.exit(1)
                    
            # IPv4
            else:
                # can not create a raw socket if not root or setuid to root
                try:
                    pingSocket = socket(AF_INET, SOCK_RAW, getprotobyname("icmp"))
                except error, e:
                    print "socket error: %s" % e
                    print "You must be root (%s uses raw sockets)" % os.path.basename(sys.argv[0])
                    sys.exit(1)

            # send the ping
            try:
                pingSocket.sendto(packet,(node,1))
            except error, e:
                print "socket error: %s" % e
                sys.exit(1)

            # reset values
            pong = ""; iwtd = [] 

            # wait until there is data in the socket
            while 1:
                # input, output, exceptional conditions
                iwtd, owtd, ewtd = select.select([pingSocket], [], [], timeout)
                break    # no data and timout occurred 

            print "data on socket"

            # data on socket - this means we have an answer
            if iwtd:                   # ok, data on socket
                endtime = time.time()  # time packet received
                # read data (we only need the header)
                pong, t = pingSocket.recvfrom(1024)   
                lost -= 1              # in case user hit ctrl-c

            # NO data on socket - timeout waiting for answer
            if not pong:
                if alive:
                    print "no reply from " + str(node) + " (" + str(host) +")"
                else:
                    print "ping timeout: %s (icmp_seq=%d) " % (host, start)

                # do not wait if number of ping packet != 1
                if number != 1:
                    time.sleep(flood ^ 1)
                start += 1
                continue  # lost a packet - try again

            # examine packet
            # fetch TTL from IP header
            if ipv6:
                # since IPv6 header and any extension header are never passed
                # to a raw socket, we can *not* get hoplimit field..
                # I hoped that a socket option would help, but it's not
                # supported:
                #   pingSocket.setsockopt(IPPROTO_IPV6, IPV6_RECVHOPLIMIT, 1)
                # so we can't fetch hoplimit..

                # fetch hoplimit
                #rawPongHop = struct.unpack("c", pong[7])[0]
                
                # fetch pong header
                pongHeader = pong[0:8]
                pongType, pongCode, pongChksum, pongID, pongSeqnr = struct.unpack("bbHHh", pongHeader)
                # fetch starttime from pong
                starttime = struct.unpack("d", pong[8:16])[0]

            # IPv4
            else:
                # time to live
                rawPongHop = struct.unpack("s", pong[8])[0]

                # convert TTL from 8 bit to 16 bit integer
                pongHop = int(binascii.hexlify(str(rawPongHop)), 16)
                
                # fetch pong header
                pongHeader = pong[20:28]
                pongType, pongCode, pongChksum, pongID, pongSeqnr = struct.unpack("bbHHh", pongHeader)
                
                # fetch starttime from pong
                starttime = struct.unpack("d", pong[28:36])[0]

            triptime  = endtime - starttime # compute RRT
            tsum     += triptime            # triptime for all packets (stddev)
            tsumsq   += triptime * triptime # triptime² for all packets (stddev)

            # compute statistic
            if max < triptime: max = triptime
            if min > triptime: min = triptime
        
            # valid ping packet received?
            if pongSeqnr == start:
                if alive:
                    print str(node) + " (" + str(host) +") is alive"
                else:
                    if ipv6:
                        # size + 8 = payload + header
                        print "%d bytes from %s: icmp_seq=%d time=%.5f ms" % (size+8, host, pongSeqnr, triptime*1000)
                    else:
                        print "%d bytes from %s: icmp_seq=%d ttl=%s time=%.5f ms" % (size+8, host, pongSeqnr, pongHop, triptime*1000)

            # do not wait one second if just send one packet
            if number != 1:
                # if flood = 1; do not sleep - just ping                
                time.sleep(flood ^ 1) # wait before send new packet

            # the last thing to do is update the counter - else the value
            # (can) get wrong when computing summary at the end (if user
            # hit ctrl-c when pinging)
            start += 1
            # end ping send/recv while

    # if user ctrl-d or ctrl-c
    except (EOFError, KeyboardInterrupt):
        # if user disrupts ping, it is most likly done before
        # the counter get updates - if do not update it here, the
        # summary get all wrong.
        start += 1
        pass

    # compute and print som stats
    # stddev computation based on ping.c from FreeBSD
    if start != 0 or lost > 0:  # do not print stats if 0 packet sent
        start -= 1              # since while is '<='
        avg = tsum / start      # avg round trip
        vari = tsumsq / start - avg * avg 
        # %-packet lost
        if start == lost:
            plost = 100
        else:
            plost = (lost/start)*100

        if not alive:
            print "\n--- %s ping statistics ---" % node
            print "%d packets transmitted, %d packets received, %d%% packet loss" % (start, start-lost, plost)
            # don't display summary if 100% packet-loss
            if plost != 100:
                print "round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms" % (min*1000, (tsum/start)*1000, max*1000, math.sqrt(vari)*1000)
    else:
        print "exit"
        sys.exit(1)

    pingSocket.close()

########################## usage
def usage(error):
    """Print usage of program"""
    if error:
        print "%s: %s" % (os.path.basename(sys.argv[0]), str(error))
        print "Try `%s --help' for more information." % os.path.basename(sys.argv[0])
    else:
        print """usage: %s [OPTIONS] HOST
Send ICMP ECHO_REQUEST packets to network hosts.

Mandatory arguments to long options are mandatory for short options too.
  -c, --count=N    Stop after sending (and receiving) 'N' ECHO_RESPONSE
                   packets.
  -s, --size=S     Specify the number of data bytes to be sent. The default
                   is 56, which translates into 64 ICMP data bytes when
                   combined with the 8 bytes of ICMP header data.
  -f, --flood      Flood ping. Outputs packets as fast as they come back. Use
                   with caution!
  -6, --ipv6       Ping using IPv6.
  -t, --timeout=s  Specify a timeout, in seconds, before a ping packet is
                   considered 'lost'.
  -h, --help       Display this help and exit

Report bugs to lars [at] gnist org""" % os.path.basename(sys.argv[0])
    
########################## main
if __name__ == '__main__':
    """Main loop"""

    # version control
    version = string.split(string.split(sys.version)[0], ".")
    if map(int, version) < [2, 3]:
        usage("You need Python ver 2.3 or higher to run!")
        sys.exit(1)

    try:
        # opts = arguments recognized,
        # args = arguments NOT recognized (leftovers)
        opts, args = getopt.getopt(sys.argv[1:-1], "hat:6c:fs:", ["help", "alive", "timeout=", "ipv6", "count=", "flood", "packetsize="])
    except getopt.GetoptError:
        # print help information and exit:
        usage("illegal option(s) -- " + str(sys.argv[1:]))
        sys.exit(2)

    # test whether any host given
    if len(sys.argv) >= 2:
        node = sys.argv[-1:][0]   # host to be pinged
        if node[0] == "-":        # is last option start with '-', it's no host
            usage("")
            sys.exit(1)
    else:
        usage("")
        sys.exit(1)        

    if args:
        usage("illegal option -- " + str(args))
        sys.exit(2)
        
    # default variables
    alive = 0; timeout = 1.0; ipv6 = 0; count = sys.maxint;
    flood = 0; size = ICMP_DATA_STR

    # run through arguments and set variables
    for o, a in opts:
        if o == "-h" or o == "--help":    # display help and exit
            usage()
            sys.exit(0)
        if o == "-t" or o == "--timeout": # timeout before "lost"
            try:
                timeout = float(a)
            except:
                usage("invalid timout: '" + str(a) + "'")
        if o == "-6" or o == "--ipv6":    # ping ipv6
            ipv6 = 1
        if o == "-c" or o == "--count":   # how many pings?
            try:
                count = int(a)
            except:
                usage("invalid count of packets to transmit: '" + str(a) + "'")
                sys.exit(1)
        if o == "-f" or o == "--flood":   # no delay between ping send
            flood = 1
        if o == "-s" or o == "--packetsize":    # set the ping payload size
            try:
                size = int(a)
            except:
                usage("invalid packet size: '" + str(a) + "'")
                sys.exit(1)
        # just send one packet and say "it's alive"
        if o == "-a" or o == "--alive":   
            alive = 1

    # here we send
    pingNode(alive=alive, timeout=timeout, ipv6=ipv6, number=count, node=node, flood=flood, size=size)
    #pingNode(alive, timeout, ipv6, count, node, flood, size)
    # if we made it this far, do a clean exit
    sys.exit(0)

### end
