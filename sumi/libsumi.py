#!/usr/bin/env python
# Created:20040117
# By Jeff Connelly

# $Id$

# Python library for common SUMI functions, shared between client and server
# Copyright (C) 2003-2005  Jeff Connelly <jeffconnelly@users.sourceforge.net>

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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, 
# USA, or online at http://www.gnu.org/copyleft/gpl.txt .

import sys
import struct 
import base64
import sha
import zlib
import types
import os
import socket
from itertools import izip, chain

SUMI_VER = "0.8.14"

SUMIHDRSZ = 11#bytes
UDPHDRSZ = 8#bytes
IPHDRSZ = 20#bytes
SUMIAUTHHDRSZ = 4#bytes

# Time to sleep between interlock protocol exchanges
INTERLOCK_DELAY = 1#second

# Size of chunk when reading files from _disk_ into memory (not used online)
READ_CHUNK_SIZE = 1024 * 1024#bytes
def log(msg):
    print "(libsumi) %s" % msg

def unpack_args(raw):
    """Parse arguments in the form of aFOO\tbBAR\tcQUUX\to23948\tfhello
    world. Each parameter begins with a single letter, followed by its value,
    separated by tabs."""

    args = {}
    for x in raw.split("\t"):
        args[x[:1]] = x[1:]
    return args

def pack_args(args):
   """Given a dictionary of arguments and their values, pack them for 
   transmission."""
   array = []
   for k in args:
       array.append(k + str(args[k]))
   raw = "\t".join(array)
   return raw

rand_obj = cipher_mod = None

def random_init():
    """Initialize RNG and crypto."""
    global rand_obj, cipher_mod
    try:
        import Crypto.Util.randpool
        from Crypto.Cipher import AES
    except Exception, x:
        log("Error importing PyCrypto: %s" % str(x))
        log("Disable crypt or install PyCrypto")
        raise SystemExit
    if rand_obj: return
    log("Initializing RNG...")
    # TODO: Better RNG, faster startup is needed!
    rand_obj = Crypto.Util.randpool.PersistentRandomPool("sumi.rng")

    # TODO: /dev/u?random, Windows cryptographic random services
    # LibTomCrypt has access to these, TODO: Python wrapper

    cipher_mod = AES

def random_bytes(n):
    """Return n random bytes."""
    global rand_obj
    if not rand_obj: return random_bytes_weak(n)
    m = rand_obj.get_bytes(n)
    return m

def random_bytes_weak(n):
    """Return n random bytes, generated using Python's random module.
    Only used if random_init() is not called, i.e., if crypto is not
    available."""
    import random
    # Bad RNG
    m = ""
    for i in range(n):
        m += struct.pack("B", random.randint(0, 255))
    return m

def unpack_keys(raw):
    """Unpack a packed data structure of three public EC-DH keys, returning
    an array of tuples suitable for ecc.DH_recv() (in cryptkit library)."""
    ckeys = []
    # Three 32-byte keys, all pushed together (TODO: larger keys)
    for i in range(3):
        start = i * 32
        ckeys.append((raw[start:start+16], raw[start+16:start+32]))
    return ckeys

def capture(decoder, filter, callback):
    """Generic function to capture packets using pcapy, available to
    transports. Useful to receive incoming messages without proxying. Returns
    if callback returns a true value."""

    import pcapy
    print "Receiving messages on %s" % cfg["interface"]
    # 1500 bytes, promiscuous mode.
    p = pcapy.open_live(cfg["interface"], 1500, 1, 0)
    if filter:
        p.setfilter(filter)
    while 1:
        # Occasionally, throws a pcapy.PcapError. Not sure why.
        pkt = p.next()
        pkt_data = pkt[1]
        (user, msg) = decoder(pkt_data)
        #(sn, msg) = decode_aim(get_tcp_data(pkt_data))
        if user:
            #print "<%s> %s" % (sn, msg)
            ret = callback(user, msg)
            if ret:
                return ret
    return 1

def get_tcp_data(pkt_data):
    """Returns the TCP data of an Ethernet frame, or None."""
    return get_transport_data(pkt_data, 20)

def get_transport_data(pkt_data, transport_size):
    """Returns the data inside a transport header of transport_size
    encapsulated in IPv4 over Ethernet, or None."""
    try:
        # TODO: Other transport types besides Ethernet, and make
        # this more informative. Use all this.
        #eth_hdr = pkt_data[0:14]     # Dst MAC, src MAC, ethertype
        #ip_hdr = pkt_data[14:14+20]  # 20-byte IPv4 header (no opts)
        #t_hdr = pkt_data[14+20:14+20+transport_size]  # 20-byte TCP header
        t_data = pkt_data[14+20+transport_size:]
    except:
        return None
    return t_data

def get_udp_data(pkt_data):
    """Return the UDP data of an Ethernet frame, or None."""
    return get_transport_data(pkt_data, 8)

def b64(data):
    """Base64 data, without newlines.
    
    >>> b64("spam")
    'c3BhbQ=='

    """
    b = base64.encodestring(data)
    b = b.replace("\n", "")   # annoying...
    return b

def decrypt_msg(msg, k, iv):
    """Symmetric decipher msg with k and IV iv."""
    a = cipher_mod.new(k, cipher_mod.MODE_CBC, iv)
    return a.decrypt(msg) 

def encrypt_msg(msg, k, iv):
    """Symmetric encipher msg with k and IV iv."""
    assert cipher_mod, "encrypt_msg called before random_init"
    # Why create a new AES object for every encryption? Its only used
    # once per packet/message, since the IV changes. So we have to 
    # recreate the object with a new IV. 
    # XXX: Using counter for IV in CBC mode is a bad idea--see:
    # http://www.cs.ucdavis.edu/~rogaway/papers/draft-rogaway-ipsec-comments-00.txt
    # (LibTomCrypt might not require
    # recreating new object each time, look into it.)
    # ECB mode *may* be OK, since the data is so small. Look into this!
    a = cipher_mod.new(k, cipher_mod.MODE_CBC, iv)
    # Pad to multiple of block size
    pad = "\0" * ((cipher_mod.block_size - len(msg) 
        % cipher_mod.block_size) & (cipher_mod.block_size - 1))
    return a.encrypt(msg + pad)

def get_cipher():
    """Return a PEP272-compliant symmetric cipher module."""
    return cipher_mod

def interleave(evens, odds):
    """Interleave evens with odds, such that 
    interleave(a[0::2], a[1::2) == a.

    Typical usage:
   
>>> msg="interlocked"
>>> e = msg[0::2]
>>> o = msg[1::2]
>>> e, o 
('itrokd', 'nelce')
>>> interleave(e, o)
'interlocked'

>>> interleave("xyzzy"[0::2], "xyzzy"[1::2])
'xyzzy'

>>> interleave("abcd"[0::2], "abcd"[1::2])
'abcd'

    """
    #return "".join(imap("".join, izip(evens, odds)))
    # Better--uses itertools 
    i = "".join(chain(*(izip(evens, odds))))
    if len(i) != len(evens) + len(odds):
         # If interleaved string is odd length, append last character.
         # There might be a better way to do this...
         i += evens[-1]
    return i
    
def hash160(msg):
    """Return a 160-bit SHA-1 digest."""
    # TODO: Use SHA-2 hashes, esp. SHA-256
    return sha.new(msg).digest()

def hash128(msg):
    """Return a SHA-1 digest truncated to 128 bits."""
    # MD5 used to be used here until it was broken.
    return sha.new(msg).digest()[0:16]

def pack_num(n):
    """Pack an arbitrary sized integer into as many bytes as required."""
    s = ""
    while n:
        s += chr(n % 256)
        n /= 256
    return s

def unpack_num(s):
    """Unpack an arbitrary-sized string into its integer equivalent."""
    n = 0
    for i in range(0,len(s)):
        n += ord(s[i]) * (256 ** i)
    return n

def inc_str(s):
    """Numerically increment string (little-endian)."""
    return pack_num(unpack_num(s) + 1)

def take(data, n, at):
    """Take n bytes from data, starting at 'at', incrementing at by n.
    Return the taken data and the new offset."""
    x = data[at:at + n]
    at += n
    return (x, at)

def pack_range(a):
    """Pack a list of lost packets sorted ascending, a, 
    into a compact string with ranges. For example:
    
    >>> pack_range([1,5,7])
    '1,5,7'
    >>> pack_range([1,2,3,4,5,7,10,12,13,14])
    '1-5,7,10,12-14'
    >>> pack_range(42)
    Traceback (most recent call last):
    AssertionError: pack_range: <type 'int'> not a list
    >>> pack_range([])
    ''

    """
    assert type(a) == types.ListType, "pack_range: %s not a list" % type(a)
    if len(a) == 0: return ""
    s = str(a[0])
    run = False
    for i in range(1, len(a)):
        this = a[i]
        prev = a[i - 1]
        change = this - prev
        # a-b indicates an inclusive range, [a,b]
        if change == 1: run = True
        if change != 1 and run: s += "-%s" % prev; run = False
        if change != 1 and not run: s += ",%s" % this
        if i == len(a) - 1 and run: s += "-%s" % this
    return s

def unpack_range(s):
    """Unpack a string packed with pack_range into a corresponding list.
    The string may contain multiple integers separated by commas, and 
    inclusive ranges specified by start-end. For example:
    
    >>> unpack_range("1-3")
    [1, 2, 3]
    >>> unpack_range("1,2,3")
    [1, 2, 3]
    >>> unpack_range("")
    []
    >>> unpack_range("1-5,7,10,12-14")
    [1, 2, 3, 4, 5, 7, 10, 12, 13, 14]
    """
    a = []
    # This kind of compression is used within some print dialogs for the
    # page range, and also in the HTTP spec to request partial data
    for p in s.split(","):
        if "-" in p:
            start, end = map(int, p.split("-"))
            a += range(start, end + 1)
        elif len(p) != 0:
            a.append(int(p))
    return a

# TLV routines for working with binary packed requests/auth responses
# Currently this isn't used, but its here.

global code2name, name2code

def init_tlv():
    global code2name, name2code
    # List of codes. r=used in request (sumi send), a=used in sumi auth
    name2code = {
        # "name": [code, how_to_pack]
        "none": [0, None],    # (r) not used
        "file": [1, str],     # (r) filename to request
        "ip": [2, "I"],       # (r) IP address to send to
        "port": [3, "H"],     # (r) port to send to
        "mss": [4, "H"],      # (ra)Maximum Segment Size
        "prefix": [5, str],   # (r) prefix on data packets
        "bandwidth": [6, "I"],# (r) allowable bandwidth (bps)
        "rwinsz": [7, "B"],   # (r) receive window size (secs)
        "dchantype": [8, "B"],# (r) data channel type
        "source": [9, "I"],   # (a) source address of authentication packet
        "hashcode": [10, str],# (a) hash code of authentication packet
        "offset": [11, "I"],  # (a) requested resume offset
        # Add new codes here
        }
    code2name = [None] * len(name2code.values())
    for k in name2code:
        code2name[name2code[k][0]] = [k, name2code[k][1]]

init_tlv()

def pack_tlv(d):
    """Pack a dictionary into Mini-TLV format."""
    s = ""
    for k in d:
        if name2code[k][1] != str:
            v = struct.pack(name2code[k][1], d[k])
        else:
            v = d[k]
        s += struct.pack("!BB", name2code[k][0], len(v)) + v
    return s

def unpack_tlv(s):
    """Unpack a Mini-TLV string into a dictionary."""
    i = 0
    d = {}
    while i < len(s):
        t, l = struct.unpack("!BB", s[i:i + 2])
        i += 2
        v_str = s[i:i + l]
        i += l
        if code2name[t][1] != str:
            v = struct.unpack(code2name[t][1], v_str)[0]
        else:
            v = v_str
        d[code2name[t][0]] = v
    return d

def calc_blockno(seqno, payloadsz):
    """Calculate the first block cipher block number in the given packet.
    Data packets consist of a number of smaller blocks, often 16 bytes,
    which are used for encryption. 

    seqno: packet sequence number, 1-based
    payloadsz: size of data being sent

    Example:
    payloadsz=1456 and block_size=16:
        bytes range   seqno   block range
         0 - 1456        1       0-91
         1457 - 2913     2       92-183
         ...             3       184-275

    Assuming cipher is AES:

    >>> from Crypto.Cipher import AES
    >>> get_cipher() == AES
    True
    >>> calc_blockno(1, 1456)
    0
    >>> calc_blockno(2, 1456)
    92
    >>> calc_blockno(3, 1456)
    184
    """
    bs = get_cipher().block_size
    return (bs + payloadsz) * (seqno - 1) / bs 

    # Unsimplified version (thanks to Mathematica for simplified eqn, ^^)
    #clients[nick]["ctr"] = (seqno - 1) * payloadsz / bs + seqno - 1

### Routines to obtain the network interfaces.
##
# Currently most are broken.

# While we're at it, also get netmask and offer to use it
#        <a href="http://tgolden.sc.sabren.com/python/wmi_cookbook.html#ip_addresses">link</a>
#          has WMI to get IP and MACs of IP-enabled network devices, can
#          use ioctl for BSD. However, making a remote connection and using
#          the local sockname works better.</p>
# http://tgolden.sc.sabren.com/python/wmi_cookbook.html#ip_addresses
#def get_ifaces_win32():
#    import wmi
#    c = wmi.WMI()
#    ifaces = {}
#
#    # Caption, ServiceName
#    for interface in c.Win32_NetworkAdapterConfiguration():
#        # Win32 stores a bunch of stuff secondary to the interface config,
#        # like DHCP, DNS, firewall, IPX, TCP, WINS
#        ifaces[interface.ServiceName] = {
#            "media": interface.Caption,
#            "name": interface.ServiceName,
#            "description": interface.Description,
#            "ether": interface.MACAddress,
#            "inet": interface.IPAddress != None and interface.IPAddress[0],
#        #   "inets": interface.IPAddress,   # can have >1 IP/subnet?
#            "netmask": interface.IPSubnet != None and interface.IPSubnet[0],
#        #    #"netmasks": interface.IPSubnet,
#            "status": interface.IPEnabled,
#            "mtu": interface.MTU }
#    return ifaces

# coded for BSD's ifconfig
# TODO: port to Linux
#def get_ifaces_unix():
#    import os
#
#    ifconfig = os.popen("ifconfig")
#    all_opts = {}
#    ifaces = {}
#    while 1:
#        line = ifconfig.readline()
#        if line == "": break  
#        line = line[:-1]
#        if line[0] != "\t":    # interface name, flags, and mtu line
#            if (all_opts != {}):
#                all_opts["mtu"] = mtu 
#                all_opts["flags"] = flags
#                ifaces[ifname] = all_opts
#            (ifname, rest) = line.split(":")
#            (rest, mtu) = line.split("mtu ")
#            flags = rest.split("<")[1].split(">")[0].split(",")
#            all_opts = {}
#        else:
#            line = line[1:]
#            a = line.split(" ")
#            if (a[0][-1] == ":"):      # media:, status: take a full line
#                (k, v) = line.split(": ")
#                all_opts[k] = v
#            else:                      # list of dict values
#                opts = dict(zip(*[iter(a)] * 2))
#                for k in opts:
#                    if (k == "netmask"):
#                        # Convert 0x.. netmask to dotted quad
#                        import socket, struct, string
#                        opts[k] = socket.inet_ntoa(struct.pack("!L", 
#                                      string.atoi(opts[k], 16)))
#                    all_opts[k] = opts[k]
#            #print "\t", opts 
#    return ifaces

# broken, need pointers?
#def get_ifaces_unix_IOCTL():
#    import socket
#    import fcntl
#    import IN
#    import struct
#
#    SIOCGIFCONF = -1073190620   #  FreeBSD
#    MAX_IFS = 32
#
#    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
#    buf = "\0" * (32 * MAX_IFS)   # 32 = sizeof(ifreq)
#    ifc = struct.pack("!L", len(buf)) + "\0";
#    fcntl.ioctl(sockfd, SIOCGIFCONF, ifc)

#def get_ifaces():
#    if (sys.platform == "win32"):
#        return get_ifaces_win32()
#    else:
#        return get_ifaces_unix()

# Connects to a given host and gets its the address of our side of the socket
# If behind a NAT this still will return the local IP, not the WAN IP
# Seems to be easier and work better than get_ifaces(), regrettably, because
# it may be detectable by a third party.
def get_default_ip(test_host="google.com", test_port=80):
    log("WARNING: Connecting to %s to obtain IP." % test_host)
    log("Please specify your address in the config file to avoid this test.")
    import socket
    sockfd = socket.socket()
    sockfd.connect((test_host, test_port)) 
    (ip, port) = sockfd.getsockname()
    sockfd.close()
    return ip

def datalink2mtu(d):
    """Given a datalink type pcapy.DLT_*, return a guess at the MTU of the
    datalink."""
    import pcapy
    # These may be 
    return {pcapy.DLT_NULL: 16384,      # BSD Loopback (may vary)
        pcapy.DLT_EN10MB: 1500,         # Ethernet
        pcapy.DLT_IEEE802: 1500,        # 802.5 Token Ring
        pcapy.DLT_ARCNET: 9072,         # Attached Resource Computer Network
        pcapy.DLT_SLIP: 1006,           # SLIP
        pcapy.DLT_PPP: 1452,            # Point-to-Point Protocol
        pcapy.DLT_FDDI: 4352,           # Fiber Distributed Data Interface
        pcapy.DLT_ATM_RFC1483: 9180,    # LLC/SLAM-encapsulated ATM
        pcapy.DLT_RAW: 1500,            # packet begins with IP header
        pcapy.DLT_PPP_SERIAL: 576,      # PPP in HDLC-like framing
        pcapy.DLT_PPP_ETHER: 1492,      # PPPoE
        pcapy.DLT_C_HDLC: 1600,         # Cisco PPP w/ HDLC framing
        pcapy.DLT_IEEE802_11: 1500,     # Wi-Fi
        pcapy.DLT_LOOP: 9244,           # OpenBSD loopback
        pcapy.DLT_LINUX_SLL: 1500,      # Linux cooked capture
        pcapy.DLT_LTALK: 1500,          # Apple LocalTalk            
        }.get(d, 1500)

def select_if():
    """Display network interfaces, selecting the first one.
    
    Return (interface, ip, mask, mtu)."""
    import pcapy

    # getnet()/getmask() return all 0's in 0.10.3, unless the patch
    # "pcapy.getnet.patch" is applied, or a newer version fixes it.

    import pcapy
    ifaces = []
    log("%s. %-16s %-16s %5s\n\t%s\n" % (
        "#", "IP Address", "Netmask", "MTU?", "Device"))
    i = 0
    for dev in pcapy.findalldevs():
        try:
            p = pcapy.open_live(dev, 0, 0, 0)
        except pcapy.PcapError, e:
            log("error opening %s: %s" % (dev, e))
            continue
        # Pcapy doesn't provide MAC addr, or the real MTU, so we use
        # the datalink field to guestimate the MTU.
        mtu = datalink2mtu(p.datalink()) 
        ip = p.getnet()
        # Don't list interfaces without IP addresses--probably means
        # they are down.
        if ip == "0.0.0.0": 
            continue            # skip for brevity
        mask = p.getmask()
        log("%s. %-16s %-16s %5s\n\t%s\n" % (i, ip, mask, mtu, dev))
        ifaces.append({"ip": ip, 
                       "mask": mask, 
                       "mtu": mtu, 
                       "dev": dev})
        i += 1

    # Removed the choice; doesn't work in GUI
    #log("Please enter the number of an interface on the console")
    #log("or use Control-C on the console to exit.")
    #while True:
    #    print "Which interface? "
    #    try:
    #        i = int(sys.stdin.readline().strip())
    #    except:
    #        print "Please enter an integer."
    #        i = 0
    #    if i < 0 or i > len(ifaces): continue
    #    break
    #
    #log("Selected interface #%s" % i)
    #interface = ifaces[i]["dev"]

    assert len(ifaces) != 0, "No interfaces found!"

    i = 0
    interface = ifaces[i]["dev"]

    log("Using interface %s" % interface)

    myip = ifaces[i]["ip"]
    log("Using IP %s" % myip)

    # Useful for sumiserv..put this in libsumi, set_src_allow
    mask = ifaces[i]["mask"]
    log("Using mask %s" % mask)

    mtu = ifaces[i]["mtu"]
    log("Using MSS %s" % mtu)

    return (interface, myip, mask, mtu)

def mtu2mss(mtu, dchantype):
    """Given MTU and data channel type, find the maximum data size that SUMI
       can transmit (not including header)."""
    mtu -= SUMIHDRSZ 
    if dchantype == "u":
        return mtu - IPHDRSZ - UDPHDRSZ
    elif dchantype == "e" or dchantype == "i":
        return mtu - IPHDRSZ - ICMPHDRSZ
    raise Exception("mtu2mss: invalid dchantype: %s" % dchantype)

def mss2mtu(mss, dchantype):
    mss += SUMIHDRSZ
    if dchantype == "u":
        return mss + IPHDRSZ + UDPHDRSZ
    elif dchantype == "e" or dchantype == "i":
        return mss + IPHDRSZ + ICMPHDRSZ
    raise Exception("mss2mtu: invalid dchantype: %s" % dchantype)

def pack_dict(d):
    """Convert a dictionary of ASCII strings to a single string."""
    s = ""
    for k in d:
        s += "%s=%s\n" % (k, d[k])
    return s

def unpack_dict(s):
    d = {}
    for item in s.split("\n"):
        if not "=" in item:
            continue
        k, v = item.split("=")
        d[k] = v
    return d

# set_crc() and check_crc() aren't both called in the same program, but its
# useful to keep them together here in case one changes.

def calc_crc(pkt):
    r'''Calculate the CRC32 of a SUMI packet and return a packet with the
    CRC32 field filled in.

>>> pkt = "fooXXXX\0\0\0\0ZZZZZZ"
>>> calc_crc(pkt)
'fooXXXX\xd25\xe93ZZZZZZ'
>>> check_crc(calc_crc(pkt))
True

'''

    # Make sure the CRC hasn't been filled in yet
    assert pkt[7:11] == "\0\0\0\0", "calc_crc() on pkt without CRC=0!"

    crc = struct.pack("!i", zlib.crc32(pkt))

    return pkt[:7] + crc + pkt[11:]

def check_crc(pkt):
    r'''Check the CRC32 of a packet, returning True if it is correct.
    
    >>> pkt = calc_crc("fooXXXX\0\0\0\0ZZZZZZ")
    >>> pkt
    'fooXXXX\xd25\xe93ZZZZZZ'
    >>> check_crc(pkt)
    True
    >>> check_crc(pkt[0:11])          # Detect truncation
    (libsumi) ** CRC32 Failure from ['foo'] in 1482184792: -2dca16cd vs 0e97bd2c
    False
    >>> check_crc('g' + pkt[1:])      # Detect modification
    (libsumi) ** CRC32 Failure from ['goo'] in 1482184792: -2dca16cd vs 55932270
    False
    '''

    assert len(pkt) >= 11, "check_crc() on incomplete packet: %s" % len(pkt)

    # Use lowercase i since zlib's CRC is signed
    crc_pkt, = struct.unpack("!i", pkt[7:11])
    crc_calc = zlib.crc32(pkt[:7] + "\0\0\0\0" + pkt[11:])

    if crc_pkt != crc_calc:
        prefix = pkt[0:3]
        seqno, = struct.unpack("!I", pkt[3:7])

        # If don't have L suffix, will cause warning:
        #
        #   FutureWarning: %u/%o/%x/%X of negative int will return a signed
        #   string in Python 2.4 and up
        # 
        # And there doesn't seem to be an import __future__ statement to
        # use this behavior, and filtering warnings is inelegant.
        #
        # And %+x should show the sign, but the + seems to be ignored.
        #
        # That is why I have to convert to long using *1L.
        log("** CRC32 Failure from %s in %d: %.8x vs %.8x" % 
                ([prefix], seqno, crc_pkt * 1L, crc_calc * 1L))

    return crc_pkt == crc_calc

_abbrevs = [
    (1 << 50L, "P"),
    (1 << 40L, "T"),
    (1 << 30L, "G"),
    (1 << 20L, "M"),
    (1 << 10L, "k"),
    (1, "")
    ]

def human_readable_size(size):
    """Convert a byte count to a human-readable size. From
       http://mail.python.org/pipermail/python-list/1999-December/018406.html
       and modified to suit the program's needs."""

    for factor, suffix in _abbrevs:
        if size >= factor:   # >= to repr "1024*1024" as "1M"
            break
    coef = (size/(factor * 1.0))
    if (coef >= 10):    # larger coefficients can't have a pt, not enough room
        return "%d" % (coef,) + suffix
    else:               # smaller ones can because there's room, more info=good
        return "%.1f" % (coef,) + suffix

def hash_file(fn, callback=None):
    """Return the SHA-1 hash of a file, optionally calling
    callback(bytes_hashed) every chunk, if callback is not None."""

    size = os.path.getsize(fn)
    f = file(fn, "rb")
    hash_obj = sha.new()

    log("Hashing file %s..." % fn)
    n = 0
    while True:
        chunk = f.read(READ_CHUNK_SIZE)
        if len(chunk) == 0: break
        if callback: 
            callback(n)
            n += len(chunk)
        hash_obj.update(chunk)

       
    return hash_obj.digest()

def is_multicast(addr):
    """Return whether addr is a multicast (Class D) IPv4 addresss.

    Example usage:
        >>> is_multicast("224.0.0.0")
        True
        >>> is_multicast("239.53.23.3")
        True
        >>> is_multicast("240.255.255.255")
        True
        >>> is_multicast("127.0.0.1")
        False
        >>> is_multicast("255.255.255.255")
        False
    """

    # inet_aton can't handle
    if addr == "255.255.255.255":
        return False

    # Multicast addresses have upper octets beginning with bits 1110
    log("Checking if %s is class d" % addr)
    n = ord(socket.inet_aton(addr)[0])
    return n >= 224 and n <= 240

if __name__ == "__main__":
    random_init()

    import doctest
    doctest.testmod()
