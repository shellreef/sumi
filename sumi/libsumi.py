#!/usr/bin/env python
# Created:20040117
# By Jeff Connelly

# Python library for common SUMI functions, shared between client and server

import sys
import struct 
import base64
import sha
from itertools import izip, chain

SUMIHDRSZ = 6#bytes
UDPHDRSZ = 8#bytes
IPHDRSZ = 20#bytes
SUMIAUTHHDRSZ = 4#bytes
PKT_TIMEOUT = 3#seconds

# Time to sleep between interlock protocol exchanges
INTERLOCK_DELAY = 1#second

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
    except:
        log("Error importin PyCrypto. Disable crypto or install PyCrypto")
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
    """Base64 data, without newlines."""
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
    interleave(a[0::2], a[1::2) == a."""
    #return "".join(imap("".join, izip(evens, odds)))
    # Better--uses itertools 
    return "".join(chain(*(izip(evens, odds))))

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
        
        pack_range([1,2,3,4,5,7,10,12,13,14) => "1-5,7,10,12-14"
    """
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

        unpack_range("1-5,7,10,12-14") => [1,2,3,4,5,7,10,12,13,14]
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
    MSS=1462 (payloadsz=1462-SUMIHDRSZ=1462-6=1456) and block_size=16:
        bytes range   seqno   block range
         0 - 1456        1       0-91
         1457 - 2913     2       92-183
         ...             3       184-275"""
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
    """Display network interfaces, allow user to choose one.
    
    Return (interface, ip, mask, mss)."""
    import pcapy

    # getnet()/getmask() return all 0's in 0.10.3, unless the patch
    # "pcapy.getnet.patch" is applied, or a newer version fixes it.

    # TODO: I'd like a warning if an interface is used without an IP;
    # because I do that often (switching between WiFi & Ethernet).
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
        if ip == "0.0.0.0": 
            continue            # skip for brevity
        mask = p.getmask()
        log("%s. %-16s %-16s %5s\n\t%s\n" % (i, ip, mask, mtu, dev))
        ifaces.append({"ip": ip, 
                       "mask": mask, 
                       "mtu": mtu, 
                       "dev": dev})
        i += 1
    log("Please enter the number of an interface on the console")
    log("or use Control-C on the console to exit.")
    while True:
        print "Which interface? "
        try:
            i = int(sys.stdin.readline().strip())
        except:
            print "Please enter an integer."
            i = 0
        if i < 0 or i > len(ifaces): continue
        break

    log("Selected interface #%s" % i)
    interface = ifaces[i]["dev"]
    log("Using interface %s" % interface)

    myip = ifaces[i]["ip"]
    log("Using IP %s" % myip)

    # Useful for sumiserv..put this in libsumi, set_src_allow
    mask = ifaces[i]["mask"]
    log("Using mask %s" % mask)

    mss = ifaces[i]["mtu"] - IPHDRSZ - UDPHDRSZ
    log("Using MSS %s" % mss)

    return (interface, myip, mask, mss)

# Bitmaps - from images.py from wxPython demo, modified for new version
import wx
import cStringIO
def getSmilesData():
    return \
'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\
\x00\x00\x00\x1f\xf3\xffa\x00\x00\x00\x04sBIT\x08\x08\x08\x08|\x08d\x88\x00\
\x00\x02\x97IDATx\x9ce\x93\xcdkSi\x18\xc5\x7f\xef\xfd\x88iC\x85\x11\xeaW\xbd\
1Z\x83D\x04\x11a\x18\xc4\x8e\xd8\x8e\x9dB\x87Y\xe8N\xc2(6\xf1\x82[).\xdd\xa6\
\xfe\x01nj7\xf3?\x14\x06k\xbb)sA\x04Q\xd3!\tZ\xda\xe9\x07\xc8\xc0\x08\xc5\
\xb64\xefm<.r[[}\xe0,\xde\x8f\xf3>\xbc\xe7<\x07\xe3\xb8\xec\xc5\xf4\xf4\xb4\
\x8a\xc5[\xca\xe5\x8e\xc9\xf3\x8c|\xdfQ>\x1f(\x0c\xcb\x8a\xa2H\xdf\xde\xdf\
\xb7\x08\xc3\xb2\x82 \xa3J\xe5\'U\xab7emQ\xd6\xdeR\xb5\xfa\x9b*\x95\xac\x82\
\xc0(\x0cK\xfb\x1f1\x8e\x0b\xc0\xf5_~V6\xfb?O\x9e\xfc\x8e\xef[`\x03X\x07Z@\
\x13\x98\'\x8ek\xdc\xbfoYZ\xba\xcc\xd4\xf3\xc8\x008\x00\xf7\xcaw\x95\xcd\xc2\
\xf8x\x05\xdf/\x00\x99\x84(\xda\xb5\x05l\xe2\xfb\x86\xf1\xf1\x03d\xb3\xb3\
\xdc+\xdfi\x1fFQ\xa4 8$kk\x92\x16%=\xd3\xe8\xe8\xa8\x00IEIE\x01\xea\xee\xee\
\x96\xd4)\xa9C\xd6\xa2\xe0\x04mM\xc2\xb0\xacS\xa7\xb6y\xf8\xf0\x11\xe0\x02\
\xff`\xcc\x10\x00R\x11X\xa3PxG\xbd^G\xea\x04\xb5`\xdb0\xf6\xb8\xc5\xc2R\x11g\
f\xe6/\x86\x87{\x80U`\x1ex\xcd\xd7j\x02\xab,//\xef\xd9\xfb\x0c\xcdN\x86\x07\
\xba\x98\x99\x99\xc4\xf8\xbe\xa3\x8d\x8d\x07\xf8~\x17\xb0\xc5\xc8\xc8\x07&&\
\xec\xaep\xb0\x9c\x08\x9a\x90[-X;L\xbc\xe5\x929\xb9\xd4\x16\x11l\xa2\xf8\'&&\
b`\r\xa8\x02\x8d=d\x81\xb69}"\rq\x07\xc4i\x00\x9c\\\xae\x87Fc\x05\xf8\x0fhP(\
\xbc\x04^$\x9d\xf5\x95L\x0c-\x87\x85\x0f\x9f`\xb3\x8bF\xdd\x90;\xd9\x8d\xd7\
\xdf\xff+\x93\x93\x7fr\xfe|\n\x10\xb5\x1ad2bc\xa71\x9f\x81mh\x19.\x9d\xebB\
\x8b=\xb0y\x90\xc9g\x1f\xe9\xbf:\xb0c\xa3\x91\xb5\x1d\x89Mm\xab\x94N+\x95J\
\xc9\xf3\\e\xd2\x9e.\xf4\x1e\x92V\xcfJ\xb5>\xd9W\xd7\x14\x1cM)\x9a\x9dV2\xc2\
#*\x95\x8c$?\x81\'\xc9\x95\x8c\x91\x0ex\xea\xbfx\\Z\xbc \xd5\xafH\xd5\x01\
\x95n\x1cWx\xfb\x86\xf6eap\xb0O\xa5\x12\xb2\x16I\tZ\x8e\xb4\xfe\x83\xb4R\x90\
\xde\xff(\xfb\xe6\x8aJ7\x8fj\xf0\xea\xc5\xdd<8;?\x9dz\x1e\x19\xd7\x1d\xa1\
\xb7\x17\xc6\xc6`n\x0e\xe2\xa6K\xdct\x98{\xb7\xce\xd8\xd3\x7f\xe9\x1dz\x81{\
\xb0\x8f\xa9\xd9\xb7fw,\xbe\x8dg\x14E\n\xc3\xbb\xca\xe7\x8f\xc8\xf7\x90\xef\
\xa1\xfc\x99\xc3\n\xcb\x7f(\xfa{\xf6\xbb8\x7f\x01 \xf1c\xdaX\x1e\x99\x02\x00\
\x00\x00\x00IEND\xaeB`\x82' 

def getSmilesBitmap():
    return wx.BitmapFromImage(getSmilesImage())

def getSmilesImage():
    stream = cStringIO.StringIO(getSmilesData())
    return wx.ImageFromStream(stream)

#----------------------------------------------------------------------
def getSmallUpArrowData():
    return \
'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\
\x00\x00\x00\x1f\xf3\xffa\x00\x00\x00\x04sBIT\x08\x08\x08\x08|\x08d\x88\x00\
\x00\x00<IDATx\x9ccddbf\xa0\x040Q\xa4{h\x18\xf0\xff\xdf\xdf\xffd\x1b\x00\xd3\
\x8c\xcf\x10\x9c\x06\xa0k\xc2e\x08m\xc2\x00\x97m\xd8\xc41\x0c \x14h\xe8\xf2\
\x8c\xa3)q\x10\x18\x00\x00R\xd8#\xec\x95{\xc4\x11\x00\x00\x00\x00IEND\xaeB`\
\x82' 

def getSmallUpArrowBitmap():
    return wx.BitmapFromImage(getSmallUpArrowImage())

def getSmallUpArrowImage():
    stream = cStringIO.StringIO(getSmallUpArrowData())
    return wx.ImageFromStream(stream)

#----------------------------------------------------------------------
def getSmallDnArrowData():
    return \
"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\
\x00\x00\x00\x1f\xf3\xffa\x00\x00\x00\x04sBIT\x08\x08\x08\x08|\x08d\x88\x00\
\x00\x00HIDATx\x9ccddbf\xa0\x040Q\xa4{\xd4\x00\x06\x06\x06\x06\x06\x16t\x81\
\xff\xff\xfe\xfe'\xa4\x89\x91\x89\x99\x11\xa7\x0b\x90%\ti\xc6j\x00>C\xb0\x89\
\xd3.\x10\xd1m\xc3\xe5*\xbc.\x80i\xc2\x17.\x8c\xa3y\x81\x01\x00\xa1\x0e\x04e\
\x1d\xc4;\xb7\x00\x00\x00\x00IEND\xaeB`\x82" 

def getSmallDnArrowBitmap():
    return wx.BitmapFromImage(getSmallDnArrowImage())

def getSmallDnArrowImage():
    stream = cStringIO.StringIO(getSmallDnArrowData())
    return wx.ImageFromStream(stream)


