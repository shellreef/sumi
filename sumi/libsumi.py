#!/usr/bin/env python
# Created:20040117
# By Jeff Connelly

# Python library for common SUMI functions, shared between client and server

import struct 
import base64
import sha
from itertools import izip, chain

SUMIHDRSZ = 6#bytes
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
    # Why create a new AES object for every encryption? Its only used
    # once per packet/message, since the IV changes. So we have to 
    # recreate the object with a new IV. I think this is better than
    # CTR mode since it uses cipherblocks. LibTomCrypt might not require
    # recreating new object each time, look into it.
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

