#!/usr/bin/env python
# Created:20040117
# By Jeff Connelly

# Python library for common SUMI functions, shared between client and server

import struct 
import Crypto.Util.randpool
import base64
import sha
from itertools import izip, chain
from Crypto.Cipher import AES

cipher_mod = AES

SUMIHDRSZ = 6#bytes
SUMIAUTHHDRSZ = 4#bytes
PKT_TIMEOUT = 3#seconds

# Time to sleep between interlock protocol exchanges
INTERLOCK_DELAY = 1#second

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

rand_obj = None

def random_init():
    global rand_obj
    if rand_obj: return
    log("Initializing RNG...")
    # TODO: Better RNG, faster startup is needed!
    rand_obj = Crypto.Util.randpool.PersistentRandomPool("sumi.rng")

    # TODO: /dev/u?random, Windows cryptographic random services
    # LibTomCrypt has access to these, TODO: Python wrapper

def random_bytes(n):
    """Return n random bytes."""
    global rand_obj
    m = rand_obj.get_bytes(n)
    # Bad RNG
    #m = ""
    #for i in range(n):
    #    m += struct.pack("B", random.randint(0, 255))
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

def decipher(msg, k, iv):
    """Symmetric decipher msg with k and IV iv."""
    a = cipher_mod.new(k, cipher_mod.MODE_CBC, iv)
    return a.decrypt(msg) 

def encipher(msg, k, iv):
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


