#!/usr/bin/env python
# Created:20030402
# By Jeff Connelly

# SUMI server
# Now uses transports/ to communicate with client, and can
# send data using UDP, ICMP, or raw Ethernet

import thread
import base64
import binascii
import random
import socket
import struct
import sys
import os
import md5
import time
import Queue
import libsumi

from libsumi import *
from getifaces import get_default_ip, get_ifaces

# Root is exposed here so the config file can use it
root = os.path.abspath(os.path.dirname(sys.argv[0])) + os.sep

# Log/print -- users of this module can replace this function
def log(msg):
    """Log a message 'msg', followed by a newline.

    Within the module, use log() instead of print. Users of
    the module can then redirect output to their own function.

    Do not use the '+' to form 'msg', except with string literals.
    For example: do NOT use: log("The user's name is: "+nick). If
    nick is not a string, Python will raise a TypeError. Even if it
    is None, you'll get the error. However, log("foo"+"bar") is okay.

    Instead, use formatting strings. Always use the "%s" format
    specifier, not any other specifiers (such as %d). For example,
    this is correct: log("The user's name is: %s" % nick). %s will
    work with any types that define a str() method, including strings,
    None, integers, arrays, tuples, dictionaries, and more. Please
    do NOt use, for example, log("Count: %d" % i), because if i is not
    an integer, %d will raise a TypeError. %s should only raise a 
    TypeError if the str() method isn't defined.

    These rules may seem strict, but are important because logging
    should NEVER cause an error. Some code paths involving log() may be
    only executed in exceptional cases, and there is no room for error."""

    print msg

def load_cfg():
    """Load configuration file (a Python script)."""
    global root, cfg, config_file
    config_file = root + "sumiserv.cfg"

    log("Using config file: " + config_file)
    #eval(compile(open(config_file).read(), "", "exec"))

    cfg = eval("".join(open(config_file, "rU").read()))
    libsumi.cfg = cfg
    libsumi.log = log

load_cfg()

# Initial values below shouldn't need to be configured
resend_queue = Queue.Queue(0)
clients = { }
casts = { }
SUMIHDRSZ = 6 
IPHDRSZ = 20 
ICMPHDRSZ = 8
UDPHDRSZ = 8  
raw_socket = 0
raw_proxy = None

SRC_IP_MASK = None
SRC_IP_ALLOW = None

def fatal(code, msg):
    log("Fatal error #%.2d: %s" % (code, msg))
    sys.exit(code)

# https://sourceforge.net/tracker/?func=detail&atid=105470&aid=860134&group_id=547
# https://sf.net/tracker/?group_id=5470&atid=105470&func=detailed&aid=860134
# PATCH: http://mail.python.org/pipermail/patches/2004-March/014218.html
# audit trail: https://sourceforge.net/tracker/?func=detail&atid=305470&aid=908631&group_id=5470
# -- Update 2004-09-18: seems to be fixed
# After recompiling, copy the _socket.pyd to your C:\python23\DLLs directory
# The old _socket.pyd should be 49KB, the new one 53KB

# This is for Win32
if (not hasattr(socket, "IP_HDRINCL")):
    fatal(1, 
"""Your Python is missing IP_HDRINCL in its socket library.
Most likely, you are on Windows and need to use a patched _socket.pyd that 
links with ws2_32.lib instead of wsock32.lib. Please open sumiserv.py in a 
text editor and read the comments for more information.""")
    # 2.3.2 - no Winsock2
    # 2.3.4 - no Winsock2
    # 2.4a2 - has an IP_HDRINCL, but actually links to wsock32.lib...
    #  (see pcbuild\_socket.vcproj)
    # 

if sys.platform == 'win32':
    # Test if using patched _socket.pyd with Winsock2
    import _socket
    if hasattr(_socket, "AI_ALL"):
        fatal(2, 
"""You are on Windows and your Python socket library has AI_ALL. 
Most likely, you need to use the patched _socket.pyd that uses Winsock2 instead
of Winsock1. Please see sumiserv.py for more information. If you did that and 
this error still occurs, please contact the author.""")

def set_src_allow(allow_cidr):
    """Set the allowed source address in CIDR-notation. For example:
       set_src_allow("4.0.0.0/24") -> allow 4.0.0.0 - 4.255.255.255"""
    global SRC_IP_MASK, SRC_IP_ALLOW
    (allow, cidr) = allow_cidr.split("/")
    cidr = int(cidr)
    # 1 bits = random, 0 bits = fixed
    SRC_IP_MASK = ~(0xffffffffL << cidr) & 0xffffffffL
    allow_list = map(int, allow.split("."))
    a = b = c = d = 0
    try:
        a = allow_list[0]
        b = allow_list[1]
        c = allow_list[2]
        d = allow_list[3]
    except IndexError:    # digits are allowed to be omitted, ex: 4/24
        pass
    # Where mask is 0, SRC_IP_ALLOW specifies fixed, unchanging bits in IP
    SRC_IP_ALLOW = d + c*256 + b*256**2 + a*256**3

    # For consistency. SRC_IP_ALLOW bits are only meaningful when the
    # corresponding bits are 1 in SRC_IP_MASK.
    SRC_IP_ALLOW &= ~SRC_IP_MASK  
    log("Allowing: %s, mask=%.8x, allow=%.8x" % (allow_cidr, SRC_IP_MASK,
        SRC_IP_ALLOW))

def recv_multipart(nick, msg):
    """Accumulate a continued message (beginning with >), returning
    True if the message is currently incomplete or False if the message
    is complete and should be processed.

    In order to handle messages which may be too long for the transport,
    we allow splitting up the message by beginning all parts except
    the last with >. For example, >foo\n>bar\nbaz = foobarbaz."""
    if (msg[0] == ">"):
        if (not clients[nick].has_key("msg")): 
            clients[nick]["msg"] = msg[1:]
        else:
            clients[nick]["msg"] += msg[1:]
        log("ACCUMULATED MSG: %s" % clients[nick]["msg"])
        return True
    else:
        if clients[nick].has_key("msg"):
            msg = clients[nick]["msg"] + msg
            clients[nick]["msg"] = ""
        log("COMPLETE MSG:  %s" % msg)   # Now handle
        return False

def handle_dir(nick, msg):
    """Handle sumi dir -- send directory list."""
    log("%s is calling sumi dir" % nick)

    handle_request(nick, msg)
    
    # TODO
    # How should sumi dir work? Can we authenticate only once, then
    # allow multiple transfers (including sends and dirs)? Also, we
    # should allow multiple simultaneous transfers, so one can browse
    # while transferring large files.
    send_auth(nick, "")

def handle_request(nick, msg):
    """Handle a generic transfer request, returning arguments dictionary.
    
    Setup basic fields, MSS, communication channel, prefix, and IP
    (possibly multicast)."""
    if (clients.has_key(nick) and not clients[nick].has_key("preauth")):
        log("CLEARING LEFT OVERS")
        clients[nick].clear()
    args = unpack_args(msg)
    log("ARGS=%s" % args)
    try:
        # Basic fields
        ip       = args["i"]
        port     = int(args["n"])
        mss      = int(args["m"])
        b64prefix= args["p"] 
        speed    = int(args["b"])   # b=bandwidth
        rwinsz   = int(args["w"])
        dchantype= args["d"]            
    except KeyError:
        log("not enough fields/missing fields")
        return sendmsg_error(nick, "not enough fields/missing fields")

    # Verify MSS. A packet is sent with size clients[nick]["mss"]
    # Limit minimum MSS to 256 (in reality, it has a minimum of ~548)
    # This is done to block an attack whereby the attacker chooses a MSS
    # very small MSS, so only the non-random data fits in the packet.
    # She then can hash our nick and verify it, without verifying the UDP
    # transmission. If we allow this to happen, then we may be sending UDP
    # packets to a host that didn't request them -- DoS attack. Stop that.
    # This check is also repeated in the second stag            
    ##clients[nick]["last_winsz"] = winsz
    #     256 MSS has to be small enough for anybody.
    log("Verifying MSS")
    if (mss < 256):
        return sendmsg_error(nick, "MSS too small: %d" % (mss,))
    if (mss > cfg["global_mss"]):
        return sendmsg_error(nick, "MSS too large")

    # Prefix is base64-encoded for IRC transport
    # Note: There is no need to use Base85 - Base94 (RFC 1924) because
    # it can increase by a minimum of one byte. yEnc might work, but
    # its not worth it really. Base64 is perfect for encoding these 3 bytes
    log("Decoding prefix")
    prefix = base64.decodestring(b64prefix)

    # Prefix has to be 3 bytes, because if we allow larger, then clients
    # will choose larger prefixes filling up the auth packet with data
    # of their choice, circumventing the auth process
    if (len(prefix) != 3):   # b64-encoded:4 decoded:3
        return sendmsg_error(nick, "prefix length != 3, but %d" % (
                                   len(prefix)))
    #b64prefix = base64.encodestring(prefix)

    try:
        socket.inet_aton(ip)
    except:
        return sendmsg_error(nick, "invalid IP address: %s" % ip)

    log("nick=%s,IP=%s:%d MSS=%d PREFIX=%02x%02x%02x" % (
          nick, ip, port, mss, ord(prefix[0]), \
          ord(prefix[1]), ord(prefix[2])))

    clients[nick]["addr"] = (ip, port)
    clients[nick]["mss"] = int(mss)
    clients[nick]["prefix"] = prefix
    clients[nick]["speed"] = int(speed)
    clients[nick]["authenticated"] = 1   # first step complete
    clients[nick]["xfer_lock"] = thread.allocate_lock()  # lock to pause
    clients[nick]["rwinsz"] = rwinsz 
    clients[nick]["dchantype"] = dchantype

    # The data channel type determines how to send, and make src & dst addrs
    # of the sent packets
    if (dchantype == "u"):
        # The normal, spoofed UDP transfer
        clients[nick]["send"] = send_packet_UDP
        clients[nick]["src_gen"] = randip
        clients[nick]["dst_gen"] = lambda : clients[nick]["addr"]
    elif (dchantype == "e"):
     # "echo mode" (which uses this) can be very laggy! Many lost packets.
     # Transfer speed is limited by the weakest link; the ping proxy. 
        clients[nick]["send"] = \
             lambda s,d,p: send_packet_ICMP(s, d, p, 8, 0)
        clients[nick]["src_gen"] = lambda : clients[nick]["addr"]
        clients[nick]["dst_gen"] = rand_pingable_host  # no port
    elif (dchantype == "i"):
         # Type+code used to be in dchantype, now its inside myport, packed
         type = int(port // 0x100)
         code =     port % 0x100
         log("type,code=%s %s" % (type,code))
         clients[nick]["send"] = \
             lambda s,d,p: send_packet_ICMP(s, d, p, type, code)
         clients[nick]["src_gen"] = randip
         clients[nick]["dst_gen"] = lambda : clients[nick]["addr"]
    else:
         sendmsg_error(nick, "invalid dchantype")
    # TODO:others: t (TCP)

    clients[nick]["ack_ts"] = time.time()

    # 24-bit prefix. The server decides on the prefix to use for the auth
    # packet, but here we embed the prefix that we, the server, decide to
    # use for the data transfer. 
    clients[nick]["prefix1"] = clients[nick]["prefix"]   # first prefix

    if casts.has_key(clients[nick]["addr"]):
        # Use prefix of client already sending to
        log("Multicast detected: %s:%s" % (clients[nick]["addr"],
              casts[clients[nick]["addr"]]))

        cs = casts[clients[nick]["addr"]]
        found = 0
        for c in cs:
            if clients.has_key(c) and clients[c].has_key("authenticated") and clients[c]["authenticated"] == 2:
                clients[nick]["prefix"] = clients[c]["prefix"]
                found = 1
                break

        if found == 0:
            log("No transferring clients found, assuming unicast")
            casts[clients[nick]["addr"]] = { nick: 1 }
            mcast = 0
        else:
            casts[clients[nick]["addr"]][nick] = 1

            log("    Using old prefix: %02x%02x%02x" % \
                (ord(clients[nick]["prefix"][0]), \
                 ord(clients[nick]["prefix"][1]), \
                 ord(clients[nick]["prefix"][2])))
            mcast = 1
    else:
        # An array would do here, but a hash easily removes the possibility
        # of duplicate keys. List of clients that have the same address.
        casts[clients[nick]["addr"]] = { nick: 1 }
        mcast = 0
    clients[nick]["mcast"] = mcast

    return args

def send_auth(nick, file_info):
    """Send authentication packet to nick.

    file_info contains information on the file."""
    if not clients[nick].has_key("prefix"):
        return sendmsg_error(nick, "missing prefix")

    # Build the authentication packet using the client-requested prefix
    # 3-byte prefix, 3-byte seqno (0)
    pkt = "%s\0\0\0" % clients[nick]["prefix"]
    assert len(pkt) == SUMIHDRSZ, "pkt + seqno != SUMIHDRSZ";

    # Payload is file information, followed by random data, up to MSS
    payload = file_info
    mss = clients[nick]["mss"]
    payload += random_bytes(mss - SUMIHDRSZ - len(file_info))

    clear_pkt = pkt + payload
    assert len(clear_pkt) == mss, \
            "bad pkt generation: %d != %d" % (len(clear_pkt), mss)
    clients[nick]["authpkt"] = clear_pkt   # Save so can hash when find out MSS

    if clients[nick].has_key("preauth"):
        # Encrypt payload--after saved in "authpkt" for hashing.
        clients[nick]["sessiv"] = inc_str(clients[nick]["sessiv"])
        payload = encrypt(nick, payload)
    pkt += payload

    clients[nick]["authpkt_enc"] = pkt

    # Send raw UDP from: src_gen(), to: dst_gen()
    # This will trigger client to send sumi auth
    clients[nick]["asrc"] = clients[nick]["src_gen"]()
    # Note, if execution reaches here and then stops, its a problem
    # with a) the server sending the packet b) the client receiving the
    # packet (in both cases, the authentication packet). Some ICMP codes
    # blocked/handled by kernel, for example, or src may be blocked.
    log("Sending auth packet now.")
    clients[nick]["send"](clients[nick]["asrc"], \
                          clients[nick]["dst_gen"](), pkt)
    log(" AUTH PREFIX=%02x%02x%02x" % (ord(pkt[0]), \
        ord(pkt[1]), ord(pkt[2])))
    #send_packet(clients[nick]["asrc"], (ip, port), pkt)
    return True

def handle_send(nick, msg):
    """Handle sumi send -- setup a new transfer."""
    log("%s is sumi sending" % nick)

    args = handle_request(nick, msg)

    try: 
        #(file, offset, ip, port, mss, b64prefix, speed)=msg.split("\t") 
        filename = args["f"]
    except:
        return sendmsg_error(nick, "not enough fields for send")

    log("FILE=%s" % filename)

    if (filename[0] == "#"):
        clients[nick]["file"] = int(filename[1:]) - 1
    else:
        return sendmsg_error(nick, "file must be integer") 

    # Make sure the filename/pack number is valid
    if not clients[nick]["file"] in range(len(cfg["filedb"])):
        return sendmsg_error(nick, "no such pack number")
    
    # Build header -- this contains file information.
    # TODO: put more information about the file here. hash?

    # This is the size of the cleartext, not necessarily size on the wire
    clear_size = os.path.getsize(cfg["filedb"][clients[nick]["file"]]["fn"])
    file_info = struct.pack("!I", clear_size)
    clients[nick]["clear_size"] = clear_size

    # Used for data transfer, may differ from client-chosen auth pkt prefix
    file_info += clients[nick]["prefix"]

    file_info += chr(clients[nick]["mcast"])
    if clients[nick].has_key("preauth"):
        file_info += hash160(clients[nick]["nonce"])
    file_info += os.path.basename(cfg["filedb"][clients[nick]["file"]]["fn"]+\
               "\0");  # Null-term'd

    if clients[nick].has_key("crypto_state"):
        # Outer encryption: CTR mode
        clients[nick]["ctr"] = unpack_num(clients[nick]["sessiv"]) + 1
        def ctr_proc():
            clients[nick]["ctr"] += 1
            x = pack_num(clients[nick]["ctr"])
            x = "\0" * (16 - len(x)) + x
            assert len(x) == 16, "ctr is %s not 16 bytes" % len(x)
            return x
        clients[nick]["crypto_obj"] = get_cipher().new(
                clients[nick]["sesskey"], get_cipher().MODE_CTR,
                counter=ctr_proc)

        # Inner encryption: package ECB mode
        from AONT import AON
        clients[nick]["aon"] = AON(get_cipher(), get_cipher().MODE_ECB)

    send_auth(nick, file_info)
    return True

def handle_auth(nick, msg):
    """Handle sumi auth -- authentication."""
    if (not clients.has_key(nick) or clients[nick]["authenticated"] != 1):
        return sendmsg_error(nick, "step 1 not complete")

    log("message: %s" % msg)
    #(their_mss, asrc, hash) = msg.split("\t")
    args = unpack_args(msg)
    log("args: %s" % args)
    their_mss = int(args["m"])
    asrc      = args["s"]
    hashcode  = args["h"]
    offset    = int(args["o"])

    if offset: 
        clients[nick]["seqno"] = offset   # resume here
    else:
        clients[nick]["seqno"] = 1

    clients[nick]["last_rwinsz"] = 1024   # initial, if needed

    if (clients[nick]["mss"] != their_mss):
        if (their_mss < 256):
            return sendmsg_error(nick, "MSS too small: %d" % their_mss)
        if (their_mss > clients[nick]["mss"]): 
            return sendmsg_error(nick, "MSS too high (%d>%d)!" % (their_mss, clients[nick]["mss"]))
        # Client might have received less than full packet; this says they
        # require a smaller packet size
        log("Downgrading MSS of %s: %d->%d" % (nick, clients[nick]["mss"],
            their_mss))
        clients[nick]["mss"] = their_mss

    # Now we know MSS, so calculate send delay (in seconds)
    # delay = MTU / bandwidth
    # s = b / (b/s)  <- units
    # MTU = MSS + 28
    # bytes/sec = bits/sec / 8
    # min(their_dl_bw, our_ul_bw) = transfer speed
    clients[nick]["delay"] =  \
        (clients[nick]["mss"] + 28.) / \
        (min(clients[nick]["speed"], cfg["our_bandwidth"])/8)  
         # ^^^  whichever slower
    log("Using send delay: %s" % clients[nick]["delay"])
       
    log("Verifying spoofing capabilities...")
    if (clients[nick]["asrc"][0] != asrc):
        log("*** Warning: Possible spoof failure! We sent from %s,\n"\
              "but client says we sent from %s. If this happens often,"\
              "either its a problem with your ISP, or the work of\n"\
              "mischevious clients. Dropping connection." %
              (clients[nick]["asrc"][0], asrc))
        #return sendmsg_error(nick, "srcip")
    
    log("Verifying authenticity of client...")
    # The hash has to be calculated AFTER the auth string is received so
    # we know how much of it to hash (number of bytes: the MSS)
    if (their_mss > len(clients[nick]["authpkt"])):   # trying to overflow, eh..
        return sendmsg_error(nick, "claimed MSS > pktlength!")

    # The client (or really, the transmission medium) may have truncated 
    # the datagram to match their MSS, so only hash up to their MSS. Similar
    # to MTU path discovery?
    derived_hash = b64(hash128(clients[nick]["authpkt"]\
        [0:clients[nick]["mss"]]))
    #log("Clear payload: %s" % ([clients[nick]["authpkt"]],))
    if (derived_hash != hashcode):
        return sendmsg_error(nick, "hashcode: %s != %s" % 
                (derived_hash, hashcode))

    clients[nick]["fh"] = \
        open(cfg["filedb"][clients[nick]["file"]]["fn"], "rb")

    # Find size...
    clients[nick]["fh"].seek(0, 2)   # SEEK_END
    clients[nick]["size"] = clients[nick]["fh"].tell()
    clients[nick]["fh"].seek(0, 0)   # SEEK_SET

    log("Starting transfer to %s..." % nick)
    log("Sending: %s" % cfg["filedb"][clients[nick]["file"]]["fn"])
    ##

    log("%s is fully verified!" % nick)
    clients[nick]["authenticated"] = 2    # fully authenticated, let xfer

    # When multicasting, the same address is sent by multiple clients.
    # Only send to mcast address once. TODO: full multicast support
    # TODO: Clients in a multicast stream have to have the same prefix,
    # the same dchantype, our bandwidth is the same as well, and same MSS
    # (or at least compatible). TODO: Have the server (us) pick the prefix,
    # and the client reject it (not ack the auth packet, but redo sumi send
    # again) if the prefix conflicts. This way the server can assign 
    # multiple clients the same prefix, and they all can get it!
    if clients[nick]["mcast"]:
        log("Since multicast, not starting another transfer")
        return
    else:
        log("Unicast - starting transfer")

    # In a separate thread to allow multiple transfers
    #thread.start_new_thread(xfer_thread, (nick,))
    thread.start_new_thread(make_thread, (xfer_thread_loop, nick,))
        #make_thread(xfer_thread, nick)

    return True

def handle_done(nick, msg):
    """Handle sumi done -- graceful ending of transfer."""
    # Possible thread concurrency issues here. Client can do sumi done at
    # any time, which will result in accessing nonexistant keys
    log("Transfer to %s complete (%s)\n" % (nick, msg))
    try:
        casts[clients[nick]["addr"]].remove(nick)
    except:
        pass
    if (clients[nick].has_key("file")):
        cfg["filedb"][clients[nick]["file"]]["gets"] += 1
        log("NUMBER OF GETS: %s" %
                cfg["filedb"][clients[nick]["file"]]["gets"])
    else:
        log("Somehow lost filename")
    destroy_client(nick)

def encrypt(nick, msg):
    """Encrypt msg to nick."""
    e = encrypt_msg(msg, clients[nick]["sesskey"], clients[nick]["sessiv"])
    return e

def decrypt(nick, msg):
    """Decrypt msg from nick."""
    return decrypt_msg(msg, clients[nick]["sesskey"], clients[nick]["sessiv"])

def generate_nonce(nick):
    """Generate and encrypt a random nonce (number used only once) for nick.
    Returns two cleartext and two encrypted halves."""

    nonce = random_bytes(32)
    nonce_enc = encrypt(nick, nonce)

    # Split into even and odd bytes for interlock protocol. Better than
    # beginning and end because can't be decrypted as easily.
    nonce_1 = nonce_enc[0::2]
    nonce_2 = nonce_enc[1::2]
   
    return (nonce, nonce_1, nonce_2)

def handle_sec(nick, msg):
    """Receive sumi sec messages from client. These contain client's public
    key, which will cause us to respond with our public key and the first
    half of the encrypted prefix. Uses Elliptic Curve Diffie-Hellman (EC-DH)
    and the Interlock Protocol.

    A                   B
    Ka------------------>                   sumi sec 
     <------------------ Kb + Ea,b(Pb)<1>   1/2 prefix response
     Ea,b(Pa)<1>-------->                   1/2 sumi send
     <------------------ Ea,b(Pb)<2>        2/2 prefix response
     Ea,b(Pa)<2>-------->                   2/2 sumi send

    A=client
    B=server
    Pa=prefix, randomly generated by us here
    Pb=request
    Ea,b(M)<n>=encrypt message M with key a,b, take nth half

    The <1> and <2> responses from us (B) are delayed INTERLOCK_DELAY.
    """

    #from Crypto.PublicKey import RSA
    # EC-DH instead of RSA, since it has smaller keys for same security.
    from ecc.ecc import ecc   # cryptkit library has ECC, PyCrypto doesn't
    print "%s's key: %s" % (nick, msg)
    try:
        raw = base64.decodestring(msg)
    except (binascii.Error, IndexError):
        return sendmsg_error(nick, "invalid public triple-key")

    ckeys = unpack_keys(raw)
    print ckeys

    # Generate random keys. This is fast with ECC, so it doesn't hurt
    # to generate new keys every time.
    skeys = []
    for i in range(3):
        skeys.append(ecc(ord(random_bytes(1))))
    
    clients[nick] = {}   # Remember nothing
    # Save client and server keys
    clients[nick]["ckeys"] = ckeys
    clients[nick]["skeys"] = skeys

    str_skeys = ""
    for k in skeys:
        str_skeys += "".join(k.publicKey())

    # Calculate private (but shared) keys using Diffie-Hellman
    pkeys = []
    for i in range(3):
        pkeys.append(skeys[i].DH_recv(ckeys[i]))
    clients[nick]["sesskey"] = hash128(pkeys[0]) + hash128(pkeys[1])
    clients[nick]["sessiv"] = pkeys[2]
    log("session key/iv: %s" % ([clients[nick]["sesskey"],
        clients[nick]["sessiv"]],))

    # Calculate and save unencrypted nonce (nonce), and two halves encrypted.
    nonce, nonce_1, nonce_2 = generate_nonce(nick)
    clients[nick]["crypto_state"] = 1
    clients[nick]["nonce"] = nonce
    clients[nick]["nonce_1"] = nonce_1
    clients[nick]["nonce_2"] = nonce_2
    clients[nick]["preauth"] = True

    # We rarely send messages to the client over the transport, but it is
    # necessary here, because the data channel isn't setup yet (we want to
    # let them encrypt the send request, since it includes their IP).

    # Send our public keys + 1/2 encrypted nonce after INTERLOCK_DELAY
    log("Waiting to send pk+nonce1/2...")
    thread.start_new_thread(delayed_send, 
                            (nick, b64(str_skeys + nonce_1)))
    return True

def delayed_send(nick, msg):
    """Send msg to nick after INTERLOCK_DELAY seconds."""
    time.sleep(INTERLOCK_DELAY)
    log("Sending delayed message: %s" % msg)
    sendmsg(nick, msg)

def recvmsg_secure(nick, msg):
    """Handle an encrypted message from the client. Return a cleartext
    message, or None if we handled the message."""

    if "sumi sec " in msg:
        # Not meant for us; restarting crypto
        return msg
    if clients[nick]["crypto_state"] == 1:       # 1/2 request->nonce 2/2
        print "msg=%s"%msg
        try:
            clients[nick]["req1"] = base64.decodestring(msg)
        except binascii.Error:
            del clients[nick]["crypto_state"]
            return sendmsg_error(nick, "bad encoding of req 1/2+nonce 2/2")
        # Send 2/2 nonce
        log("Got 1/2 request--delaying")
        time.sleep(INTERLOCK_DELAY)
        sendmsg(nick, b64(clients[nick]["nonce_2"]))
        log("Got 1/2 request, sent 2/2 nonce")
        clients[nick]["crypto_state"] = 2
    elif clients[nick]["crypto_state"] == 2:     # 2/2 request->auth pkt
        req1 = clients[nick]["req1"]
        try:
            req2 = base64.decodestring(msg)
        except binascii.Error:
            del clients[nick]["crypto_state"]
            return sendmsg_error(nick, "bad encoding of req 2/2")
        req_enc = interleave(req1, req2)
        #log("REQ_ENC=%s" % ([req_enc],))
        req = decrypt(nick, req_enc)
        log("Got 2/2 request: %s" % ([req,]))
        # (No delay here--immediate; if client detects a delay=MITM)
        clients[nick]["crypto_state"] = 3
        # Have recvmsg handle it
        return req
    elif clients[nick]["crypto_state"] == 3:      # sumi auth->data
        try:
            auth_enc = base64.decodestring(msg)
        except binascii.Error:
            del clients[nick]["crypto_state"]
            return sendmsg_error(nick, "bad encoding of auth")
        clients[nick]["sessiv"] = inc_str(clients[nick]["sessiv"])
        auth = decrypt(nick, auth_enc)
        if not auth:
            log("Failed to decrypt auth %s" % auth_enc)
            return
        auth = "sumi auth " + auth
        log("DECRYPTED AUTH: %s" % auth)

        clients[nick]["crypto_state"] = 4
        # Handled in recvmsg
        return auth
    # crypto_state == 4 is file transfer

    return None

def recvmsg(nick, msg):
    """Handle an incoming message.

       Returns True if successful, False if unsuccessful, or
       None if neither (multipart continuation)."""

    if nick == None and msg == "on_exit":
        on_exit()

    log("<%s>%s" % (nick, msg))

    if not clients.has_key(nick):
        clients[nick] = {}

    if recv_multipart(nick, msg):
        return None    # neither success or failure

    # If transfer in progress, allowed to use abbreviated protocol
    if  clients[nick].has_key("authenticated") and \
        clients[nick]["authenticated"] == 2:
        transfer_control(nick, msg)

    # Encrypted messages
    if clients.has_key(nick) and clients[nick].has_key("crypto_state"):
        cleartext = recvmsg_secure(nick, msg)
        if not cleartext:
            return    # handled (key exchange, etc.)
        msg = cleartext.replace("\0", "")
        log(";;; decrypted: %s" % msg)

    all = msg.split(" ", 2)
    if len(all) != 3: return False

    magic, cmd, arg = all
    if magic != "sumi": return False
    table = {
        "sec":  handle_sec,
        "send": handle_send,
        "auth": handle_auth,
        "dir":  handle_dir,
        "done": handle_done}
    if table.has_key(cmd):
        table[cmd](nick, arg)

    return True

def load_transport(transport):
    """Load the transport module used for the backchannel. This is similar
    to sumiget's load_transport, but the transport is used for ALL transfers;
    not on a per-user basis as with sumiget."""
    global sendmsg
    # Import the transport. This may fail, if, for example, there is
    # no such transport module.
    log(sys.path)
    try:
        sys.path.insert(0, os.path.dirname(sys.argv[0]))
        t = __import__("transport.mod" + transport, None, None,
                       ["transport_init", "sendmsg", "recvmsg"])
    except ImportError:
        fatal(3, 
"""Loading transport " + transport + "failed: " + sys.exc_info() + 
"\nPlease specify 'transport' in sumiserv.cfg""")

    import sumiget
    # Export some useful functions to the transports
    t.segment = sumiget.segment
    t.cfg = cfg
    t.capture = capture
    t.get_tcp_data = get_tcp_data
    t.human_readable_size = human_readable_size
    t.log = log

    #clients[nick]["sendmsg"] = t.sendmsg
    #clients[nick]["recvmsg"] = t.recvmsg
    #clients[nick]["transport_init"] = t.transport_init
    t.transport_init()
    sendmsg = t.sendmsg
    t.recvmsg(recvmsg)

def xfer_thread_loop(nick):
    """Transfer the file, possibly in a loop for multicast."""
    if clients[nick]["mcast"]: 
       i = 0
       while 1:
           log("Multicast detected - loop #%d" % i)  # "data carousel"
           i += 1
           xfer_thread(nick)
    else:
       xfer_thread(nick)

# TODO: The following conditions need to be programmed in:
# * If peer QUITs, kill transfer
def xfer_thread(nick):
    """File transfer thread, called for each file transfer."""
    log("clients[nick][seqno] exists? %s" % clients[nick].has_key("seqno"))

    # Not actually used here.
    #blocksz = clients[nick]["mss"] - SUMIHDRSZ
    while 1:
        # Resend queued resends if they come up, but don't dwell
        try:
            while 1:
                resend = resend_queue.get_nowait()   # TODO: multiple users!
                log("Q: %s %s" % (nick,resend))
                datapkt(nick, resend)
        except Queue.Empty:
            log("Q: empty")
            pass

        if (clients[nick]["seqno"]):
            blocklen = datapkt(nick, clients[nick]["seqno"])

        d = time.time() - clients[nick]["ack_ts"]

        # * If peer doesn't send NAK within 2*RWINSZ, pause transfer (allocate_lock?)
        # * If above, and peer sends a NAK again, release the lock allowing to resume
        # Original idea was to pause if haven't received any messages in
        # RWINSZ*2, and then resume if we received a message within RWINSZ*5.
        # This may help SUMI withstand temporary congestion problems, but I
        # haven't been able to get it working well.
        #if (float(d) >= float(clients[nick]["rwnisz"] * 2)):
        #    print "Since we haven't heard from %s in %f (> %d), PAUSING" % \
        #           (nick, int(d), float(clients[nick]["rwinsz"] * 2))
        #     clients[nick]["xfer_lock"].acquire()

        # If haven't received ack from user since RWINSZ*5, stop.
        if (float(d) >= float(clients[nick]["rwinsz"] * 5)):
            #clients[nick]["xfer_lock"].acquire() 
            log("Since we haven't heard from %s in %f (> %d), stopping" %  \
                (nick, int(d), float(clients[nick]["rwinsz"] * 5)))
            clients[nick]["xfer_stop"] = 1

        # If transfer lock is locked (pause), then wait until unpaused
        #  might be better for us to stop transfer in 2*RWINSZ, but be polite
        if (clients[nick]["xfer_lock"].locked()):
            log("TRANSFER TO %s PAUSED" % nick)
            clients[nick]["xfer_lock"].acquire()
            log("TRANSFER TO %s RESUMED" % nick)

        if (clients[nick].has_key("xfer_stop")):
            #print "TRANSFER TO",nick,"STOPPED:",clients[nick]["xfer_stop"]
            log("TRANSFER TO %s STOPPED: %s" % (nick,
                clients[nick]["xfer_stop"]))
            clients[nick] = {}
            return

        # End of file if short block. Second case is redundant but will
        # occur if file size is an exact multiple of MSS.
        if (not clients[nick].has_key("seqno")):
            # TODO: Allow multiple transfers per server? No, queue instead.
            fatal(4, ("Client %s has no seqno" % nick) +
                "\nMost likely client is trying to get >1 files at once.")
        #print "#%d, len=%d" % (clients[nick]["seqno"], blocklen)
        if (blocklen < clients[nick]["mss"] - SUMIHDRSZ or blocklen == 0):
            clients[nick]["seqno"] = None  # no more sending, but can resend
            break
        clients[nick]["seqno"] += 1

    # Wait for any more resends until 2*RWINSZ
    while 1:
        try:
            resend = resend_queue.get(True, 2*int(clients[nick]["rwinsz"]))
            datapkt(nick, resend)
        except Queue.Empty:
            break 

    log("Transfer complete.")

def destroy_client(nick):
    """Clear all information about a client."""
    log("Severing all ties to %s" % nick)
    try:
        casts[clients[nick]["addr"]].pop(nick)
        if len(casts[clients[nick]["addr"]]) == 0:
            log("Last client for %s exited: %s" %
                (clients[nick]["addr"], nick))
            # TODO: stop all transfers to this address
            casts.pop(clients[nick]["addr"])
        clients.pop(nick)
    except:
        pass

def handle_nak(nick, msg):
    """Handle a negative acknowledgement, of the form
        n<win>,<resend-1>,<resend-2>,...,<resend-N>. We will
        resend the requested packets, as well as any normal
        non-lost packets."""
    #resends = msg[1:].split(",")
    resends = unpack_range(msg[1:])   # Compressed naks
    resends.reverse()
    if (msg == "n"):
        if (not clients[nick].has_key("last_winsz")):
            winsz = 1024
        else:
            winsz = clients[nick]["last_winsz"]
    else:
        winsz = int(resends.pop())
        clients[nick]["last_winsz"] = winsz

    clients[nick]["ack_ts"] = time.time()   # got ack within timeframe
    if (clients[nick]["xfer_lock"].locked()):
        clients[nick]["xfer_lock"].release()
        log("Lock released by control message.")

    # TODO: Slow bandwidth (increase delay) based on lost packets. The
    # lost packets can tell us what bandwidth and thus delay we should use.
    # Take the amount of data received over the time to get bandwidth,
    # and then use delay=MTU/bandwidth to find the new delay. Additionally
    # the b/w can be throttled up optimistically sometimes, if good
    # conditions and no/little losses. TCP has a "slow start" where it
    # starts out with low bandwidth and increases until too much. Consid.
    # TODO: How about this... set bandwidth requested to actual bandwidth
    #print "Lost bytes: ", clients[nick]["mss"] * len(resends)

    # If any resends, push these onto global resend_queue
    for resend in resends:
        if len(resend) == 0: continue
        try:
            resend = int(resend)
        except ValueError:
            log("Invalid packet number: %s" % resend)
            continue
        log("Queueing resend of %d" % resend)
        resend_queue.put(resend)

def transfer_control(nick, msg):
    """Handle an in-transfer control message.
    
    In-transfer messages use an abbreviated protocol."""
    global resend_queue
    log("(authd)%s: %s" % (nick, msg))
    if msg[0] == "k":     # TFTP-style transfer, no longer supported here
        pass 
    elif msg[0] == "n":          
        handle_nak(nick, msg)
    elif msg[0] == '!':        # abort transfer
        log("Aborting transfer to %s" % nick)
        destroy_client(nick)

def datapkt(nick, seqno):
    """Send data packet number "seqno" to nick, for its associated file. 
       Returns the length of the block sent.
       
       Delegates actual sending to a send_packet_* function."""
    if seqno > 16777216:
        destroy_client(nick)
        return sendmsg_error(nick, "file too large: 8-10GB is "+
                "the limit, depending on MSS")

    blocksz = clients[nick]["mss"] - SUMIHDRSZ
    
    if cfg["noise"] and random.randint(0, int(cfg["noise"])) == 0:
        # lose packet (for testing purposes)
        return blocksz

    log("Sending to %s #%s %s" % (nick, seqno, blocksz))
    #print "I AM GOING TO SEEK TO ",blocksz*(seqno-1)

    #if (blocksz * (seqno - 1)) > clients[nick]["size"]:
    #    print nick,"tried to seek past end-of-file"
    #    return

    # Many OS's allow seeking past the end of file
    file_pos = blocksz * (seqno - 1)
    clients[nick]["fh"].seek(file_pos)

    block = clients[nick]["fh"].read(blocksz)

    # Crypto, anyone?
    # XXX: broken
    if False and clients[nick].has_key("crypto_state"):
        assert blocksz % get_cipher().block_size == 0, \
                "%s (MSS-%s) is not a multiple of %s, which is required" + \
                "for crypto. This should've been fixed in cfg validation." % (
                        blocksz, SUMIHDRSZ, get_cipher().block_size)

        pseudotext = clients[nick]["aon"].digest_next(block)
        if file_pos > clients[nick]["clear_size"] - blocksz: 
            # Last packet, so include last block
            log("(last packet!)")
            pseudotext += clients[nick]["aon"].digest_last()
        clients[nick]["ctr"] = (seqno - 1) * blocksz / get_cipher().block_size
        ciphertext = clients[nick]["crypto_obj"].encrypt(pseudotext)
        log("(encrypted pkt)")

        block = ciphertext

    pkt = clients[nick]["prefix"]        # 3-byte prefix
    pkt += struct.pack("!I", seqno)[1:]  # 3-byte seq no
    if (len(pkt) != SUMIHDRSZ):
        fatal(5, "internal failure: header not expected size")
    pkt += block
    if (len(pkt) > clients[nick]["mss"]):
        fatal(6, "internal: trying to send packet >MSS, should not happen")

    #src = randip()
    clients[nick]["send"](clients[nick]["src_gen"](), \
                          clients[nick]["dst_gen"](), pkt)
    #send_packet(src, clients[nick]["addr"], pkt, clients[nick]["dchanmode"])
    #print "DATA to %s(%s:%d)<-%s:%d, #%d len=%d (at=%d)" % (nick, clients[nick]["addr"][0], clients[nick]["addr"][1], src[0], src[1], seqno, len(block), clients[nick]["fh"].tell())
    time.sleep(clients[nick]["delay"])

    return len(block)

def in_cksum(str): 
  """Calculate the Internet checksum of str. (Note, when packing for
     a packet, use the <H format specifier.)
     
     From http://mail.python.org/pipermail/python-list/2003-January/137366.html
     with slight Pythonic improvements."""
  csum=0
  countTo=(len(str)/2)*2
  count=0
  while count<countTo:
    thisVal=ord(str[count+1])*256+ord(str[count])
    csum+=thisVal
    csum&=0xffffffffL # Necessary?
    count+=2

  if countTo<len(str):
    csum+=ord(str[len(str)-1])
    csum&=0xffffffffL # Necessary?

  csum=(csum >> 16) + (csum & 0xffff)
  csum+=csum >> 16
  answer=~csum
  answer&=0xffff
  # 0x0000 and 0xffff are equivalent in 1's complement arithmetic,
  # but the latter must be used for UDP checksums as 0 indicates no checksum.
  if answer==0: return 0xffff
  return answer

def sendto_raw(s, data, dst):
    """Send data to a (possibly proxied) raw socket. 
    
    Use instead of sendto()."""

    global raw_proxy
    try:
        if raw_proxy == None:
            r=s.sendto(data, dst)
            log("RET=%s" % r)
        else:
            #print "USING RAW PROXY"
            raw_proxy.send("RP" + struct.pack("!H", len(data)) + data)
            # Return value not useful because it wouldn't be valid here
    except socket.error, e:
        fatal(7, "Couldn't send raw data: %s %s " % (e[0], e[1]))

def send_packet_UDP(src, dst, payload):
    """Send a UDP packet, using one of four modes."""
    if cfg["dchanmode"] == "debug":    # For debugging, no spoofing
        return send_packet_UDP_DEBUG(src, dst, payload)
    elif cfg["dchanmode"] == "raw":    # Raw sockets
        return send_packet_UDP_SOCKET(src, dst, payload)
    elif cfg["dchanmode"] == "pcap":   # Link-layer frames
        return send_packet_UDP_PCAP(src, dst, payload)
    elif cfg["dchanmode"] == "libnet":
        return send_packet_UDP_LIBNET(src, dst, payload)
    # XXX: http://sourceforge.net/forum/forum.php?thread_id=1211034&forum_id=388659
    # http://larytet.sourceforge.net/userManual.shtml#Lesson%203.0
    # Would it be feasible to assign another IP to an interface, or bind to a
    # dummy interface? My initial evaluation: not worth it; interferes too
    # much. The netsh ip address add command changes the IP of the interface
    # completely. Aliases? Dummy interfaces seem too permanent as well.
    else:
        fatal(23, "'dchanmode' must be one of: debug raw pcap libnet")
        return False

def send_packet_UDP_DEBUG(src, dst, payload):
    """Send a non-spoofed UDP packet. Use *only* for debugging!
    
    Utilizes the high(er)-level socket routines; useful because you
    don't need to run as root when testing."""
    log("ns")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(dst)
    s.send(payload)
    s.close()

# This is broken and sometimes produces non-receivable packets...hmm?
def send_packet_UDP_LIBNET(src, dst, payload):
    """Send a UDP packet using pylibnet. Currently broken."""
    ifc = libnet.interface()
    ifc.open_raw(libnet.IPPROTO_UDP)
    pkt = libnet.packet()  # py-libnet no payload??
    pkt.payload = payload
    # XXX: py-libnet has a bug somewhere where the UDP ports are treated as
    # signed, and higher ports will raise an exception.
    pkt.build_udp(src[1], dst[1])
    pkt.build_ip(len(pkt),0,1,0,255,libnet.IPPROTO_UDP,libnet.name_resolve(src[0],0),libnet.name_resolve(dst[0],0))
    #+len(payload) sends the payload twice?? But without it, incorrect cksum
    pkt.do_checksum(libnet.IPPROTO_UDP, libnet.UDP_H + len(payload))
    pkt.do_checksum(libnet.IPPROTO_IP, libnet.IP_H + libnet.UDP_H + len(payload))
    ifc.write(pkt)

def setup_pcap():
    """Verify pcap is available and working."""
    try:
        import pcapy
    except:
        fatal(8, """Couldn't import pcapy. Have you installed either 
WinPcap (for Win32) or libpcap from tcpdump (for Unix)?
Error: %s: %s""" \
        % (sys.exc_info()[0], sys.exc_info()[1]))

    if cfg["interface"] == "":
        devs = pcapy.findalldevs()
        if len(devs) == 1:
            cfg["interface"] = devs[0]
            log("Single network interface, auto-selected %s" %
                    cfg["interface"])

    try:
        p = pcapy.open_live(cfg["interface"], 1500, 1, 0)
    except pcapy.PcapError:
        log("Error opening %s" % cfg["interface"])
        select_if()

    if not hasattr(p, "sendpacket"):
        fatal(10, """Your pcapy is lacking sendpacket, please use modified
pcapy.pyd with SUMI distribution if latest pcapy fails.
On Unix, you may also need a new libpcap that has the
pcap_sendpacket API (see tcpdump.org).""")

    log("pcapy loaded successfully")

def setup_rawproxd():
    """Login to a rawproxd (raw proxy daemon)."""
    global raw_proxy

    raw_proxy_addr_pw = cfg["raw_proxy"].split(" ")

    if len(raw_proxy_addr_pw) == 1:
        raw_proxy_ipport = raw_proxy_addr_pw[0]
        pw = ""
    elif len(raw_proxy_addr_pw) == 2:
        (raw_proxy_ipport, pw) = raw_proxy_addr_pw
    else:
        fatal(11, "Invalid raw proxy format: " + cfg["raw_proxy"])

    raw_proxy_list = raw_proxy_ipport.split(":")
    if len(raw_proxy_list) == 1:
        raw_proxy_ip = raw_proxy_list[0]
        raw_proxy_port = 7010
    elif len(raw_proxy_list) == 2:
        (raw_proxy_ip, raw_proxy_port) = raw_proxy_list
        raw_proxy_port = int(raw_proxy_port)
    else:
       fatal(12, "Invalid raw proxy format2: " + cfg["raw_proxy"])
    log("Using raw proxy server at %s on port %s" %
        (raw_proxy_ip, raw_proxy_port))
    try:
        raw_proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        raw_proxy.connect((raw_proxy_ip, raw_proxy_port))
    except socket.error, e:
        fatal(13, "Raw proxy connection error: %s %s" % (e[0], e[1]))

    # Authenticate
    challenge = raw_proxy.recv(32)
    if len(challenge) != 32:
       log("Couldn't read challenge from raw proxy server: %s" %
               len(challenge))
       sys.exit(-6)

    # Raw proxy still uses MD5
    ctx = md5.md5()
    ctx.update(challenge)
    ctx.update(pw)
    log("Logging into raw proxy...")
    raw_proxy.send(ctx.digest())
    if len(raw_proxy.recv(1)) != 1:
        fatal(14, """Raw proxy refused our password!
Make sure your password is correctly set in sumiserv.cfg. For example,
'raw_proxy': '192.168.1.1:7010 xyzzy'.""")
    if cfg["broadcast"]:
        log("Enabling broadcast support (via rawproxd)")
        raw_proxy.send("RB")  #  raw-socket, set broadcast 

    # sendto_raw() will use raw_proxy to send now 

def setup_raw(argv):
    """Setup the raw socket. Only one raw socket is needed to send any number
    of packets, so it can be created at startup and root can be dropped; 
    alternatively, a setuid program can set envar RAWSOCKFD and pass it here.
    The third option is to set raw_proxy in sumiserv.cfg to the address of a
    server running rawproxd, in which case all raw socket writes will be 
    sent to and sent by that server."""

    global raw_socket, raw_proxy

    set_options = True

    if os.environ.has_key("RAWSOCKFD"):   # Launched from 'launch'
        # fromfd unavailable on Win32. FastCGI for Perl has an ugly hack
        # to use fromfd on Windows, but for now 'launch' is Unix-only.
        if not hasattr(socket, "fromfd"):
            fatal(25, """RAWSOCKFD envar exists, but fromfd is not available
on your system. Sorry, you cannot use 'launch'. Consider using 'rawproxd'.""")
        raw_socket = socket.fromfd(int(os.environ["RAWSOCKFD"]), socket.AF_INET, socket.IPPROTO_UDP)
    elif cfg.has_key("raw_proxy"):          # Remote raw proxy server
        setup_rawproxd()
        set_options = False
    else:    # have to be root, create socket
        if hasattr(os, "geteuid") and hasattr(os, "getuid"):
            log("EUID=%s, UID=%s" % (os.geteuid(), os.getuid()))
        try:
            # IPPROTO_UDP? does it matter?
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        except socket.error, e:
            log("Raw socket error: %s" % e[1])
            if (e[0] == 1):
                if (os.getuid() != 0):
                    log("Tip: run as root, not %s" % os.getuid())
                else:
                    log("Running as root, but error...?")
                os.system("sudo python %s" % argv[0])
                sys.exit(-1)
        # Drop privs-this needs to be worked on
        if hasattr(os, "setuid"):
            os.setuid(os.getuid()) 
            log("Running with uid: %s" % os.getuid())

    # Include header option if needed
    if set_options:
        err = raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if err:
            fatal(15, "setsockopt IP_HDRINCL: %s" % err)

        if cfg["broadcast"]:
            log("Enabling broadcast support")
            err = raw_socket.setsockopt(socket.SOL_SOCKET, 
                                        socket.SO_BROADCAST, 1)
            if err:
                fatal(16, "setsockopt SO_BROADCAST: %s" % err)

    #print "Binding to address:", cfg["bind_address"]
    # XXX: why IPPROTO_UDP? and why even bind? Seems to work without it.
    #raw_socket.bind( (cfg["bind_address"], socket.IPPROTO_UDP) )
    #raw_socket.bind( (cfg["bind_address"], socket.IPPROTO_ICMP) )
    #raw_socket.bind( (cfg["bind_address"], socket.IPPROTO_RAW) )

# TODO: allow other protocols, like ICMP, to use any mode (pcap, etc.)
def send_packet_ICMP(src, dst, payload, type, code):
    """Send an ICMP packet through "dst" (ICMP proxy) to "src". The src and
       dst are swapped by the proxy. Note that "dst" must respond to ICMP 
       echo's, although using multiple ICMP proxies is recommended. Works like:
         (us)ICMP_echo TO:src FROM:dst
       ->(proxy)reply  FROM:src TO:dst
       ->src. The src and dst are swapped by the proxy and sent out.
      You still need to spoof src addresses, so this won't work with NAT.
      PROBLEM: Some hosts only relay X number of bytes, limiting MSS drastically      """
  
    totlen = IPHDRSZ + ICMPHDRSZ + len(payload)

    packet = build_iphdr(totlen, src[0], dst[0], 1)   # 1 = ICMP
    icmphdr = struct.pack("!BBHHH", 
                          type,     # ICMP echo request = 8
                          code,     # no code
                          0,        # checksum (not calculated yet)
                          0,        # identifier
                          0,        # ICMP sequence number
                        )  # ^^ i'd be a good idea to use these for SUMI seqno
                          # ^ actually, no its not, some routers mangle them

    #   Without an ICMP checksum (which is REQUIRED), stacks will drop the
    # packets. Ethereal shows it being received, but its not passed to the
    # receiving raw socket. Routers may also drop it. The checksum is
    # now implemented correctly. The trick is to not include the IP header.
    #   Note, running Ethereal on local machine (even if not loopback) will
    # show "Header checksum: 0x0000 (incorrect, should be [...])" on IP
    # packet headers. The 0 signals to the kernel to calculate it for us.
    # Rest assured, the checksum will be filled in once it leaves the host.
    # (Verified with Ethereal on laptop). 
    checksum = in_cksum(icmphdr + payload)
    # Checksum is little-endian
    icmphdr = struct.pack("!BB", type, code) +  \
              struct.pack("<H", checksum) + \
              struct.pack("!HH", 0, 0)

    packet += icmphdr
    packet += payload
    #raw_socket.sendto(packet, dst) 
    sendto_raw(raw_socket, packet, dst)

def build_udphdr(src, dst, payload):
    """Build a UDP header followed by the payload, given the source and
    destination as (IP, port) tuples. The UDP checksum will be calculated."""
    # Pseudoheader for checksum
    pseudo = struct.pack("!IIBBH", 
        struct.unpack("!I", socket.inet_aton(src[0]))[0],
        struct.unpack("!I", socket.inet_aton(dst[0]))[0],
        0, 17, UDPHDRSZ + len(payload))

    # Build UDP header
    hdr = struct.pack("!HHHH",
        src[1],                              # Source port
        dst[1],                              # Destination port
        UDPHDRSZ + len(payload),
        0,     # Checksum - must set by fixULPChecksum after this call
       )
    if len(hdr) != UDPHDRSZ:
        fatal(17, "internal error: build_udphdr is broken, %d %d" %
                (len(hdr),UDPHDRSZ))

    hdr += payload  #  Checksum data as well
    # Fill in UDP checksum. This is actually optional (it can be 0), but
    # highly recommended. SUMI has no other way to ensure no corruption.
    cksum = int(in_cksum(pseudo + hdr))
    hdr = hdr[:6] + struct.pack("<H",  cksum) + hdr[8:]
    return hdr   # hdr + payload

    return hdr

# TODO: Look into using dpkt http://monkey.org/~dugsong/dpkt/ !
def build_iphdr(totlen, src_ip, dst_ip, type):
    """Return an IP header with given parameters."""
    global cfg

    # A major source of confusion. The IP length field has to be in
    # host byte order for FreeBSD & Windows, network byte order for Linux.
    if (not cfg["IP_TOTLEN_HOST_ORDER"]):
        totlen = socket.htons(totlen)
  
    hdr = struct.pack("!BBHHHBBHII",
        0x40 | IPHDRSZ >> 2,                   # version+IHL little endian
        #payload = ((IPHDRSZ >> 2) << 4) | 4,  # big endian
        0,                                     # DSCP/TOS
        totlen,                                # total length
        0,                                     # IP ID (let kernel)
        0,                                     # Frag offset & flags=none
        128,                                   # Time to live
        type,                                  # UDP=User datagram protocol,etc
        0,                                     # Checksum (fill in below)
        struct.unpack("!L", socket.inet_aton(src_ip))[0], # Source address
        struct.unpack("!L", socket.inet_aton(dst_ip))[0], # Destination address
       );
    # Fill in IP checksum. The kernel will do this for raw sockets,
    # but not for data-link sockets, so just always do it.
    hdr = hdr[:10] + struct.pack("<H", in_cksum(hdr)) + hdr[12:]

    if len(hdr) != IPHDRSZ:
        fatal(18, "internal error: build_iphdr is broken, %d %d" \
                % (len(hdr),IPHDRSZ))
    return hdr

def build_ethernet_hdr(src_mac, dst_mac, type_code):
    """Build Ethernet header (for spoofing on the same network segment).

    Routers replace the MAC with theirs when they route, but if there are no
    routers between the source and destination, the identity will be revealed
    in the source MAC address."""
    # 6-byte addresses
    return struct.pack("!Q", dst_mac)[2:] + \
           struct.pack("!Q", src_mac)[2:] + \
           struct.pack("!H", type_code)

#def send_packet_TCP(src, dst, payload):
    # TODO: TCP aggregates are efficient! So, offer an option to send
    #       spoofed TCP packets, which form streams, so it looks real + valid.
    #       UDP is often discarded more by routers, best of both worlds=TCP!
    #     However, receiving it would require pylibcap, and the extra TCP
    #     segments might confuse the OS TCP stack...
#    log("TODO: implement")
#    assert False, "send_packet_TCP not implemented %s %s %s" % \
#            (src, dst, payload)

def send_packet_UDP_PCAP(src, dst, payload):
    """Send a UDP packet using pcap's pcap_sendpacket.
    This call originated in WinPcap, but newer TcpDump versions of libpcap
    include pcap_sendpacket (and also pcap_inject from OpenBSD, which
    we don't use)."""
    # Regular socket() calls work fine on Win2K/XP, but WinPcap's will work
    # on 95, 98, Me... provided that the winpcap library is installed.
    # Also, sumiserv could run as a non-admin user (more secure), and 
    # WinPcap can spoof data-link addresses.

    # Source and destination addresses -- not sure what to fill in for
    # these, especially destination address. I normally use 
    #dst_mac = 0xFFFFFFFFFFFF    # Broadcast (for now) (TODO: SendARP)
    # TODO: Find out local gateway address..argh
    src_mac = cfg["src_mac"]
    dst_mac = cfg["dst_mac"]
    #src_mac = 0x112233445566

    totlen = IPHDRSZ + UDPHDRSZ + len(payload)
    pkt = build_iphdr(totlen, src[0], dst[0], 17)

    pkt += build_udphdr(src, dst, payload)

    send_frame_ETHER(src_mac, dst_mac, pkt)

def send_frame_ETHER(src_mac, dst_mac, payload, ethertype=0x0800): # IPv4
    """Send a raw Ethernet frame with the given source and destination
    MAC address, payload, and type (defaults to 0x0800, IPv4)."""
    # Send raw Ethernet frames with spoofed source MAC address,
    # Several possible different layers of spoofing:
    # * Spoof Ethernet MAC address, send raw data following
    #   - Useful if on local LAN segment and passes no routers
    # * Spoof MAC + IP
    #   - Useful if routers will pass spoofed source MACs, and the
    #     destination lies beyond a router. Might become de-facto.
    #     Or is it dangerous, as router could fwd IP and change MACs?
    # * Spoof IP 
    #   - No MAC spoofing, useful if routers drop faked MACs - not here
    #
    # If we do decide to implement this, note that the datalink headers
    # need to be included as well. Could perhaps spoof these to thwart
    # detection on a totally switched network? (See build_ethernet_hdr #'s)
    
    import pcapy
    if not cfg.has_key("interface"):
        log("The 'interface' configuration item is not set. ")
        select_if() 
    p = pcapy.open_live(cfg["interface"], 1500, 1, 1)

    if not hasattr(p, "sendpacket"):
        # A NOTE ON THE MODIFIED PCAPY
        # The original pcapy at http://oss.coresecurity.com/projects/pcapy.html
        # (at the time of this writing)
        # does not wrap pcap_sendpacket. Use the modified distribution in
        # pcapy-0.10.3-sendpacket.tar.gz, or the patch pcapy-sendpacket.patch,
        # to build the new pcapy from source. Alternatively, copy pcapy.pyd
        # to C:\Python23\lib\site-packages (or equivalent). 
        #   Update: I sent Maximiliano Caceres the patch, pcap_sendpacket
        # should be in a future release of pcapy.
        fatal(19,
"""pcapy is missing sendpacket - please use modified pcapy.pyd
included with SUMI distribution, or use modified winpcap (see sumiserv.py).""")
        # XXX: WinPcap includess pcap_sendpacket, Unix users may need to
        # apply the patch at
        # http://www.tcpdump.org/lists/workers/2004/03/msg00055.html 
        # if pcap 1.0 hasn't been released yet.
    # TODO: find correct dst_mac, optionally spoof src_map, spoof UDP header
    # ARP cache? arp -a, of default gateway?
    pkt = build_ethernet_hdr(src_mac, dst_mac, ethertype) + payload
    p.sendpacket(pkt)

def select_if():
    """List all network interfaces and tell user to choose one."""
    import pcapy
    #i = 0
    log("Available network interfaces:")
    for name in pcapy.findalldevs():
        #i += 1
        #print "%d. %s" % (i, name)
        log(name)
    log("pcapy error opening interface: %s" % pcapy.PcapError)
    fatal(20, "Please set 'interface' to one of the values in sumiserv.cfg,"+
        "\nthen restart sumiserv.")
    # TODO: GUI to edit configuration file, within program

def send_packet_UDP_SOCKET(src, dst, payload):
    """Send a UDP packet from src to dst.
       This uses the standard socket() functions, and is recommended."""
    global raw_socket

    #print "Sending UDP",src,dst,payload
    totlen = IPHDRSZ + UDPHDRSZ + len(payload)
    
    # Leave the IP checksum 0 -- the kernel will fill it in
    packet = build_iphdr(totlen, src[0], dst[0], 17)
    packet += build_udphdr(src, dst, payload)

    #print packet
    # Win32: socket.error (10049, "Can't assign requested address")
    # ^ If you get that error message, use _socket.pyd (ws2_32 vs. wsock32)
    #raw_socket.sendto(packet, dst)
    sendto_raw(raw_socket, packet, dst)

# Random IP for spoofing
# From http://cvs.sourceforge.net/viewcvs.py/*checkout*/udpp2p/udpp2p/todo?rev=HEAD&content-type=text/plain:
## Adjustable IP randomising. /24, /20, /16?
## Maybe some kind of ping packet to determine how wide the filter that the 
## ISP uses is.
## Eg. If my IP is 60.60.60.60, I should start by pinging with a source 
## address of 50.60.60.60 and see if I get a reply. If yes, then try 
## 40.60.60.60. If no, then try 60.0.0.0. After a few pings, I will have 
## worked out what range of addresses I can spoof that will be allowed through
## the ISPs filters.
# How do they expect to get a reply?? Maybe, set the dest to self, and see
# if it goes through... Also, interface subnet mask
def randip():
    """Generate a random IP and port to use as a source address."""
    # CIDR notation; 4/24 = 4.0.0.0 - 4.255.255.255, masks, and TODO: excludes
    raw_ip = random.randint(0, 2 ** 32)
    raw_ip &= SRC_IP_MASK          # clear where mask 0
    raw_ip |= SRC_IP_ALLOW         # set where allow 1
    str_ip =".".join(map(str,struct.unpack("!BBBB", struct.pack("!I", raw_ip))))
    # TODO: generate another if nonroutable
    #if (is_nonroutable_ip(str_ip)):
    #    print "WARNING: Using non-routable IP"
    return (str_ip, random.randint(0, 65535))

def rand_pingable_host():
    """Return a random host that can be pinged, from 'icmp_proxies'."""
    # List of pingable hosts. Some hosts limit their bytes of the payload to
    # 56 or other small values. To check, use:
    #   sudo ping -s `expr X - 8` google.com
    # where X is the number of bytes to send (payload+ICMP header), default
    # being 64 (this is the limit of google.com). 1466 is good.
    # UPDATE: google.com 216.239.57.99 can take ping -s 1472 (1480 bytes)!
    # UPDATE2: not anymore...
    l = cfg["icmp_proxies"]
    return (l[random.randint(0, len(l) - 1)], 0)

def sendmsg(nick, msg):
    """Dummy function, replaced by the transport to send messages."""
    fatal(24, "somehow sendmsg wasn't set by transport (%s: %s)" % (nick, msg))

def sendmsg_error(nick, msg):
    """Report an error message, if not in quiet mode. Returns False.
    Also destroys client information, assuming a fatal error."""
    if (not cfg["quiet_mode"]):
        sendmsg(nick, "error: %s" % msg)
    log("%s -> error: %s" % (nick, msg))

    clients[nick] = {}
    return False

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

def setup_config():
    """Load file database and configuration."""

    for offer in cfg["filedb"]:
        fn   = offer["fn"]
        if not "gets" in offer: offer["gets"] = 0
        if not "desc" in offer: offer["desc"] = fn
        try:
            size = os.path.getsize(fn)
        except OSError:
            fatal(21, ("Exception occured while reading size of %s" % fn)+
                "\nPlease check that the file exists and is readable.")
        offer["size"] = size
        offer["hsize"] = human_readable_size(size)   
    if cfg["crypto"]: random_init()

_abbrevs = [
    (1 << 50L, "P"),
    (1 << 40L, "T"),
    (1 << 30L, "G"),
    (1 << 20L, "M"),
    (1 << 10L, "k"),
    (1, "")
    ]

def sigusr2(a, b):
    # Doesn't work--can't reload __main__
    #for m in sys.modules.values():
    #    reload(m)
    log("Re-reading config file: %s %s" % (a, b))
    load_cfg() 
 
def main(argv):
    import signal
    if hasattr(signal, "SIGUSR2"):
        signal.signal(signal.SIGUSR2, sigusr2)
        log("Use kill -USR2 %s to reload" % os.getpid())
    else:
        log("No SIGUSR2, not setting up handler")

    setup_config()

    if cfg["dchanmode"] == "raw":
        setup_raw(argv)
    if cfg["dchanmode"] == "pcap" or cfg["transport"] == "aim":
        setup_pcap()

    set_src_allow(cfg["src_allow"])

    if not cfg.has_key("transport"):
        fatal(22, "Please specify 'transport'")
    load_transport(cfg["transport"])

def make_thread(f, arg):
    try:
        f(arg)
    except (KeyboardInterrupt, SystemExit):
        on_exit()
    except KeyError:
        # Client finished while we were trying to help it, oh well
        log("Lost client")
        pass
    except:
        x = sys.exc_info()
        log("Unhandled exception in %s: %s line %s %s" 
                % (f, x[0], x[2].tb_lineno, x[1]))
 
def on_exit():
    global config_file, cfg

    log("Cleaning up...")
    import pprint      # pretty print instead of ugly print repr
    pprint.pprint(cfg, open(config_file, "w"))

    #print "CFG=",cfg
    sys.exit()
    raise SystemExit
    raise KeyboardInterrupt
 
if __name__ == "__main__":
    main(sys.argv)
