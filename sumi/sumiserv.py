#!/usr/bin/env python
# Created:20030402
# By Jeff Connelly

# SUMI server
# Now uses transports/ to communicate with client, and can
# send data using UDP, ICMP, or raw Ethernet

import string
import thread
import base64
import random
import socket
import struct
import sys
import operator
import os
import md5
import time
import Queue

from libsumi import *
from getifaces import get_default_ip, get_ifaces

# Root is exposed here so the config file can use it
root = os.path.abspath(os.path.dirname(sys.argv[0])) + os.sep

def load_cfg():
    """Load configuration file (a Python script)."""
    global root, cfg, config_file
    config_file = root + "sumiserv.cfg"

    print "Using config file: ", config_file
    #eval(compile(open(config_file).read(), "", "exec"))

    cfg = eval("".join(open(config_file, "rU").read()))

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

def fatal(code, msg):
    print "Fatal error #%.2d: %s" % (code, msg)
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


# set_src_allow("4.0.0.0/24") -> allow 4.0.0.0 - 4.255.255.255
def set_src_allow(allow_cidr):
    """Set the allowed source address in CIDR-notation. For example:
       set_src_allow("4.0.0.0/24") -> allow 4.0.0.0 - 4.255.255.255"""
    global SRC_IP_MASK, SRC_IP_ALLOW
    (allow, cidr) = allow_cidr.split("/")
    cidr = int(cidr)
    SRC_IP_MASK = (0xffffffffL >> (32 - cidr) << (32 - cidr))
    allow_list = map(int, allow.split("."))
    a = b = c = d = 0
    try:
        a = allow_list[0]
        b = allow_list[1]
        c = allow_list[2]
        d = allow_list[3]
    except IndexError:    # digits are allowed to be omitted
        pass
    (SRC_IP_ALLOW, ) = struct.unpack("L", struct.pack("BBBB", a, b, c, d))
    # For consistency. SRC_IP_ALLOW bits are only meaningful when the
    # corresponding bits are 1 in SRC_IP_MASK
    SRC_IP_ALLOW &= ~SRC_IP_MASK  
    print "Allowing: %s, mask=%.8x, allow=%.8x" % (allow_cidr, SRC_IP_MASK, SRC_IP_ALLOW)

def recvmsg_secure(nick, msg):
    """Receive an encrypted message."""
    if (clients[nick]["crypto"] == "s"):
        # TODO: Find out if we need to de-base64 it somehow more consistantly
        #print msg
        msg = base64.decodestring(msg)

        #from aes.aes import aes
        #aes_crypto = aes()
        #print "Dec with =",clients[nick]["pkey"]
        #aes_crypto.setKey(clients[nick]["pkey"])
        #msg = aes_crypto.decrypt(msg)
        from Crypto.Cipher import AES
        aes_crypto = AES.new(clients[nick]["pkey"], AES.MODE_CFB)
        msg = aes_crypto.decrypt(msg)
    elif (clients[nick]["crypto"] == "a"):
        msg = base64.decodestring(msg)
        import cPickle

        print "pkey = ", clients[nick]["pkey"]
# bails with:
#AttributeError: RSAobj instance has no attribute '__setitem__'

        key = cPickle.loads(clients[nick]["pkey"])
        if (key.has_private):
            print "Good, key has private"
        msg = key.decrypt(msg)  
        # key.decrypt???
    return msg

def recvmsg(nick, msg, no_decrypt=0):
    """Handle an incoming message."""
    if nick == None and msg == "on_exit":
        on_exit()

    print "<%s>%s" % (nick, msg) 

    if not clients.has_key(nick):
        clients[nick] = {}

    # handle multi-part segmented continued msgs, >asdf\n>asdf\nasdf
    if (msg[0] == ">"):
        if (not clients[nick].has_key("msg")): 
            clients[nick]["msg"] = msg[1:]
        else:
            clients[nick]["msg"] += msg[1:]
        print "ACCUMULATED MSG: ", clients[nick]["msg"]
        return
    else:
        if clients[nick].has_key("msg"):
            msg = clients[nick]["msg"] + msg
            clients[nick]["msg"] = ""
        print "COMPLETE MSG: ", msg   # Now handle

    # If encrypted, decrypt
    if clients.has_key(nick) and clients[nick].has_key("crypto") \
        and not no_decrypt:       # its encrypted
        #print nick,"IS SECURED"
        msg = recvmsg_secure(nick, msg)
        print "(*%s): %s" % (nick, msg)

    # If transfer in progress, allowed to use abbreviated protocol
    if (clients.has_key(nick) and clients[nick].has_key("authenticated") and \
        clients[nick]["authenticated"] == 2):
        transfer_control(nick, msg)


    if (msg.find("sumi sec ") == 0):        # should be as opaque as possible
        print nick, " is request security"   
        args = msg[len("sumi sec "):]
        # This is sent in the clear, so it should be made uniform and
        # not suspicious. Instead of using pack_args(), go for something like
        #   <X><key>
        # where X is one byte: O=one-time pad, S=symmetric, A=asymmetric 
        #                   ^ or lowercase if wants to encrypt acks, too!
        clients[nick] = { }
        clients[nick]["preauth"] = 1
        clients[nick]["crypto"] = args[0]
        key_ = args[1:]
        clients[nick]["sec_acks"] = 0
        if (clients[nick]["crypto"] >= "a" and
            clients[nick]["crypto"] <= "z"):
            clients[nick]["sec_acks"] = 1
        #print "sec_acks=",clients[nick]["sec_acks"] 
        try:
            print "Decoding ",key_
            key_ = base64.decodestring(key_ + "=")
        except None: #base64.binascii.Error:
            clients[nick] = {}     # forget them, they dont know how to b64
            return sendmsg_error(nick, "sec invalid key")
        if (clients[nick]["crypto"] == "O" or clients[nick]["crypto"] == "o"):
            clients[nick]["otppos"] = struct.unpack("!L", key_[0:4])
            clients[nick]["otpid"] = key_[4:]
            print "pos=",clients[nick]["otppos"]
            print "otpid=",clients[nick]["otpid"]
        else:
            clients[nick]["pkey"] = key_   # pre-auth key
            print "Yeah the pw is",key_
            clients[nick]["passwd"] = clients[nick]["pkey"]  # backwards
    elif (msg.find("sumi send ") == 0):
        print nick, "is sumi sending"
        if (clients.has_key(nick) and not clients[nick].has_key("preauth")):
            print "CLEARING LEFT OVERS"
            clients[nick].clear()
        msg = msg[len("sumi send "):]
        try: 
            #(file, offset, ip, port, mss, b64prefix, speed)=msg.split("\t") 
            args = unpack_args(msg)
            print "ARGS=",args
            file     = args["f"]
            offset   = int(args["o"])
            ip       = args["i"]
            port     = int(args["n"])
            mss      = int(args["m"])
            b64prefix= args["p"] 
            speed    = int(args["b"])   # b=bandwidth
            rwinsz   = int(args["w"])
            dchantype= args["d"]            
            crypto   = None
            passwd   = None
            otpfile  = None
            if args.has_key("x"): crypto = args["x"]
            # Don't do this; moved to sumi sec
            #if args.has_key("K"): passwd = base64.decodestring(args["K"])
            if args.has_key("O"): otpfile = args["O"]
            if args.has_key("@"): otpfile = args["@"]
        except KeyError:
             print "not enough fields/missing fields"
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
        print "Verifying MSS"
        if (mss < 256):
            return sendmsg_error(nick, "MSS too small: %d" % (mss,))
        if (mss > cfg["global_mss"]):
            return sendmsg_error(nick, "MSS too large")

        # Prefix is base64-encoded for IRC transport
        # Note: There is no need to use Base85 - Base94 (RFC 1924) because
        # it can increase by a minimum of one byte. yEnc might work, but
        # its not worth it really. Base64 is perfect for encoding these 3 bytes
        print "Decoding prefix"
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

        # TODO: make sure the filename/pack number is valid, and we have it
        print"nick=%s,FILE=%s,OFFSET=%d,IP=%s:%d MSS=%d PREFIX=%02x%02x%02x" % (
              nick, file, offset, ip, port, mss, ord(prefix[0]), \
              ord(prefix[1]), ord(prefix[2]))

        # Build the authentication packet using the client-requested prefix
        key = "%s\0\0\0" % prefix       # 3-byte prefix, 3-byte seqno (0)
        if (len(key) != SUMIHDRSZ):
            return sendmsg_error(nick, "key + seqno != SUMIHDRSZ")

        #clients[nick] = {}   # This appears to be done up there ^^^
        if (file[0] == "#"):
            clients[nick]["file"] = int(file[1:]) - 1
        else:
            return sendmsg_error(nick, "file must be integer") 
        clients[nick]["offset"] = int(offset)
        clients[nick]["addr"] = (ip, port)
        clients[nick]["mss"] = int(mss)
        clients[nick]["prefix"] = prefix
        clients[nick]["speed"] = int(speed)
        clients[nick]["authenticated"] = 1   # first step complete
        clients[nick]["xfer_lock"] = thread.allocate_lock()  # lock to pause
        clients[nick]["rwinsz"] = rwinsz 
        clients[nick]["dchantype"] = dchantype
 
        # The data channel type determins how to send, and make src & dst addrs
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
             #(type, code) = dchantype[1:].split(",")
             #type = int(type)
             #code = int(code)
             type = port / 0x100
             code = port % 0x100
             print "type,code=",type,code
             clients[nick]["send"] = \
                 lambda s,d,p: send_packet_ICMP(s, d, p, type, code)
             clients[nick]["src_gen"] = randip
             clients[nick]["dst_gen"] = lambda : clients[nick]["addr"]
        else:
             sendmsg_error(nick, "invalid dchantype")
        # TODO:others: t (TCP)

        clients[nick]["ack_ts"] = time.time()
        clients[nick]["crypto"] = crypto

        if (clients[nick]["crypto"] == "o"):    # one-time pad
            clients[nick]["otpfile"] = open(cfg["otpdir"] + otpfile, "rb")
            # Per-client OTPs are best, otherwise, anyone with the OTP can
            # intercept, and if client sends OTP file offset it hasn't use
            # yet, but we have used already up to, then client has to use
            # our offset, resulting in gaps unused/used in the pad, which may
            # be too large to transfer other files in..a housekeeping mess.
            clients[nick]["otppos"] = otppos

            # XXX: to XOR two strings, use: (my own creation)
            # "".join(map(chr, map(operator.xor, map(ord, a), map(ord, b))))
            # Also, auth packet should be encrypted too, and data packets.
            # Everything should be encryptable except the prefix, otherwise
            # client won't know how to decrypt(prefix=virtual address).
          # AES encryption often makes it larger - encrypt file only, before
          # sending?
        elif (clients[nick]["crypto"] == "s"):   # symmetric
            #clients[nick]["passwd"] = passwd
            print "SYMMETRIC"
        # TODO: put information about the file here. hash?

        try:
            # XXX: This should be the encrypted size; size on wire.
            authhdr = struct.pack("!L", \
            os.path.getsize(cfg["filedb"][clients[nick]["file"]]["fn"]))
        except IndexError:
            return sendmsg_error(nick, "no such pack number")

        # 24-bit prefix. The server decides on the prefix to use for the auth
        # packet, but here we embed the prefix that we, the server, decide to
        # use for the data transfer. 
        clients[nick]["prefix1"] = clients[nick]["prefix"]   # first prefix

        if casts.has_key(clients[nick]["addr"]):
            # Use prefix of client already sending to
            print "Multicast detected:", clients[nick]["addr"],":",\
                  casts[clients[nick]["addr"]]

            cs = casts[clients[nick]["addr"]]
            found = 0
            for c in cs:
                if clients.has_key(c) and clients[c].has_key("authenticated") and clients[c]["authenticated"] == 2:
                    clients[nick]["prefix"] = clients[c]["prefix"]
                    found = 1
                    break

            if found == 0:
                print "No transferring clients found, assuming unicast"
                casts[clients[nick]["addr"]] = { nick: 1 }
                mcast = 0
            else:
                casts[clients[nick]["addr"]][nick] = 1

                print "    Using old prefix: %02x%02x%02x" % \
                    (ord(clients[nick]["prefix"][0]), \
                     ord(clients[nick]["prefix"][1]), \
                     ord(clients[nick]["prefix"][2]))
                mcast = 1
        else:
            # An array would do here, but a hash easily removes the possibility
            # of duplicate keys. List of clients that have the same address.
            casts[clients[nick]["addr"]] = { nick: 1 }
            mcast = 0
        clients[nick]["mcast"] = mcast

        # Used for data transfer, may differ from client-chosen auth pkt prefix
        authhdr += clients[nick]["prefix"]

        authhdr += chr(mcast) 

        authhdr += os.path.basename(cfg["filedb"][clients[nick]["file"]]["fn"]+\
                   "\0");  # Null-term'd

        #if (len(authhdr) != SUMIAUTHHDRSZ):
        #    print "internal error: auth header incorrect"
        #    sys.exit(-4)
        key += authhdr

        # Payload is random data to fill MSS
        for i in range(mss - SUMIHDRSZ - len(authhdr)):
            key += struct.pack("B", random.randint(0, 255))
        if (len(key) != mss):
            # This is an internal error, and should never happen, but might
            return sendmsg_error(nick, "bad key generation: %d != %d" % (
                                       len(key), mss))
        clients[nick]["key"] = key       # Save so can hash when find out MSS

        # Send raw UDP from: src_gen(), to: dst_gen()
        # This will trigger client to send sumi auth
        clients[nick]["asrc"] = clients[nick]["src_gen"]()
        # Note, if execution reaches here and then stops, its a problem
        # with a) the server sending the packet b) the client receiving the
        # packet (in both cases, the authentication packet). Some ICMP codes
        # blocked/handled by kernel, for example, or src may be blocked.
        print "Sending auth packet now."
        clients[nick]["send"](clients[nick]["asrc"], \
                              clients[nick]["dst_gen"](), key)
        print " AUTH PREFIX=%02x%02x%02x" % (ord(key[0]), \
            ord(key[1]), ord(key[2]))
        #send_packet(clients[nick]["asrc"], (ip, port), key)
 
    elif (msg.find("sumi auth ") == 0):
        if (not clients.has_key(nick) or clients[nick]["authenticated"] != 1):
            return sendmsg_error(nick, "step 1 not complete")

        print "message: ", msg
        msg = msg[len("sumi auth "):]
        #(their_mss, asrc, hash) = msg.split("\t")
        args = unpack_args(msg)
        print "args: ", args
        their_mss = int(args["m"])
        asrc      = args["s"]
        hash      = args["h"]
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
            print "Downgrading MSS of %s: %d->%d" % (nick, clients[nick]["mss"], their_mss)
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
        print "Using send delay: ",clients[nick]["delay"]
           
        print "Verifying spoofing capabilities..."
        if (clients[nick]["asrc"][0] != asrc):
            print "*** Warning: Possible spoof failure! We sent from %s,\n"\
                  "but client says we sent from %s. If this happens often,"\
                  "either its a problem with your ISP, or the work of\n"\
                  "mischevious clients. Dropping connection." % (clients[nick]["asrc"][0], asrc)
            #return sendmsg_error(nick, "srcip")
        
        print "Verifying authenticity of client..."
        # The hash has to be calculated AFTER the auth string is received so
        # we know how much of it to hash (number of bytes: the MSS)
        if (their_mss > len(clients[nick]["key"])):   # trying to overflow, eh..
            return sendmsg_error(nick, "claimed MSS > keylength!")

        # The client may have truncated the datagram to match their MSS
        context = md5.md5() 
        context.update(clients[nick]["key"][0:clients[nick]["mss"]])

        #derived_hash = context.hexdigest()
        derived_hash = base64.encodestring(context.digest())[:-1]
        if (derived_hash != hash):
            return sendmsg_error(nick, "hash: %s != %s" % (derived_hash, hash))

        #XXX  Setup crypto on our part
        ## THIS ALL SHOULD BE MOVED INTO PRE-AUTH (sumi sec)
        if clients[nick]["crypto"] == "s":
            from aes.aes import aes
            aes_crypt = aes()
            print "PW=",clients[nick]["passwd"]
            aes_crypt.setKey(clients[nick]["passwd"])
            ciphered = open(cfg["filedb"][clients[nick]["file"]]["fn"] + ".aes", "wb+")
            ciphered.write(aes_crypt.encrypt(   \
                open(cfg["filedb"][clients[nick]["file"]]["fn"], "rb").read()))
            ciphered.close()
            clients[nick]["fh"] = \
                open(cfg["filedb"][clients[nick]["file"]]["fn"] + ".aes", "rb")
        else:
            clients[nick]["fh"] = \
                open(cfg["filedb"][clients[nick]["file"]]["fn"], "rb")   


        # Find size...
        clients[nick]["fh"].seek(0, 2)   # SEEK_END
        clients[nick]["size"] = clients[nick]["fh"].tell()
        clients[nick]["fh"].seek(0, 0)   # SEEK_SET

        print "Starting transfer to %s..." % nick
        print "Sending: ", cfg["filedb"][clients[nick]["file"]]["fn"]
        ##

        print nick,"is fully verified!"
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
            print "Since multicast, not starting another transfer"
            return
        else:
            print "Unicast - starting transfer"

        # In a separate thread to allow multiple transfers
        #thread.start_new_thread(xfer_thread, (nick,))
        thread.start_new_thread(make_thread, (xfer_thread_loop, nick,))
        #make_thread(xfer_thread, nick)
    elif (msg.find("sumi dir ") == 0):
        # Directory list TODO
        pass
    elif (msg.find("sumi done") == 0):
        # Possible thread concurrency issues here. Client can do sumi done at
        # any time, which will result in accessing nonexistant keys
        print "Transfer to %s complete\n" % nick
        try:
            casts[clients[nick]["addr"]].remove(nick)
        except:
            pass
        if (clients[nick].has_key("file")):
            cfg["filedb"][clients[nick]["file"]]["gets"] += 1
            print "NUMBER OF GETS: ", cfg["filedb"][clients[nick]["file"]]["gets"]
        else:
            print "Somehow lost filename"
        destroy_client(nick)

def load_transport(transport):
    """Load the transport module used for the backchannel. This is similar
    to sumiget's load_transport, but the transport is used for ALL transfers;
    not on a per-user basis as with sumiget."""
    global sendmsg
    # Import the transport. This may fail, if, for example, there is
    # no such transport module.
    print sys.path
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

    #clients[nick]["sendmsg"] = t.sendmsg
    #clients[nick]["recvmsg"] = t.recvmsg
    #clients[nick]["transport_init"] = t.transport_init
    t.transport_init()
    sendmsg = t.sendmsg
    t.recvmsg(recvmsg)

def capture(decoder, filter, callback):
    """Generic function to capture packets using pcapy, available to
    transports. Useful to receive incoming messages without proxying. Never
    returns."""

    import pcapy
    print "Receiving messages on ", cfg["interface"]
    # 1500 bytes, promiscuous mode.
    p = pcapy.open_live(cfg["interface"], 1500, 1, 0)
    if filter:
        p.setfilter(filter)
    while 1:
        pkt = p.next()
        pkt_data = pkt[1]
        (user, msg) = decoder(pkt_data)
        #(sn, msg) = decode_aim(get_tcp_data(pkt_data))
        if user:
            #print "<%s> %s" % (sn, msg)
            callback(user, msg)

def get_tcp_data(pkt_data):
    """Returns the TCP data of an Ethernet frame, or None."""
    return get_transport_data(pkt_data, 20)

def get_transport_data(pkt_data, transport_size):
    """Returns the data inside a transport header of transport_size
    encapsulated in IPv4 over Ethernet, or None."""
    try:
        # TODO: Other transport types besides Ethernet
        eth_hdr = pkt_data[0:14]     # Dst MAC, src MAC, ethertype
        ip_hdr = pkt_data[14:14+20]  # 20-byte IPv4 header (no opts)
        t_hdr = pkt_data[14+20:14+20+transport_size]  # 20-byte TCP header
        t_data = pkt_data[14+20+transport_size:]
    except:
        return None
    return t_data

def get_udp_data(pkt_data):
    """Return the UDP data of an Ethernet frame, or None."""
    return get_transport_data(pkt_data, 8)


def xfer_thread_loop(nick):
    """Transfer the file, possibly in a loop for multicast."""
    if 0 and clients[nick]["mcast"]: 
       i = 0
       while 1:
           print "Multicast detected - loop #%d" % i  # "data carousel"
           i += 1
           xfer_thread(nick)
    else:
       xfer_thread(nick)

# TODO: The following conditions need to be programmed in:
# * If peer QUITs, kill transfer
# * If peer doesn't send NAK within 2*RWINSZ, pause transfer (allocate_lock?)
# * If above, and peer sends a NAK again, release the lock allowing to resume
# * If peer is paused for >=30s, kill transfer
# XXX: ^^ This is all important, because right now a dead client isn't noticed
def xfer_thread(nick):
    """File transfer thread, called for each file transfer."""
    print "clients[nick][seqno] exists?", clients[nick].has_key("seqno")

    blocksz = clients[nick]["mss"] - SUMIHDRSZ
    while 1:
        # Resend queued resends if they come up, but don't dwell
        try:
            while 1:
                resend = resend_queue.get_nowait()   # TODO: multiple users!
                print "Q: ",nick,resend
                datapkt(nick, resend)
        except Queue.Empty:
            print "Q: empty"
            pass

        if (clients[nick]["seqno"]):
            blocklen = datapkt(nick, clients[nick]["seqno"])

        ## If haven't received ack from user since RWINSZ*5, pause
        # ^ now we stop instead
        d = time.time() - clients[nick]["ack_ts"]
        if (float(d) >= float(clients[nick]["rwinsz"] * 5)):
            #clients[nick]["xfer_lock"].acquire() 
            print "Since we haven't heard from %s in %f (> %d), stopping" %  \
                (nick, int(d), float(clients[nick]["rwinsz"] * 5))
            clients[nick]["xfer_stop"] = 1

        # If transfer lock is locked (pause), then wait until unpaused
        #  might be better for us to stop transfer in 2*RWINSZ, but be polite
        if (clients[nick]["xfer_lock"].locked()):
            print "TRANSFER TO",nick,"PAUSED"
            clients[nick]["xfer_lock"].acquire()
            print "TRANSFER TO",nick,"RESUMED"

        if (clients[nick].has_key("xfer_stop")):
            print "TRANSFER TO",nick,"STOPPED:",clients[nick]["xfer_stop"]
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

    print "Transfer complete."

def destroy_client(nick):
    print "Severing all ties to",nick
    try:
        casts[clients[nick]["addr"]].pop(nick)
        if len(casts[clients[nick]["addr"]]) == 0:
            print "Last client for",clients[nick]["addr"],"exited:",nick
            # TODO: stop all transfers to this address
            casts.pop(clients[nick]["addr"])
        clients.pop(nick)
    except:
        pass

def transfer_control(nick, msg):
    """Handle an in-transfer control message."""
    global resend_queue
    print "(authd)%s: %s" % (nick, msg)
    if (msg[0] == "k"):     # TFTP-style transfer, no longer supported here
        pass 
    elif (msg[0] == "n"):          # n<win>,<resend-1>,<resend-2> (neg acks)
        resends = msg[1:].split(",")
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
                print "Invalid packet number: %s" % resend;
                continue
            print "Queueing resend of %d" % (resend)
            resend_queue.put(resend)
    elif msg[0] == '!':        # abort transfer
        print "Aborting transfer to ", nick
        destroy_client(nick)

def datapkt(nick, seqno):
    """Send data packet number "seqno" to nick, for its associated file. 
       Returns the length of the block sent."""
    if (seqno > 16777216):   # 8-10GB is limit, depends on MSS
        clients[nick] = []
        return sendmsg_error(nick, "file too large")

    if (random.randint(0, 100) == 0):   # lose packet (testing purposes)
        return 1466

    blocksz = clients[nick]["mss"] - SUMIHDRSZ

    print "Sending to ",nick,"#",seqno,blocksz
    #print "I AM GOING TO SEEK TO ",blocksz*(seqno-1)

    #if (blocksz * (seqno - 1)) > clients[nick]["size"]:
    #    print nick,"tried to seek past end-of-file"
    #    return

    # Many OS's allow seeking past the end of file
    clients[nick]["fh"].seek(blocksz * (seqno - 1))

    block = clients[nick]["fh"].read(blocksz)

    pkt = clients[nick]["prefix"]        # 3-byte prefix
    pkt += struct.pack("!L", seqno)[1:]  # 3-byte seq no
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

# From http://mail.python.org/pipermail/python-list/2003-January/137366.html.
def in_cksum(str): 
  """Calculate the Internet checksum of str. (Note, when packing for
     a packet, use the <H format specifier.)"""
  sum=0
  countTo=(len(str)/2)*2
  count=0
  while count<countTo:
    thisVal=ord(str[count+1])*256+ord(str[count])
    sum=sum+thisVal
    sum=sum & 0xffffffffL # Necessary?
    count=count+2

  if countTo<len(str):
    sum=sum+ord(str[len(str)-1])
    sum=sum & 0xffffffffL # Necessary?

  sum=(sum >> 16) + (sum & 0xffff)
  sum=sum+(sum >> 16)
  answer=~sum
  answer=answer & 0xffff
  # 0x0000 and 0xffff are equivalent in 1's complement arithmetic,
  # but the latter must be used for UDP checksums as 0 indicates no checksum.
  if answer==0: return 0xffff
  return answer

# Send data to raw socket, use this in place of sendto()
def sendto_raw(s, data, dst):
    """Send data to a (possibly proxied) raw socket."""
    global raw_proxy
    try:
        if raw_proxy == None:
            r=s.sendto(data, dst)
            print "RET=",r
        else:
            #print "USING RAW PROXY"
            raw_proxy.send("RP" + struct.pack("!H", len(data)) + data)
    except socket.error, e:
        fatal(7, "Couldn't send raw data: %s %s " % (e[0], e[1]))

def send_packet_UDP(src, dst, payload):
    if cfg["dchanmode"] == "debug":    # For debugging, no spoofing
        return send_packet_UDP_DEBUG(src, dst, payload)
    elif cfg["dchanmode"] == "raw":    # Raw sockets
        return send_packet_UDP_SOCKET(src, dst, payload)
    elif cfg["dchanmode"] == "pcap":   # Link-layer frames
        return send_packet_UDP_PCAP(src, dst, payload)
    elif cfg["dchanmode"] == "libnet":
        return send_packet_UDP_LIBNET(src, dst, payload)

# Send non-spoofed packet. For debugging purposes ONLY.
# This uses the high(er)-level socket routines; its useful because you
# don't need to run as root when testing it.
def send_packet_UDP_DEBUG(src, dst, payload):
    """Send a non-spoofed UDP packet. Use only for debugging!"""
    print "ns",
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
            print "Single network interface, auto-selected", cfg["interface"]

    try:
        p = pcapy.open_live(cfg["interface"], 1500, 1, 0)
    except pcapy.PcapError:
        print "Error opening ", cfg["interface"]
        select_if()

    if not hasattr(p, "sendpacket"):
        fatal(10, """Your pcapy is lacking sendpacket, please use modified
pcapy.pyd with SUMI distribution if latest pcapy fails.
On Unix, you may also need a new libpcap that has the
pcap_sendpacket API (see tcpdump.org).""")

    print "pcapy loaded successfully"

def setup_raw(argv):
    """Setup the raw socket. Only one raw socket is needed to send any number
    of packets, so it can be created at startup and root can be dropped; 
    alternatively, a setuid program can set envar RAWSOCKFD and pass it here.
    The third option is to set raw_proxy in sumiserv.cfg to the address of a
    server running rawproxd, in which case all raw socket writes will be 
    sent to and sent by that server."""

    global raw_socket, raw_proxy

    set_options = 1

    if (os.environ.has_key("RAWSOCKFD")):   # Launched from 'launch'
        # fromfd unavailable on Win32. FastCGI for Perl has an ugly hack
        # to use fromfd on Windows, but for now 'launch' is Unix-only.
        raw_socket = socket.fromfd(int(os.environ["RAWSOCKFD"]), socket.AF_INET, socket.IPPROTO_UDP)
    elif cfg.has_key("raw_proxy"):          # Remote raw proxy server
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
        print "Using raw proxy server at",raw_proxy_ip,"on port",raw_proxy_port
        try:
            raw_proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            raw_proxy.connect((raw_proxy_ip, raw_proxy_port))
        except socket.error, e:
            fatal(13, "Raw proxy connection error: %s %s" % (e[0], e[1]))

        # Authenticate
        challenge = raw_proxy.recv(32)
        if len(challenge) != 32:
           print "Couldn't read challenge from raw proxy server: ", len(challenge)
           ss.exit(-6)

        ctx = md5.md5()
        ctx.update(challenge)
        ctx.update(pw)
	print "Logging into raw proxy...";
        raw_proxy.send(ctx.digest())
        if len(raw_proxy.recv(1)) != 1:
            fatal(14, """Raw proxy refused our password!
Make sure your password is correctly set in sumiserv.cfg. For example,
'raw_proxy': '192.168.1.1:7010 xyzzy'.""")
        if cfg["broadcast"]:
            print "Enabling broadcast support (via rawproxd)"
            raw_proxy.send("RB")  #  raw-socket, set broadcast 

        set_options = 0
        
        # sendto_raw() will use raw_proxy to send now 
    else:    # have to be root, create socket
        if (dir(os).__contains__("geteuid")):
            print "EUID=", os.geteuid(), "UID=", os.getuid()
        try:
            # IPPROTO_UDP? does it matter?
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        except socket.error, e:
            print "Raw socket error:", e[1]
            if (e[0] == 1):
                if (os.getuid() != 0):
                    print "Tip: run as root, not",os.getuid()
                else:
                    print "Running as root, but error...?"
                os.system("sudo python %s" % argv[0])
                sys.exit(-1)
        # Drop privs-this needs to be worked on
        if (dir(os).__contains__("setuid")):
            os.setuid(os.getuid()) 
            print "Running with uid: ", os.getuid()

    # Include header option if needed
    if set_options:
        err = raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if err:
            fatal(15, "setsockopt IP_HDRINCL: ",err)

        if cfg["broadcast"]:
            print "Enabling broadcast support"
            err = raw_socket.setsockopt(socket.SOL_SOCKET, 
                                        socket.SO_BROADCAST, 1)
            if err:
                fatal(16, "setsockopt SO_BROADCAST: ",err)

    #print "Binding to address:", cfg["bind_address"]
    # XXX: why IPPROTO_UDP? and why even bind? Seems to work without it.
    #raw_socket.bind( (cfg["bind_address"], socket.IPPROTO_UDP) )
    #raw_socket.bind( (cfg["bind_address"], socket.IPPROTO_ICMP) )
    #raw_socket.bind( (cfg["bind_address"], socket.IPPROTO_RAW) )

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
    pseudo = struct.pack("!LLBBH", 
        struct.unpack("!L", socket.inet_aton(src[0]))[0],
        struct.unpack("!L", socket.inet_aton(dst[0]))[0],
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
  
    hdr = struct.pack("!BBHHHBBHLL",
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
    # Build Ethernet header (for spoofing on the same network segment)
    # Routers replace the MAC with theirs when they route, but if there are no
    # routers between the source and destination, the identity will be revealed
    # in the source MAC address.
    # To send, might need to write a driver for Win32:
    #   http://www.thecodeproject.com/csharp/SendRawPacket.asp
    # Libnet on Unix?
    # 6-byte addresses
    return struct.pack("!Q", dst_mac)[2:] + \
           struct.pack("!Q", src_mac)[2:] + \
           struct.pack("!H", type_code)

def send_packet_TCP(src, dst, payload):
    # TODO: TCP aggregates are efficient! So, offer an option to send
    #       spoofed TCP packets, which form streams, so it looks real + valid.
    #       UDP is often discarded more by routers, best of both worlds=TCP!
    #     However, receiving it would require pylibcap, and the extra TCP
    #     segments might confuse the OS TCP stack...
    print "TODO: implement"

def send_packet_UDP_PCAP(src, dst, payload):
    """Send a UDP packet using pcap's pcap_sendpacket.
    This call originated in WinPcap, but newer TcpDump versions of libpcap
    include pcap_sendpacket (and also pcap_inject from OpenBSD)."""
    # Regular socket() calls work fine on Win2K/XP, but WinPcap's will work
    # on 95, 98, Me... provided that the winpcap library is installed.
    # Also, sumiserv could run as a non-admin user (more secure), and 
    # WinPcap can spoof data-link addresses.
    src_mac = cfg["src_mac"]
    dst_mac = cfg["dst_mac"]
    #src_mac = 0x112233445566
    #dst_mac = 0xFFFFFFFFFFFF    # Broadcast (for now) (TODO: SendARP)

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
    
    # pcap_open_live()
    # pcap_send_packet()
    import pcapy
    if not cfg.has_key("interface"):
        print "The 'interface' configuration item is not set. "
        select_if() 
    p = pcapy.open_live(cfg["interface"], 1500, 1, 1)

    if not hasattr(p, "sendpacket"):
        # A NOTE ON THE MODIFIED PCAPY
        # The original pcapy at http://oss.coresecurity.com/projects/pcapy.html
        # does not wrap pcap_sendpacket. Use the modified distribution in
        # pcapy-0.10.3-sendpacket.tar.gz, or the patch pcapy-sendpacket.patch,
        # to build the new pcapy from source. Alternatively, copy pcapy.pyd
        # to C:\Python23\lib\site-packages (or equivalent).
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
    print "Available network interfaces:"
    for name in pcapy.findalldevs():
        #i += 1
        #print "%d. %s" % (i, name)
        print name
    print "pcapy error opening interface: %s" % pcapy.PcapError
    fatal(20, "Please set 'interface' to one of the values in sumiserv.cfg,"+
        "\nthen restart sumiserv.")
    # TODO: GUI to edit configuration file, within program

# Send packet from given source.
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
    raw_ip &= SRC_IP_MASK
    raw_ip |= SRC_IP_ALLOW
    str_ip = ".".join(map(str, struct.unpack("BBBB", struct.pack("L", raw_ip))))
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

def sendmsg_error(nick, msg):
    """Report an error message, if not in stealth mode."""
    if (not cfg["stealth_mode"]):
        sendmsg(nick, "error: %s" % msg)
    print "%s -> error: %s" % (nick, msg)

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
        gets = offer["gets"]
        fn   = offer["fn"]
        desc = offer["desc"]
        try:
            size = os.path.getsize(fn)
        except OSError:
            fatal(21, ("Exception occured while reading size of %s" % fn)+
                "\nPlease check that the file exists and is readable.")
        offer["size"] = size
        offer["hsize"] = human_readable_size(size)   

_abbrevs = [
    (1 << 50L, "P"),
    (1 << 40L, "T"),
    (1 << 30L, "G"),
    (1 << 20L, "M"),
    (1 << 10L, "k"),
    (1, "")
    ]

def sigusr2(a, b):
    print "Re-reading config file"
    load_cfg() 
 
def main(argv):
    import signal
    if hasattr(signal, "SIGUSR2"):
        signal.signal(signal.SIGUSR2, sigusr2)
    else:
        print "No SIGUSR2, not setting up handler"

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
    except KeyboardInterrupt, SystemExit:
        on_exit()
    except KeyError:
        # Client finished while we were trying to help it, oh well
        print "Lost client"
        pass
    except:
        import sys
        x = sys.exc_info()
        print "Unhandled exception in ",f,": ",x[0]," line",x[2].tb_lineno,x[1]
 
def on_exit():
    global config_file, cfg

    print "Cleaning up..."
    import pprint      # pretty print instead of ugly print repr
    pprint.pprint(cfg, open(config_file, "w"))

    #print "CFG=",cfg
    sys.exit()
    sys._exit(1)
    raise SystemExit
    raise KeyboardInterrupt
 
if __name__ == "__main__":
    main(sys.argv)
