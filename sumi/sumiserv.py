#!/usr/bin/env python
# Created:20030402
# By Jeff Connelly

# SUMI server
# Communicates with client via IRC, sends data via UDP

# TODO: This needs to be generalized to use transports like sumiget.
# However, transports must be made 2-way and more informative before this
# happens.

import string
import thread
import irclib
from irclib import nm_to_n
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
    global root, cfg, config_file
    config_file = root + "sumiserv.cfg"

    print "Using config file: ", config_file
    #eval(compile(open(config_file).read(), "", "exec"))

    cfg = eval("".join(open(config_file, "r").read()))

load_cfg()

# Initial values below shouldn't need to be configured
resend_queue = Queue.Queue(0)
clients = { }
SUMIHDRSZ = 6 
IPHDRSZ = 20 
ICMPHDRSZ = 8
UDPHDRSZ = 8  
raw_socket = 0

# https://sourceforge.net/tracker/?func=detail&atid=105470&aid=860134&group_id=5
470
# https://sf.net/tracker/?group_id=5470&atid=105470&func=detailed&aid=860134
# This is for Win32
if (not hasattr(socket, "IP_HDRINCL")):
    print "Your Python is not using Winsock 2.0. Please upgrade."

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
            rwinsz   = args["w"]
            dchantype= args["d"]            
            crypto   = None
            passwd   = None
            otpfile  = None
            if args.has_key("x"): crypto = args["x"]
            # Don't do this; moved to sumi sec
            #if args.has_key("K"): passwd = base64.decodestring(args["K"])
            if args.has_key("O"): otpfile = args["O"]
            if args.has_key("@"): otpfile = args["@"]
        except None:# KeyError:
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

        # TODO: make sure the filename/pack number is valid, and we have it
        print "nick=%s, FILE=%s, OFFSET=%d, IP=%s:%d MSS=%d PREFIX=%s" % (
              nick, file, offset, ip, port, mss, b64prefix)

        # Build the authentication packet
        key = "%s\0\0\0" % prefix       # 3-byte prefix, 3-byte seqno 0
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
            clients[nick]["send"] = send_packet_UDP_SOCKET
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
             # XXX: Why is type+code inside dchantype and not myport?
             # TODO: Put type+code in myport, possibly packed, unify it
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

        # XXX: This should be the encrypted size; size on wire.
        authhdr = struct.pack("!L", \
            os.path.getsize(cfg["filedb"][clients[nick]["file"]]["fn"]))
        #XYZ
        authhdr += os.path.basename(cfg["filedb"][clients[nick]["file"]]["fn"] + \
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
        print "Starting transfer to %s..." % nick
        print "Sending: ", cfg["filedb"][clients[nick]["file"]]["fn"]
        ##

        print nick,"is fully verified!"
        clients[nick]["authenticated"] = 2    # fully authenticated, let xfer

        # In a separate thread to allow multiple transfers
        #thread.start_new_thread(xfer_thread, (nick,))
        thread.start_new_thread(make_thread, (xfer_thread, nick,))
        #make_thread(xfer_thread, nick)

    elif (msg.find("sumi done") == 0):
        print "Transfer to %s complete\n" % nick
        if (clients[nick].has_key("file")):
            cfg["filedb"][clients[nick]["file"]]["gets"] += 1
            print "NUMBER OF GETS: ", cfg["filedb"][clients[nick]["file"]]["gets"]
        else:
            print "Somehow lost filename"
        clients.pop(nick)   # destroy client

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
                resend = resend_queue.get_nowait()
                datapkt(nick, resend)
        except Queue.Empty:
            pass

        if (clients[nick]["seqno"]):
            blocklen = datapkt(nick, clients[nick]["seqno"])

        ## If haven't received ack from user since RWINSZ*2, pause
        # ^ now we stop instead
        d = time.time() - clients[nick]["ack_ts"]
        if (float(d) >= float(clients[nick]["rwinsz"] * 2)):
            #clients[nick]["xfer_lock"].acquire() 
            print "Since we haven't heard from %s in %f (> %f), stopping" %  \
                (nick, d, clients[nick]["rwinsz"] * 2)
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
            print "Client %s has no seqno" % nick
            # TODO: Allow multiple transfers per server?
            print "Most likely client is trying to get >1 files at once."
            sys.exit(42)
        print "#%d, len=%d" % (clients[nick]["seqno"], blocklen)
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

def transfer_control(nick, msg):
    """Handle an in-transfer message"""
    global resend_queue
    print "(authd)%s: %s" % (nick, msg)
    if (msg[0] == "k"):
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

def datapkt(nick, seqno):
    """Send data packet number "seqno" to nick, for its associated file. 
       Returns the length of the block sent."""
    if (seqno > 16777216):   # 8-10GB is limit, depends on MSS
        clients[nick] = []
        return sendmsg_error(nick, "file too large")

    if (random.randint(0, 100) == 0):   # lose packet
        return 1466

    blocksz = clients[nick]["mss"] - SUMIHDRSZ

    clients[nick]["fh"].seek(blocksz * (seqno - 1))
    block = clients[nick]["fh"].read(blocksz)

    pkt = clients[nick]["prefix"]        # 3-byte prefix
    pkt += struct.pack("!L", seqno)[1:]  # 3-byte seq no
    if (len(pkt) != SUMIHDRSZ):
        print "internal failure: header not expected size"
        sys.exit(3)
    pkt += block
    if (len(pkt) > clients[nick]["mss"]):
        print "fatal: trying to send packet >MSS"
        sys.exit(4)

    src = randip()
    clients[nick]["send"](clients[nick]["src_gen"](), \
                          clients[nick]["dst_gen"](), pkt)
    #send_packet(src, clients[nick]["addr"], pkt, clients[nick]["dchanmode"])
    #print "DATA to %s(%s:%d)<-%s:%d, #%d len=%d (at=%d)" % (nick, clients[nick]["addr"][0], clients[nick]["addr"][1], src[0], src[1], seqno, len(block), clients[nick]["fh"].tell())
    time.sleep(clients[nick]["delay"])

    return len(block)

# From http://mail.python.org/pipermail/python-list/2003-January/137366.html
def in_cksum(str): 
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

  return answer

# this function was also taken from comp.lang.python, some modifications
# subject: "ping multiple IPs with python", from Andrew McGregor
def fixULPChecksum(packet):
    # evil assumptions: no IP options, IPv4
    pseudopkt = ''.join([packet[:IPHDRSZ][-8:],
                         '\x00',
                         packet[:IPHDRSZ][-11],
                         struct.pack('!H', len(packet) - IPHDRSZ),
                         packet[IPHDRSZ:IPHDRSZ+16],
                         '\x00\x00',
                         packet[IPHDRSZ+18:]]
                        + [x for x in ['\x00'] if len(packet) & 1])
    csum = reduce(operator.add,
                  struct.unpack('!%dH' % (len(pseudopkt)>>1),
                         pseudopkt))
    csum = (csum>>16) + (csum&0xffff)
    csum += (csum>>16)
    csum = (csum&0xffff)^0xffff
    return ''.join([packet[:IPHDRSZ+16],
                    struct.pack('!H', csum),
                    packet[IPHDRSZ+18:]])

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

def setup_raw(argv):
    """Setup the raw socket. Only one raw socket is needed to send any number
    of packets, so it can be created at startup and root can be dropped; 
    alternatively, a setuid program can set envar RAWSOCKFD and pass it here."""

    global raw_socket
    if (os.environ.has_key("RAWSOCKFD")):
        raw_socket = socket.fromfd(int(os.environ["RAWSOCKFD"]), socket.AF_INET, socket.IPPROTO_UDP)
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
                sys.exit(1)
        # Drop privs-this needs to be worked on
        if (dir(os).__contains__("setuid")):
            os.setuid(os.getuid()) 
            print "Running with uid: ", os.getuid()

    # Bind raw socket to interface
    raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

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
    # Checksum is in host order
    icmphdr = struct.pack("!BB", type, code) +  \
              struct.pack("H", checksum) + \
              struct.pack("!HH", 0, 0)

    packet += icmphdr
    packet += payload
    raw_socket.sendto(packet, dst) 

def build_iphdr(totlen, src_ip, dst_ip, type):
    """Return an IP header with given parameters."""
    global cfg

    # XXX: Major source of confusion. The IP length field has to be in
    # host byte order for FreeBSD, network byte order for Linux.
    if (cfg["IP_TOTLEN_HOST_ORDER"]):
        totlen = socket.ntohs(totlen)
  
    return struct.pack("!BBHHHBBHLL",
        0x40 | IPHDRSZ >> 2,                   # version+IHL little endian
        #payload = ((IPHDRSZ >> 2) << 4) | 4,  # big endian
        0,                                     # DSCP/TOS
        totlen,                                # total length
        0,                                     # IP ID (let kernel)
        0,                                     # Frag offset & flags=none
        128,                                   # Time to live
        type,                                  # UDP=User datagram protocol,etc
        0,                                     # Checksum (let kernel)
        struct.unpack("!L", socket.inet_aton(src_ip))[0], # Source address
        struct.unpack("!L", socket.inet_aton(dst_ip))[0], # Destination address
       );

def send_packet_TCP(src, dst, payload):
    # TODO: TCP aggregates are efficient! So, offer an option to send
    #       spoofed UDP packets, which form streams, so it looks real + valid.
    #       UDP is often discarded more by routers, best of both worlds=TCP!
    #     However, receiving it would require pylibcap.
    print "TODO: implement"

def send_packet_UDP_WINPCAP(src, dst, payload):
    # TODO: Use pcap_sendpacket from WinPcap. See
    # http://winpcap.polito.it/docs/docs31beta3/html/group__wpcapfunc.html#a41
    # Regular socket() calls work fine on Win2K/XP, but WinPcap's will work
    # on 95, 98, Me... provided that the winpcap library is installed.
    # Implementing this isn't a very high priority because the older OS's
    # are, well, old. However, being able to run sumiserv as a non-admin user
    # might be more secure, and spoofing data-link addresses may prove useful.

    # Pcapy: http://oss.coresecurity.com/projects/pcapy.html

    # If we do decide to implement this, note that the datalink headers
    # need to be included as well. Could perhaps spoof these to thwart
    # detection on a totally switched network?
    
    # pcap_open_live()
    # pcap_send_packet()
    pass

# Send packet from given source.
def send_packet_UDP_SOCKET(src, dst, payload):
    """Send a UDP packet from src to dst.
       This uses the standard socket() functions, and is recommended."""
    global raw_socket

    totlen = IPHDRSZ + UDPHDRSZ + len(payload)

    packet = build_iphdr(totlen, src[0], dst[0], 17)
 
    # Pseudoheader for checksum
    pseudo = struct.pack("!LLBBH", 
        struct.unpack("!L", socket.inet_aton(src[0]))[0],
        struct.unpack("!L", socket.inet_aton(dst[0]))[0],
        0, 17, UDPHDRSZ)

    # Build UDP header
    packet += struct.pack("!HHHH",
        src[1],                              # Source port
        dst[1],                              # Destination port
        UDPHDRSZ + len(payload),
        0,     # Checksum - not set (TODO: fix it)
       )
    packet += payload
    fixULPChecksum(packet)

    #raw_socket.connect(dst)
    #raw_socket.send(packet)
    #print packet
    raw_socket.sendto(packet, dst)

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
    """Return a random host that can be pinged."""
    # List of pingable hosts. Some hosts limit their bytes of the payload to
    # 56 or other small values. To check, use:
    #   sudo ping -s `expr X - 8` google.com
    # where X is the number of bytes to send (payload+ICMP header), default
    # being 64 (this is the limit of google.com). 1466 is good.
    l = ("216.239.39.4", "216.239.39.5", "216.239.39.248", "216.239.39.234",
         "216.239.39.249", "216.239.39.252", "64.56.182.1", "64.56.182.6",
         "64.56.182.51", "64.56.182.52") 
    return (l[random.randint(0, len(l) - 1)], 0)
 
def on_msg(c, e):
    try:
        recvmsg(nm_to_n(e.source()), e.arguments()[0])
    except None:   # remove None in production use to not crash on exceptions
        print "Unhandled exception caused by %s: " % nm_to_n(e.source()), sys.exc_info()

def on_nickinuse(c, e):
    global cfg
    old_nick = e.arguments()[0]
    new_nick = old_nick + "_"
    print "%s nick in use, using %s" % (old_nick, new_nick)
    cfg["irc_nick"] = new_nick
    c.nick(new_nick)

def on_notregistered(c, e):
    print "We have not registered."

def on_welcome(c, e):
    global cfg

    print "We're logged in"
    c.mode(cfg["irc_nick"], "+ix")

    for chan in cfg["irc_chans"]:
        key = cfg["irc_chans"][chan]
        print "Joining channel %s..." % (chan,),
        print c.join(chan, key)
    join_lock.release()
 
def on_umodeis(c, e):
    modes = e.arguments()
    print "User modes: ", modes
 
def on_cantjoin(c, e):
    (chan, errmsg) = e.arguments()
    print "Can't join %s: %s" % (chan, errmsg)

def on_quit(c, e):
    nick, msg = nm_to_n(e.source()), e.arguments()[0]
    print "User quit: <%s>%s" % (nick, msg)
    if (clients.has_key(nick)):
        clients[nick]["xfer_stop"] = 1     # Terminate transfer thread

def sendmsg_error(nick, msg):
    """Report an error message, if not in stealth mode."""
    if (not cfg["stealth_mode"]):
        sendmsg(nick, "error: %s" % msg)
    print "%s -> error: %s" % (nick, msg)

def sendmsg(nick, msg):
    """Send a message over IRC."""
    global server
    print nick,"->",msg
    #server.notice(nick, msg) 
    server.privmsg(nick, msg)

def to_all(chans, msg):
    """Send a message to all channels."""
    for chan in chans:
        server.privmsg(chan, msg)

# List files to channels
def thread_notify(ignored):
    """List all files to joined channels."""
    global server, cfg
    join_lock.acquire()
    if (cfg["sleep_interval"] == 0):     # 0=no public listings
        return

    while 1:

        chans = cfg["irc_chans"].keys()
        # we're a lot like iroffer.org xdcc, so it makes sense to look similar
        # and it may allow irc spoders to find us
        to_all(chans, "** %d packs ** X of Y slots open, Record: Z" % \
               len(cfg["filedb"]))
        to_all(chans, "** Bandwidth Usage ** Current: X, Record: Y")
        to_all(chans, '** To request a file type: "/sumi get %s #x"' % \
               cfg["irc_nick"])
        total_offered = 0
        total_xferred = 0
        for n in range(len(cfg["filedb"])):
            to_all(chans, "#%d %3dx [%4s] %s" % (n + 1, 
                   cfg["filedb"][n]["gets"], \
                   cfg["filedb"][n]["hsize"], cfg["filedb"][n]["desc"]))
            total_offered += cfg["filedb"][n]["size"]
            total_xferred += cfg["filedb"][n]["size"] * cfg["filedb"][n]["gets"]
        to_all(chans, "** Offered by SUMI")
        to_all(chans, "Total Offered: %4s  Total Transferred: %4s" % \
            (human_readable_size(total_offered), 
            human_readable_size(total_xferred)))

        time.sleep(cfg["sleep_interval"])

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

def setup_config():
    """Load file database and configuration."""

    for offer in cfg["filedb"]:
        gets = offer["gets"]
        fn   = offer["fn"]
        desc = offer["desc"]
        try:
            size = os.path.getsize(fn)
        except OSError:
            print "Exception occured while reading size of %s" % fn
            print "Please check that the file exists and is readable."  
            sys.exit(-1)
        offer["size"] = size
        offer["hsize"] = human_readable_size(size)   

def sigusr2(a, b):
    print "Re-reading config file"
    load_cfg() 
 
def main(argv):
    global server, irc_server, irc_port, cfg, join_lock

    import signal
    signal.signal(signal.SIGUSR2, sigusr2)

    setup_raw(argv)
    setup_config()

    set_src_allow(cfg["src_allow"])

    join_lock = thread.allocate_lock()
    irc = irclib.IRC()
    irc.add_global_handler("privmsg", on_msg)
    irc.add_global_handler("nicknameinuse", on_nickinuse)
    irc.add_global_handler("notregistered", on_notregistered)
    irc.add_global_handler("welcome", on_welcome)
    irc.add_global_handler("umodeis", on_umodeis)
    irc.add_global_handler("umode", on_umodeis)
    irc.add_global_handler("channelisfull", on_cantjoin)
    irc.add_global_handler("inviteonlychan", on_cantjoin)
    irc.add_global_handler("badchannelkey", on_cantjoin)
    irc.add_global_handler("quit", on_quit)
    server = irc.server()
    print "Connecting to IRC server %s:%s as %s..." % (cfg["irc_server"], 
        cfg["irc_port"], 
        cfg["irc_nick"]),
    try:
        server.connect(cfg["irc_server"], cfg["irc_port"], cfg["irc_nick"])
    except:
        print "couldn't connect to server"
        sys.exit(4)
    print "OK."
    join_lock.acquire()   #  will be released when channels are joined
    #thread.start_new_thread(thread_notify, (None))
    thread.start_new_thread(make_thread, (thread_notify, None))
    try:
        irc.process_forever()
    except KeyboardInterrupt, SystemExit:
        on_exit()
    #while(1):
    #    irc.process_once()

def make_thread(f, arg):
    try:
       f(arg)
    except KeyboardInterrupt, SystemExit:
       on_exit()

def on_exit():
    global config_file, cfg

    print "Cleaning up..."
    import pprint      # pretty print instead of ugly print repr
    pprint.pprint(cfg, open(config_file, "w"))

    print "CFG=",cfg
    sys.exit()
    sys._exit(1)
    raise SystemExit
    raise KeyboardInterrupt
 
if __name__ == "__main__":
    #setup_raw(sys.argv)
    #send_packet_ICMP(("1.2.3.4", 0), ("4.46.200.132", 1), "hi", 0, 0)
    #sys.exit(0)
    main(sys.argv)
