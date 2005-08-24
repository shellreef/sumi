#!/usr/bin/env python

# Created:20040117M
# By Jeff Connelly

# SUMI downloader, invoke: sumiget.py <transport> <server> <filename>
# See also: sumigetw.py

import thread
import binascii
import base64
import socket
import struct
import signal
import sys
import os
import time
import libsumi

from libsumi import *
from nonroutable import is_nonroutable_ip

def log(msg):
    print msg

# Modules used by transports. Imported here so they compile in.
if sys.platform == 'win32':
    import win32api
    import mmap

input_lock = thread.allocate_lock()
#transport = "python -u transport/sumi-irc.py"
#global transport   
#transport = "mirc"

base_path = os.path.abspath(os.path.dirname(sys.argv[0])) + os.sep
config_file = base_path + "config.py"
log("Using config file: %s" % config_file)

# Setup run-time path for loading transports
sys.path.append(os.path.realpath(os.path.dirname(sys.argv[0])))
sys.path.append(os.path.realpath(os.path.dirname(sys.argv[0])) + "/../")
#print "USING PATH = ", sys.path

#import transport.modmirc

global transports
transports = {}

# Make stdout unbuffered. Not sure if this is still needed.
real_stdout = sys.stdout
class unbuffered_stdout(object):
    def write(self, s):
        real_stdout.write(s)
        # Check to see if hash flush attribute, because the Blcakhole object
        # (used when ran as a GUI app with no console) does not
        if (hasattr(real_stdout, "flush")): real_stdout.flush()
sys.stdout = unbuffered_stdout()

# Used by transports to segment messages
def segment(nick, msg, max, callback):
    n = 0
    # Length of each segment, to overcome limitations of IRC privmsg's, the
    # msg will be split into segments within range of privmsg limit. The
    # last segment has no ">" prefix, other segments do.
    #MAX_LEN = 550#3#512 - len(":PRIVMSG") - len(nick)
    prefix = ">"
    #print "I'm segmenting **%s**" % (msg) 
    while len(msg[n:n+max]):
        if n + max >= len(msg):
            prefix = ""
        #print ">", nick, prefix + msg[n:n+max]
        callback(nick, prefix + msg[n:n+max])
        #sendmsg_1(prefix + msg[n:n+max])
        #print(prefix + msg[n:n+MAX_LEN])
        n += max

class Client(object):
    def __init__(self):
        log("Loading config...")
        # Mode "U" for universal newlines, so \r\n is okay
        self.config = eval("".join(open(config_file, "rU").read()))
        libsumi.cfg = self.config
        libsumi.log = log
        log("OK")

        self.validate_config()
        self.senders = {}

        self.set_callback(self.default_cb)   # override me please

    def save_lost(self, u, finished=0):
        """Write the resume file for transfer from the user."""
        finished=0    # no special case

        if not u.has_key("fs"):
            log("Not saving resuming file for %s" % u["nick"])
            return

        u["fs"].seek(0)    
        u["fs"].truncate()    # Clear
        u["fs"].flush()
        if not finished:
            # .sumi file format: lostpkt1,lostpkt2,...,lostpktn,current_pkt
            lost = ",".join(map(str, u.get("lost", {}).keys()))
            lost += "," + str(u["at"])   # last is at, cur/last
            u["fs"].write(lost)   # Overwrite with new lostdata
            u["fs"].flush()
            #print "WROTE LOST: ",lost
        else:    # NOT REACHED
            # Don't remove the resume file. Leave it around so know finished.
            #lfn = (self.config["dl_dir"] + os.path.sep 
            #      + u["fn"] + ".sumi")
            #print "Removing resume file ",lfn
            #os.unlink(lfn) 
            # Mark as finished
            u[x]["fs"].write("FIN")
            u[x]["fs"].flush() 

    def prefix2user(self, prefix):
        """Find user that is associated with the random prefix; which is the
        only way to identify the source. Return None if no user."""
       
        # The data structures aren't setup very efficiently.
        for x in self.senders:
            if self.senders[x].has_key("prefix") and \
               self.senders[x]["prefix"] == prefix:
                #xprint "DATA:Prefix=%02x%02x%02x its %s" %\
                #    (tuple(map(ord, prefix)) + (x, ))
                return self.senders[x]
        return None

        #print "Incoming:",len(data),"bytes from",addr,"=",u["nick"]," #",seqno

    def setup_resuming(self, u, lostdata):
        """Setup data structures to resume a file."""

        u["at"] = int(lostdata.pop())

        log("RESUMING AT %s" % u["at"])
        log("IS_RESUMING: LOST: %s" % lostdata)
        u["lost"] = {}
        for x in lostdata:
            try:
                u["lost"][int(x)] = 1
            except ValueError:
                pass    # don't add non-ints
        log("LOADED LOSTS: %s" % u["lost"])

        # Initialize the rwin with empty hashes, mark off missings
        u["rwin"] = {}
        for x in range(1, u["at"] + 1):
            u["rwin"][int(x)] = 1   # received 

        for L in u["lost"]:    # mark losses
            u["rwin"][int(L)] = 0

        #print "RESUME RWIN: ", u["rwin"]

        # Total bytes received is file length minus lost packet sizes.
        # (Note: MTU may be inconsistant across users, so resuming files
        # cannot be shared across users with different MTUs.)
        s = u["fh"].tell()
        u["fh"].seek(0, 2)   # SEEK_END
        u["bytes"] = u["fh"].tell() #- (self.mss * len(u["lost"].keys()))#XXX
        u["fh"].seek(s, 0)


        #print "STORED BYTES: ", u["bytes"]
        #print "AND THE SIZE: ", u["size"]

        # Files don't store statistics like these
        u["all_lost"] = []  # blah
        u["rexmits"] = 0

    def setup_non_resuming(self, u):
        """Setup data structures for a new file."""
        # Initialize
        u["at"] = 0
        u["rexmits"] = 0
        u["all_lost"] = []
        u["bytes"] = 0  # bytes received
        u["lost"] = {}    # use: keys(), pop()..
        # RWIN is a list of all the packets, and if they occured (0=no),
        # incremented each time a packet of that seqno is received. Since
        # Python arrays don't automatically grow with assignment, a hash
        # is used instead. If "rwin" was an array, [], missed packets would
        # cause an IndexError. See
        #http://mail.python.org/pipermail/python-list/2003-May/165484.html
        # for rationale and some other class implementations
        u["rwin"] = {}

    def setup_file(self, u):
        """Setup the file to save to."""
        fn = self.config["dl_dir"] + os.path.sep + u["fn"]
        log("Opening %s for %s..." % (fn, u["nick"]))
        u["start"] = time.time()

        # These try/except blocks try to open the file rb+, but if
        # it fails with 'no such file', create them with wb+ and
        # open with rb+. Good candidate for a function!
        try:
            u["fh"] = open(fn, "rb+")
        except IOError:
            open(fn, "wb+").close()
            u["fh"] = open(fn, "rb+")
        log("open")

        # Open a new resuming file (create if needed)
        try:
            u["fs"] = open(fn + ".sumi", "rb+")
            is_resuming = 1  # unless proven otherwise
        except IOError:
            open(fn + ".sumi", "wb+").close()
            u["fs"] = open(fn + ".sumi", "rb+")
            is_resuming = 0   # empty resume file, new download

        # Lost data format: lostpkt1,lostpkt2,...,current_pkt
        lostdata = None

        # Check if the data file exists, and if so, resume off it
        if os.access(fn, os.R_OK):
            # The data file is readable, read lost data 
            lostdata = u["fs"].read().split(",")
        else: 
            is_resuming = 0     # Can't read data file, so can't resume

        # Need at least an offset to resume...
        if len(lostdata) <= 1: 
            is_resuming = 0
        log("LEN LOSTDATA=%s" % len(lostdata))#,"and lostdata=",lostdata

        #is_resuming=0#FORCE

        # Setup lost packets
        if is_resuming:   # this works
            self.setup_resuming(u, lostdata)
        else:
            self.setup_non_resuming(u)

    def handle_auth(self, u, prefix, addr, data):
        """Handle the authentication packet."""
        log("Got auth packet from %s for %s" % (addr,u["nick"]))

        if u.has_key("crypto_state"):
            g = time.time()
            d3 = g - u["sent_req2"]
            if d3 >= INTERLOCK_DELAY:  # really 2*INTERLOCK_DELAY
                log("WARNING: POSSIBLE MITM ATTACK! %s seconds is too long."
                        % d3)
                log("Your request may have been intercepted.")
                # only a warning because first data packet should catch it

            # Setup data encryption (CTR & package ECB)
            u["sessiv"] = inc_str(u["sessiv"])
            from AONT import AON
            u["aon"] = AON(get_cipher(), get_cipher().MODE_ECB)

            #log("Decrypted payload: %s" % ([data],))
        
        if self.config["crypt_data"]:
            # Decrypt payload, THEN hash. Note that crypt_data enables auth
            # pkt to be encrypted, since it goes over the data channel.
            u["ctr"] = u["data_iv"]
            log("DEC AP WITH: %s" % u["ctr"])
            data = data[0:SUMIHDRSZ] + u["crypto_obj"].decrypt(
                    data[SUMIHDRSZ:])

        hashcode = b64(hash128(data))

        # File length, new prefix, flags, filename
        i = SUMIHDRSZ
        size_str, i = take(data, SUMIAUTHHDRSZ, i)
        new_prefix, i = take(data, 3, i)
        flags_str, i = take(data, 1, i)

        u["size"], = struct.unpack("!I", size_str)
        log("SIZE:%s" % u["size"])
        assert len(new_prefix) == 3, "Missing new_prefix in auth packet!"
        flags = ord(flags_str)
        log("FLAGS:%s" % flags)
        u["mcast"] = flags & 1
        if u.has_key("crypto_state"):
            recvd_hash, i = take(data, 20, i)
            derived_hash = u["nonce_hash"]
            if recvd_hash != derived_hash:
                log("Server verification failed! %s != %s" % (
                        ([recvd_hash], [derived_hash])))
                clear_server(u)
                return
            log("Server verified: interlock nonce matches auth pkt nonce")
        else:
            log("Skipping server verification, crypto disabled")

        filename = data[i:data[i:].find("\0") + i]

        u["fn"] = filename
        log("Filename: <%s>" % filename)

        # Server can change prefix we suggested (negotiated).
        log("OLD PREFIX: %02x%02x%02x" % (tuple(map(ord, u["prefix"]))))
        log("NEW PREFIX: %02x%02x%02x" % (tuple(map(ord, new_prefix))))

        if new_prefix != u["prefix"]:
            # Most likely, switching because server is already sending the 
            # file (multicasting for example)
            log("Switching to a new prefix!")
        u["prefix"] = new_prefix

        self.callback(u["nick"], "info", u["size"], 
            b64(prefix), filename, 
            u["transport"], 
            self.config["data_chan_type"])

        new_mss = len(data) - SUMIHDRSZ

        assert new_mss <= self.mss, \
                "Auth packet MSS too large: %s > %s" % (new_mss, self.mss)

        if self.mss != new_mss:
            # This is a temporary downgrade, since the server might have the
            # MTU limitation, not us.
            log("Downgrading MSS %s->%s" % (self.mss, new_mss))

            # If using crypto, MSS normally rounded to block size
            if self.config.get("crypt_data"):
                log("If this happens consistently, considering lowering MTU.")

            self.mss = new_mss
            if self.mss < 256:
                log("MSS is extremely low (%d), quitting" % self.mss)
                sys.exit(-1)

        # Open the file and set it up
        if not u.has_key("fh"):  #  file not open yet
            self.setup_file(u)

        # Tell the sender to start sending, we're ok
        # Resume /after/ our current offset: at + 1.
        # And in sumi auth, **"m" is MSS**
        log("Sending sumi auth")
        auth = pack_args({"m":self.mss,
               "s":addr[0], "h":hashcode, "o":u["at"] + 1})
        if u.has_key("crypto_state"):
            #u["sessiv"] = inc_str(u["sessiv"])
            auth = b64(self.encrypt(u["nick"], auth))
            log("Encrypted sumi auth: %s" % auth)
        else:
            auth = "sumi auth " + auth
        self.sendmsg(u, auth)

        self.on_timer()    # instant update

        return

    def undigest_file(self, u):
        """After a file is complete, undigest (unpackage) it."""
        # Something is broken
        print [u["aon"].undigest(d)]

    def handle_first(self, u, seqno):
        """Handle the first packet from the server."""
        u["start_seqno"] = seqno
        log("FIRST PACKET: %s" % seqno)

        u["got_first"] = True

        if u.has_key("crypto_state"):
            # Make sure first data packet is received soon enough
            g = time.time()
            d4 = g - u["sent_req2"]
            if d4 >= 2*INTERLOCK_DELAY-0.1:
                log("POTENTIAL MITM ATTACK DETECTED--DELAY TOO LONG. %s"%d4)
                os._exit(-1)
                return
            else:
                log(":) No MITM detected")
        self.callback(u["nick"], "recv_1st")

    def handle_data(self, u, prefix, addr, seqno, data):
        """Handle data packets."""

        # Prefix has been checked, seqno calculated, so just get to the data
        data = data[SUMIHDRSZ:]

        payloadsz = len(data)

        if not u.has_key("got_first"):
            self.handle_first(u, seqno)

        # All file data is received here

        u["last_msg"] = time.time()
        offset = (seqno - 1) * self.mss

        # Mark down each packet in our receive window
        if u["rwin"].has_key(seqno):
            u["rwin"][seqno] += 1
        else:
            u["rwin"][seqno] = 1    # create

        if u["rwin"][seqno] >= 2:
            log("(DUPLICATE PACKET %d, IGNORED)" % seqno)
            return

        #print "THIS IS RWIN: ", u["rwin"]

        if not u.has_key("crypto_state"):
            # Without crypto (AONT), last packet is when completes file
            if offset + payloadsz >= u["size"]:
                u["got_last"] = True

        if self.config["crypt_data"]:
            # Outer crypto: CTR mode
            u["ctr"] = (calc_blockno(seqno, self.mss) + u["data_iv"])
            log("CTR:pkt %s -> %s" % (seqno, u["ctr"]))
            data = u["crypto_obj"].decrypt(data)
        
        # XXX: broken
        if False and u.has_key("crypto_state"):
            # With crypto (AONT), last packet goes OVER the end of the file,
            # specifically, by one block--the last block, encoding K'.
            if offset + payloadsz > u["size"]:
                u["got_last"] = True

            # Inner "crypto": ECB package mode, step 1 (gathering)

            if u.has_key("got_last"):
                # Pass last block to gather_last(), then can decrypt
                last_block = data[-get_cipher().block_size:]
                pseudotext = data[0:-get_cipher().block_size]

                u["aon"].gather(pseudotext)
                u["aon"].gather_last(last_block)

                u["aon_last"] = last_block

                log("Gathered last block!")
                u["can_undigest"] = True
            else:
                u["aon"].gather(pseudotext, ctr)

            # Save data in file and unpackage after finished
            print "LEN:%s vs. %s" % (len(data), len(pseudotext))
            #data = pseudotext

        # New data (not duplicate, is cleartext) - add to running total
        u["bytes"] += len(data) 

        u["fh"].seek(offset)
        u["fh"].write(data)

        if u.has_key("can_undigest"):
            self.undigest_file(u)

        # Note: callback called every packet; might be too excessive
        self.callback(u["nick"], "write", offset, u["bytes"],
            u["size"], addr)

        # Check previous packets, see if they were lost (unless first packet)
        if seqno > 1:
            i = 1 
            # Nice little algorithm. Work backwards, searching for gaps.
            #print "I'm at ",seqno
            while seqno - i >= 0:
                #print "?? ", seqno-i
                if not u["rwin"].has_key(seqno - i):
                    u["lost"][seqno - i] = 1
                    u["all_lost"].append(str(seqno - i))
                    i += 1
                else:
                    #print "ITS THERE!"
                    break  # this one wasn't lost, so already checked

            if u["mcast"]:
                log("using mcast, so not re-requesting these lost pkts")
                # we'll get these packets next time around 
            if u.get("lost", {}).has_key(seqno):
                u["lost"].pop(seqno)
                log("Recovered packet %s %s" % (seqno, len(u["lost"])))
                u["rexmits"] += 1
                log("(rexmits = %s" % u["rexmits"])
                self.callback(u["nick"], "rexmits", u["rexmits"])
                #on_timer()   # Maybe its all we need
            if u.has_key("got_last"):
                log("LAST PACKET: %d =? %d" % (len(data), self.mss))
                # File size is now sent in auth packet so no need to calc it
                #u["size"] = u["fh"].tell()
                self.on_timer()     # have it check if finished

        if u:
            self.save_lost(u)  # for resuming

        if u and u.get("lost"):
            self.callback(u["nick"], "lost", u["lost"].keys())
            #print "These packets are currently lost: ", u["lost"].keys()
        else:
            self.callback(u["nick"], "lost", ())

    def handle_packet(self, data, addr):
        """Handle received packets."""
        if len(data) < 6:   # prefix(3) + seqno(3)
            log("Short packet: %s bytes from %s" % (len(data), addr))
            return

        prefix  = data[:3]
        (seqno, ) = struct.unpack("!I", "\0" + data[3:6])

        u = self.prefix2user(prefix)
        if not u:
            p = "%02x%02x%02x" % (tuple(map(ord, prefix)))
            # On Win32 this takes up a lot of time
            log("DATA:UNKNOWN PREFIX! %s %s bytes from %s"
                    % (p,len(data),addr))
            return None

        u["retries"] = 0   # acks worked

        u["last_msg"] = time.time()

        # Last most recently received packet, for resuming
        u["at"] = seqno 

        log("PACKET: %s" % seqno)

        # Sequence number is 3 bytes in the SUMI header in network order
        # (so a null can easily be prepended for conversion to a long),
        # this used to be partially stored in the source port, but PAT--
        # Port Address Translation--closely related to NAT, can mangle 
        # the srcport
        if seqno == 0:       # all 0's = auth packet
            self.handle_auth(u, prefix, addr, data)
        else:
            self.handle_data(u, prefix, addr, seqno, data)

    def thread_timer(self):
        """Every RWINSZ seconds, send a nak of missing pkts up to that point."""
        try:
            while 1:
                time.sleep(self.rwinsz)
                self.on_timer()
        except:
            log("thread_timer exception: %s %s line=%s file=%s" 
                    % (sys.exc_info(), sys.exc_info()[1].args, 
                       sys.exc_info()[2].tb_lineno,
                       sys.exc_info()[1].filename))

    def on_timer(self):
        """Acknowledge to all senders and update bytes/second."""
        tmp_senders = self.senders.copy()
        for x in tmp_senders:
            u = self.senders[x]
            if not u.has_key("lost"):  # not xfering yet
                u["retries"] = 0   # initialize
                continue

            # Update rate display
            if u.has_key("bytes"):
                if u.has_key("last_bytes"):
                    bytes_per_rwinsz = u["bytes"] - u["last_bytes"]
          
                    rate = float(bytes_per_rwinsz) / float(self.rwinsz) 
                    # rate = delta_bytes / delta_time   (bytes arrived)
                    # eta = delta_bytes * rate          (bytes not arrived)
                    if (rate != 0):
                        eta = (u["size"] - u["bytes"]) / rate
                    else:
                        eta = 0
                    # Callback gets raw bits/sec and seconds remaining
                    self.callback(x, "rate", rate, eta)
                    u["last_bytes"] = u["bytes"]
                else:
                    u["last_bytes"] = u["bytes"]

            # Old way: EOF if nothing missing and got_last
            #if (len(u["lost"]) == 0 and 
            #    usenders[x].has_key("got_last")):
            #    return self.finish_xfer(x) # there's nothing left, we're done!
            # New way: EOF if total bytes recv >= size and nothing missing
            if u["bytes"] >= u["size"] and not u.get("lost"):
                 return self.finish_xfer(u)

            try:
                # Some missing packets, finish it up
    
                if len(u.get("lost", {})) > 100:
                    log(u["lost"])
                    log("Excessive amount of packet loss!")
                    log("could be a programming error. quitting")
                    raise SystemExit

                # Join by commas, only lost packets after start_seqno
                alost = u.get("lost", {}).keys()
                log("ALOST1: %s" % len(alost))
                if u.has_key("start_seqno"):
                    ss = u["start_seqno"]
                else:
                    log("WARNING: NO START_SEQO SET!")
                    ss = 0
                # NOTE: _y isn't localized here! Don't use x!
                # won't request any lost packets with seqno's below start_seqno
                alost = [ _y for _y in alost if _y >= ss ]

                log("ALOST2 (ss=%s): %s" % (ss, len(alost)))
                #lost = ",".join(map(str, alost))
                # XXX: Compressed NAKs
                lost = pack_range(alost)

                # Compress by omitting redundant elements to ease bandwidth
                if self.rwinsz_old == self.rwinsz and lost == "":
                    self.sendmsg(u, "n")
                elif lost == "":
                    self.sendmsg(u, "n%d" % self.rwinsz)
                else:
                    self.sendmsg(u, ("n%d," % self.rwinsz) + lost)

                u["retries"] += 1
                if u["retries"] > 3:
                    log("%s exceeded maximum retries (3), cancelling" % x)
                    self.senders.pop(x)
                    self.callback(x, "timeout")

                self.rwinsz_old = self.rwinsz# TODO: update if changes..but need
                                          # to give the win on first(right)

            except KeyError:   # sender ceased existance
                pass
        return None

    def finish_xfer(self, u):
        """Finish the file transfer."""

        # Nothing lost anymore, update. Saved as ",X" where X = last packet.
        log("DONE - UPDATING")
        self.save_lost(u, 1)

        self.sendmsg(u, "sumi done")

        duration = time.time() - u["start"]
        u["fh"].close()
        self.callback(u["nick"], "fin", duration, u["size"], 
              u["size"] / duration / 1024, 
              u["all_lost"])
        
        #print "Transfer complete in %.6f seconds" % (duration)
        #print "All lost packets: ", u["all_lost"]
        #print str(u["size"]) + " at " + str(
        #     u["size"] / duration / 1024) + " KB/s"
        self.clear_server(u)
        self.senders.pop(u["nick"])    # delete the server key

        # Don't raise SystemExit
        #sys.exit(0) # here now for one file xfer per program

    def recv_packets(self):
        """Receive anonymous packets."""
        log("THREAD 1 - PACKET RECV")
        if self.config["dchanmode"] == "socket":
            if self.config["data_chan_type"] == "u":
                self.server_udp()
            elif self.config["data_chan_type"] == "e":
                self.server_icmp()
            elif self.config["data_chan_type"] == "i":
                self.server_icmp()
            else:
                log("data_chan_type invalid, see config.html" 
                    "(dchanmode=socket)")
                sys.exit(-2)
        elif self.config["dchanmode"] == "pcap":
            if self.config["data_chan_type"] == "u":
                self.server_udp_PCAP()
            else:
                log("data_chan_type invalid, see config.html"
                        "(dchanmode=pcap)")
                sys.exit(-3)
        else:
            log("*** dchanmode invalid, set to socket or pcap")
            sys.exit(-4)

    def server_icmp(self):
        """Receive ICMP packets. Requires raw sockets."""

        #thread.start_new_thread(self.server_udp, (self,))
        thread.start_new_thread(self.wrap_thread, (self.server_udp, (self,)))
        #print "UID=", os.getuid()
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 
                             socket.IPPROTO_ICMP)
        log("ICMP started.")   # At the moment, needs to be ran as root
        sock.bind((self.localaddr, 0))
        while 1:
            (data, addr) = sock.recvfrom(65535)
            data = data[20 + 8:]     # IPHDRSZ + ICMPHDRSZ, get to payload
            self.handle_packet(data, addr)

    def server_udp(self):
        """Receive UDP packets."""
        log("UDP started (socket mode)")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while 1:
            try:
                sock.bind((self.localaddr, self.myport))
            except socket.error:
                failed = 0
                if (sys.exc_info()[1].args[0] == 48):
                    log("Port %s in use, trying next" % self.myport)
                    self.myport += 1
                    failed = 1
                if not failed: break
        log("Bound to %s" % self.myport)
 
        while 1:
            # This is interrupted...?
            try:
                (data, addr) = sock.recvfrom(65535)
            except socket.error:
                if sys.exc_info()[1].args[0] != 4: # Interrupted system call
                    raise sys.exc_info()[1]     # not for us to catch 
                # Reinvoke it
                continue 
            self.handle_packet(data, addr)

    def server_udp_PCAP(self):
        log("UDP started (pcap mode)")
        if self.config["interface"] == "":
            import pcapy
            devs = pcapy.findalldevs()
            log("Network interfaces: %s" % devs)
            if len(devs) == 1:
                self.config["interface"] = devs[0]
                log("Automatically setting to %s" % self.config["interface"])
            else:
                log("*** Please set 'interface' in config.py to one of ")
                log("*** the interfaces above and restart.")
                sys.exit(-5)
        import sumiserv
        sumiserv.cfg = {"interface": self.config["interface"]}
        def callback(data, pkt):
            #addr = ("0.0.0.0.","0.0.0.0") #?? TODO: find address from pkt IP header
            addr = (".".join(map(str, struct.unpack("!4B", pkt[14+12:14+16]))),
                   ".".join(map(str, struct.unpack("!4B", pkt[14+16:14+20]))))
            self.handle_packet(data, addr)

        def decode(pkt):
            return (sumiserv.get_udp_data(pkt), pkt)

        capture(decode, "udp", callback)

    def cli_user_input(self):
        """Client user input (not used anymore), belongs in separate program."""
        input_lock.acquire()   # wait for messaging program to be connected
        log("Started user input thread... you may now type")
        while 1:
            line = sys.stdin.readline()
            if line == "":    # EOF, exit
                return
            line = line[:-1]  # Strip \n
            if line == "":    # blank line (\n), ignore
                continue
            args = line.split()
            if (args[0] == "/get"):
                try:
                    self.request(*args)
                except IndexError:
                    log("Usage: sumiget <transport> <server_nick> <file>")
            else:
                log("Unrecognized command: %s" % line)
                #self.sendmsg(irc_chan, line)
        # DO SUMI SEC THEN ENCRYPT MSGS & PACKETS
        # Pre-auth. aes'd sumi send > irc_maxlen
        # MAX IRC PRIVMSG IN XCHAT: 452 in #sumi, 454 in #a (??) 462 in #a*31
        # ON NGIRCD: COMMAND_LEN - 1, is 513-1 is 512. Room for PRIVMSG+nick.
        # ":jeff PRIVMSG " = 14
        # Continuations are now implemented in some transports (segment()),
        # TODO: Also, think about combining some elements of sumi send with
        # sumi sec. Consider making sumi sec handle the auth packet, and
        # sumi send deal strictly with file transfers. This way, sumi sec+
        # sumi login can be implemented later; allowing remote admin.
        # TODO: Actually, why not simply extend sumi send to allow remote admn.

    def crypto_thread(self, u):
        """Thread to wait for messages from server to setup crypto.
        Passes messages to handle_server_message."""
        def crypto_callback(user_nick, msg):
            return self.handle_server_message(user_nick, msg)

        if not u.has_key("recvmsg"):
            log("%s is missing recvmsg transport" % u["nick"])
            log("recvmsg is necessary for crypto (shouldn't happen)")
            sys.exit(-2)
        u["recvmsg"](crypto_callback)
    
    def encrypt(self, u, msg):
        """Encrypt a message using u's key and IV."""
        e = encrypt_msg(msg, u["sesskey"], u["sessiv"])
        return e

    def decrypt(self, nick, msg):
        """Decrypt a message using nick's key and IV."""
        return decrypt_msg(msg, u["sesskey"], u["sessiv"])

    def handle_server_message(self, nick, msg):
        """Handle a message received from the server on the transport.
        Used for crypto."""
        if not self.senders.has_key(nick):
            return False

        u = self.senders[nick]

        if msg.startswith("error: "):
            error_msg = msg[len("error: "):]
            log("*** Error: %s: %s" % (nick, error_msg))
            self.callback(u["nick"], "error", error_msg)
            return None

        # Always base64'd
        try:
            raw = base64.decodestring(msg)
        except binascii.Error:
            log("%s couldn't decode?!" % msg)
            return False

        # Server will send three things: pubkeys, nonce1/2, nonce2/2
        # in two messages (pubkeys+nonce1/2, nonce2/2). We can tell which
        # message we are receiving by what we received previously.
        if not u.has_key("crypto_state"):  # pubkeys+nonce1/2
            g = time.time()                                 #  -> req1/2
            u["got_nonce1"] = g
            d1 = g - u["sent_sec"]
            log("Took %s seconds to get pk+nonce1/2 after sumi sec" % d1)
            if round(d1) < INTERLOCK_DELAY:
                self.callback(u["nick"], "sec_fail1")
                log("INTERLOCK FAILURE 1! %s < %s" % (d1, INTERLOCK_DELAY))
                log("Possible attack. Not trusting the server. Aborting.")
                return False

            self.set_handshake_status(u, "Interlocking-1")
            log("Got pubkeys + nonce1/2")
            # First message...its pubkeys + nonce1/2
            skeys = unpack_keys(raw[0:32*3])
            log("skeys=%s" % skeys)

            if True:#self.config.get("crypt_active"):
                nonce_1 = raw[32*3:]
                # can't decrypt now, since only have half; keep it
                log("nonce_1=%s" % ([nonce_1,]))
                u["nonce_1"] = nonce_1

            # Find out shared/private keys (pkeys)
            ckeys = u["ckeys"]
            pkeys = []
            for ck, sk in zip(ckeys, skeys):
                pkeys.append(ck.DH_recv(sk))
            log("pkeys=%s" % pkeys)
            sesskey = hash128(pkeys[0]) + hash128(pkeys[1])
            sessiv = pkeys[2]
            u["sesskey"] = sesskey
            u["sessiv"] = sessiv

            clear_req = u["request_clear"]
            log("sesskey/iv: %s" % ([sesskey, sessiv],))
            enc_req = self.encrypt(u, clear_req)
            log("ENC REQ: %s" % ([enc_req],))
            u["request_enc"] = enc_req

            req1 = enc_req[0::2]   # even
            req2 = enc_req[1::2]   # odd 
            u["request_1"] = req1
            u["request_2"] = req2

            # Send 1/2 of encrypted sumi send request 
            u["sent_req1"] = time.time()
            self.sendmsg(u, b64(req1))
        
            u["crypto_state"] = 1

        elif u["crypto_state"] == 1:   # nonce2/2->req2/2
            g = time.time()
            u["got_nonce2"] = g
            d2 = g - u["sent_req1"]
            log("Took %s seconds to get nonce2" % d2)
            if round(d2) < INTERLOCK_DELAY:
                self.callback(u["nick"], "sec_fail2")
                log("INTERLOCK FAILURE 2! Possible attack, aborting.")
                log("%s < %s" % (d2, INTERLOCK_DELAY))
                return False

            log("Got nonce 2/2")
            self.set_handshake_status(u, "Interlocking-2")
            # Second message: nonce2/2j
            nonce_1 = u["nonce_1"]
            nonce_2 = raw
            nonce = self.decrypt(u, interleave(nonce_1, nonce_2))
            print "NONCE=%s" % ([nonce,])
            u["nonce"] = nonce
            u["nonce_hash"] = hash160(nonce)

            # Send 2/2 of encrypted sumi send request. Expect response soon.
            self.sendmsg(u, b64(u["request_2"]))
            u["sent_req2"] = time.time()

            u["crypto_state"] = 2

        return True

    def set_handshake_status(self, u, status):
        """Set handshake status to status, and send a callback message
        updating it with the new status and existing countdown."""
        u["handshake_status"] = status
        self.callback(u["nick"], "req_count",
            u["handshake_count"],
            u["handshake_status"])

    def setup_transport_crypto(self, u):
        """Send sumi sec (secure) command, setting up an encrypted channel."""
        log("Setting up cryptography...")

        self.set_handshake_status(u, "Key exchange")

        # All crypto library imports are inside functions, rather than at
        # the top of the file, so that we can run without them if needed.
        from ecc.ecc import ecc

        # Generate our keys
        ckeys = []
        for i in range(3):
            log("Generating key #%s" % i)
            # XXX: ECC key generation crashes on amd64
            ckeys.append(ecc(ord(random_bytes(1))))
       
        # Send our public keys to server
        raw = ""
        for k in ckeys:
            raw += "".join(k.publicKey())

        log("Our keys: %s" % b64(raw))
        u["ckeys"] = ckeys

        u["sent_sec"] = time.time()
        self.sendmsg(u, "sumi sec %s" % b64(raw))

        # Wait for server's public keys. Start a receiving thread here
        # because setting up crypto is the only time we receive transport
        # messages from the server. 
        log(">>>>> %s" % u["nick"])
        def wrap():
            try:
                self.crypto_thread(u["nick"])
            except: #Exception, x:
                print "(thread) Exception: %s at %s" % (x,
                        sys.exc_info()[2].tb_lineno)
                raise x
        #thread.start_new_thread(self.crypto_thread, (u["nick"], ))
        #thread.start_new_thread(wrap, ())
        thread.start_new_thread(self.wrap_thread, 
                (self.crypto_thread, (u["nick"], )))

    def wrap_thread(f, args):
        try:
            f(*args)
        except Exception, x:
            print "(thread) Exception: %s at %s" % (x,
                    sys.exc_info()[2].tb_lineno)
            raise x

    def validate_config(self):
        """Validate configuration after loading it, possibly modifying it
           by filling in defaults.

           Return None if configurationi s valid, or an error message if
           not."""
        if self.config.has_key("myip"):
            if self.config["myip"] != "":
                self.myip = self.config["myip"]
                try:
                    self.myip = socket.gethostbyname(self.myip)
                except:
                    log("Couldn't resolve %s" % self.myip)
                    sys.exit(3)
                log("Resolved hostname to: %s" % self.myip)
            else:
                self.myip = get_default_ip()
                log("Using IP: %s" % self.myip)
        else:
            log("IP not specified, getting network interface list...")
            log("\nSelect an interface, or set 'myip' in config.py for auto.")

            (self.config["interface"], self.config["myip"], ignore,
                self.config["mtu"]) = select_if()

            log("Saving settings. Please review them in config.py, edit "
                    "as necessary, and restart.")
            self.on_exit()

        if self.config.has_key("myport"):
            self.myport = self.config["myport"]
        else:
            log("defaulting to port 41170")
            self.myport = 41170

        # Your local IP to bind to. This can be your private IP if you're behind
        # a NAT it can be the same as "myip", or it can be "" meaning bind to
        # all ifaces
        self.localaddr = ""

        # Not used in all transports
        if self.config.has_key("irc_nick"):
            self.irc_nick = self.config["irc_nick"]
        else:
            log("No IRC nick specified. What to use? ")
            self.irc_nick = sys.stdin.readline()[:-1]
       
        if self.config.has_key("irc_name"):
            self.irc_name = self.config["irc_name"]
        else:
            self.irc_name = self.irc_nick

        if self.config.has_key("mtu"):
            self.mss = mtu2mss(self.config["mtu"], self.config["data_chan_type"])
        else:
            try:
                self.mss
            except:
                return "MSS was not set, please set it in the Client tab."
        if self.config.get("crypt_data") or self.config.get("crypt_req"):
            random_init()

        if self.config.has_key("rwinsz"):
            self.rwinsz = self.config["rwinsz"]
            self.rwinsz_old = 0
                                  #RWINSZ never changes here! TODO:if it does,
                                  # then rwinsz_old MUST be updated to reflect.
        else:
            return "Please set rwinsz. Thank you."  

        if self.config.has_key("bandwidth"):
            self.bandwidth = self.config["bandwidth"]
        else:
            return "Please set your bandwidth,"
            sys.exit(5)

        # More validation, prompted by SJ
        if not self.config.has_key("allow_local") and \
           is_nonroutable_ip(self.myip):
               return """Your IP address, %s (%s) is nonroutable.
Please choose a real, valid IP address. If you are not sure what your IP is,
go to http://whatismyip.coo/. Your IP can be set in the Client tab of
sumigetw.""" % (self.myip, self.config["myip"])

        # Force trailing slash?
        #if self.config["dl_dir"][:1] != "/" and \
        #   self.config["dl_dir"][:1] != "\\": 
        #   self.config["dl_dir"] += "/"
        if not os.access(self.config["dl_dir"], os.W_OK | os.X_OK | os.R_OK):
            # TODO: Choose a reasonable default instead of this warning
            return """Your download directory, %s, is not writable.
You can select a valid download directory in the Client tab of sumigetw
by clicking the ... button."""

        # Passed all the tests
        return None

    def sendmsg(self, u, msg):
        """Send a message over the covert channel using the loaded
        transport module."""
        log(">>%s>%s" % (u["nick"], msg))
        return u["sendmsg"](u["nick"], msg)

    def abort(self, u):
        self.sendmsg(u, "!")
        self.callback(u["nick"], "aborting")

    def make_request(self, u, file):
        """Build a message to request file and generate a random prefix."""
        prefix = random_bytes(3)
        u["prefix"] = prefix

        if self.config["crypt_data"]:
            # Choose the 256-bit symmetric key and 128-bit IV, which will be
            # sent over the transport channel. The transport channel should be
            # secure. TODO: mark transports secure (Tor), crypt_req if not.
            data_key = random_bytes(32)
            data_iv = random_bytes(16)
            u["data_key"] = data_key
            u["data_iv"] = unpack_num(data_iv)
            def ctr_proc():
                u["ctr"] += 1
                x = pack_num(u["ctr"] % 2**128)
                x = "\0" * (16 - len(x)) + x
                assert len(x) == 16, "ctr_proc len %s not 16" % len(x)
                return x
            u["crypto_obj"] = get_cipher().new(
                    data_key, get_cipher().MODE_CTR, counter=ctr_proc)
        else:
            data_key = data_iv = ""

        msg = "sumi send " + pack_args({"f":file,
            #"o":offset,  # offset moved to sumi auth (know file size)
            "i":self.myip, "n":self.myport, "m":self.mss,
            "p":b64(prefix),
            "b":self.bandwidth,
            "w":self.rwinsz, 
            "x":b64(data_key + data_iv),
            "d":self.config["data_chan_type"]})
        return msg

    def clear_server(self, u):
        """Clear information about a server, but saving their nick."""
        nick = u["nick"]
        u.clear()
        u["nick"] = nick
        return u

    def request(self, transport, nick, file):
        """Request a file from a server.
        
        Return whether succeeded, but also callsback if fails."""

        # command line args are now the sole form of user input;
        self.callback(nick, "t_wait")   # transport waiting, see below

        if self.senders.has_key(nick):
            # TODO: Index senders based on unique key..instead of nick
            # Then we could have multiple transfers from same user, same time!
            log("Already have an in-progress transfer from %s" % nick)
            log(self.senders)
            self.callback(nick, "1xferonly")
            #print "Senders: ", self.senders
            return False

        self.senders[nick] = {}   # create
        u = self.senders[nick]
        u["nick"] = nick

        # Setup transport system
        u["transport"] = transport
        if not self.load_transport(transport, u):
            return False

        u["handshake_count"] = 0
        u["handshake_status"] = "Handshaking"

        if self.config.get("crypt_req"):
            if not "recvmsg" in u:
                log("Sorry, this transport lacks a recvmsg, so "
                        "transport encryption is not available.")
                sys.exit(-1)
                return False
            # Store request since its sent in halves
            u["request_clear"] = self.make_request(u, file)
            self.setup_transport_crypto(u)
        else:
            msg = self.make_request(u, file)
            self.sendmsg(u, msg) 

        log("Sent")
        self.callback(nick, "req_sent") # request sent (handshaking)

        # Countdown. This provides a timeout for handshaking with nonexistant
        # senders, so the user isn't left hanging.
        maxwait = self.config["maxwait"]

        if self.config["crypt_req"]:
            # Factor in time to interlock (2*T, plus another T for safety)
            maxwait += 3 * INTERLOCK_DELAY

        for x in range(maxwait, 0, -1):
            # If received fn in this time, then exists, so stop countdown
            if not self.senders.has_key(u["nick"]):
                return False    # some other error
            if u.has_key("fn"):
                return True     # don't break - otherwise will timeout
            u["handshake_count"] = x 
            self.callback(u["nick"], "req_count", x,
                    u["handshake_status"])
            time.sleep(1)

        self.callback(u["nick"], "timeout")
        self.clear_server(u)
        self.senders.pop(u["nick"])
        return False

    def set_callback(self, f):
        """Set callback to be used for handling notifications."""
        self.callback = f

    def default_cb(self, cmd, *args):
        log("(CB)%s: %s" % (cmd, ",".join(list(map(str, args)))))

    def load_transport(self, transport, u):
        """Load transport/mod<transport> for user, and initialize if not
        already initialized.
 
        Returns whether succeeds."""

        global input_lock, sendmsg, transport_init, transports
        # Import the transport. This may fail, if, for example, there is
        # no such transport module.
        try:
            sys.path.insert(0, os.path.dirname(sys.argv[0]))
            t = __import__("transport.mod" + transport, None, None,
                           ["transport_init", "sendmsg"])
        except ImportError:
            # Anytime a transfer fails, or isn't in progress, should pop it
            # So more transfers can come from the same users.
            self.clear_server(u)
            self.senders.pop(u["nick"])
            self.callback(u["nick"], "t_fail", sys.exc_info())
            return False

        t.segment = segment
        t.cfg = self.config
        t.log = log
        t.capture = capture
        t.get_tcp_data = get_tcp_data
    
        print "t=",t

        u["sendmsg"] = t.sendmsg
        u["transport_init"] = t.transport_init

        # Initialize if not
        if transports.has_key(transport) and transports[transport]:
            pass    # already initialized
            log("Not initing %s" % transport)
        else:
            u["transport_init"]()
            transports[transport] = 1   # Initialize only once
            log("Just inited %s" % transport)

        if hasattr(t, "recvmsg"):
            # If can't receive messages, crypto not available
            u["recvmsg"] = t.recvmsg
       
        # Initialize user if possible
        if hasattr(t, "user_init"):
            u["user_init"] = t.user_init
            self.callback(u["nick"], "t_user")
            log("Initializing user...")
            if u["user_init"](u["nick"]):
                log("user_init(%s) failed" % u["nick"])
                self.callback(u["nick"], "t_fail", "user_init failed")
                return False

        return True

    def main(self, transport, nick, file):
        """Text-mode client. There isn't much user-friendliness here--the
        callbacks simply dump the passed arguments to stdout. There used to
        be an interactive interface, cli_user_input, but it is no longer
        supported.
        
        In the future, this interface should be more usable."""
        #thread.start_new_thread(self.thread_timer, ())
        #thread.start_new_thread(self.request, (transport, nick, file))
        thread.start_new_thread(self.wrap_thread, (self.thread_timer, ()))
        thread.start_new_thread(self.wrap_thread, (self.request, 
            (transport, nick, file)))

        # This thread will release() input_lock, letting thread_request to go
        #transport_init()

        input_lock.acquire()
        log("RELEASED")
        input_lock.release()

        # Main thread is UDP server. There is no transport thread, its sendmsg
        self.recv_packets()   # start waiting before requesting

    def on_exit(self):    # GUI uses this on_exit
        log("Cleaning up...")
        import pprint

        savefile = open(config_file, "w")
        savefile.write("# Client configuration file\n")
        savefile.write("# Please note - ALL COMMENTS IN THIS FILE WILL BE DESTROYED\n")
        # ^ I place all comments in config.py.default instead, or the docs
        pprint.pprint(self.config, savefile)
        savefile.close()

        self.set_callback(lambda *x: 0)

        # Abort all the transfers, be polite. Rudely leaving without aborting
        # will cause the server to time out after not receiving our acks, but
        # it takes a while to time out and wastes bandwidth.
        if hasattr(self, "senders"):
            for x in self.senders.keys():
                log("Aborting %s" % x)
                self.abort(self.senders[x])

        log("Exiting now")
        sys.exit()
        os._exit()

def on_sigusr1(signo, intsf):
    """SIGUSR1 is used on Unix for signalling multiple transfers."""
    global base_path
    log("Got SIGUSR1 (%s %s) calling" % (signo, intsf))
    (transport, nick, filename) = open(base_path + "run", 
        "rb").readline().split("\t")
    log("-> %s %s %s " % (transport,nick,filename))
    #Client().main(transport, nick, file)
    # TODO: it needs to be possible to run multiple xfers per program, fix it
    #client.main(transport, nick, file)   # Runs servers twice (init_t + udp)
    #client.request(nick, file)    # Interrupted system call recvfrom(65535)
    #sys.exit(0)

# CLI uses this on-exit
def on_exit(signo=0, intsf=0):
    log("Cleaning up...(signal %s %s)" % (signo, intsf))
    #os.unlink(base_path + "sumiget.pid") 

def pre_main(invoke_req_handler):
    """Before creating the client, this function handles multiple instances."""
    global client

    # Multi-client support
    if sys.platform == 'win32':
        # win32gui.PumpWaitingMessages()?   # will be handled by wxWindows
        pass 
    else:
        signal.signal(signal.SIGUSR1, invoke_req_handler)    # set handler
    signal.signal(signal.SIGINT, on_exit)

    if len(sys.argv) >= 3:
        transport = sys.argv[1] 
        nick, filename = sys.argv[2], sys.argv[3]
    else:
        log("Usage: sumiget <transport> <nick> <filename>")
        sys.exit(-1)

    # 0=seperate program per transfer, 1=all in one (current)
    # =1 works in Unix using signals, but have to resize the frame.
    multiple_instances = 1

    if (multiple_instances and os.access(base_path + "sumiget.pid", os.F_OK)):
        # TODO: file locking so will be unlocked if crashes
        # PID file exists, program (should) be running
        # So signal it, pass control onto - it does work, not us
        master = open(base_path+"sumiget.pid","rb").read()
        if (len(master) != 0):   # If empty, be master
            open(base_path + "run", "wb").write("%s\t%s\t%s" % 
                (transport, nick, filename))
            my_master = int(master)
            log("Passing to: %s" % my_master)
            failed = 0 
            try:
                if (sys.platform == 'win32'):
                    import win32gui
                    import win32con
                    try:
                        win32gui.BringWindowToTop(my_master)
                    except: 
                        failed = 1
                    else:
                        win32gui.SendMessage(my_master, win32con.WM_SIZE, 0, 0)
                else:
                    os.kill(my_master, signal.SIGUSR1) 
            except OSError:
                failed = 1
            if not failed: sys.exit(0)   # Otherwise, will be master
            log("Failed to pass to %s" % my_master)
            #sys.exit(-1)
        # File locking would be good; if locked then write cmdline, os.kill other
    # Moved to GUI
    #pidf = open(base_path + "sumiget.pid", "wb")
    #pidf.write(str(os.getpid()))
    #pidf.close() 

if __name__ == "__main__":
    pre_main(on_sigusr1)

    transport, nick, filename = sys.argv[1], sys.argv[2], sys.argv[3]

    log("Getting <%s> from <%s> using <%s>..." % (filename, nick, transport))

    try:
        client = Client()
        client.main(transport, nick, filename)
    except (KeyboardInterrupt, SystemExit):
        on_exit(None, None)
