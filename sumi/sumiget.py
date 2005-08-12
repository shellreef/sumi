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
class unbuffered_stdout:
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

class Client:

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

    def on_msg(self, nick, msg):
        """Handle incoming messages."""
        log("<%s> %s" % (nick, msg))
        # This isn't used anymore - its in the auth packet instead
        if (msg.find("sumi start ") == 0):
            args = unpack_args(msg[len("sumi start "):])
            (filename, offset, size) = (args["f"], args["o"], args["l"])

            offset = int(offset)
            size = int(size)

            if (self.senders.has_key(nick)):
                self.sendmsg(nick, "n%d" % self.rwinsz)
                self.rwinsz_old = self.rwinsz
                log("Starting n%d %s for %s,%d,%d" % (self.rwinsz, nick,
                    filename, offset, size))
            else:
                log("ERROR: user not known, stranger trying to sumi start!")
                log("Senders: %s" % self.senders)
        elif (msg.find("error: ") == 0):
            errmsg = msg[len("error: "):]
            log("*** Error: " % errmsg)

    def save_lost(self, x, finished=0):
        """Write the resume file for transfer from nick."""
        finished=0    # no special case
        self.senders[x]["fs"].seek(0)    
        self.senders[x]["fs"].truncate()    # Clear
        self.senders[x]["fs"].flush()
        if not finished:
            # .sumi file format: lostpkt1,lostpkt2,...,lostpktn,current_pkt
            lost = ",".join(map(str, self.senders[x]["lost"].keys()))
            lost += "," + str(self.senders[x]["at"])   # last is at, cur/last
            self.senders[x]["fs"].write(lost)   # Overwrite with new lostdata
            self.senders[x]["fs"].flush()
            #print "WROTE LOST: ",lost
        else:    # NOT REACHED
            # Don't remove the resume file. Leave it around so know finished.
            #lfn = self.config["dl_dir"] + os.path.sep \
            #      + self.senders[x]["fn"] + ".sumi"
            #print "Removing resume file ",lfn
            #os.unlink(lfn) 
            # Mark as finished
            self.senders[x]["fs"].write("FIN")
            self.senders[x]["fs"].flush() 

    def prefix2nick(self, prefix):
        """Find nick that is associated with the random prefix; which is the
        only way to identify the source."""
       
        # The data structures aren't setup very efficiently.
        for x in self.senders:
            if self.senders[x].has_key("prefix") and \
               self.senders[x]["prefix"] == prefix:
                #xprint "DATA:Prefix=%02x%02x%02x its %s" %\
                #    (tuple(map(ord, prefix)) + (x, ))
                return x
        return None

        #print "Incoming:",len(data),"bytes from",addr,"=",nick," #",seqno

    def setup_resuming(self, nick, lostdata):
        """Setup data structures to resume a file."""

        self.senders[nick]["at"] = int(lostdata.pop())

        log("RESUMING AT %s" % self.senders[nick]["at"])
        log("IS_RESUMING: LOST: %s" % lostdata)
        self.senders[nick]["lost"] = {}
        for x in lostdata:
            try:
                self.senders[nick]["lost"][int(x)] = 1
            except ValueError:
                pass    # don't add non-ints
        log("LOADED LOSTS: %s" % self.senders[nick]["lost"])

        # Initialize the rwin with empty hashes, mark off missings
        self.senders[nick]["rwin"] = {}
        for x in range(1, self.senders[nick]["at"] + 1):
            self.senders[nick]["rwin"][int(x)] = 1   # received 

        for L in self.senders[nick]["lost"]:    # mark losses
            self.senders[nick]["rwin"][int(L)] = 0

        #print "RESUME RWIN: ", self.senders[nick]["rwin"]

        # Formula below is WRONG. Last packet is not size of MSS.
        # Bytes received = (MSS * at) - (MSS * numlost)
        # XXX: MSS's may be inconsistant across users! Corruption
        #self.senders[nick]["bytes"] = \
        #    (self.mss * self.senders[nick]["at"]) - \
        #    (self.mss * len(self.senders[nick]["lost"].keys()))
        s = self.senders[nick]["fh"].tell()
        self.senders[nick]["fh"].seek(0, 2)   # SEEK_END
        self.senders[nick]["bytes"] = \
            self.senders[nick]["fh"].tell()
        self.senders[nick]["fh"].seek(s, 0)

        #print "STORED BYTES: ", self.senders[nick]["bytes"]
        #print "AND THE SIZE: ", self.senders[nick]["size"]

        # Files don't store statistics like these
        self.senders[nick]["all_lost"] = []  # blah
        self.senders[nick]["rexmits"] = 0

    def setup_non_resuming(self, nick):
        """Setup data structures for a new file."""
        # Initialize
        self.senders[nick]["at"] = 0
        self.senders[nick]["rexmits"] = 0
        self.senders[nick]["all_lost"] = []
        self.senders[nick]["bytes"] = 0  # bytes received
        self.senders[nick]["lost"] = {}    # use: keys(), pop()..
        # RWIN is a list of all the packets, and if they occured (0=no),
        # incremented each time a packet of that seqno is received. Since
        # Python arrays don't automatically grow with assignment, a hash
        # is used instead. If "rwin" was an array, [], missed packets would
        # cause an IndexError. See
        #http://mail.python.org/pipermail/python-list/2003-May/165484.html
        # for rationale and some other class implementations
        self.senders[nick]["rwin"] = {}

    def setup_file(self, nick):
        """Setup the file to save to."""
        fn = self.config["dl_dir"] + os.path.sep + \
            self.senders[nick]["fn"]
        log("Opening %s for %s..." % (fn, nick))
        self.senders[nick]["start"] = time.time()

        # These try/except blocks try to open the file rb+, but if
        # it fails with 'no such file', create them with wb+ and
        # open with rb+. Good candidate for a function!
        try:
            self.senders[nick]["fh"] = open(fn, "rb+")
        except IOError:
            open(fn, "wb+").close()
            self.senders[nick]["fh"] = open(fn, "rb+")
        log("open")

        # Open a new resuming file (create if needed)
        try:
            self.senders[nick]["fs"] = open(fn + ".sumi", "rb+")
            is_resuming = 1  # unless proven otherwise
        except IOError:
            open(fn + ".sumi", "wb+").close()
            self.senders[nick]["fs"] = open(fn + ".sumi", "rb+")
            is_resuming = 0   # empty resume file, new download

        # Lost data format: lostpkt1,lostpkt2,...,current_pkt
        lostdata = None

        # Check if the data file exists, and if so, resume off it
        if os.access(fn, os.R_OK):
            # The data file is readable, read lost data 
            lostdata = self.senders[nick]["fs"].read().split(",")
        else: 
            is_resuming = 0     # Can't read data file, so can't resume

        # Need at least an offset to resume...
        if (len(lostdata) <= 1): is_resuming = 0
        log("LEN LOSTDATA=%s" % len(lostdata))#,"and lostdata=",lostdata

        #is_resuming=0#FORCE

        # Setup lost packets
        if (is_resuming):   # this works
            self.setup_resuming(nick, lostdata)
        else:
            self.setup_non_resuming(nick)

    def handle_auth(self, nick, prefix, addr, data):
        """Handle the authentication packet."""
        log("Got auth packet from %s for %s" % (addr,nick))

        if self.senders[nick].has_key("crypto_state"):
            g = time.time()
            d3 = g - self.senders[nick]["sent_req2"]
            if d3 >= INTERLOCK_DELAY:  # really 2*INTERLOCK_DELAY
                log("WARNING: POSSIBLE MITM ATTACK! %s seconds is too long."\
                        % d3)
                log("Your request may have been intercepted.")
                # only a warning because first data packet should catch it

            # Setup data encryption (CTR & package ECB)
            self.senders[nick]["sessiv"] = inc_str(self.senders[nick]["sessiv"])
            from AONT import AON
            self.senders[nick]["aon"] = AON(get_cipher(),
                    get_cipher().MODE_ECB)

            #log("Decrypted payload: %s" % ([data],))
        
        if self.config["crypt_data"]:
            # Decrypt payload, THEN hash. Note that crypt_data enables auth
            # pkt to be encrypted, since it goes over the data channel.
            self.senders[nick]["ctr"] = self.senders[nick]["data_iv"]
            log("DEC AP WITH: %s" % self.senders[nick]["ctr"])
            data = data[0:SUMIHDRSZ] + self.senders[nick]["crypto_obj"].decrypt(
                    data[SUMIHDRSZ:])

        hashcode = b64(hash128(data))

        # File length, new prefix, flags, filename
        i = SUMIHDRSZ
        size_str, i = take(data, SUMIAUTHHDRSZ, i)
        new_prefix, i = take(data, 3, i)
        flags_str, i = take(data, 1, i)

        (self.senders[nick]["size"], ) = struct.unpack("!I", size_str)
        log("SIZE:%s" % self.senders[nick]["size"])
        assert len(new_prefix) == 3, "Missing new_prefix in auth packet!"
        flags = ord(flags_str)
        log("FLAGS:%s" % flags)
        self.senders[nick]["mcast"] = flags & 1
        if self.senders[nick].has_key("crypto_state"):
            recvd_hash, i = take(data, 20, i)
            derived_hash = self.senders[nick]["nonce_hash"]
            if recvd_hash != derived_hash:
                log("Server verification failed! %s != %s" % (\
                        ([recvd_hash], [derived_hash])))
                self.senders[nick] = {}
                return
            log("Server verified: interlock nonce matches auth pkt nonce")

        filename = data[i:data[i:].find("\0") + i]

        self.senders[nick]["fn"] = filename
        log("Filename: <%s>" % filename)

        # Server can change prefix we suggested (negotiated).
        log("OLD PREFIX: %02x%02x%02x" % 
            (tuple(map(ord, self.senders[nick]["prefix"]))))
        log("NEW PREFIX: %02x%02x%02x" % 
            (tuple(map(ord, new_prefix))))

        if new_prefix != self.senders[nick]["prefix"]:
            # May be already being used by server
            log("Switching to a new prefix!")
        self.senders[nick]["prefix"] = new_prefix

        self.callback(nick, "info", self.senders[nick]["size"], \
            b64(prefix), filename, \
            self.senders[nick]["transport"], \
            self.config["data_chan_type"])

        if (self.mss != len(data)):
            log("WARNING: Downgrading MSS %d->%d, maybe set it lower?" 
                % (self.mss, len(data)))
            self.mss = len(data)
            if (self.mss < 256):
                log("MSS is extremely low (%d), quitting" % self.mss)
                sys.exit(-1)

        # Open the file and set it up
        if not self.senders[nick].has_key("fh"):  #  file not open yet
            self.setup_file(nick)

        # Tell the sender to start sending, we're ok
        # Resume /after/ our current offset: at + 1
        log("Sending sumi auth")
        auth = pack_args({"m":self.mss,
               "s":addr[0], "h":hashcode, "o":self.senders[nick]["at"] + 1})
        if self.senders[nick].has_key("crypto_state"):
            #self.senders[nick]["sessiv"] = inc_str(
            #        self.senders[nick]["sessiv"])
            auth = b64(self.encrypt(nick, auth))
            log("Encrypted sumi auth: %s" % auth)
        else:
            auth = "sumi auth " + auth
        self.sendmsg(nick, auth)

        self.on_timer()    # instant update

        return

    def undigest_file(self, nick):
        """After a file is complete, undigest (unpackage) it."""
        print [self.senders[nick]["aon"].undigest(d)]

    def handle_first(self, nick, seqno):
        """Handle the first packet from the server."""
        self.senders[nick]["start_seqno"] = seqno
        log("FIRST PACKET: %s" % seqno)

        self.senders[nick]["got_first"] = True

        if self.senders[nick].has_key("crypto_state"):
            # Make sure first data packet is received soon enough
            g = time.time()
            d4 = g - self.senders[nick]["sent_req2"]
            if d4 >= 2*INTERLOCK_DELAY-0.1:
                log("POTENTIAL MITM ATTACK DETECTED--DELAY TOO LONG. %s"%d4)
                os._exit(-1)
                return
            else:
                log(":) No MITM detected")
        self.callback(nick, "recv_1st")

    def handle_data(self, nick, prefix, addr, seqno, data):
        """Handle data packets."""

        # Prefix has been checked, seqno calculated, so just get to the data
        data = data[SUMIHDRSZ:]

        payloadsz = len(data)
        full_payload = self.mss - SUMIHDRSZ

        if not self.senders[nick].has_key("got_first"):
            self.handle_first(nick, seqno)

        # All file data is received here

        self.senders[nick]["last_msg"] = time.time()
        offset = (seqno - 1) * (self.mss - SUMIHDRSZ)

        # Mark down each packet in our receive window
        if self.senders[nick]["rwin"].has_key(seqno):
            self.senders[nick]["rwin"][seqno] += 1
        else:
            self.senders[nick]["rwin"][seqno] = 1    # create

        if self.senders[nick]["rwin"][seqno] >= 2:
            log("(DUPLICATE PACKET %d, IGNORED)" % seqno)
            return

        #print "THIS IS RWIN: ", self.senders[nick]["rwin"]

        if not self.senders[nick].has_key("crypto_state"):
            # Without crypto (AONT), last packet is when completes file
            if offset + payloadsz >= self.senders[nick]["size"]:
                self.senders[nick]["got_last"] = True

        if self.config["crypt_data"]:
            # Outer crypto: CTR mode
            self.senders[nick]["ctr"] = (calc_blockno(seqno, payloadsz)
                    + self.senders[nick]["data_iv"])
            log("CTR:pkt %s -> %s" % (seqno,
                self.senders[nick]["ctr"]))
            data = self.senders[nick]["crypto_obj"].decrypt(data)
        
        # XXX: broken
        if False and self.senders[nick].has_key("crypto_state"):
            # With crypto (AONT), last packet goes OVER the end of the file,
            # specifically, by one block--the last block, encoding K'.
            if offset + payloadsz > self.senders[nick]["size"]:
                self.senders[nick]["got_last"] = True

            # Inner "crypto": ECB package mode, step 1 (gathering)

            if self.senders[nick].has_key("got_last"):
                # Pass last block to gather_last(), then can decrypt
                last_block = data[-get_cipher().block_size:]
                pseudotext = data[0:-get_cipher().block_size]

                self.senders[nick]["aon"].gather(pseudotext)
                self.senders[nick]["aon"].gather_last(last_block)

                self.senders[nick]["aon_last"] = last_block

                log("Gathered last block!")
                self.senders[nick]["can_undigest"] = True
            else:
                self.senders[nick]["aon"].gather(pseudotext, ctr)

            # Save data in file and unpackage after finished
            print "LEN:%s vs. %s" % (len(data), len(pseudotext))
            #data = pseudotext

        # New data (not duplicate, is cleartext) - add to running total
        self.senders[nick]["bytes"] += len(data) 

        self.senders[nick]["fh"].seek(offset)
        self.senders[nick]["fh"].write(data)

        if self.senders[nick].has_key("can_undigest"):
            self.undigest_file(nick)

        # Note: callback called every packet; might be too excessive
        self.callback(nick, "write", offset, self.senders[nick]["bytes"],
            self.senders[nick]["size"], addr)

        # Check previous packets, see if they were lost (unless first packet)
        if (seqno > 1):
            i = 1 
            # Nice little algorithm. Work backwards, searching for gaps.
            #print "I'm at ",seqno
            while seqno - i >= 0:
                #print "?? ", seqno-i
                if not self.senders[nick]["rwin"].has_key(seqno - i):
                    self.senders[nick]["lost"][seqno - i] = 1
                    self.senders[nick]["all_lost"].append(str(seqno - i))
                    i += 1
                else:
                    #print "ITS THERE!"
                    break  # this one wasn't lost, so already checked

            if self.senders[nick]["mcast"]:
                log("using mcast, so not re-request these lost pkts")
                # we'll get these packets next time around 
            if self.senders[nick]["lost"].has_key(seqno):
                self.senders[nick]["lost"].pop(seqno)
                log("Recovered packet %s %s" 
                        % (seqno, len(self.senders[nick]["lost"])))
                self.senders[nick]["rexmits"] += 1
                log("(rexmits = %s" % self.senders[nick]["rexmits"])
                self.callback(nick, "rexmits", self.senders[nick]["rexmits"])
                #on_timer()   # Maybe its all we need
            if self.senders[nick].has_key("got_last"):
                log("LAST PACKET: %d =? %d" 
                        % (len(data), self.mss - SUMIHDRSZ))
                # File size is now sent in auth packet so no need to calc it
                #self.senders[nick]["size"] = self.senders[nick]["fh"].tell()
                self.on_timer()     # have it check if finished

        if self.senders.has_key(nick):
            self.save_lost(nick)  # for resuming

        if (self.senders.has_key(nick) and len(self.senders[nick]["lost"])):
            self.callback(nick, "lost", self.senders[nick]["lost"].keys())
            #print "These packets are currently lost: ", self.senders[nick]["lost"].keys()
        else:
            self.callback(nick, "lost", ())

    def handle_packet(self, data, addr):
        """Handle received packets."""
        if len(data) < 6:   # prefix(3) + seqno(3)
            log("Short packet: %s bytes from %s" % (len(data), addr))
            return

        prefix  = data[:3]
        (seqno, ) = struct.unpack("!I", "\0" + data[3:6])

        nick = self.prefix2nick(prefix)
        if not nick:
            p = "%02x%02x%02x" % (tuple(map(ord, prefix)))
            # On Win32 this takes up a lot of time
            log("DATA:UNKNOWN PREFIX! %s %s bytes from %s"
                    % (p,len(data),addr))
            return None

        self.senders[nick]["retries"] = 0   # acks worked

        self.senders[nick]["last_msg"] = time.time()

        # Last most recently received packet, for resuming
        self.senders[nick]["at"] = seqno 

        log("PACKET: %s" % seqno)

        # Sequence number is 3 bytes in the SUMI header in network order
        # (so a null can easily be prepended for conversion to a long),
        # this used to be partially stored in the source port, but PAT--
        # Port Address Translation--closely related to NAT, can mangle 
        # the srcport
        if seqno == 0:       # all 0's = auth packet
            self.handle_auth(nick, prefix, addr, data)
        else:
            self.handle_data(nick, prefix, addr, seqno, data)

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
            if (not self.senders[x].has_key("lost")):  # not xfering yet
                self.senders[x]["retries"] = 0   # initialize
                continue

            # Update rate display
            if self.senders[x].has_key("bytes"):
                if self.senders[x].has_key("last_bytes"):
                    bytes_per_rwinsz = \
                        self.senders[x]["bytes"] - self.senders[x]["last_bytes"]
          
                    rate = float(bytes_per_rwinsz) / float(self.rwinsz) 
                    # rate = delta_bytes / delta_time   (bytes arrived)
                    # eta = delta_bytes * rate          (bytes not arrived)
                    if (rate != 0):
                        eta = (self.senders[x]["size"] - self.senders[x]["bytes"]) / rate
                    else:
                        eta = 0
                    # Callback gets raw bits/sec and seconds remaining
                    self.callback(x, "rate", rate, eta)
                    self.senders[x]["last_bytes"] = self.senders[x]["bytes"]
                else:
                    self.senders[x]["last_bytes"] = self.senders[x]["bytes"]

            # Old way: EOF if nothing missing and got_last
            #if (len(self.senders[x]["lost"]) == 0 and 
            #    self.senders[x].has_key("got_last")):
            #    return self.finish_xfer(x) # there's nothing left, we're done!
            # New way: EOF if total bytes recv >= size and nothing missing
            if self.senders[x]["bytes"] >= self.senders[x]["size"] and \
               len(self.senders[x]["lost"]) == 0:
                 return self.finish_xfer(x)

            try:
                # Some missing packets, finish it up
    
                if len(self.senders[x]["lost"]) > 100:
                    log(self.senders[x]["lost"])
                    log("Excessive amount of packet loss!")
                    log("could be a programming error. quitting")

                # Join by commas, only lost packets after start_seqno
                alost = self.senders[x]["lost"].keys()
                log("ALOST1: %s" % len(alost))
                if self.senders[x].has_key("start_seqno"):
                    ss = self.senders[x]["start_seqno"]
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
                    self.sendmsg(x, "n")
                elif lost == "":
                    self.sendmsg(x, "n%d" % self.rwinsz)
                else:
                    self.sendmsg(x, ("n%d," % self.rwinsz) + lost)

                self.senders[x]["retries"] += 1
                if (self.senders[x]["retries"] > 3):
                    log("%s exceeded maximum retries (3), cancelling" % x)
                    self.senders.pop(x)
                    self.callback(x, "timeout")

                self.rwinsz_old = self.rwinsz# TODO: update if changes..but need
                                          # to give the win on first(right)

            except KeyError:   # sender ceased existance
                pass
        return None

    def finish_xfer(self, nick):
        """Finish the file transfer."""

        # Nothing lost anymore, update. Saved as ",X" where X = last packet.
        log("DONE - UPDATING")
        self.save_lost(nick, 1)

        self.sendmsg(nick, "sumi done")

        duration = time.time() - self.senders[nick]["start"]
        self.senders[nick]["fh"].close()
        self.callback(nick, "fin", duration, self.senders[nick]["size"], \
              self.senders[nick]["size"] / duration / 1024, \
              self.senders[nick]["all_lost"])
        
        #print "Transfer complete in %.6f seconds" % (duration)
        #print "All lost packets: ", self.senders[nick]["all_lost"]
        #print str(self.senders[nick]["size"]) + " at " + str(
        #     self.senders[nick]["size"] / duration / 1024) + " KB/s"
        self.senders.pop(nick)    # delete the server key

        # Don't raise SystemExit
        #sys.exit(0) # here now for one file xfer per program

    def thread_recv_packets(self):
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
                log("data_chan_type invalid, see config.html" + \
                    "(dchanmode=socket)")
                sys.exit(-2)
        elif self.config["dchanmode"] == "pcap":
            if self.config["data_chan_type"] == "u":
                self.server_udp_PCAP()
            else:
                log("data_chan_type invalid, see config.html" + \
                        "(dchanmode=pcap)")
                sys.exit(-3)
        else:
            log("*** dchanmode invalid, set to socket or pcap")
            sys.exit(-4)

    def server_icmp(self):
        """Receive ICMP packets. Requires raw sockets."""

        thread.start_new_thread(self.server_udp, (self,))
        #print "UID=", os.getuid()
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, \
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

    def crypto_thread(self, nick):
        """Thread to wait for messages from server to setup crypto.
        Passes messages to handle_server_message."""
        def crypto_callback(user_nick, msg):
            return self.handle_server_message(user_nick, msg)

        if not self.senders[nick].has_key("recvmsg"):
            log("%s is missing recvmsg transport" % nick)
            log("recvmsg is necessary for crypto (shouldn't happen)")
            sys.exit(-2)
        self.senders[nick]["recvmsg"](crypto_callback)
    
    def encrypt(self, nick, msg):
        """Encrypt a message using nick's key and IV."""
        e = encrypt_msg(msg, self.senders[nick]["sesskey"], 
                self.senders[nick]["sessiv"])
        return e

    def decrypt(self, nick, msg):
        """Decrypt a message using nick's key and IV."""
        return decrypt_msg(msg, self.senders[nick]["sesskey"], 
                self.senders[nick]["sessiv"])

    def handle_server_message(self, nick, msg):
        """Handle a message received from the server on the transport.
        Used for crypto."""
        if not self.senders.has_key(nick):
            return

        # Always base64'd
        try:
            raw = base64.decodestring(msg)
        except binascii.Error:
            log("%s couldn't decode?!" % msg)
            return

        # Server will send three things: pubkeys, nonce1/2, nonce2/2
        # in two messages (pubkeys+nonce1/2, nonce2/2). We can tell which
        # message we are receiving by what we received previously.
        if not self.senders[nick].has_key("crypto_state"):  # pubkeys+nonce1/2
            g = time.time()                                 #  -> req1/2
            self.senders[nick]["got_nonce1"] = g
            d1 = g - self.senders[nick]["sent_sec"]
            log("Took %s seconds to get pk+nonce1/2 after sumi sec" % d1)
            if round(d1) < INTERLOCK_DELAY:
                self.callback(nick, "sec_fail1")
                log("INTERLOCK FAILURE 1! %s < %s" % (d1, INTERLOCK_DELAY))
                log("Possible attack. Not trusting the server. Aborting.")
                return

            self.set_handshake_status(nick, "Interlocking-1")
            log("Got pubkeys + nonce1/2")
            # First message...its pubkeys + nonce1/2
            skeys = unpack_keys(raw[0:32*3])
            log("skeys=%s" % skeys)

            if True:#self.config.get("crypt_active"):
                nonce_1 = raw[32*3:]
                # can't decrypt now, since only have half; keep it
                log("nonce_1=%s" % ([nonce_1,]))
                self.senders[nick]["nonce_1"] = nonce_1

            # Find out shared/private keys (pkeys)
            ckeys = self.senders[nick]["ckeys"]
            pkeys = []
            for ck, sk in zip(ckeys, skeys):
                pkeys.append(ck.DH_recv(sk))
            log("pkeys=%s" % pkeys)
            sesskey = hash128(pkeys[0]) + hash128(pkeys[1])
            sessiv = pkeys[2]
            self.senders[nick]["sesskey"] = sesskey
            self.senders[nick]["sessiv"] = sessiv

            clear_req = self.senders[nick]["request_clear"]
            log("sesskey/iv: %s" % ([sesskey, sessiv],))
            enc_req = self.encrypt(nick, clear_req)
            log("ENC REQ: %s" % ([enc_req],))
            self.senders[nick]["request_enc"] = enc_req

            req1 = enc_req[0::2]   # even
            req2 = enc_req[1::2]   # odd 
            self.senders[nick]["request_1"] = req1
            self.senders[nick]["request_2"] = req2

            # Send 1/2 of encrypted sumi send request 
            self.senders[nick]["sent_req1"] = time.time()
            self.sendmsg(nick, b64(req1))
        
            self.senders[nick]["crypto_state"] = 1

        elif self.senders[nick]["crypto_state"] == 1:   # nonce2/2->req2/2
            g = time.time()
            self.senders[nick]["got_nonce2"] = g
            d2 = g - self.senders[nick]["sent_req1"]
            log("Took %s seconds to get nonce2" % d2)
            if round(d2) < INTERLOCK_DELAY:
                self.callback(nick, "sec_fail2")
                log("INTERLOCK FAILURE 2! Possible attack, aborting.")
                log("%s < %s" % (d2, INTERLOCK_DELAY))
                return

            log("Got nonce 2/2")
            self.set_handshake_status(nick, "Interlocking-2")
            # Second message: nonce2/2j
            nonce_1 = self.senders[nick]["nonce_1"]
            nonce_2 = raw
            nonce = self.decrypt(nick, interleave(nonce_1, nonce_2))
            print "NONCE=%s" % ([nonce,])
            self.senders[nick]["nonce"] = nonce
            self.senders[nick]["nonce_hash"] = hash160(nonce)

            # Send 2/2 of encrypted sumi send request. Expect response soon.
            self.sendmsg(nick, b64(self.senders[nick]["request_2"]))
            self.senders[nick]["sent_req2"] = time.time()

            self.senders[nick]["crypto_state"] = 2

    def set_handshake_status(self, nick, status):
        """Set handshake status to status, and send a callback message
        updating it with the new status and existing countdown."""
        self.senders[nick]["handshake_status"] = status
        self.callback(nick, "req_count",
            self.senders[nick]["handshake_count"],
            self.senders[nick]["handshake_status"])

    def setup_transport_crypto(self, nick):
        """Send sumi sec (secure) command, setting up an encrypted channel."""
        log("Setting up cryptography...")

        self.set_handshake_status(nick, "Key exchange")

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
        self.senders[nick]["ckeys"] = ckeys

        self.senders[nick]["sent_sec"] = time.time()
        self.sendmsg(nick, "sumi sec %s" % b64(raw))

        # Wait for server's public keys. Start a receiving thread here
        # because setting up crypto is the only time we receive transport
        # messages from the server. 
        log(">>>>> %s" % nick)
        def wrap():
            try:
                self.crypto_thread(nick)
            except None: #Exception, x:
                raise x
                print "(thread) Exception: %s at %s" % (x,
                        sys.exc_info()[2].tb_lineno)
        #thread.start_new_thread(self.crypto_thread, (nick, ))
        thread.start_new_thread(wrap, ())


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
                self.config["mss"]) = select_if()

            log("Saving settings. Please review them in config.py, edit "+
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

        if self.config.has_key("mss"):
            self.mss = self.config["mss"]
        else:
            try:
                self.mss
            except:
                return "MSS was not set, please set it in the Client tab."
        if self.config.get("crypt_data") or self.config.get("crypt_req"):
            random_init()
        if self.config.get("crypt_data"):
            bs = get_cipher().block_size
            if (self.mss - SUMIHDRSZ) % bs:
                self.mss -= (self.mss - SUMIHDRSZ) % 16
                self.config["mss"] = self.mss
                log("Fit MSS-SUMIHDRSZ to cipher block size: %s" % self.mss)

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
            return "Your IP address,"+self.myip+" ("+self.config["myip"] + "), is nonroutable. Please choose\n"+\
                   "a real, valid IP address. If you are not sure what your IP is, go to \n" +\
                   "http://whatismyip.com/. Your IP can be set in the Client tab of sumigetw." 

        # Force trailing slash?
        #if self.config["dl_dir"][:1] != "/" and \
        #   self.config["dl_dir"][:1] != "\\": 
        #   self.config["dl_dir"] += "/"
        if not os.access(self.config["dl_dir"], os.W_OK | os.X_OK | os.R_OK):
            return "Your download directory, " + self.config["dl_dir"] + ", is not writable. You can \n"+\
                   "select a valid download directory in the Client tab of sumigetw by\n"  +\
                   "clicking the ... button." 

        # Passed all the tests
        return None

#    def sendmsg(self, nick, msg):
#        """Send a message over the covert channel using loaded module."""
#        #print "SENDING |%s| to |%s|" % (msg, nick)
#        #return sendmsg(nick, msg)
#        return self.senders[nick]["sendmsg"](nick, msg)

    # Send a message to nick
    def sendmsg(self, nick, msg):
        log(">>%s>%s" % (nick, msg))
        return self.senders[nick]["sendmsg"](nick, msg)

    def abort(self, nick):
        self.sendmsg(nick, "!")
        self.callback(nick, "aborting")

    def make_request(self, nick, file):
        """Build a message to request file and generate a random prefix."""
        prefix = random_bytes(3)
        self.senders[nick]["prefix"] = prefix

        if self.config["crypt_data"]:
            # Choose the 256-bit symmetric key and 128-bit IV, which will be
            # sent over the transport channel. The transport channel should be
            # secure. TODO: mark transports secure (Tor), crypt_req if not.
            data_key = random_bytes(32)
            data_iv = random_bytes(16)
            self.senders[nick]["data_key"] = data_key
            self.senders[nick]["data_iv"] = unpack_num(data_iv)
            def ctr_proc():
                self.senders[nick]["ctr"] += 1
                x = pack_num(self.senders[nick]["ctr"] % 2**128)
                x = "\0" * (16 - len(x)) + x
                assert len(x) == 16, "ctr_proc len %s not 16" % len(x)
                return x
            self.senders[nick]["crypto_obj"] = get_cipher().new(
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

    def request(self, transport, nick, file):
        """Request a file from a server."""

        # command line args are now the sole form of user input;
        self.callback(nick, "t_wait")   # transport waiting, see below

        # Input lock is mostly obsolete -- it is supposed to wait for
        # transport_init() to return, but we already wait for it 
        #input_lock.acquire()   # wait for transport connection

        if (self.senders.has_key(nick)):
            # TODO: Index senders based on unique key..instead of nick
            # Then we could have multiple transfers from same user, same time!
            log("Already have an in-progress transfer from %s" % nick)
            log(self.senders)
            self.callback(nick, "1xferonly")
            #print "Senders: ", self.senders
            return -1

        self.senders[nick] = {} 

        # Setup transport system
        self.senders[nick]["transport"] = transport
        self.load_transport(transport, nick)

        self.senders[nick]["handshake_count"] = 0
        self.senders[nick]["handshake_status"] = "Handshaking"

        if self.config.get("crypt_req"):
            if not "recvmsg" in self.senders[nick]:
                log("Sorry, this transport lacks a recvmsg, so " +
                        "transport encryption is not available.")
                sys.exit(-1)
                return
            # Store request since its sent in halves
            self.senders[nick]["request_clear"] = \
                    self.make_request(nick, file)
            self.setup_transport_crypto(nick)
        else:
            msg = self.make_request(nick, file)
            self.sendmsg(nick, msg) 

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
            if not self.senders.has_key(nick):
                return -1    # some other error
            if self.senders[nick].has_key("fn"):
                return 0     # don't break - otherwise will timeout
            self.senders[nick]["handshake_count"] = x 
            self.callback(nick, "req_count", x,
                    self.senders[nick]["handshake_status"])
            time.sleep(1)

        self.callback(nick, "timeout")
        self.senders.pop(nick)
        return -1

    def set_callback(self, f):
        """Set callback to be used for handling notifications."""
        self.callback = f

    def default_cb(self, cmd, *args):
        log("(CB)%s: %s" % (cmd, ",".join(list(map(str, args)))))

    def load_transport(self, transport, nick):
        global input_lock, sendmsg, transport_init, transports
        # Import the transport. This may fail, if, for example, there is
        # no such transport module.
        log(sys.path)
        try:
            sys.path.insert(0, os.path.dirname(sys.argv[0]))
            t = __import__("transport.mod" + transport, None, None,
                           ["transport_init", "sendmsg"])
        except ImportError:
            # Anytime a transfer fails, or isn't in progress, should pop it
            # So more transfers can come from the same users.
            self.senders.pop(nick)
            self.callback(nick, "t_fail", sys.exc_info())
            return

        t.segment = segment
        t.cfg = self.config
        t.log = log
        t.capture = capture
        t.get_tcp_data = get_tcp_data
    
        print "t=",t

        self.senders[nick]["sendmsg"] = t.sendmsg

        self.senders[nick]["transport_init"] = t.transport_init

        # Initialize if not
        if (transports.has_key(transport) and transports[transport]):
            pass    # already initialized
            log("Not initing %s" % transport)
        else:
            self.senders[nick]["transport_init"]()
            transports[transport] = 1   # Initialize only once
            log("Just inited %s" % transport)

        if hasattr(t, "recvmsg"):
            # If can't receive messages, crypto not available
            self.senders[nick]["recvmsg"] = t.recvmsg

    def main(self, transport, nick, file):
        self.senders[nick] = {}
        self.load_transport(transport, nick)

        thread.start_new_thread(self.thread_timer, ())
        #senders[nick]["transport_init"] = t.transport_init
        thread.start_new_thread(self.request, (transport, nick, file))

        # This thread will release() input_lock, letting thread_request to go
        #transport_init()

        input_lock.acquire()
        log("RELEASED")
        input_lock.release()

        # Main thread is UDP server. There is no transport thread, its sendmsg
        self.thread_recv_packets()
   # start waiting before requesting

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
                self.abort(x)

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

    if (len(sys.argv) >= 3):
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
            open(base_path + "run", "wb").write("%s\t%s\t%s" % \
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
