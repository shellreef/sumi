# Created:20040805
# By Jeff Connelly

# Windows AOL Instant Messenger

# Tested on 5.5.3595, 5.5.3292

import win32api
import win32gui
import win32con
import urllib
import time
import struct

def is_secure():
    return cfg.get("aim_is_secure", False)

def transport_init():
    log("Initializing WinAIM transport")

def sendmsg(nick, msg):
    # segment() is provided by the framework to split up a message
    # and call sendmsg_1 if needed. Do this if transport has msg len limits.
    segment(nick, msg, 500, sendmsg_1)

# Return a list of open IM window handles
def get_aim_wins(filter):
    allwins = []
    aimwins = []
    win32gui.EnumWindows(lambda x,y: allwins.append(x), [])
    for w in allwins:
        # Look for class AIM_IMessage
        if win32gui.GetClassName(w) == 'AIM_IMessage' and filter(w):
            aimwins.append(w)
    return aimwins

def sendmsg_1(nick, msg):
    #print "Trying to send %s to %s", msg, nick

    im = 0

    # See if there is already an AIM window for this user open
    aimwins = get_aim_wins(lambda x: \
        win32gui.GetWindowText(x).find(" - Instant Message") != -1)
    #print aimwins

    for aimwin in aimwins:
        title = win32gui.GetWindowText(aimwin)
        # to : from - Instant Message OR to - Instant Message (older AIMs)
        if (title.find(" : ") != -1):
            to = title[0:title.find(" : ")]
        else:
            to = title[0:title.find(" - ")]

        if (to == nick):
            im = aimwin
            break

    if not im:
        # Not already open, have to create it. Before any messages are sent
        # (goim only types the message - doesn't send it), AIM windows have
        # a title of "Instant Message", plain. Close any of these to prevent
        # confusion in finding our new AIM window after the ShellExecute.
        aimwins = get_aim_wins(lambda x: \
            win32gui.GetWindowText(x) == "Instant Message")
        for aimwin in aimwins: 
            win32gui.SendMessage(aimwin, win32con.WM_CLOSE, 0, 0)
        # Open the window
        url = "aim:goim?" + urllib.urlencode({"screenname": nick})
        win32api.ShellExecute(0, "", url, None, None, win32con.SW_SHOW)

    # Type out the message. This is aim URL style, don't use it anymore
    # because although it supports HTML, it steals focus.
    #url = "aim:goim?" + urllib.urlencode({"screenname": nick, "message": msg})
    #win32api.ShellExecute(0, "", url, None, None, win32con.SW_HIDE)

    # Need to locate actual AIM window to press Enter
    wait = 0
    while not im and wait < 1000:
        # Since there wasn't an existing AIM window, look for an untitled one
        aimwins = get_aim_wins(lambda x: \
            win32gui.GetWindowText(x) == "Instant Message")
        time.sleep(0.01)
        if len(aimwins) == 0:
            continue
        im = aimwins[0] 
        wait += 1

    if not im:
        log("couldn't find AIM window!")
        return -1

    # Find the input control
    found_atewin = 0
    txtwin = 0
    kids = []

    # It might take a while to load all the controls. There should be 45.
    # Timeout after 10 seconds.
    started = time.time()
    while len(kids) < 45:
        kids = []
        win32gui.EnumChildWindows(im, lambda x,y: kids.append(x), 0)
        if time.time() - started > 10:
            log("Couldn't locate 45 child windows. Located %s." % len(kids))
            log("AIM may have changed.")
            break
        time.sleep(0.01)
    for kid in kids:
        #print "Child window: %x" % kid
        #print "\t", win32gui.GetWindowText(kid)
        if 1 and win32gui.GetWindowText(kid) == "AteWindow":
            found_atewin = 1
            kids2 = []
            win32gui.EnumChildWindows(kid, lambda x,y: kids2.append(x), 0)
            #print "Found AteWindow, kids2=",kids2
            # Has two children - a CBClass and Ate32Class
            if len(kids2) != 2:
                continue

            if win32gui.GetClassName(kids2[1]) != "CBClass":
                log("The second child window wasn't a CBClass. Unexpected.")
                log("AIM may have changed. If so please edit the code.")
                return -3
  
            if win32gui.GetClassName(kids2[0]) != "Ate32Class":
                log("First child window wasn't an Ate32Class. The required")
                log("window is missing. AIM have changed. Fatal error.")
                return -4
          
            txtwin = kids2[0] 
            break          
    if not found_atewin:
        log("Sorry couldn't find AteWindow. AIM might have changed ")
        log("windows, rendering this program incompatible.")
        return -2
    if not txtwin:
        log("Somehow txtwin wasn't found.")
        return -5

    # Type out the message. WM_CHAR doesn't steal focus, but it can't
    # handle some characters and doesn't allow HTML.
    for ch in msg:
        win32api.SendMessage(txtwin, win32con.WM_CHAR, ord(ch), 0)

    win32api.SendMessage(txtwin, win32con.WM_KEYDOWN, win32con.VK_RETURN, 0)
    win32api.SendMessage(txtwin, win32con.WM_KEYUP, win32con.VK_RETURN, 0)

# that's it! but receiving is 20x more complicated 

# Receiving incoming AIM messages is done in a slightly unorthodox manner.
# Instead of forcing users to connect through a proxy, pcapy is used to
# sniff the existing AIM packets. This is much more unintrusive than a proxy.
# 
# Should be called with a callback function taking transport,sn,msg arguments.
# Never returns.
def recvmsg(callback):
    def decoder(pkt_data):
        return decode_aim(get_tcp_data(pkt_data))
    # Capture only incoming OSCAR IM's. Exclude packets with options
    # because tcp[20:2] and tcp[26:4] won't refer to the payload if there
    # are options. Filter it here instead of in Python for efficiency.
    filter = ("tcp and (tcp[12] & 0xf0) <= 0x50 " +   # TCP & no options
             "and tcp[20:2] = 0x2a02 " +    # OSCAR magic & channel 2
             "and tcp[26:4] = 0x00040007") # Family 4,subtype 7=incoming IM
    callback("(transport_ready)", "aim")
    # pcapy capture - never returns
    capture(decoder, filter, callback)

# Decode an AIM packet, from Ethernet to OSCAR
# TODO: Use dpkt http://monkey.org/~dugsong/dpkt/pydoc/index.html
def decode_aim(oscar_data):
    if len(oscar_data) < 1+1+2+2 or oscar_data[0] != chr(0x2a):  # OSCAR magic
        return (None, "Not OSCAR")
    #print "Got OSCAR packet: ",len(oscar_data)  # Not necessarily
    (flap_chan, flap_seq, flap_size) = struct.unpack("!BHH",
            oscar_data[1:1+1+2+2])
    #print "Flap channel: ",flap_chan
    #print "Flap seq#:    ",flap_seq
    #print "Data size:    ",flap_size
    if flap_chan != 2:   # If not SNAC data, ignore
        return (None, "Not FLAP channel 2")
    snac = oscar_data[1+1+2+2:]
    (family, subtype, flags, reqid) = struct.unpack("!HHHL",
            snac[0:2+2+2+4])
    snac_data = snac[2+2+2+4:]
    #print "Family: ", family
    #print "Subtype: ", subtype
    #print "Flags: ", flags
    #print "Reqid: ", reqid
    sn = None
    msg = "(none yet)"
    if family == 0x04 and subtype == 0x07:
        # "Message for client from server" = incoming message
        (cookie, msgchan, snlen) = struct.unpack("!QHB",
                snac_data[0:8+2+1])
        sn = snac_data[8+2+1:8+2+1+snlen]
        #print "Sn: |%s|" % sn
        (warnlev, numtlvs) = struct.unpack("!HH",
                snac_data[8+2+1+snlen:8+2+1+snlen+2+2])
        tlvs = get_tlvs(snac_data[8+2+1+snlen+2+2:]) 
        #print tlvs
        msg = decode_im(tlvs[2])
    return (sn, msg)

# Decode a list of OSCAR's type-length-values
def get_tlvs(data):
    tlvs = {}
    i = 0
    while i < len(data):
        (t, l) = struct.unpack("!HH", data[i:i+2+2])
        #print "Type: ", t
        #print "Length: ", l
        i += 2+2
        v = data[i:i+l]
        i += l
        #print "Value: ", v
        tlvs[t] = v
        #print
    return tlvs

# Decode a TLV type 0.02, returning the message contents in plain text
def decode_im(im):
    (fragid1, fragver1, caplen) = struct.unpack("!BBH", im[0:1+1+2])
    caps = im[1+1+2:1+1+2+caplen]
    (fragid2, fragver2, msglen) = struct.unpack("!BBH", 
            im[1+1+2+caplen:1+1+2+caplen+1+1+2])
    msgset = im[1+1+2+caplen+1+1+2:]
    (charset, subset) = struct.unpack("!HH", msgset[0:2+2])
    msg = strip_html(msgset[2+2:])
    return msg

# Strip HTML, leaving only the text
def strip_html(html):
    import HTMLParser
    class Stripper(HTMLParser.HTMLParser):
        text = ""
        def handle_data(self,data):
            self.text += data
    s = Stripper()
    s.feed(html)
    return s.text

