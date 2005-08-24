# Created:20040216
# By Jeff Connelly

# xchat transport

# You need at least xchat 2, load ../client-side/xchat.pl in xchat before
# using this.

import os
import sys

import capture_irc

recvmsg = capture_irc.recvmsg

XCHAT_FILE = "/tmp/xchat"

def is_secure():
    return cfg.get("xchat_is_secure", False)

def transport_init():
    # No other portable way to find if xchat is running?
    if os.system("killall -0 xchat 2>/dev/null") != 0:
        log("An error occured while trying to locate 'xchat'.")
        log("Is 'xchat' running?")
        sys.exit(-1)
    log("Located xchat, running...")

def sendmsg(nick, msg):
    segment(nick, msg, 550, sendmsg_1)

# TODO: This requires 2-way transports to get the user info back
def userinfo(nick):
    sendcmd("/whois %s")

def sendmsg_1(nick, msg):
    sendcmd("/msg %s %s" % (nick, msg))

def sendcmd(cmd):
    global g_mem, g_xchat

    xchat = open(XCHAT_FILE, "wb")
    xchat.write(cmd)
    xchat.close()

    if os.system("killall -USR2 xchat") != 0:
        log("SYS:xchat lost!")
        sys.exit(-2) 

