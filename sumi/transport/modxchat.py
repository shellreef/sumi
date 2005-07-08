# Created:20040216
# By Jeff Connelly

# xchat 

import os
import sys

XCHAT_FILE = "/tmp/xchat"

def transport_init():
    if os.system("killall -0 xchat") == 0:  # No other portable way(?)
        pass
    else:
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

transport_init()

