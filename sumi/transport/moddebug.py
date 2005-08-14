# Created:20040711
# By Jeff Connelly

# Debug transport module. Can use this for debugging or the basis for your
# own transport module. Enjoy. P.S.: Handshaking will always timeout here.

# Previously known as the 'fake' module

import sys

def transport_init():
    log("Initializing debug transport")

def sendmsg(nick, msg):
    # segment() is provided by the framework to split up a message
    # and call sendmsg_1 if needed. Do this if transport has msg len limits.
    segment(nick, msg, 500, sendmsg_1)

def sendmsg_1(nick, msg):
    log("(debug) <%s>%s" % (nick, msg))

def recvmsg(callback):
    log("Debug recvmsg() started - type messages on console")
    log("In the format: username<space>message of any length, or empty to end.")
    while True:
        nick, msg = sys.stdin.readline().strip().split(" ", 1)
        if nick == "":
            break
        log("(debug) <%s>%s" % (nick, msg))
        callback(nick, msg)
    log("Debug recvmsg() terminated") 

