#!/usr/bin/env python
# Created:20030430
# By Jeff Connelly

# SUMI IRC transport program, based on stream/sumi-irc.py

# This uses irclib (python-irclib.sourceforge.net) to establish
# its own connection to an IRC server. Such a connection is often
# undesirable to server administrators as it could be used for
# a real user, so tunnelling through existing IRC clients is recommended
# (i.e., not using this module) but if none of that matters to you,
# (i.e., you're not using a real IRC client) modirclib can be just what you want

import irclib
import thread
import sys

irc_lock = thread.allocate_lock()
server = None
irc_nick = "sumiget"
(irc_chan, irc_chankey) = ("#sumi", "anon")
irc_server, irc_port = "irc2.liquidirc.net", 6667

def on_msg(c, e):
    nick, msg = irclib.nm_to_n(e.source()), e.arguments()[0]
    print "MSG:%s:%s" % (nick, msg)  

def on_nickinuse(c, e):
    c.nick(e.arguments()[0] + "_")

def on_welcome(c, e):
    c.mode(irc_nick, "+ix")
    print "Joining %s..." % (irc_chan,),
    c.join(irc_chan, irc_chankey)
    irc_lock.release()
    print "OK"

def irc_thread():
    global server
    irc = irclib.IRC()
    irc.add_global_handler("privmsg", on_msg)
    irc.add_global_handler("nicknameinuse", on_nickinuse)
    irc.add_global_handler("welcome", on_welcome)
    try:
        server = irc.server()
        print "Connecting to IRC server...",
        server.connect(irc_server, irc_port, irc_nick)
    except irclib.ServerConnectionError, e:
        print "Error connecting to",irc_server,"port",irc_port
        print e, dir(e)
        sys.exit(1)
    print "OK."
    irc.process_forever() 

def sendmsg(nick, msg):
    segment(nick, msg, 550, sendmsg_1)

def sendmsg_1(nick, msg):
    irc_lock.acquire()   # wait until server connects if not connected
    server.privmsg(nick, msg)
    irc_lock.release()

def transport_init():
    irc_lock.acquire()
    thread.start_new_thread(irc_thread, ())

