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

def on_nickinuse(c, e):
    print "Nickname in use"
    old_nick = e.arguments()[0]
    new_nick = old_nick[:-1] + chr(ord(old_nick[-1]) + 1)
    print "%s nick in use, using %s" % (old_nick, new_nick)
    cfg["irc_nick"] = new_nick
    c.nick(new_nick)

def on_notregistered(c, e):
    print "We have not registered."

def on_welcome(c, e):
    print "We're logged in"
    c.mode(cfg["irc_nick"], "+ix")

    for chan in cfg["irc_chans"]:
        key = cfg["irc_chans"][chan]
        print "Joining channel %s..." % (chan,),
        print c.join(chan, key)
    irc_lock.release()

def on_umodeis(c, e):
    modes = e.arguments()
    print "User modes: ", modes
    
def on_cantjoin(c, e):
    (chan, errmsg) = e.arguments()
    print "Can't join %s: %s" % (chan, errmsg)

def on_quit(c, e):
    nick, msg = irclib.nm_to_n(e.source()), e.arguments()[0]
    print "User quit: <%s>%s" % (nick, msg)
    import sumiserv
    clients = sumiserv.clients
    if (clients.has_key(nick)):
        clients[nick]["xfer_stop"] = 1     # Terminate transfer thread

def generic_callback(user, msg):
    print "<%s> %s" % (user, msg)

def irc_thread(callback):
    global server
    irc = irclib.IRC()

    def on_msg(c, e):
        try:
            callback(irclib.nm_to_n(e.source()), e.arguments()[0])
        except None:   
            # remove None in production use to not crash on exceptions
            print "Unhandled exception caused by %s: " %  \
                irclib.nm_to_n(e.source()), sys.exc_info()
        #nick, msg = irclib.nm_to_n(e.source()), e.arguments()[0]
        #print "MSG:%s:%s" % (nick, msg)  

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
    except irclib.ServerConnectionError, e:
        print "Error connecting to",cfg["irc_server"],"port",cfg["irc_port"]
        print e, dir(e)
        sys.exit(1)
    print "OK."
    if callback != generic_callback:
        thread.start_new_thread(thread_notify, ())
    #import sumiserv
    #thread.start_new_thread(sumiserv.make_thread, (thread_notify, None))
    try:
        print "irc.process_forever()"
        irc.process_forever()
    except KeyboardInterrupt, SystemExit:
        callback(None, "on_exit")

# List files to channels
def thread_notify():
    """List all files to joined channels."""
    global server, cfg
    #join_lock.acquire()
    if (cfg["sleep_interval"] == 0):     # 0=no public listings
        return

    while 1:
        chans = cfg["irc_chans"].keys()
        # we're a lot like iroffer.org xdcc, so it makes sense to look similar
        # and it may allow irc spiders to find us
        to_all(chans, "** %d packs ** all slots open, Record: N/A" % \
               len(cfg["filedb"]))
        to_all(chans, "** Bandwidth Usage ** Current: N/A, Record: N/A")
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
        to_all(chans, "Total Offered: %4s  Total Transferred: %4s  Bandwidth Cap: %4s" % \
            (human_readable_size(total_offered), 
            human_readable_size(total_xferred),
            "%d bps" % cfg["our_bandwidth"]))

        import time
        time.sleep(cfg["sleep_interval"])

def sendmsg(nick, msg):
    if not server:
        thread.start_new_thread(irc_thread, (generic_callback,))
        print "Waiting to join channels..."
        irc_lock.acquire()    # wait until channels joined
        print "Acquired lock"
        irc_lock.release()
    segment(nick, msg, 550, sendmsg_1)

def to_all(chans, msg):
    """Send a message to all channels."""
    irc_lock.acquire()
    for chan in chans:
        server.privmsg(chan, msg)
    irc_lock.release()

def sendmsg_1(nick, msg):
    irc_lock.acquire()   # wait until server connects if not connected
    server.privmsg(nick, msg)
    irc_lock.release()

def transport_init():
    irc_lock.acquire()   # will be released when channels are joined
    #thread.start_new_thread(irc_thread, ())
    pass

def recvmsg(callback):
    irc_thread(callback)

