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

# Note: 
# - 'cfg' is used for program-wide settings, such as _my_ nickname
# - 'u' is used for per-user settings, such as _the server's_ irc nickname

import irclib
import thread
import sys

irc_lock = thread.allocate_lock()
server = None

def is_secure():
    # Might be secure if somehow connected over SSL
    return cfg.get("irclib_is_secure", False)

def on_nickinuse(c, e):
    log("Nickname in use")
    old_nick = e.arguments()[0]
    new_nick = old_nick[:-1] + chr(ord(old_nick[-1]) + 1)
    log("%s nick in use, using %s" % (old_nick, new_nick))
    cfg["irc_nick"] = new_nick
    c.nick(new_nick)

def on_notregistered(c, e):
    log("We have not registered.")

def on_cantjoin(c, e):
    (chan, errmsg) = e.arguments()
    log("Can't join %s: %s" % (chan, errmsg))

def on_quit(c, e):
    nick, msg = irclib.nm_to_n(e.source()), e.arguments()[0]
    log("User quit: <%s>%s" % (nick, msg))
    #XXX doesn't work--should have a callback
    #import sumiserv
    #clients = sumiserv.clients
    #if (clients.has_key(nick)):
    #    clients[nick]["xfer_stop"] = 1     # Terminate transfer thread

def on_umodeis(c, e):
    modes = e.arguments()
    log("User modes: %s" % modes)
    
def generic_callback(user, msg):
    log("<%s> %s" % (user, msg))

def irc_thread(callback):
    global server
    irc = irclib.IRC()

    #log("Inside irc_thread, acquiring lock")
    #irc_lock.acquire()

    def on_msg(c, e):
        try:
            callback(irclib.nm_to_n(e.source()), e.arguments()[0])
        except None:   
            # remove None in production use to not crash on exceptions
            log("Unhandled exception caused by %s: %s" %  \
                (irclib.nm_to_n(e.source()), sys.exc_info()))
        #nick, msg = irclib.nm_to_n(e.source()), e.arguments()[0]
        #print "MSG:%s:%s" % (nick, msg)  

    def on_welcome(c, e):
        log("We're logged in")
        c.mode(cfg["irc_nick"], "+ix")

        # Program-wide channels to join
        for chan in cfg.get("irc_chans", {}):
            key = cfg["irc_chans"][chan]
            log("Joining channel %s..." % chan)
            log(c.join(chan, key))
     
        if u.get("irc_channel"):
            log("Joining channel for %s: %s" % (u["nick"], u["irc_channel"]))
            log(c.join(u["irc_channel"], u.get("irc_channel_password","")))

        log("Joined, releasing lock")
        irc_lock.release()
        # Tell client we're good to go
        callback("(unlock_transport)", "irclib")

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
    log("Connecting to IRC server %s:%s as %s..." % (u["irc_server"], 
        int(u["irc_port"]), 
        cfg["irc_nick"]))
    try:
        server.connect(u["irc_server"], int(u["irc_port"]), cfg["irc_nick"])
    except irclib.ServerConnectionError, e:
        log("Error connecting to %s port %s"
                % (u["irc_server"], int(u["irc_port"])))
        log("%s %s" % (e, dir(e)))
        sys.exit(1)
    log("OK.")
    if callback != generic_callback:
        thread.start_new_thread(thread_notify, ())
    #import sumiserv
    #thread.start_new_thread(sumiserv.make_thread, (thread_notify, None))
    try:
        log("irc.process_forever()")
        irc.process_forever()
    except (KeyboardInterrupt, SystemExit):
        callback(None, "on_exit")

# List files to channels
def thread_notify():
    """List all files to joined channels (used by server)."""
    global server, cfg, u
    #join_lock.acquire()
    if not cfg.get("sleep_interval"):  # False,0,None,empty=no public listings
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
        assert False#DBG
        irc_lock.acquire()    # wait until channels joined
        # Its valid to call sendmsg() without recvmsg() first (which calls
        # irc_thread with a custom callback not in a thread), it just means
        # that we'll have to start irc_thread in the background.
        thread.start_new_thread(irc_thread, (generic_callback,))
        log("sendmsg() called for first time, connecting...")
        log("Acquired lock, releasing it")
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
    required = ["irc_server", "irc_port"]
    for k in required:
        if not u.has_key(k):
            log(("Error: irclib requires key %s, try using a .sumi file with " +
                    "this key specified.") % str(k))
            import os
            os._exit(1)
    log("irclib: keys in u: " + str(u.keys()))
    # Inside recvmsg() instead
    #thread.start_new_thread(irc_thread, ())

def recvmsg(callback):
    irc_lock.acquire()
    # Since sendmsg() starts its own irc_thread() when first called, cannot
    # call recvmsg() after it or will end up with TWO irc_thread()s!
    assert not server, \
            "recvmsg() called after sendmsg()"
    log("recvmsg() starting irc_thread")
    irc_thread(callback)

