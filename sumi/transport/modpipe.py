# Created:20040130
# By Jeff Connelly

# Pipe to a stream transport (see streams/) -- OBSOLETE

# this might not work

import popen2

transport = r"/home/jeff/p2p/sumi/transport/stream/sumi-irc.py"

def transport_init():
    global msgin, msgout, transport
    log("Connecting to transport...")
    (msgin, msgout) = popen2.popen2(transport)
    log("OK")
    while 1:
        line = msgin.readline()
        log("Got line: %s" % line)
        if line == "":
            log("Got EOF, exiting")
            return 0
        line = line[:-1]
        args = line.split(":", 2)
        if args[0] == "MSG":   # not really used
            log("Incoming: %s->%s" % (args[1], args[2]))
        elif args[0] == "SYS":  
            log("SystemMessage: %s" % args)

def sendmsg(nick, msg):
    global msgout
    log("sending: %s %s " % (nick,msg))
    msgout.write("MSG:%s:%s\n" % (nick, msg))
    msgout.flush()

