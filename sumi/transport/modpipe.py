# Created:20040130
# By Jeff Connelly

# Pipe to a stream transport (see streams/)

# this might not work

import popen2

transport = r"/home/jeff/p2p/sumi/transport/stream/sumi-irc.py"

def transport_init():
    global msgin, msgout, transport
    print "Connecting to transport...",
    (msgin, msgout) = popen2.popen2(transport)
    print "OK"
    while 1:
        line = msgin.readline()
        print "Got line: ",line
        if line == "":
            print "Got EOF, exiting"
            return 0
        line = line[:-1]
        args = line.split(":", 2)
        if (args[0] == "MSG"):   # not really used
            print "Incoming:",args[1],"->",args[2]
        elif (args[0] == "SYS"):  
            print "SystemMessage: ",args

def sendmsg(nick, msg):
    global msgout
    print "sending: ",nick,msg
    msgout.write("MSG:%s:%s\n" % (nick, msg))
    msgout.flush()

