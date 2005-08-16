# Created:20050811
# By Jeff Connelly

# Tor transport

# For "Tor: An anonymous Internet communication system" http://tor.eff.org/

# idea: server hosts a "hidden service" via tor
# client would connect, via tor, to the hidden service...

from twisted.internet import protocol, reactor
from twisted.protocols import basic
from twisted.python import threadable
import thread

PORT = 2773

global connections, tor_callback, cli_locks
connections = cli_locks = {}
threadable.init()

def default_cb(nick, msg):
    print "(tor) <%s> %s" % (nick, msg)
tor_callback = default_cb

class SUMIProtocol(basic.LineReceiver):
    def setAddr(self, addr):
        self.addr = addr

    def connectionMade(self):
        global connections, cli_locks

        # \r\n is standard, but \n allows using netcat easily for debugging
        self.delimiter = "\n"

        source = self.transport.getHandle().getpeername()
        dest = self.transport.getHandle().getsockname()
        # We may have been exposed!
        assert source[0] == "127.0.0.1", \
                "Non-local connection from %s!" % (source, )

        # Use source port for client identification, or hostname for server id
        if source[1] != PORT:
            self.nick = "tor-%s" % source[1]
        else:
            self.nick = dest[0]
       
        if cli_locks.has_key(self.nick):
            cli_locks[self.nick].release()
        #print "SETTING CXN TO: ", self
        connections[self.nick] = self

        print "Got connection from %s" % self.nick

    def lineReceived(self, msg):
        tor_callback(self.nick, msg)
  
class SUMIServerFactory(protocol.ServerFactory):
    protocol = SUMIProtocol

class SUMIClientFactory(protocol.ClientFactory):
    protocol = SUMIProtocol

    def startedConnecting(self, connector):
        print "Started to connect."

    def buildProtocol(self, addr):
        return SUMIProtocol()

    def clientConnectionLost(self, connector, reason):
        print "Lost connection: %s" % reason

    def clientConnectionFailed(self, connector, reason):
        print "Connection failed: %s" % reason
        for x in cli_locks:
            cli_locks[x].release()

def recvmsg(callback=default_cb):
    global tor_callback

    tor_callback = callback

    # Make sure this is exposed in torrc, for example:
    # /usr/local/etc/tor/torrc:
    #  HiddenServiceDir /usr/local/etc/tor/hidden_service
    #  HiddenServicePort 2773 127.0.0.1:2773

    # XXX: Make sure to only listen on localhost!
    print "Starting server on %s" % PORT
    reactor.listenTCP(PORT, SUMIServerFactory(), interface="localhost")
    reactor.run(installSignalHandlers=False)

def user_init(nick):
    global cli_locks

    cli_locks[nick] = thread.allocate_lock()
    cli_locks[nick].acquire()

    # TODO: use SOCKS to connect to hidden host over Tor

    # Start thread for reactor
    def t():
        reactor.connectTCP(nick, PORT, SUMIClientFactory())
        reactor.run(installSignalHandlers=False)

    thread.start_new_thread(t, ())

    # Wait until thread connects
    print "user_init waiting for connection..."
    cli_locks[nick].acquire()
    print "user_init returning"

# TODO: connect to hidden service, over SOCKS proxy localhost:9050 for client
# Need to find a Python SOCKS library, better to natively support it than try
# to wrap with torify, and also then can ensure no DNS leakage.
# http://www.w3.org/People/Connolly/drafts/socksForPython.html ?

def sendmsg(nick, msg):
    global connections
    if connections.has_key(nick) and hasattr(connections[nick], "sendLine"):
        #print "sending: %s" % msg
        connections[nick].sendLine(msg)
    else:
        raise Exception("modtor: no user %s - call user_init to connect" % nick)

def test():
    import sys

    print "Starting server"
    thread.start_new_thread(recvmsg, ())
    print "Making connection"
    user_init("127.0.0.1")
    print "Type messages to send, or blank to exit."
    print "You can also connect to %s on another console." % PORT
    
    while True:
        import sys
        msg = sys.stdin.readline().strip()
        if len(msg) == 0:
            break
        sendmsg("127.0.0.1", msg)

def test_SOCKS():
    # Twisted only has a SOCKS4 server, no client?
    #from twisted.protocols.socks import SOCKSv4Factory
    #reactor.listenTCP(1080, SOCKSv4Factory("/dev/ttyp1"))
    #reactor.run(installSignalHandlers=False)
    pass

if __name__ == "__main__":
    test()
    #test_SOCKS()
