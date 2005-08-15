# Created:20050811
# By Jeff Connelly

# Tor transport

# For "Tor: An anonymous Internet communication system" http://tor.eff.org/

# idea: server hosts a "hidden service" via tor
# client would connect, via tor, to the hidden service...

from SocketServer import TCPServer, BaseRequestHandler
import socket

PORT = 2773

global tor_sockets, tor_callbacks
tor_sockets = {}
def default_cb(nick, msg):
    print "(tor) <%s> %s" % (nick, msg)
tor_callback = default_cb

class RequestHandler(BaseRequestHandler):
    def handle(self):
        global tor_sockets
        print "Incoming connnection from %s" % (self.client_address, )
        nick = "tor%s" % self.client_address[1]   # port number

        tor_sockets[nick] = self.request

        while True:
            msg = self.request.makefile().readline().strip()
            if msg == '':
                break
            print "Read msg |%s|" % msg
            tor_callback(nick, msg)

def recvmsg(callback=default_cb):
    global tor_callback

    tor_callback = default_cb

    # Make sure this is exposed in torrc, for example:
    # /usr/local/etc/tor/torrc:
    #  HiddenServiceDir /usr/local/etc/tor/hidden_service
    #  HiddenServicePort 2773 127.0.0.1:2773
    t = TCPServer(("localhost", PORT), RequestHandler)
    print "Starting local server on %s" % PORT
    t.serve_forever()

def user_init(nick):
    global tor_users

    # TODO: use SOCKS
    tor_users[nick] = socket.socket()
    print "Connecting to %s:%s" % (nick, PORT)
    tor_users.connect((nick, PORT))
    print "Connected"

# TODO: connect to hidden service, over SOCKS proxy localhost:9050 for client
# Need to find a Python SOCKS library, better to natively support it than try
# to wrap with torify, and also then can ensure no DNS leakage.
# http://www.w3.org/People/Connolly/drafts/socksForPython.html ?

def sendmsg(nick, msg):
    if tor_users.has_key(nick):
        tor_users[nick].write("%s\r\n" % msg)
    else:
        raise RuntimeException("modtor: no user %s" % nick)

