# Created:20050811
# By Jeff Connelly

# Tor transport

# For "Tor: An anonymous Internet communication system" http://tor.eff.org/

# The server hosts a "hidden service" via Tor.
# Client connects, via Tor, to the hidden service.

import thread
import sys
import socket
import select

# Tor offers a SOCKS server to allow entry into the network
# Use socks5 module (included with SUMI) to access it:
sys.path.append("..")
import socks5

TOR_PORT = 9050          # Tor's SOCKS port, SocksPort in torrc
PORT = 3490              # Our port

global connections
connections =  {}

def is_secure():
    return True     # finally a secure transport

def default_cb(nick, msg):
    print "(tor) <%s> %s" % (nick, msg)

def recvmsg_client(callback=default_cb):
    """Receive messages as a client."""
    global connections

    while True:
        # Look for readable sockets
        readable, writable, exceptable = select.select(connections.values(),
                [], [], 1)
        for s in readable:
            msg = s.recv(65535)
            if len(msg) == 0:
                # EOF, so find this connection, remove it 
                for x in connections:
                    if connections[x] == s:
                        connections.pop(x)
                        break

            callback("tor-%d" % s.getsockname()[1], msg)

def recvmsg(callback=default_cb, server=True):
    if server:
        return recvmsg_server(callback)
    else:
        return recvmsg_client(callback)

def recvmsg_server(callback=default_cb):
    """Start a local server to share over Tor.
    Note: make sure this is exposed in torrc, for example:

    /usr/local/etc/tor/torrc:
    HiddenServiceDir /usr/local/etc/tor/hidden_service
    HiddenServicePort 2773 127.0.0.1:2773"""


    print "Starting local server on %s" % PORT
    ss = socket.socket()

    # Allow reusing local addresses and ports so don't have to wait to timeout
    ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    ss.bind(("localhost", PORT))
    ss.listen(5)

    callback("(transport_ready)", "tor")

    while True:
        accept_client(ss, callback)

def accept_client(ss, callback):
    global connections

    cs, client_address = ss.accept()

    # Start a new thread upon accepting a client, to listen for new clients.
    # We don't prefork or anything. I tried some frameworks that handle this
    # automatically (Twisted Matrix, SocketServer) but they are quite complex,
    # and their OO approach doesn't integrate well with the procedural style
    # of transports. Might look back into them if this becomes a problem...
    thread.start_new_thread(accept_client, (ss, callback))

    # Make sure we are not exposed.        
    assert client_address[0] == "127.0.0.1", \
            "modtor received connection from %s:%s not local!" % client_address
    nick = "tor-%s" % client_address[1]
    print "Connected to %s" % nick
    connections[nick] = cs

    while True:
        msg = cs.makefile().readline()
        
        if len(msg) == 0:
            break

        callback(nick, msg.strip("\n"))
    print "Lost connection to %s" % nick

def user_init(nick):
    global connections

    # Use SOCKS to connect to hidden host over Tor's SOCKS proxy. SOCKS5
    # is supported natively; there is no need to Torify, and there is no
    # DNS leakage because the hostname is sent as is (not resolved here).
    # Note: this may raise a socks5.Error
    #s = socks5.connect_via((nick, PORT), ("localhost", TOR_PORT))

    # For testing without SOCKS XXX XXX
    s = socket.socket()
    s.connect(("localhost", PORT))
    
    connections[nick] = s
    return True

def transport_init():
    pass

def sendmsg(nick, msg):
    global connections

    if not connections.has_key(nick):
        log("modtor: not connected to %s, call user_init (c=%s)" % (nick,
            connections))
        return False

    connections[nick].send("%s\n" % msg)

    return True

def test():
    import sys
    
    nick = "upzt3xumxtpslxkb.onion"

    print "Starting server"
    thread.start_new_thread(recvmsg, ())
    print "Making connection"

    user_init(nick)
    print "Type messages to send, or blank to exit."
    print "You can also connect to %s on another console." % PORT
    
    while True:
        import sys
        msg = sys.stdin.readline()
        if len(msg) == 0:
            break
        sendmsg(nick, msg.strip())

if __name__ == "__main__":
    test()
