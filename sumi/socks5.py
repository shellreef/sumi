"""SOCKS5 client module.

Based on spec at http://www.faqs.org/rfcs/rfc1928.html.

Created:20050815
By Jeff Connelly"""

import socket
import struct

SOCKS_VER = 5

# Authentication methods
METHOD_NO_AUTH       = 0x00
METHOD_GSSAPI        = 0x01
METHOD_USERNAME      = 0x02
METHOD_NO_ACCEPTABLE = 0xff

# Commands
CMD_CONNECT          = 0x01
CMD_BIND             = 0x02
CMD_UDP_ASSOCIATE    = 0x03

# Address types
ATYP_IPV4            = 0x01
ATYP_DOMAINNAME      = 0x03
ATYP_IPV6            = 0x04

supported_methods = [METHOD_NO_AUTH]

class SOCKS5_Exception:
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return msg

def setup(socks_host, socks_port=1080):
    """Connects to given SOCKS proxy and negotiates authentication."""
    s = socket.socket()
    try:
        s.connect((socks_host, socks_port))
    except socket.error, e:
        raise SOCKS5_Exception("couldn't connect to SOCKS: %s" % e)
    
    negotiate(s)

    return s
    
def negotiate(s):
    """Negotiate authentication methods with server. The global array
    supported_methods contains methods we support. Currently, no
    authentication is suppored."""
    # +----+----------+----------+
    # |VER | NMETHODS | METHODS  |
    # +----+----------+----------+
    # | 1  |    1     | 1 to 255 |
    # +----+----------+----------+
    n = len(supported_methods)
    pkt = struct.pack("!BB" + "B"*n, *([SOCKS_VER, n] + supported_methods))
    s.sendall(pkt)

    # +----+--------+
    # |VER | METHOD |
    # +----+--------+
    # | 1  |   1    |
    # +----+--------+
    response = s.recv(2)
    assert len(response) == 2, "invalid response from server: %s" % response
    assert response[0] == chr(SOCKS_VER), "unrecognized server version"

    server_methods = map(ord, list(response[1:]))
    if METHOD_NO_ACCEPTABLE in server_methods:
        raise SOCKS5_Exception, "No acceptable methods supported by server"

    if not METHOD_NO_AUTH in server_methods:
        raise SOCKS5_Exception, "Authentication not supported by this module"

def request(s, cmd, hostname, port):
    """Send a SOCKS5 request for hostname:port. Always uses a fully-qualified
    domain name address type.
    @return (hostname, port) from proxy. For bind, this will be the address
    bound to. It may be all zeroes, especially for CMD_CONNECT requests."""

    # We always send domain name and let server resolve it, to avoid DNS leaks
    req = struct.pack("!BBBBB", SOCKS_VER, cmd, 0, ATYP_DOMAINNAME,
        len(hostname)) + hostname + struct.pack("!H", port)

    s.sendall(req)

    resp = s.recv(4)
    ver, rep, rsv, atyp = struct.unpack("!BBBB", resp)
    assert ver == SOCKS_VER, "invalid version from server"

    if atyp == ATYP_IPV4:
        address = ".".join(map(str, struct.unpack("!BBBB", s.recv(4))))
    elif atyp == ATYP_DOMAINNAME:
        length = struct.unpack("!H", s.recv(2))
        address = s.recv(length)
    elif atyp == ATYP_IPV6:
        address = s.recv(16).encode("hex")  # could use some colons...
    else:
        assert False, "unknown address type: %s" % atyp

    port, = struct.unpack("!H", s.recv(2))

    return (address, port)

def connect_via(address, proxy):
    """Negotiate and send a connect request to address = (hostname, port).
    Provides a similar address to socket's connect()."""
    hostname, port = address

    s = socket.socket()
    s.connect(proxy)
    negotiate(s)

    # Return value not usually meaningful for connect command
    request(s, CMD_CONNECT, hostname, port)

    return s

def test1():
    # Lower-level API
    print "Connecting to Tor..."
    s = setup("localhost", 9050)
    print "Connected"

    request(s, CMD_CONNECT, "google.com", 80)

    s.send("GET / HTTP/1.0\r\n\r\n")
    print s.recv(100)

def test2():
    # Simplified API
    s = connect_via(("google.com",80), ("localhost", 9050))
    s.send("GET / HTTP/1.0\r\n\r\n")
    print s.recv(100)

if __name__ == "__main__":
    #test1()
    test2()
