"""SOCKS5 client module.

Based on spec at http://www.faqs.org/rfcs/rfc1928.html.

Created:20050815
By Jeff Connelly

$Id$"""

# Python SOCKS5 Client
# Copyright (C) 2005-2006  Jeff Connelly <jeffconnelly@users.sourceforge.net>

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, 
# USA, or online at http://www.gnu.org/copyleft/gpl.txt .



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

class Error(Exception):
    def __init__(self, msg, original_exception=None):
        self.msg = msg
        self.original_exception = original_exception
    
    def __str__(self):
        return self.msg

    def get_original_exception(self):
        return self.original_exception

def setup(socks_host, socks_port=1080):
    """Connects to given SOCKS proxy and negotiates authentication."""
    s = socket.socket()
    try:
        s.connect((socks_host, socks_port))
    except socket.error, e:
        raise Error("couldn't connect to SOCKS: %s" % e, e)
    
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
    if len(response) != 2:
        raise Error("Unrecognized response from proxy: %s" % response)
    if ord(response[0]) != SOCKS_VER:
        raise Error("Proxy is using SOCKS%s, not SOCKS%s" 
                % (ord(response[0]), SOCKS_VER))

    server_methods = map(ord, list(response[1:]))
    if METHOD_NO_ACCEPTABLE in server_methods:
        raise Error("No acceptable methods supported by server")

    if not METHOD_NO_AUTH in server_methods:
        raise Error("Authentication not supported by this module")

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
    if ver != SOCKS_VER:
        raise Error("Invalid version from server: %s != %s" % (ver, SOCKS_VER))

    if atyp == ATYP_IPV4:
        address = ".".join(map(str, struct.unpack("!BBBB", s.recv(4))))
    elif atyp == ATYP_DOMAINNAME:
        length = struct.unpack("!H", s.recv(2))
        address = s.recv(length)
    elif atyp == ATYP_IPV6:
        address = s.recv(16).encode("hex")  # could use some colons...
    else:
        raise Error("Unknown address type: %s" % atyp)

    port, = struct.unpack("!H", s.recv(2))

    return (address, port)

def connect_via(address, proxy=None, s=None):
    """Negotiate and send a connect request to address = (hostname, port).
    Provides a similar address to socket's connect(). If proxy=None,
    socket is assumed to already be connected to a SOCKS server.
    
    If s is provided, it is used as a socket, otherwise a new socket is
    created."""
    hostname, port = address

    if proxy:
        try:
            s = socket.socket()
            s.connect(proxy)
        except socket.error, e:
            raise Error(("connect_via proxy error: %s" % e), e)

    negotiate(s)

    # Return value not usually meaningful for connect command
    request(s, CMD_CONNECT, hostname, port)

    return s

def test1():
    # Test the lower-level API
    print "Connecting to Tor..."
    s = setup("localhost", 9050)
    print "Connected"

    request(s, CMD_CONNECT, "google.com", 80)

    s.send("GET / HTTP/1.0\r\n\r\n")
    print s.recv(100)

def test2(site="google.com",port=80):
    # Test higher-level API. 'site' can be a hidden service for Tor.
    s = connect_via((site,port), ("localhost", 9050))
    s.send("GET / HTTP/1.0\r\n\r\n")
    print s.recv(100)

# These tests require Tor
if __name__ == "__main__":
    test1()
    #test2("5mg27ujynvojkdpq.onion", 3490)
    test2()
