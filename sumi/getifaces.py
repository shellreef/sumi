#!/usr/bin/env python
# Created:20040130
# By Jeff Connelly

# get network interfaces

import sys

def get_ifaces_win32():
    import wmi
    c = wmi.WMI()
    ifaces = {}

    # Caption, ServiceName
    for interface in c.Win32_NetworkAdapterConfiguration():
        # Win32 stores a bunch of stuff secondary to the interface config,
        # like DHCP, DNS, firewall, IPX, TCP, WINS
        ifaces[interface.ServiceName] = {
            "media": interface.Caption,
            "name": interface.ServiceName,
            "description": interface.Description,
            "ether": interface.MACAddress,
            "inet": interface.IPAddress != None and interface.IPAddress[0],
        #   "inets": interface.IPAddress,   # can have >1 IP/subnet?
            "netmask": interface.IPSubnet != None and interface.IPSubnet[0],
        #    #"netmasks": interface.IPSubnet,
            "status": interface.IPEnabled,
            "mtu": interface.MTU }
    return ifaces

# coded for BSD's ifconfig
# TODO: port to Linux
def get_ifaces_unix():
    import os

    ifconfig = os.popen("ifconfig")
    all_opts = {}
    ifaces = {}
    while 1:
        line = ifconfig.readline()
        if line == "": break  
        line = line[:-1]
        if line[0] != "\t":    # interface name, flags, and mtu line
            if (all_opts != {}):
                all_opts["mtu"] = mtu 
                all_opts["flags"] = flags
                ifaces[ifname] = all_opts
            (ifname, rest) = line.split(":")
            (rest, mtu) = line.split("mtu ")
            flags = rest.split("<")[1].split(">")[0].split(",")
            all_opts = {}
        else:
            line = line[1:]
            a = line.split(" ")
            if (a[0][-1] == ":"):      # media:, status: take a full line
                (k, v) = line.split(": ")
                all_opts[k] = v
            else:                      # list of dict values
                opts = dict(zip(*[iter(a)] * 2))
                for k in opts:
                    if (k == "netmask"):
                        # Convert 0x.. netmask to dotted quad
                        import socket, struct, string
                        opts[k] = socket.inet_ntoa(struct.pack("!L", 
                                      string.atoi(opts[k], 16)))
                    all_opts[k] = opts[k]
            #print "\t", opts 
    return ifaces

# broken, need pointers?
def get_ifaces_unix_IOCTL():
    import socket
    import fcntl
    import IN
    import struct

    SIOCGIFCONF = -1073190620   #  FreeBSD
    MAX_IFS = 32

    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    buf = "\0" * (32 * MAX_IFS)   # 32 = sizeof(ifreq)
    ifc = struct.pack("!L", len(buf)) + "\0";
    fcntl.ioctl(sockfd, SIOCGIFCONF, ifc)

def get_ifaces():
    if (sys.platform == "win32"):
        return get_ifaces_win32()
    else:
        return get_ifaces_unix()

# Connects to a given host and gets its the address of our side of the socket
# If behind a NAT this still will return the local IP, not the WAN IP
def get_default_ip(test_host="google.com", test_port=80):
    import socket
    sockfd = socket.socket()
    sockfd.connect((test_host, test_port)) 
    (ip, port) = sockfd.getsockname()
    sockfd.close()
    return ip

if __name__ == "__main__":
    print get_ifaces()

