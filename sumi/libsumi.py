#!/usr/bin/env python
# Created:20040117
# By Jeff Connelly

# Python library for common SUMI functions, shared between client and server

import string

SUMIHDRSZ = 6#bytes
SUMIAUTHHDRSZ = 4#bytes
PKT_TIMEOUT = 3#seconds

# TODO: Move these out of here! Doesn't below here at all.
(irc_chan, irc_chankey) = ("#sumi", "riaa")
# IRC server. Set this to 127.0.0.1 if you're using IIP
(irc_server, irc_port) = ("10.0.0.1", 6667)

# Parse arguments in the form of aFOO\tbBAR\tcQUUX\to23948\tfhello world
def unpack_args(raw):
    args = {}
    for x in raw.split("\t"):
        args[x[:1]] = x[1:]
    return args

# Given a dictionary of arguments and their values, pack them for transmission
def pack_args(args):
   array = []
   for k in args:
       array.append(k + str(args[k]))
   raw = string.join(array, "\t")
   return raw

