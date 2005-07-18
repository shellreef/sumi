#!/usr/bin/env python
# Created:20040117
# By Jeff Connelly

# Python library for common SUMI functions, shared between client and server

import string

SUMIHDRSZ = 6#bytes
SUMIAUTHHDRSZ = 4#bytes
PKT_TIMEOUT = 3#seconds

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

