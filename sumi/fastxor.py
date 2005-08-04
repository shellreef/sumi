# Created:20050802
# By Jeff Connelly

# Various string bitwise XOR implementations

# XOR has many uses in cryptography, for chaining modes etc., so its
# a good idea to have an efficient implementation. Python, unfortunately,
# gets in our way here--it doesn't allow strings to be modified in-place.
# A good workaround is to list("the string"), converting it to an array,
# XOR each byte, then join it back, but I think we can do faster in C w/ SWIG.

import time
import random
import struct

import AONTransform
from libsumi import *
from UserString import MutableString

TIMES = 100

def benchmark(fs, data):
    i = 0
    ans = [{}] * TIMES
    times = {}
    for f in fs:
        g = time.time()
        for i in range(TIMES):
            ans[i][f.__name__] = f(data[i][0], data[i][1])
        t = time.time() - g
        times[f.__name__] = t
        i += 1
    verify(ans, data)
    return times

def verify(ans, data):
    """Make sure all the answers match."""
    fail = False
    def eq(a, b):
        # A better equals, suitable for reducing
        if a == b: return a
        return False

    for i in range(TIMES):
        if not reduce(eq, ans[i].values()):
            fail = True
            print "FAIL: ", ans[i], "data=", data[i]
    if not fail:
        print "All answers matched"
    return fail 

def make_data():
    from Crypto.Util.randpool import RandomPool
    r = RandomPool()
    data = []
    for i in range(TIMES):
        data.append([r.get_bytes(100), r.get_bytes(100)])
    return data

def xor_bigint(a,b):
    """Convert string to a bigint, XOR it, then convert back."""
    # Cons: conversion, storing all data twice--probably the worst idea ever
    # Pros: none!
    c = pack_num(unpack_num(a) ^ unpack_num(b))
    c += "\0" * (len(a) - len(c))    # Important: little-endian
    return c

def xor_long(a,b):
    """Convert string to an array of longs, XOR them, then convert back."""
    i = 0
    x = ""
    # Pros: 32-bit size may match word size of processor
    # Cons: unpacking/packing negates any benefit
    while i < len(a):
        x += struct.pack("L",
                struct.unpack("L", a[i:i+4])[0] ^ 
                struct.unpack("L", b[i:i+4])[0])
        i += 4
    return x

def xor_byte_pack(a,b):
    """Loop over the strings byte-by-byte, using pack/unpack."""
    # Cons: += creates len(a) new strings, not word size
    c = ""
    for i in range(len(a)):
        c += struct.pack("B", 
                struct.unpack("B", a[i])[0] ^
                struct.unpack("B", b[i])[0])
    return c

def xor_ord(a,b):
    """Loop over the string byte-by byte using ord/chr."""
    # Cons: += creates many new strings, not word size
    # Pro: faster than xor_byte_pack
    c = ""
    for i in range(len(a)):
        c += chr(ord(a[i]) ^ ord(b[i]))
    return c

# XXX: Broken
def BROKEN_xor_ord_mutable(a,b):
    """Byte-by-byte XOR using ord, in-place using MutableString."""
    # Cons: MutableString is awkward
    am = MutableString(a)
    for i in range(len(a)):
        am[i] = chr(ord(chr(am[i])) ^ ord(b[i]))
    return am

def xor_ord_array(a,b):
    """Convert to an array, XOR in place using ord."""
    # Pros: XORs in place, doesn't need to create more strings, fast!
    la = list(a)
    for i in range(len(a)):
        la[i] = chr(ord(la[i]) ^ ord(b[i]))
    return "".join(la)

def xor_ord_array_xrange(a,b):
    """Convert to an array, XOR in place using ord, looping over an
    iterator."""
    # Pros: with xrange, no need to create an actual list
    la = list(a)
    for i in xrange(len(a)):
        la[i] = chr(ord(la[i]) ^ ord(b[i]))
    return "".join(la)

# TODO: cStringIO, list comprehensions?
# TODO: C implementations, using SWIG, over bytes, shorts, longs, qwords

def show(times):
    """Display the times, from worst to best."""
    k = times.keys()
    k.sort(lambda x,y: times[y].__cmp__(times[x]))
    for f in k:
        print "%20s: %-s" % (f, times[f])

# All the routines defined here. Have to do this here instead of inside
# main() because dir() returns symbols in the current scope.
all_xors = map(eval, filter(lambda x: x.startswith("xor"), dir()))

def main():
    return show(benchmark(all_xors, make_data()))

if __name__ == "__main__":
    main()
