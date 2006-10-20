#!env python
# Created:2006102
# By Jeff Connelly

# Create 1MB test file with recognizable packets

import sys

# set to whatever you want
mss = 1461
limit = 1024 * 1024

size = 0
filler = 1
pkts = []
while size < limit:
    if size + mss > limit:
        # Last packet
        reps = limit % mss
    else:
        reps = mss

    block = chr(filler % 254 + 1) * reps
    pkts.append(block)
    size += reps

    filler += 1

assert size == len("".join(pkts)), "Size miscounted: %d != %d" % (
        size, len("".join(pkts)))
assert size == limit, "Size %d did not reach desired limit %d" % (
    size, limit)

sys.stderr.write("Generated %s packets, for %s bytes\n" % (len(pkts), size))
file("1mb","wb").write("".join(pkts))

