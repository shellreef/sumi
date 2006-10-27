#!env python
# Created:20061026
# By Jeff Connelly

# Compare received transefr to analyze what packets were corrupted/missing

import sys

mss = 1461

f1 = file(sys.argv[1], "rb")
f2 = file(sys.argv[2], "rb")

n = 0
while True:
    n += 1   # start from seqno = 1
    b1 = f1.read(mss)
    b2 = f2.read(mss)

    if b1 != b2:
        print "%s differs" % n
  
    if b1 == "\0" * mss:
        print "\tmissing from %s" % sys.argv[1]
    if b2 == "\0" * mss:
        print "\tmissing from %s" % sys.argv[2]

    if len(b1) == 0 and len(b2) == 0:
        break
    if len(b1) == 0:
        print "eof from %s" % sys.argv[1]
        break
    if len(b2) == 0:
        print "eof from %s" % sys.argv[2]
        break

print "%s blocks compared" % n
