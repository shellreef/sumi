import  sys
from ctomcrypt import *

assert CRYPT_OK == 0
print "CRYPT_OK exists"
print [rng_get_bytes1(10)]
print "docstring=",rng_get_bytes1.__doc__

p = malloc_prng_state()
print "start=",fortuna_start(p)
print "add=",fortuna_add_entropy("foo", p);
print "ready=",fortuna_ready(p)
print "read=",[fortuna_read1(10,p)]
print "export=",str([fortuna_export1(2048,p)])[0:50],"..."
#try:
#    print "export(bad)=",fortuna_export1(10,p)
#except:
#    print "exception handling works"
#sys.exc_clear()
imp = fortuna_export(2048,p)[1]
print "\texported %s bytes" % len(imp)
q = malloc_prng_state()
print "import=", fortuna_import1(imp)
print "ready=",fortuna_ready(q)
print "read=",[fortuna_read1(10,q)]

p = malloc_prng_state()
print "start=",yarrow_start(p)
print "add=",yarrow_add_entropy("foo", p);
print "ready=",yarrow_ready(p)
print "read=",[yarrow_read1(10,p)]
print "export=",str([yarrow_export(2048,p)])[0:50],"..."
print "\texported %s bytes" % len(yarrow_export(2048,p)[1])
