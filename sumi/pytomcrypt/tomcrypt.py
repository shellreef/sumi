# Created:20050807
# By Jeff Connelly

# Wrapper for ctomcrypt

from types import *

from ctomcrypt import *
import ctomcrypt

class LTC_Exception:
    def __init__(self, code, msg):
        self.code = code
        self.msg = msg
    def __str__(self):
        return "%s: %s" % (self.code, self.msg)

def ltc_check(err):
    """If err is not CRYPT_OK, raise an exception with the given code.
    Otherwise, return any additional arguments passed. Used to check 
    return codes."""
    # The SWIG-generated wrapper allows multiple return values in the form of
    # lists. The first element will be the C return value (usually an int--
    # the error code) and the others will be output arguments. For example:
    #  [0, "\x02\x01\x02\x00\x00..."]        # return value of export
    # In this case, we want to check that the first argument is CRYPT_OK, and
    # if it is, return the additional arguments. But if there is only one
    # return value, SWIG will just return it--not wrap inside a list, so we
    # handle that case too.
    args = None
    if type(err) == ListType or type(err) == TupleType:
        if type(err[0]) == IntType:         # the usual [err, args...]
            args = err[1:]
            if len(args) == 1: args = args[0]
            err = err[0]
        elif type(err[1]) == IntType and len(err) == 2:  # [arg, err]
            args = err[0]
            err = err[1]
    assert type(err) == IntType, "%s is not an int, but a %s" % (
            err, type(err))
    if err != CRYPT_OK:
        raise LTC_Exception(err, error_to_string(err))
    return args

class PRNG:
    """Wraps pseudo random number generators."""
    def __init__(self, name="fortuna", load=None):
        """Create a new pseudo random number generator.

        name: name of the algorithm to use
        load_new: a string produced by export(), used to import
        """
        self.name = name
        if load:
            p = ltc_check(fortuna_import1(load))
        else:
            p = malloc_prng_state()

        def f(method):
            return eval("%s_%s" % (self.name, method))

        # Load the functions once
        start = f("start")
        ready = f("ready")
        read = f("read1")
        add = f("add_entropy")
        export = f("export1")

        self.start = lambda: ltc_check(start(p))
        self.ready = lambda: ltc_check(ready(p))
        self.read = lambda length: read(length, p)   # Returns # of bytes
        self.add = lambda data: ltc_check(add(data, p))

        self.export = lambda maxlen=2048: ltc_check(export(maxlen, p))
        
        self.obj = p

    def algorithms():
        as = []
        for a in dir(ctomcrypt):
            if a.endswith("_start"):
                as.append(a.split("_")[0])
        return as

    algorithms = staticmethod(algorithms)


def test_prng():
    print "Available algorithms: ", PRNG.algorithms()

    p = PRNG("fortuna")
    print "start=",p.start()
    print "ready=",p.ready()
    save = p.export(2048)
    print "read=",[p.read(10)]
    print "export=",len(save),"bytes"
   
    q = PRNG("fortuna", save)
    print "read=",[q.read(10)]
    print

class PK:
    def __init__(self, name, size, load=None):
        """Create a new asymmetric key or load an existing key.

        size: size in bytes
        load: export()'d data to load, or None.
        """
        self.name = name
        self.size = size

        def f(method):
            return eval("%s_%s" % (self.name, method))
        malloc_key = eval("malloc_%s_key" % self.name)
        make_key = f("make_key")
        import_key = f("import1")
        self.__export_key = f("export")
        self.__shared_secret = f("shared_secret")

        if not load:
            self.k = malloc_key()
            ltc_check(make_key(None, find_prng("sprng"), size, self.k))
        else:
            self.k = ltc_check(import_key(load))

    def export_public(self):
        """Export the public portion of the key."""
        return ltc_check(self.__export_key(MAXBLOCKSIZE, PK_PUBLIC, self.k))

    def export_private(self):
        """Export the private portion of the key, if any."""
        return ltc_check(self.__export_key(MAXBLOCKSIZE, PK_PRIVATE, self.k))

    def shared_secret(self, pubkey):
        """Calculate the shared secret using our private key, and pubkey."""
        return ltc_check(self.__shared_secret(self.k, pubkey.k, MAXBLOCKSIZE))

    #def __del__(self):
    #    if self.k:
    #        ecc_free(self.k)

def test_ecc():
    l, h = ecc_sizes()
    print "Available ECC keysizes: %s-%s bits" % (l*8, h*8)
    sprng_register_prng()
    k = PK("ecc", 32)
    exp = k.export_public()
    print "export1=",[exp]
    k2 = PK("ecc", 32,exp)
    assert k2.export_public() == exp, "import/export is broken";
    print "import/export works"
    k3 = PK("ecc", 32)  # should be different?
    print "export2=",[k3.export_public()]

    print
    print "secret=",[k.shared_secret(k3)]
    print "secret=",[k3.shared_secret(k)]
    print

    print "export_private=",[k3.export_private()]

    k4 = None
    try:
        k4 = PK("ecc", 32, "this is not a valid public key")
    except LTC_Exception, x:
        print "exception handling works: ",x
    assert not k4, "imported invalid key without error"

class Hash:
    def __init__(self, name, initial_data=None):
        self.h = h = malloc_hash_state()
        self.name = name
        def f(method):
            return eval("%s_%s" % (self.name, method))

        init = f("init")
        process = f("process")
        done = f("done")

        self.init = lambda: ltc_check(init(h))
        self.init()

        self.process = lambda data: ltc_check(process(h, data))
        self.done = lambda: ltc_check(done(h))

        if initial_data:
            self.process(initial_data)

def test_hash():
    h = Hash("sha256")
    h.process("hello world")
    print "A SHA-256 hash:", [h.done()]

    h1 = Hash("sha1", "")
    #print "SHA-1('') = ", [h1.done()]
    assert h1.done() == \
        "\xda9\xa3\xee^kK\r2U\xbf\xef\x95`\x18\x90\xaf\xd8\x07\t", \
        "hash of zero-length string failed to match test vector."
    print "sha-1 works"

    # TODO: test CHC
    chc_register_hash()

# TODO: fix. Broken now. 
class Cipher:
    def __init__(self, name, key, rounds=0):
        self.name = name
        def f(method):
            return eval("%s_%s" % (self.name, method))
        self.c = malloc_symmetric_key()

        setup = f("setup")
        ecb_encrypt = f("ecb_encrypt")
        ecb_decrypt = f("ecb_decrypt")
        test = f("test")
        keysize = f("keysize")

        setup(key, rounds, self.c)

        self.ecb_encrypt = lambda pt: ecb_encrypt(pt, self.c)
        self.ecb_decrypt = lambda ct: ecb_decrypt(ct, self.c)

def test_cipher():
    c = Cipher("aes","0"*32)
    print "Cipher=",[c.ecb_encrypt("hi"*8)]

if __name__ == "__main__":
    test_prng()
    test_ecc()
    test_hash()
    #test_cipher()
