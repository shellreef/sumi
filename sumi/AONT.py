"""Implements an all-or-nothing transformation algorithm.

All-or-nothing was originally described in:

Ronald L. Rivest.  "All-Or-Nothing Encryption and The Package Transform"
http://theory.lcs.mit.edu/~rivest/fusion.pdf

This module was inspired by Crypto.Protocol.AllOrNothing in PyCrypto.

TODO: Look at AONT OAEP at http://theory.lcs.mit.edu/~boyko/aont-oaep.html,
provably secure under random oracle model.
"""

# Created:20050731
# By Jeff Connelly

from libsumi import pack_num, unpack_num, random_bytes, random_init

def xor_str(a, b):
    """Bitwise XOR two equally-length strings together."""
    assert len(a) == len(b), "a,b: %s != %s (%s)" % (len(a), len(b), [a, b])
    # A fairly efficient technique   
    la = list(a)
    for i in xrange(len(a)):
        la[i] = chr(ord(la[i]) ^ ord(b[i]))
    c = "".join(la)
    assert len(c) == len(a), "c,a: %s != %s (%s)" % (len(c), len(a), [c, a])
    return c

class AONException:
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return "AONException: %s" % self.msg

class AON:
    def __init__(self, cipher, mode, IV, hash=None):
        """Initialize all-or-nothing transform.

        cipher: PEP272 compliant cipher module, for example. Crypto.Cipher.AES
        mode, IV: cipher mode and IV, passed to cipher.new()
        hash: hash module, defaults to SHA-1
        """

        random_init()

        self.cipher = cipher
        self.block_size = cipher.block_size
        self.mode = mode
        self.IV = IV
        if not hash: import sha; hash = sha 
        self.hash = hash
        self.block_no = 0
        self.digesting = False
        self.gathering = False
        self.undigesting = False
        self.can_undigest = False
        self.done = False

    def make_block(self, i):
        """Create a block with an integer value i, of block_size bytes."""
        x = pack_num(i)
        assert len(x) <= self.block_size
        x += "\0" * (self.block_size - len(x))
        return x


    def digest(self, msg):
        """Digest a complete message. To digest a message
        part by part, use digest_next() and digest_last() instead.""" 
        return self.digest_next(msg) + self.digest_last()

    def digest_next(self, msg):
        """Given a string of cleartext blocks, create and return the
        corresponding pseudomessage. msg must be a multiple of the block
        size of the block cipher, and the return value will be a string of
        pseudoblocks.
        
        Cannot be called after last()."""

        if self.done:
            raise AONException("called digest_next() after digest_last()")

        # First time encrypting? Setup...
        if not self.digesting:
            self.k = random_bytes(self.block_size) 
            #print "=====k=",[self.k]
            self.crypt = self.cipher.new(self.k, self.mode, self.IV)
            self.digesting = True
            self.last_block = self.k  # will be updated each with block

        if len(msg) % self.block_size:
            raise AONException("Message length %s not multiple of %s" %
                    (len(msg), self.block_size))
        pseudo = ""
        for clear_block in self.split_blocks(msg):
            pseudo += self.next_block(clear_block)
        return pseudo

    def split_blocks(self, s):
        """Split s into an array of blocks of cipher block size."""
        blocks = []
        for i in range(len(s) / self.block_size):
            blocks.append(s[i * self.block_size:(i + 1) * self.block_size])
        return blocks            

    def digest_last(self):
        """Return the last pseudomessage block. Cannot call digest_next() after."""
        self.done = True
        return self.last_block

    def xor_block(self, block, i_str):
        """XOR block with encrypted block number i_str. Used for both
        encryption and decryption. i_str is a block-sized string
        representing the block number, made from self.make_block()."""
        return xor_str(block, self.crypt.encrypt(i_str))

    def next_block(self, clear_block):
        """Transform one message block into a pseudomessage block."""
        self.block_no += 1
        block_no = self.make_block(self.block_no)
        #print "Block %s" % self.block_no
        # m'[i] = m[i] xor E(K',i) for i=1,2,3,...,s
        pseudo_block = self.xor_block(clear_block, block_no)
        #print "pseudo_block of %s = %s" % (clear_block, [pseudo_block])
        # m'[s'] = K' xor h[1] xor h[2] xor ... h[s]
        self.last_block = xor_str(self.last_block, 
                self.hash_block(pseudo_block, block_no))
        #print "k enc =",[self.last_block]
        return pseudo_block

    def hash_block(self, msg, i):
        """Return a hash of block msg, number i, truncated to block size."""
        # Rivest's hash: h[i] = E(K[0],m'[i] xor i) for i=1,2,...,s
        # Here, instead I use SHA-1 (or other hash specified in constructor)
        # instead of reusing the block cipher.
        return self.hash.new(xor_str(msg, i)).digest()[0:self.block_size]

    # == untransformation routines ==
    def gather_block(self, block, i):
        """First-pass of untransformation. Hash block number i and
        update k."""

        if not self.gathering:
            # Each hash will be XOR'd in
            self.k = "\0" * self.block_size
            self.gathering = True
        #print "\t",[self.k, self.make_block(i)] 
        # K' = ... xor h[1] xor h[2] ... h[s]
        self.k = xor_str(self.k, self.hash_block(block, self.make_block(i)))
        #print "k now =",[self.k]

    def gather(self, blocks, start=None):
        """First-pass of untransformation. 'blocks' may be multiple blocks,
        in order. If 'start' is specified, first block number starts at given
        value; otherwise, remember previous last block number and continue
        from there.
        
        gather_last must be called on the last block instead of here."""
        if start:
            self.block_no = start
        for block in self.split_blocks(blocks):
            self.block_no += 1
            self.gather_block(block, self.block_no)

    def gather_last(self, block):
        """First-pass of last block. After this call, the package encryption
        key is available in self.k and the second-pass can be used to
        undigest."""
        # K' = m'[s'] ...
        self.k = xor_str(self.k, block)
        #print "k last=",[self.k]
        self.can_undigest = True
        return self.k

    def undigest(self, blocks, start=None):
        """Undigest a string of blocks, returning cleartext."""
        if not self.can_undigest:
            # Call gather for them--assuming this is all the data.
            data_blocks = blocks[:-self.block_size]
            last_block = blocks[-self.block_size:]
            self.gather(data_blocks)
            self.gather_last(last_block)
            blocks = data_blocks
            self.can_digest = True

        if not self.undigesting:
            self.crypt = self.cipher.new(self.k, self.mode, self.IV)
            self.block_no = 0
            self.undigesting = True

        if start:
            self.block_no = start

        clear = ""
        for block in self.split_blocks(blocks):
            self.block_no += 1 
            clear += self.xor_block(block, self.make_block(self.block_no))
        return clear

    def undigest_block(self, block, i):
        """Undigest a single block."""
        return xor_str(block, self.crypt.encrypt(self.make_block(i)))

# Test using Rivest's hash, with PCT's K0. (In his
# paper Rivest suggests using the block cipher with
# a fixed encryption key for hashing.)
class CipherHash:
    """Metaclass to Implement a somewhat PEP-272 compatible hash using a 
    block cipher with a fixed key."""
    class GenericCipherHash:
        pass
    def __init__(self, ciph):
        def __init__(self, msg):
            c = ciph.new("i"*ciph.block_size,mode,iv)
            self.d = c.encrypt(msg)
        def new(msg):
            #XXX: return H(msg)
            return self.__init__(msg)
        new = staticmethod(new)
        def digest(self):
            return self.d
        cls = GenericCipherHash()
        cls.__init__ = __init__
        cls.digest = digest
        cls.new = new


def main():
    from Crypto.Cipher import AES
    ciph = AES
    mode = ciph.MODE_CBC
    iv = "0" * ciph.block_size

    import sha
    a=AON(ciph,mode,iv,sha)
    # Pseudomessage blocks
    p0=a.digest_next("hi"*8)
    p1=a.digest_next("xy"*8)
    p2=a.digest_next("."*16)
    p3=a.digest_last()

    #print [p0,p1,p2,p3]

    # Obtain key
    b=AON(ciph,mode,iv,sha)
    #b.gather_block(p0,1)
    #b.gather_block(p1,2)
    #b.gather_block(p2,3)
    b.gather(p0+p1+p2)
    b.gather_last(p3)
    k=b.k
    assert a.k==k,"key mismatch: %s" % ([a.k,k],)

    d0=b.undigest(p0)
    d1=b.undigest(p1)
    d2=b.undigest(p2)
    assert d0=="hi"*8, "undigest part 0 failed: %s" % d0
    assert d1=="xy"*8, "undigest part 1 failed: %s" % d1
    assert d2=="."*16, "undigest part 2 failed: %s" % d2
    print "Undigested: %s" % (d0+d1+d2)
    print "Passed test 1"

    # TODO: A generic metaclass for doing this
    class H:
        def __init__(self, msg):
            c = ciph.new("i"*ciph.block_size,mode,iv)
            self.d = c.encrypt(msg)
        def digest(self):
            return self.d
        def new(msg):
            return H(msg)
        new = staticmethod(new)

    c=AON(ciph,mode,iv,H)
    print [c.digest("hi"*8)]
   
    # Test PCT-compatible API
    a=AON(ciph,mode,iv)
    ct = "Test simple API."
    p=a.digest(ct)
    print
    print "Pseudomessage:", [p]
    b=AON(ciph,mode,iv)
    ct2 = b.undigest(p)
    print "Cleartext:", [ct2]
    assert ct == ct2
    print "Simple API test passed"

    raise SystemExit

if __name__ == "__main__":
    while 1: main()