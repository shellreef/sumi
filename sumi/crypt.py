# Created:20050716
# By Jeff Connelly

# $Id$

# Test crypto

keysize = 384

def test_pycrypto():
    # pycrypto is mentioned in Python manual; it is comprehensive and has AES.
    from Crypto.Cipher import AES
    from Crypto.PublicKey import RSA
    from Crypto.Util.randpool import RandomPool

    print "Creating random pool..."
    # TODO: KeyboardRandomPool, or use mouse movements or something
    r = RandomPool()
    print "Generaating RSA key..."
    # Always 48 bytes encrypted, but AES key is 32 maximum. IV is 16 bytes
    #  (AES.block_size) -- just enough.
    k = RSA.generate(keysize, r.get_bytes)
    enc = k.encrypt("x"*32 + "y"*16,"")   # Session key & IV
    print len(enc[0]), enc
    enc = enc[0]
  
    dec = k.decrypt(enc)
    sesskey = dec[0:32]
    sessiv = dec[32:32+16]
    print "Decrypted: sesskey=%s, iv=%s" % (sesskey, sessiv)

    global counter, pkt_num
    counter = pkt_num = 0
    def ctr_func():
        global counter, pkt_num
        counter += 1   # increment for each block, within packet
        # Its OK if this conter is not linear...it just needs to be repeatable
        #x = pack_bignum(counter + (pkt_num * 2**32) + IV*2**64
        # The IV isn't passed to the constructor, so its only used here.
        #return sessiv[0:8] + struct.pack("!LL", pkt_num, counter)
        # Start at the IV, add to: 32-bit block ctr, 32-bit pkt ctr
        x = pack_bignum((pkt_num * 2**32) + counter + unpack_bignum(sessiv))
        print "=> ", unpack_bignum(x)
        if len(x) != 16:
            x = "\0" * (16 - len(x)) + x
        return x

    a=AES.new(sesskey, AES.MODE_CTR, counter=ctr_func)
    import struct
    # SUMI encrypt + decrypt
    #  msg is data, num is seqno
    def s_enc(msg, num):
        global counter, pkt_num
        counter = 0
        pkt_num = num
        # Must be multiple of block size (16). (So easiest would be to restrict
        # data block size to multiple of 16, by restricting MSS.)
        #return a.encrypt(msg)
        return a.decrypt(msg)

    def s_dec(msg, num):
        global counter, pkt_num
        counter = 0
        pkt_num = num
        return a.decrypt(msg)

    def b64(msg):
        import base64
        # can't use strip--only removes trailing and leading
        #return base64.encodestring(msg).strip("\n=")  # need to repad w/ = (4)
        return base64.encodestring(msg).replace("\n","").replace("=","")

    e = s_enc("hello world....."*10, 42)
    print
    # 48 => 64 with base64 encoding. Not bad at all for full sess key & IV.
    print "encrypted: %s %s" % (len(b64(e)), b64(e))
    print "decrypted: %s" % s_dec(e, 42)

    # Conclusion : decrypt()+decrypt() is fastest for AES
    reps = 10000 
    # can't do cipher.encrypt = cipher.decrypt, since builtin
    def benchmark():
        """
C:\windows\system32\cmd.exe /c python crypt.py
encrypt/decrypt: 5.17199993134
decrypt/encrypt: 5.1400001049
decrypt/decrypt: 5.125               <-- fastest
encrypt/encrypt: 5.15700006485
Hit any key to close this window...
        """
        import time
        # interestingly, encrypt/decrypt is somewhat interchangeable
        g=time.time()
        for i in range(reps):
            c = cipher.decrypt(msg)
            if  cipher.encrypt(c) != msg: raise Exception("not same")
        print "encrypt/decrypt: %s" % (time.time() - g)

        g=time.time()
        for i in range(reps):
            c = cipher.decrypt(msg)
            if  cipher.encrypt(c) != msg: raise Exception("not same")
        print "decrypt/encrypt: %s" % (time.time() - g)

        g=time.time()
        for i in range(reps):
            c = cipher.decrypt(msg)
            if  cipher.decrypt(c) != msg: raise Exception("not same")
        print "decrypt/decrypt: %s" % (time.time() - g)

        g=time.time()
        for i in range(reps):
            c = cipher.encrypt(msg)
            if  cipher.encrypt(c) != msg: raise Exception("not same")
        print "encrypt/encrypt: %s" % (time.time() - g)
    #benchmark()   # decrypt/decrypt fastest

def test_low_level_enc():
    # SSLCrypto is a newer module, uses OpenSSL. But doesn't have AES?
    # Would need to use Blowfish for session cipher instead of AES!
    # XXX: Also, SSLCrypto uses low public exponents (5), and ._random
    # seems to read from uninitialized memory--not very random! AVOID.
    import SSLCrypto
    import struct
    print "Generating key..."
    k = SSLCrypto.key(keysize)
    print "OK"
    enc = senc_start(k)
    enc += senc_next(k, "hello world!")
    l = sdec_start(k, enc)
    print "DEC: %s" % sdec_next(k, enc[l:])
    # works
    print "DEC2:%s" % sdec_next(k, senc_next(k, "foobar"))

    # Note: if don't use CFB(?) chaining mode, might be less
    # secure but could decrypt immediately perhaps

def pack_bignum(n):
    """Convert an arbitrary sized number to a packed binary string
    with the necessary number of bytes."""
    s = ""
    while n:
        s += chr(n % 256)
        n /= 256
    return s

def unpack_bignum(s):
    """Unpack numbers packed with pack_bignum."""
    n = 0
    for i in range(len(s)):
        n += ord(s[i]) * (256 ** i)
    return n

def sdec_start(k, enc):
    """Load public key, session key, IV. Return offset where data begins."""
    # TODO: create a new key from scratch, somehow. what constructor?
    (e, ) = struct.unpack("!H", enc[0:2])
    n = unpack_bignum(enc[2:2 + keysize / 8])
    rest = enc[2+keysize/8:]
    print "Public key: e=%s n=%s" % (e, n)
    # TODO: load into k, make new

    # checks if public key inside enc is same as that inside k!
    # so why is it inside enc at all?
    #if not k._testPubKey(n):
    #    raise Exception("public key mismatch")

    #encSessKey = rest[0:128]
    #encSessIV = rest[128:128+128]  

    #print "encSessKey=%s" % unpack_bignum(encSessKey)
    #print "encSessIV=%s" % unpack_bignum(encSessIV)

    #k.sessKey = k.k.decrypt(encSessKey)
    #k.sessIV = k.k.decrypt(encSessIV)

    encSess = rest[0:128]
    sess = k.k.decrypt(encSess)
    k.sessKey = sess[0:32]
    k.sessIV = sess[32:32+16]

    print "sessKey=%s" % unpack_bignum(k.sessKey)
    print "sessIV=%s" % unpack_bignum(k.sessIV)

    print "Algorithm: %s" % k.algoSes

    k.blkCipher = k.algoSes(k.sessKey, k.sessIV)

    # crashes
    #k.sessKey = k.k.decrypt(encSessKey)

    #print "sessKey=%s" % unpack_bignum(k.sessKey)
    #print "sessIV =%s" % unpack_bignum(k.sessIV)
    return 2+keysize/8+128+128

def sdec_next(k, enc):
    #print "sdec_next %s %s" % (len(enc), enc)
    k.blkCipher.setKey(k.sessKey)   # why is this needed?
    return k.blkCipher.decrypt(enc)

def senc_next(k, clear):
    """Encrypt text."""
    k.blkCipher.setKey(k.sessKey)   # why is this needed?
    return k.blkCipher.encrypt(clear)
    #print "enc+dec: %s" % k.blkCipher.decrypt(enc)  # garbage, why?

def senc_start(k):
    """Build encryption header: public key and encrypted session key + IV."""

    # senc = SUMI's encryption API

    enc = ""
    # k._rawPubKey() = bencode((self.algoPname, self.k.pubKey())
    #print "Public key (bencoded): %s" % k._rawPubKey()
    # k.k is rsa object

    # k.k.pubKey() = bn2pyLong(self.rsaObj.e), bn2pyLong(self.rsaObj.n)
    (e, n) = k.k.pubKey()
    print "Public key: e=%s, n=%s" % (e, n)
    # Seems to always be 5. "Exponent is often 3,5,17,65537"
    # Will it be anything else, or only those? http://www.opencores.org/articles.cgi/view/8
    # Commonly: prime with only 2 bits set, for efficiency
    #   Popular choices like 3, 17 and 65537 are all primes with only two 
    #   bits set: 3 = 0011'B, 17 = 0x11, 65537 = 0x10001. 
    # So probably should transmit it, but could get away with one byte.
    # XXX: Low exponent attack, try to get it to use 65537
    enc += struct.pack("!H", e)
    enc += pack_bignum(n)
    # XXX: Does this belong in the message itself? Public key should probably
    # be exchanged through some other method, then header only 512 bytes.

    print "=%s" % len(enc)    # n-bit key, n bits here + 2-bytes for exponent

    # Constant
    print "Algorithm: %s" % k.algoSes

    # _genNewSessKey() = (sessKey, sessIV) = (_random(32), _random(8))
    # _random seems to read uninitialized data--better get it from user, like
    # WASTE uses random mouse movements to generate the key (but not
    # necessarily for the session key and initialization vector.)
    k.sessKey = "x" * 32
    k.sessIV = "y" * 8
     
    if len(k.sessKey) > k.pubBlkSize:
        raise Exception("need bigger public key")

    # _encRawPub = 2-byte length prefix + self.k.encrypt(..) 
    # No need to encode length, since always 32 and 8
    print "Appending session & IV..."
    encSess = k.k.encrypt(k.sessKey + k.sessIV)

    enc += encSess               # 128 bytes
    print "sessKey=%s" % unpack_bignum(k.sessKey)
    print "sessIV=%s" % unpack_bignum(k.sessIV)

    #print "\n"
    #print "encSessKey=%s" % unpack_bignum(encSessKey)
    #print "encSessIV=%s" % unpack_bignum(encSessIV)

    print "=%s" % len(enc)

    #print "decrypting: %s" % unpack_bignum(k.k.decrypt(encSessKey))
    #print "decrypting: %s" % k.k.decrypt(encSessKey)

    return enc

def test_bignum():
    # Serializing large numbers -- large public keys, better than bencode, more
    # compact
    N=n = 27859110510180849367346884304748568378007852043934361535371729309685933158930460484215272793854468254024060456635981670931177918884568969400682539712161222916100405524886947004914241970487327762629475331639165107145492243584132050692349637356334769316564280781071854394633512762169964547336076795491274049192217981276437180869080711651647147375372649838665274471898153144985373201446780489371453985889436228485331845336516717280445004962657897521419876434361887538386044073209635540415640935834252062494190399015435014344787689025593143300042411722072513323605011640020409069711975586307688695401972954702764475505211L
    print "Number: %s" % n
    z = ""
    while n:
        z += chr(n % 256)
        n /= 256
    #print "Serialized: %s" % z
    w = 0
    for i in range(len(z)):
        w += ord(z[i]) * (256 ** i)
    print "Number2:%s" % w
    if w == N:
        print "OK"
    else:
        print "FAILED!"

def test_medium_level_enc():
    print "Generating key..."
    k = SSLCrypto.key(1024)#2048)
    print "key=%s" % k

    k.encStart()
    print "Encrypting a byte"
    p = k.encNext("1")
    print "Took %s bytes" % len(p)
    #print p

    # For 2048 byte key, 1544 bytes of overhead. After that, 1:1 mapping of
    # ciphertext to cleartext, but this overhead is excessive, especially since it
    # includes a bencoded portion.
    #  The public key is bencoded, prefixed with a length. What determines length?
    # 2:633 for 2048-bit key.             2048/633=0.309..
    # 2:325 for 1024-bit key (default).   1024/325=0.317.. ?
    (pubkeylen, ) = struct.unpack("<H", p[0:2])
    print "Public key length: %s" % pubkeylen
    pubkey = SSLCrypto.bdecode(p[2:2+pubkeylen])
    print "Public key: %s" % pubkey

    # One bencoded public key
    a="""
    [2:633] ['RSA', [5L, 28023379740547052735555033278117293336489379321340666977541
    51651170963662301208999859953373568009586758465885286327239380367103601675724013
    95509090705944749041864017771437384950545925786112028133928836668160133859337540
    00169535743460874082346715591979935262390585299234016168508827436658484475167330
    19105294657962129630086671784747082720502311409454446476732540841273117827814381
    11171965818412853985925378346677636103143923580924749663168674850341574426268090
    71082967544102499869801928758829651837203012707114753631050238127841363059404078
    755420194862385742312454111997284299493912850024479794285194764266497163629329L]
    ]"""

    # Seems to be: ['algorithm', [5L, some sort of large key]]

    # The 1544 bytes are part of the "header block" -- see encStart SSLCrypto.pyx
            # format of header block is:
            #  - recipient public key     
            #  - stream algorithm identifiers
            #  - stream session key
            #  - stream cipher initial value
    # All stored in k._encHdrs, after k.encStart()
    # k._rawPubKey() is the bencoded public key
    # self.encHdrs =
    #   chr(len0) + chr(len1) + pubkey, 
    # where len0 = pubkeyLen%256, len1 = pubKeyLen/256
    # 
    # 2-byte length + bencoded public ke
    # algInfo - algo, session key, IV
    #   1-byte algorithms index 
    #    create new session key _genNewSessKey()
    #   1-byte len(sessKey)
    #   1-byte len(sessIV)
    #   03 00 - 2-byte length, hardwired
    #   len(self.sessKey) > self.pubBlkSize
    # sKeyEnc = _encRawPub(self.sessKey)
    # sCipherInit = _encRawPub(self.sessIV)
    # _initBlkCipher, then ready to go
     
test_pycrypto()
