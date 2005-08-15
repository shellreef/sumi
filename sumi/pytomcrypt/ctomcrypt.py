# This file was created automatically by SWIG.
# Don't modify this file, modify the SWIG interface instead.
# This file is compatible with both classic and new-style classes.

"""
A wrapper for the LibTomCrypt cryptography library.
"""

import _ctomcrypt

def _swig_setattr_nondynamic(self,class_type,name,value,static=1):
    if (name == "this"):
        if isinstance(value, class_type):
            self.__dict__[name] = value.this
            if hasattr(value,"thisown"): self.__dict__["thisown"] = value.thisown
            del value.thisown
            return
    method = class_type.__swig_setmethods__.get(name,None)
    if method: return method(self,value)
    if (not static) or hasattr(self,name) or (name == "thisown"):
        self.__dict__[name] = value
    else:
        raise AttributeError("You cannot add attributes to %s" % self)

def _swig_setattr(self,class_type,name,value):
    return _swig_setattr_nondynamic(self,class_type,name,value,0)

def _swig_getattr(self,class_type,name):
    method = class_type.__swig_getmethods__.get(name,None)
    if method: return method(self)
    raise AttributeError,name

import types
try:
    _object = types.ObjectType
    _newclass = 1
except AttributeError:
    class _object : pass
    _newclass = 0
del types


CRYPT = _ctomcrypt.CRYPT
SCRYPT = _ctomcrypt.SCRYPT
MAXBLOCKSIZE = _ctomcrypt.MAXBLOCKSIZE
TAB_SIZE = _ctomcrypt.TAB_SIZE
CRYPT_OK = _ctomcrypt.CRYPT_OK
CRYPT_ERROR = _ctomcrypt.CRYPT_ERROR
CRYPT_NOP = _ctomcrypt.CRYPT_NOP
CRYPT_INVALID_KEYSIZE = _ctomcrypt.CRYPT_INVALID_KEYSIZE
CRYPT_INVALID_ROUNDS = _ctomcrypt.CRYPT_INVALID_ROUNDS
CRYPT_FAIL_TESTVECTOR = _ctomcrypt.CRYPT_FAIL_TESTVECTOR
CRYPT_BUFFER_OVERFLOW = _ctomcrypt.CRYPT_BUFFER_OVERFLOW
CRYPT_INVALID_PACKET = _ctomcrypt.CRYPT_INVALID_PACKET
CRYPT_INVALID_PRNGSIZE = _ctomcrypt.CRYPT_INVALID_PRNGSIZE
CRYPT_ERROR_READPRNG = _ctomcrypt.CRYPT_ERROR_READPRNG
CRYPT_INVALID_CIPHER = _ctomcrypt.CRYPT_INVALID_CIPHER
CRYPT_INVALID_HASH = _ctomcrypt.CRYPT_INVALID_HASH
CRYPT_INVALID_PRNG = _ctomcrypt.CRYPT_INVALID_PRNG
CRYPT_MEM = _ctomcrypt.CRYPT_MEM
CRYPT_PK_TYPE_MISMATCH = _ctomcrypt.CRYPT_PK_TYPE_MISMATCH
CRYPT_PK_NOT_PRIVATE = _ctomcrypt.CRYPT_PK_NOT_PRIVATE
CRYPT_INVALID_ARG = _ctomcrypt.CRYPT_INVALID_ARG
CRYPT_FILE_NOTFOUND = _ctomcrypt.CRYPT_FILE_NOTFOUND
CRYPT_PK_INVALID_TYPE = _ctomcrypt.CRYPT_PK_INVALID_TYPE
CRYPT_PK_INVALID_SYSTEM = _ctomcrypt.CRYPT_PK_INVALID_SYSTEM
CRYPT_PK_DUP = _ctomcrypt.CRYPT_PK_DUP
CRYPT_PK_NOT_FOUND = _ctomcrypt.CRYPT_PK_NOT_FOUND
CRYPT_PK_INVALID_SIZE = _ctomcrypt.CRYPT_PK_INVALID_SIZE
CRYPT_INVALID_PRIME_SIZE = _ctomcrypt.CRYPT_INVALID_PRIME_SIZE
class prng_state(_object):
    """Proxy of C prng_state struct"""
    __swig_setmethods__ = {}
    __setattr__ = lambda self, name, value: _swig_setattr(self, prng_state, name, value)
    __swig_getmethods__ = {}
    __getattr__ = lambda self, name: _swig_getattr(self, prng_state, name)
    def __repr__(self):
        return "<%s.%s; proxy of C prng_state instance at %s>" % (self.__class__.__module__, self.__class__.__name__, self.this,)
    def __init__(self, *args):
        """__init__(self) -> prng_state"""
        _swig_setattr(self, prng_state, 'this', _ctomcrypt.new_prng_state(*args))
        _swig_setattr(self, prng_state, 'thisown', 1)
    def __del__(self, destroy=_ctomcrypt.delete_prng_state):
        """__del__(self)"""
        try:
            if self.thisown: destroy(self)
        except: pass


class prng_statePtr(prng_state):
    def __init__(self, this):
        _swig_setattr(self, prng_state, 'this', this)
        if not hasattr(self,"thisown"): _swig_setattr(self, prng_state, 'thisown', 0)
        _swig_setattr(self, prng_state,self.__class__,prng_state)
_ctomcrypt.prng_state_swigregister(prng_statePtr)


def find_prng(*args):
    """find_prng(char name) -> int"""
    return _ctomcrypt.find_prng(*args)

def prng_is_valid(*args):
    """prng_is_valid(int idx) -> int"""
    return _ctomcrypt.prng_is_valid(*args)

def rng_get_bytes(*args):
    """rng_get_bytes(unsigned char out, unsigned long outlen, void callback) -> unsigned long"""
    return _ctomcrypt.rng_get_bytes(*args)

def rng_make_prng(*args):
    """rng_make_prng(int bits, int wprng,  prng, void callback) -> int"""
    return _ctomcrypt.rng_make_prng(*args)

def malloc_prng_state(*args):
    """malloc_prng_state(int nbytes)"""
    return _ctomcrypt.malloc_prng_state(*args)

def fortuna_start(*args):
    """fortuna_start( prng) -> int"""
    return _ctomcrypt.fortuna_start(*args)

def fortuna_add_entropy(*args):
    """fortuna_add_entropy(unsigned char in,  prng) -> int"""
    return _ctomcrypt.fortuna_add_entropy(*args)

def fortuna_ready(*args):
    """fortuna_ready( prng) -> int"""
    return _ctomcrypt.fortuna_ready(*args)

def fortuna_read1(*args):
    """fortuna_read1(unsigned char out,  prng)"""
    return _ctomcrypt.fortuna_read1(*args)

def fortuna_done(*args):
    """fortuna_done( prng) -> int"""
    return _ctomcrypt.fortuna_done(*args)

def fortuna_export1(*args):
    """fortuna_export1(unsigned char out,  prng) -> int"""
    return _ctomcrypt.fortuna_export1(*args)

def fortuna_import1(*args):
    """fortuna_import1(unsigned char in, int err)"""
    return _ctomcrypt.fortuna_import1(*args)

def fortuna_register_prng(*args):
    """fortuna_register_prng() -> int"""
    return _ctomcrypt.fortuna_register_prng(*args)

def sprng_start(*args):
    """sprng_start( prng) -> int"""
    return _ctomcrypt.sprng_start(*args)

def sprng_add_entropy(*args):
    """sprng_add_entropy(unsigned char in,  prng) -> int"""
    return _ctomcrypt.sprng_add_entropy(*args)

def sprng_ready(*args):
    """sprng_ready( prng) -> int"""
    return _ctomcrypt.sprng_ready(*args)

def sprng_read1(*args):
    """sprng_read1(unsigned char out,  prng)"""
    return _ctomcrypt.sprng_read1(*args)

def sprng_done(*args):
    """sprng_done( prng) -> int"""
    return _ctomcrypt.sprng_done(*args)

def sprng_export1(*args):
    """sprng_export1(unsigned char out,  prng) -> int"""
    return _ctomcrypt.sprng_export1(*args)

def sprng_import1(*args):
    """sprng_import1(unsigned char in, int err)"""
    return _ctomcrypt.sprng_import1(*args)

def sprng_register_prng(*args):
    """sprng_register_prng() -> int"""
    return _ctomcrypt.sprng_register_prng(*args)

def rng_get_bytes1(*args):
    """rng_get_bytes1(unsigned char out)"""
    return _ctomcrypt.rng_get_bytes1(*args)

def error_to_string(*args):
    """error_to_string(int err) -> char"""
    return _ctomcrypt.error_to_string(*args)
PK_PRIVATE = _ctomcrypt.PK_PRIVATE
PK_PUBLIC = _ctomcrypt.PK_PUBLIC

def malloc_ecc_key(*args):
    """malloc_ecc_key(int nbytes) -> ecc_key"""
    return _ctomcrypt.malloc_ecc_key(*args)

def ecc_make_key(*args):
    """ecc_make_key( prng, int wprng, int keysize, ecc_key key) -> int"""
    return _ctomcrypt.ecc_make_key(*args)

def ecc_free(*args):
    """ecc_free(ecc_key key)"""
    return _ctomcrypt.ecc_free(*args)

def ecc_export(*args):
    """ecc_export(unsigned char out, int type, ecc_key key) -> int"""
    return _ctomcrypt.ecc_export(*args)

def ecc_import1(*args):
    """ecc_import1(unsigned char in, int err) -> ecc_key"""
    return _ctomcrypt.ecc_import1(*args)

def ecc_shared_secret(*args):
    """ecc_shared_secret(ecc_key private_key, ecc_key public_key, unsigned char out) -> int"""
    return _ctomcrypt.ecc_shared_secret(*args)

def ecc_test(*args):
    """ecc_test() -> int"""
    return _ctomcrypt.ecc_test(*args)

def ecc_sizes(*args):
    """ecc_sizes(int OUTPUT, int OUTPUT)"""
    return _ctomcrypt.ecc_sizes(*args)

def malloc_hash_state(*args):
    """malloc_hash_state(int nbytes) -> hash_state"""
    return _ctomcrypt.malloc_hash_state(*args)

def whirlpool_init(*args):
    """whirlpool_init(hash_state INPUT) -> int"""
    return _ctomcrypt.whirlpool_init(*args)

def whirlpool_process(*args):
    """whirlpool_process(hash_state INPUT, unsigned char in) -> int"""
    return _ctomcrypt.whirlpool_process(*args)

def whirlpool_done(*args):
    """whirlpool_done(hash_state INPUT, unsigned char whirlpool_out) -> int"""
    return _ctomcrypt.whirlpool_done(*args)

def whirlpool_test(*args):
    """whirlpool_test() -> int"""
    return _ctomcrypt.whirlpool_test(*args)

def whirlpool_register_hash(*args):
    """whirlpool_register_hash() -> int"""
    return _ctomcrypt.whirlpool_register_hash(*args)

def sha512_init(*args):
    """sha512_init(hash_state INPUT) -> int"""
    return _ctomcrypt.sha512_init(*args)

def sha512_process(*args):
    """sha512_process(hash_state INPUT, unsigned char in) -> int"""
    return _ctomcrypt.sha512_process(*args)

def sha512_done(*args):
    """sha512_done(hash_state INPUT, unsigned char sha512_out) -> int"""
    return _ctomcrypt.sha512_done(*args)

def sha512_test(*args):
    """sha512_test() -> int"""
    return _ctomcrypt.sha512_test(*args)

def sha512_register_hash(*args):
    """sha512_register_hash() -> int"""
    return _ctomcrypt.sha512_register_hash(*args)

def sha384_init(*args):
    """sha384_init(hash_state INPUT) -> int"""
    return _ctomcrypt.sha384_init(*args)

def sha384_process(*args):
    """sha384_process(hash_state INPUT, unsigned char in) -> int"""
    return _ctomcrypt.sha384_process(*args)

def sha384_done(*args):
    """sha384_done(hash_state INPUT, unsigned char sha384_out) -> int"""
    return _ctomcrypt.sha384_done(*args)

def sha384_test(*args):
    """sha384_test() -> int"""
    return _ctomcrypt.sha384_test(*args)

def sha384_register_hash(*args):
    """sha384_register_hash() -> int"""
    return _ctomcrypt.sha384_register_hash(*args)

def sha256_init(*args):
    """sha256_init(hash_state INPUT) -> int"""
    return _ctomcrypt.sha256_init(*args)

def sha256_process(*args):
    """sha256_process(hash_state INPUT, unsigned char in) -> int"""
    return _ctomcrypt.sha256_process(*args)

def sha256_done(*args):
    """sha256_done(hash_state INPUT, unsigned char sha256_out) -> int"""
    return _ctomcrypt.sha256_done(*args)

def sha256_test(*args):
    """sha256_test() -> int"""
    return _ctomcrypt.sha256_test(*args)

def sha256_register_hash(*args):
    """sha256_register_hash() -> int"""
    return _ctomcrypt.sha256_register_hash(*args)

def sha224_init(*args):
    """sha224_init(hash_state INPUT) -> int"""
    return _ctomcrypt.sha224_init(*args)

def sha224_process(*args):
    """sha224_process(hash_state INPUT, unsigned char in) -> int"""
    return _ctomcrypt.sha224_process(*args)

def sha224_done(*args):
    """sha224_done(hash_state INPUT, unsigned char sha224_out) -> int"""
    return _ctomcrypt.sha224_done(*args)

def sha224_test(*args):
    """sha224_test() -> int"""
    return _ctomcrypt.sha224_test(*args)

def sha224_register_hash(*args):
    """sha224_register_hash() -> int"""
    return _ctomcrypt.sha224_register_hash(*args)

def tiger_init(*args):
    """tiger_init(hash_state INPUT) -> int"""
    return _ctomcrypt.tiger_init(*args)

def tiger_process(*args):
    """tiger_process(hash_state INPUT, unsigned char in) -> int"""
    return _ctomcrypt.tiger_process(*args)

def tiger_done(*args):
    """tiger_done(hash_state INPUT, unsigned char tiger_out) -> int"""
    return _ctomcrypt.tiger_done(*args)

def tiger_test(*args):
    """tiger_test() -> int"""
    return _ctomcrypt.tiger_test(*args)

def tiger_register_hash(*args):
    """tiger_register_hash() -> int"""
    return _ctomcrypt.tiger_register_hash(*args)

def sha1_init(*args):
    """sha1_init(hash_state INPUT) -> int"""
    return _ctomcrypt.sha1_init(*args)

def sha1_process(*args):
    """sha1_process(hash_state INPUT, unsigned char in) -> int"""
    return _ctomcrypt.sha1_process(*args)

def sha1_done(*args):
    """sha1_done(hash_state INPUT, unsigned char sha1_out) -> int"""
    return _ctomcrypt.sha1_done(*args)

def sha1_test(*args):
    """sha1_test() -> int"""
    return _ctomcrypt.sha1_test(*args)

def sha1_register_hash(*args):
    """sha1_register_hash() -> int"""
    return _ctomcrypt.sha1_register_hash(*args)

def rmd160_init(*args):
    """rmd160_init(hash_state INPUT) -> int"""
    return _ctomcrypt.rmd160_init(*args)

def rmd160_process(*args):
    """rmd160_process(hash_state INPUT, unsigned char in) -> int"""
    return _ctomcrypt.rmd160_process(*args)

def rmd160_done(*args):
    """rmd160_done(hash_state INPUT, unsigned char rmd160_out) -> int"""
    return _ctomcrypt.rmd160_done(*args)

def rmd160_test(*args):
    """rmd160_test() -> int"""
    return _ctomcrypt.rmd160_test(*args)

def rmd160_register_hash(*args):
    """rmd160_register_hash() -> int"""
    return _ctomcrypt.rmd160_register_hash(*args)

def rmd128_init(*args):
    """rmd128_init(hash_state INPUT) -> int"""
    return _ctomcrypt.rmd128_init(*args)

def rmd128_process(*args):
    """rmd128_process(hash_state INPUT, unsigned char in) -> int"""
    return _ctomcrypt.rmd128_process(*args)

def rmd128_done(*args):
    """rmd128_done(hash_state INPUT, unsigned char rmd128_out) -> int"""
    return _ctomcrypt.rmd128_done(*args)

def rmd128_test(*args):
    """rmd128_test() -> int"""
    return _ctomcrypt.rmd128_test(*args)

def rmd128_register_hash(*args):
    """rmd128_register_hash() -> int"""
    return _ctomcrypt.rmd128_register_hash(*args)

def md5_init(*args):
    """md5_init(hash_state INPUT) -> int"""
    return _ctomcrypt.md5_init(*args)

def md5_process(*args):
    """md5_process(hash_state INPUT, unsigned char in) -> int"""
    return _ctomcrypt.md5_process(*args)

def md5_done(*args):
    """md5_done(hash_state INPUT, unsigned char md5_out) -> int"""
    return _ctomcrypt.md5_done(*args)

def md5_test(*args):
    """md5_test() -> int"""
    return _ctomcrypt.md5_test(*args)

def md5_register_hash(*args):
    """md5_register_hash() -> int"""
    return _ctomcrypt.md5_register_hash(*args)

def md4_init(*args):
    """md4_init(hash_state INPUT) -> int"""
    return _ctomcrypt.md4_init(*args)

def md4_process(*args):
    """md4_process(hash_state INPUT, unsigned char in) -> int"""
    return _ctomcrypt.md4_process(*args)

def md4_done(*args):
    """md4_done(hash_state INPUT, unsigned char md4_out) -> int"""
    return _ctomcrypt.md4_done(*args)

def md4_test(*args):
    """md4_test() -> int"""
    return _ctomcrypt.md4_test(*args)

def md4_register_hash(*args):
    """md4_register_hash() -> int"""
    return _ctomcrypt.md4_register_hash(*args)

def md2_init(*args):
    """md2_init(hash_state INPUT) -> int"""
    return _ctomcrypt.md2_init(*args)

def md2_process(*args):
    """md2_process(hash_state INPUT, unsigned char in) -> int"""
    return _ctomcrypt.md2_process(*args)

def md2_done(*args):
    """md2_done(hash_state INPUT, unsigned char md2_out) -> int"""
    return _ctomcrypt.md2_done(*args)

def md2_test(*args):
    """md2_test() -> int"""
    return _ctomcrypt.md2_test(*args)

def md2_register_hash(*args):
    """md2_register_hash() -> int"""
    return _ctomcrypt.md2_register_hash(*args)

def chc_init(*args):
    """chc_init(hash_state INPUT) -> int"""
    return _ctomcrypt.chc_init(*args)

def chc_process(*args):
    """chc_process(hash_state INPUT, unsigned char in) -> int"""
    return _ctomcrypt.chc_process(*args)

def chc_done(*args):
    """chc_done(hash_state INPUT, unsigned char chc_out) -> int"""
    return _ctomcrypt.chc_done(*args)

def chc_test(*args):
    """chc_test() -> int"""
    return _ctomcrypt.chc_test(*args)

def chc_register_hash(*args):
    """chc_register_hash() -> int"""
    return _ctomcrypt.chc_register_hash(*args)

def chc_register(*args):
    """chc_register(int cipher) -> int"""
    return _ctomcrypt.chc_register(*args)

def malloc_symmetric_key(*args):
    """malloc_symmetric_key(int nbytes) -> symmetric_key"""
    return _ctomcrypt.malloc_symmetric_key(*args)

def aes_setup(*args):
    """aes_setup(unsigned char key, int rounds, symmetric_key INOUT) -> int"""
    return _ctomcrypt.aes_setup(*args)

def aes_ecb_encrypt(*args):
    """aes_ecb_encrypt(unsigned char aes_in, unsigned char aes_out, symmetric_key skey)"""
    return _ctomcrypt.aes_ecb_encrypt(*args)

def aes_ecb_decrypt(*args):
    """aes_ecb_decrypt(unsigned char aes_in, unsigned char aes_out, symmetric_key skey)"""
    return _ctomcrypt.aes_ecb_decrypt(*args)

def aes_test(*args):
    """aes_test() -> int"""
    return _ctomcrypt.aes_test(*args)

def aes_keysize(*args):
    """aes_keysize(int keysize) -> int"""
    return _ctomcrypt.aes_keysize(*args)

def aes_done(*args):
    """aes_done(symmetric_key skey)"""
    return _ctomcrypt.aes_done(*args)
cvar = _ctomcrypt.cvar
whirlpool_desc = cvar.whirlpool_desc
sha512_desc = cvar.sha512_desc
sha384_desc = cvar.sha384_desc
sha256_desc = cvar.sha256_desc
sha224_desc = cvar.sha224_desc
tiger_desc = cvar.tiger_desc
sha1_desc = cvar.sha1_desc
rmd160_desc = cvar.rmd160_desc
rmd128_desc = cvar.rmd128_desc
md5_desc = cvar.md5_desc
md4_desc = cvar.md4_desc
md2_desc = cvar.md2_desc
chc_desc = cvar.chc_desc

