/* Created:20050807
 * By Jeff Connelly
 * 
 * LibTomCrypt SWIG wrapper
 *
 * $Id$
 */

%inline %{
#include <tomcrypt.h>
%}

%define DOCSTRING
"A wrapper for the LibTomCrypt cryptography library."
%enddef

/* Set docstrings to arguments - can be helpful. */
%module(docstring=DOCSTRING) ctomcrypt
%feature("autodoc", "1");

%include "cmalloc.i"
%include "typemaps.i"
%include "cstring.i"
%include "constraints.i"
%include "exception.i"

/* Binary data input -- LTC often uses long for length, instead of an int. */
%apply (char *STRING, int LENGTH) { (char *in, int inlen) };
%apply (char *STRING, int LENGTH) {
    (const unsigned char *in, unsigned long inlen) };
%apply (char *STRING, int LENGTH) {
    (const unsigned char *key, int keylen) };

/* Binary data output with size passed from user */
%cstring_output_withsize(unsigned char *out, unsigned long *plen);
/* XXX: is there a similar macro that doesn't have a ptr to len? INPUT?
  something like %cstring_input_maxsize but accepting binary data */

%cstring_output_withsize(unsigned char *out, unsigned long *outlen);

/* Some wrappers return error as an argument (_import1) */
%apply int *OUTPUT { int *err };


/* Constants */
%include </usr/local/include/tomcrypt.h>
//#define YARROW
//#define FORTUNA

/* Hide descriptors from target language; we'll deal w/ them directly. */
%ignore ltc_prng_descriptor;
%ignore prng_descriptor;
%ignore yarrow_desc;
%ignore fortuna_desc;
%ignore rc4_desc;
%ignore sprng_desc;
%ignore sober128_desc;
%ignore register_prng;
%ignore unregister_prng;

%include </usr/local/include/tomcrypt_prng.h>

%malloc(prng_state);
/* need to allow prng arg to _make_key to be null (for sprng) */
//%apply Pointer NONNULL { prng_state * };

//%typemap(ret) int "ltc_check($1);"

/************************ PRNG wrappers ***********************/
%define WRAP_PRNG(xxx)
extern int xxx ## _start(prng_state *prng);

extern int xxx ## _add_entropy(const unsigned char *in,
    unsigned long inlen, prng_state *prng);

extern int xxx ## _ready(prng_state *prng);

/* Returns binary data */
%inline %{
void xxx ## _read1(unsigned char *out, unsigned long *plen, prng_state *prng)
{
    *plen = xxx ## _read(out, *plen, prng);
}
%}

/* You can't do this */
/*%cstring_chunk_output(unsigned char *out, unsigned long outlen);*/

/*
%inline %{
void xxx ## _read2(unsigned char *out, unsigned long outlen, prng_state *prng)
{
    out = (unsigned char*)malloc(outlen); 
    *plen = xxx ## _read(out, outlen, prng);
}
%}
%newobject out;*/

extern int xxx ## _done(prng_state *prng);

//extern int xxx ## _export(unsigned char *out, unsigned long *outlen,
//    prng_state *prng);

%inline %{
extern int xxx ## _export1(unsigned char *out, unsigned long *outlen,
    prng_state *prng)
{
    return xxx ## _export(out, outlen, prng);
}
%}

/*%apply prng_state *OUTPUT { prng_state *prng_imported };
extern int xxx ## _import(const unsigned char *in, unsigned long inlen,
    prng_state *prng_imported);*/
%inline %{
extern prng_state *xxx ## _import1(const unsigned char *in, 
    unsigned long inlen, int *err)
{
    prng_state *p = (prng_state*)malloc(sizeof(prng_state));
    //xxx ## _import((const unsigned char*)in,
    //    (unsigned long)inlen, p);
    *err = xxx ## _import(in, inlen, p);
    return p;
}
%}
//%newobject

/* Client can call fortuna_register_prng() (etc.), doesn't know about *_desc. */
%inline %{
extern const struct ltc_prng_descriptor xxx ## _desc;
extern int xxx ## _register_prng()
{
    return register_prng(&(xxx ## _desc));
}
%}


/* TODO: use %extend to add these functions to fortuna_prng */
/*%extend xxx ## _prng {
    prng_state *new() { return (prng_state*)malloc_prng_state(); }
};*/
%enddef


WRAP_PRNG(fortuna)
//WRAP_PRNG(yarrow)
//WRAP_PRNG(rc4)
//WRAP_PRNG(sober128)
WRAP_PRNG(sprng)

/* Returns binary data */
%inline %{
void rng_get_bytes1(unsigned char *out, unsigned long *plen)
{
    rng_get_bytes(out, *plen, NULL);  /* No callback */
}

%}

extern const char *error_to_string(int err);

#define PK_PRIVATE  0
#define PK_PUBLIC   1

/*********************** Public key cryptosystem wrappers **************/
%define WRAP_PK(xxx)
%malloc(xxx##_key);

extern int xxx##_make_key(prng_state *prng, int wprng, 
	int keysize, xxx##_key *key);
extern void xxx##_free(xxx##_key *key);

extern int xxx##_export(unsigned char *out, unsigned long *outlen,
    int type, xxx##_key *key);

/*extern int xxx##_import(const unsigned char *in, unsigned long inlen,
    xxx##_key *key);*/

/*extern xxx##_key *xxx##_import1(const unsigned char *in, unsigned long
 * inlen)*/
%inline %{
extern xxx##_key *xxx##_import1(const unsigned char *in, unsigned long inlen,
    int *err)
{
    xxx##_key *k = (xxx##_key*)malloc(sizeof(xxx##_key));
    *err = xxx##_import(in, inlen, k);
    return k;
}
%}
//%newobject xxx##_import1

%cstring_output_withsize(unsigned char *out, unsigned long *outlen);
extern int xxx##_shared_secret(xxx##_key *private_key,
	xxx##_key *public_key, unsigned char *out, unsigned long *outlen);

extern int xxx##_test(void);

extern void xxx##_sizes(int *OUTPUT, int *OUTPUT);
%enddef

WRAP_PK(ecc)
//WRAP_PK(dh)


/*********************** Hash wrappers ************************/

/* Fixed sizes of hashes, from crypt.pdf in LTC distributon. */
%cstring_chunk_output(unsigned char *whirlpool_out, 64);
%cstring_chunk_output(unsigned char *sha512_out, 64);
%cstring_chunk_output(unsigned char *sha384_out, 48);
%cstring_chunk_output(unsigned char *sha256_out, 32);
%cstring_chunk_output(unsigned char *sha224_out, 28);
%cstring_chunk_output(unsigned char *tiger_out, 24);
%cstring_chunk_output(unsigned char *sha1_out, 20);
%cstring_chunk_output(unsigned char *rmd160_out, 20);
%cstring_chunk_output(unsigned char *rmd128_out, 16);
%cstring_chunk_output(unsigned char *md5_out, 16);
%cstring_chunk_output(unsigned char *md4_out, 16);
%cstring_chunk_output(unsigned char *md2_out, 16);

%malloc(hash_state);
%define WRAP_HASH(xxx)
extern int xxx##_init(hash_state *INPUT);
extern int xxx##_process(hash_state *INPUT, 
    const unsigned char *in, unsigned long inlen);
extern int xxx##_done(hash_state *INPUT, unsigned char *xxx##_out);
extern int xxx##_test();

%inline %{
extern const struct ltc_hash_descriptor xxx ## _desc;
extern int xxx ## _register_hash()
{
    return register_hash(&(xxx ## _desc));
}
%}
/* hash_memory, hash_file, hash_filehandle not wrapped */
%enddef

WRAP_HASH(whirlpool)
WRAP_HASH(sha512)
WRAP_HASH(sha384)
WRAP_HASH(sha256)
WRAP_HASH(sha224)
WRAP_HASH(tiger)
WRAP_HASH(sha1)
WRAP_HASH(rmd160)
WRAP_HASH(rmd128)
WRAP_HASH(md5)
WRAP_HASH(md4)
WRAP_HASH(md2)
WRAP_HASH(chc)

/* Use chc_register_hash() to register chc_desc, then use chc_register() to
   set the cipher (which was registered with *_register_cipher()) to use.*/
extern int chc_register(int cipher);


/************************ Cipher wrappers **********************/
// TODO
%malloc(symmetric_key);

/* Output blocks (plaintext for encrypt, ciphertext for decrypt) */
%cstring_chunk_output(unsigned char *blowfish_out, 8);
%cstring_chunk_output(unsigned char *xtea_out, 8);
%cstring_chunk_output(unsigned char *rc2_out, 8);
%cstring_chunk_output(unsigned char *rc5_out, 8);
%cstring_chunk_output(unsigned char *rc6_out, 16);
%cstring_chunk_output(unsigned char *saferp_out, 16);
%cstring_chunk_output(unsigned char *aes_out, 16);    /* wrap aes, instead */
%cstring_chunk_output(unsigned char *aes_enc_out, 16); /* of rijndael name */
%cstring_chunk_output(unsigned char *twofish_out, 16);
%cstring_chunk_output(unsigned char *des_out, 8);
%cstring_chunk_output(unsigned char *des3_out, 8);
%cstring_chunk_output(unsigned char *cast5_out, 8);
%cstring_chunk_output(unsigned char *noekeon_out, 16);
%cstring_chunk_output(unsigned char *skipjack_out, 8);
%cstring_chunk_output(unsigned char *anubis_out, 16);
%cstring_chunk_output(unsigned char *khazad_out, 8);
%cstring_chunk_output(unsigned char *saferp_out, 16);

%define WRAP_CIPHER(xxx)
/*%apply unsigned char *OUTPUT { unsigned char *xxx##_out };*/

extern int xxx##_setup(const unsigned char *key, int keylen, int rounds,
    symmetric_key *INOUT);
/* XXX: Probably a good idea to use pt=ct, encrypt in-place. Can SWIG do
 * this with fixed-size chunks? %cstring*mutable* assumes NULL-terminated.
 * http://mailman.cs.uchicago.edu/pipermail/swig/2004-April/009613.html
 * Write a new typemap?
 */
extern void xxx##_ecb_encrypt(const unsigned char *xxx##_in,
    unsigned char *xxx##_out, symmetric_key *skey);
extern void xxx##_ecb_decrypt(const unsigned char *xxx##_in,
    unsigned char *xxx##_out, symmetric_key *skey);
extern int xxx##_test();
extern int xxx##_keysize(int *keysize);
extern void xxx##_done(symmetric_key *skey);
%enddef

WRAP_CIPHER(aes)
