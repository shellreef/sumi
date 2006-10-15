%module elliptic
%include pointer.i
%{
#include "bigint.h"
#include "eliptic.h"
#include "protocols.h"

#define WORDSIZE	(sizeof(int)*8)
#define NUMBITS		113
#define	NUMWORD		(NUMBITS/WORDSIZE)
#define MAXLONG		(NUMWORD+1)
%}

/* Export the seed so we can set / get it in python */
extern unsigned long random_seed;

/* == Structures == */

typedef unsigned long ELEMENT;
typedef	short int INDEX;

typedef struct {
	FIELD2N();
	~FIELD2N();
	ELEMENT 	e[MAXLONG];
}  FIELD2N;


typedef struct
{
	EC_PARAMETER();
	~EC_PARAMETER();
	CURVE	crv;
	POINT	pnt;
	FIELD2N	pnt_order;
	FIELD2N	cofactor;
} EC_PARAMETER;

typedef struct
{
	EC_KEYPAIR();
	~EC_KEYPAIR();
	FIELD2N	prvt_key;
	POINT	pblc_key;
} EC_KEYPAIR;

typedef struct
{
	SIGNATURE();
	~SIGNATURE();
	FIELD2N		c;
	FIELD2N		d;
} SIGNATURE;

typedef struct
{
	POINT();
	~POINT();
	FIELD2N  x;
 	FIELD2N  y;
} POINT;


/* Return string for Python */
typedef struct {
  int sz; 		//number of bytes
  char *bytes; 	//the bytes
} safeString;


/* Typemaps */


%typemap(python,out) safeString* {
  if ( $source != NULL ) {
    $target = PyString_FromStringAndSize($source->bytes, $source->sz);
    free($source->bytes);
    free($source);
  }
  else {
    PyErr_SetString(PyExc_RuntimeError,"cipher or key error");
    return NULL;
  }
}


%typemap(python, in) char * {
  if ( !PyString_Check($source) ) {
    PyErr_SetString(PyExc_TypeError,"not a string, man.");
    return NULL;
  }
  $target = PyString_AsString($source);
}


/* ==  API Prototypes == */

extern void makeSecretKey( EC_PARAMETER* Base, EC_KEYPAIR* Key );
extern void makeKeypair( EC_PARAMETER* Base, EC_KEYPAIR* Key);
extern void makeBaseCurve(EC_PARAMETER *Base);
extern void init();

extern safeString* field2bin(FIELD2N* in);
extern FIELD2N* bin2field (char* in);



/* Key Exchange */

// Diffie-Hellman
extern void DH_gen(EC_PARAMETER *Base, EC_KEYPAIR *myKP);
extern void DH_recv(EC_PARAMETER *Base, EC_KEYPAIR *myKP, POINT* pub_pt, FIELD2N* secret);

/* Nyberg-Ruppel Signing, Verification */

extern
void NR_Signature( char *Message,
					 unsigned long length,
					 EC_PARAMETER *public_curve,
					 FIELD2N *secret_key,
					 SIGNATURE *signature);

extern
int NR_Verify( char *Message,
				 unsigned long length,
				 EC_PARAMETER *public_curve,
				 POINT *signer_point,
				 SIGNATURE *signature);

