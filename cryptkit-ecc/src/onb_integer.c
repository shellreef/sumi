/************************************************************
*															*
*  Implement combinations of math packages to create 		*
*  advanced protocols.  Massy-Omura is first example.		*
*  Nyberg_Rueppel second.									*
*															*
*				Author = Mike Rosing						*
*				 Date  = Jan 4, 1998						*
*															*
*		NR Jan. 9, 1998										*
*															*
* Modified Nov 16th, 2001 by Bryan Mongeau 					*
*															*
* Added:													*
*  - setSeed(unsigned long)									*
*  - makeBaseCurve()										*
*  - makeKeypair()											*
*  - genLambda()											*
*															*
************************************************************/


#include <stdio.h>
#include <string.h>
#include "bigint.h"
#include "eliptic.h"
#include "protocols.h"


extern unsigned long random_seed;
extern void sha_memory();

/* The public curve */
char publicCurve[MAXSTRING] = "5192296858534827627896703833467507"; /*N 113  */
/*  char publicCurve[MAXSTRING] = "680564733841876926932320129493409985129";*/ /*N~ 131 */
/*	char publicCurve[MAXSTRING] = "5444517870735015415344659586094410599059";*/ /*N 134 (g^2 = g+1)	*/
/*	char publicCurve[MAXSTRING] = "19822884620916109459140767798279811163792081";*/ /*N~ 148 GF(16) */
/*	char publicCurve[MAXSTRING] = "91343852333181432387730573045979447452365303319";*/  /* N 158 */

/* The public point, generated randomly by Bryan Mongeau */
char publicPoint_x[] = "4734744769613895326330049453781210";
char publicPoint_y[] = "7810476191732239229573578684000677";


/*  print out an integer.  input is label string and pointer
	to integer, sends to terminal.
*/


/*  function to compare BIGINT value to 1.
	Returns 1 if it is, 0 otherwise.
*/

INDEX int_onecmp( number)
BIGINT *number;
{
	INDEX	i;

	if ( number->hw[INTMAX] > 1) return (0);
	for ( i=0; i<INTMAX; i++)
		if ( number->hw[i]) return (0);
	if (number->hw[INTMAX]) return (1);
	return (0);
}

/*  Generate a key pair, a random value plus a point.
	This was called ECKGP for Elliptic Curve Key Generation
	Primitive in an early draft of IEEE P1363.

	Input:  EC parameters including public curve, point,
			point order and cofactor

	Output: EC key pair including
			secret key k and random point R = k* base point

	Broken into two functions by Bryan Mongeau to permit a
	Keypair to generate a secure secret key, then choose how
	to generate the public key, either ECKGP or DH_gen.
*/

void makeSecretKey( EC_PARAMETER* Base, EC_KEYPAIR* Key ) {

	BIGINT		key_num, point_order, quotient, remainder;
	FIELD2N		rand_key;

/*  ensure random value is less than point order  */

	random_field( &rand_key);
	field_to_int( &rand_key, &key_num);
	field_to_int( &Base->pnt_order, &point_order);
	int_div( &key_num, &point_order, &quotient, &remainder);
	int_to_field( &remainder, &Key->prvt_key);
}

void ECKGP( Base, Key)
EC_PARAMETER	*Base;
EC_KEYPAIR		*Key;
{

	elptic_mul( &Key->prvt_key, &Base->pnt, &Key->pblc_key, &Base->crv);
}

/*  As required in Massey-Omura protocol, create a number
	and its inverse over known curve order.  Input is
	public EC parameters, output is random e and d
	modulo curve order where ed = 1 mod N
*/


void hash_to_int( Message, length, hash_value)
char 			*Message;
unsigned long 	length;
BIGINT			*hash_value;		/*  then to an integer  */
{
	unsigned long	message_digest[5];	/*  from SHA-1 hash function  */
	FIELD2N		 	mdtemp;			/*  convert to NUMBITS size (if needed)  */
	INDEX			i, count;

/*  compute hash of input message  */

	sha_memory(	Message, length, message_digest);

/*  convert message digest into an integer */

	null ( &mdtemp);
	count = 0;
	SUMLOOP (i)
	{
		mdtemp.e[ NUMWORD - i] = message_digest[ 4 - i];
		count++;
		if (count > 4) break;
	}
	mdtemp.e[0] &= UPRMASK;
	field_to_int( &mdtemp, hash_value);
}

/*  Implement Nyberg-Rueppel signature scheme described in IEEE P1363 draft
	standard of August 1997.  This uses SHA-1 as the hash algorithm on the
	message.  Inputs are a pointer to Message, public elliptic curve parameters
	including the order of the curve, and the signers secret key for signing,
	or public key for verification.
*/

/*  Nyberg-Rueppel elliptic curve signature scheme.

	Inputs: pointer to Message to be signed and its length,
			pointer to elliptic curve parameters,
			pointer to signer's secret key,
			pointer to signature storage area.

	Output: fills signature storage area with 2 numbers
			first number = SHA(Message) + random value
			second number = random value - signer's secret key times first number
					both are done modulo base point order

			The output is converted back to FIELD2N variables to save space
			and to make verification easier.
*/

void NR_Signature( Message, length, public_curve, secret_key, signature)
char *Message;
unsigned long length;
EC_PARAMETER *public_curve;
FIELD2N *secret_key;
SIGNATURE *signature;
{
	BIGINT			hash_value;
	FIELD2N			random_value;
	POINT			random_point;
	BIGINT			x_value, k_value, sig_value;
	BIGINT			temp, quotient;
	BIGINT			key_value, point_order;

/*  compute hash of input message  */

	hash_to_int( Message, length,  &temp);
	field_to_int( &public_curve->pnt_order, &point_order);
	int_div( &temp, &point_order, &quotient, &hash_value);
	
/*  create random value and generate random point on public curve  */

	random_field( &random_value);
	elptic_mul( &random_value, &public_curve->pnt, 
					&random_point, &public_curve->crv);
	
/*  convert x component of random point to an integer and add to message
	digest modulo the order of the base point.
*/

	field_to_int( &random_point.x, &x_value);
	int_add( &x_value, &hash_value, &temp);

	int_div( &temp, &point_order, &quotient, &sig_value);
	int_to_field( &sig_value, &signature->c);

/*  final step is to combine signer's secret key with random value  
		second number = random value - secret key * first number
		modulo order of base point
*/

	field_to_int( &random_value, &k_value);
	field_to_int( secret_key, &key_value);
	int_mul( &key_value, &sig_value, &temp);
	int_div( &temp, &point_order, &quotient, &sig_value);
	
	int_sub( &k_value, &sig_value, &sig_value);
	while( sig_value.hw[0] & 0x8000)
		int_add( &point_order, &sig_value, &sig_value);
	int_div( &sig_value, &point_order, &quotient, &temp);
	int_to_field( &sig_value, &signature->d);
}

/*  verify a signature of a message using Nyberg-Rueppel scheme.

	Inputs:	Message to be verified of given length,
			elliptic curve parameters public_curve
			signer's public key (as a point),
			signature block.
	
	Output: value 1 if signature verifies,
			value 0 if failure to verify.
*/

int NR_Verify( Message, length, public_curve, signer_point, signature)
char			*Message;
unsigned long 	length;
EC_PARAMETER	*public_curve;
POINT			*signer_point;
SIGNATURE		*signature;
{
	BIGINT			hash_value;
	POINT			Temp1, Temp2, Verify;
	BIGINT			x_value, c_value;
	BIGINT			temp, quotient;
	BIGINT			check_value, point_order;
	INDEX			i;

/*  find hidden point from public data  */

	elptic_mul( &signature->d, &public_curve->pnt, &Temp1, &public_curve->crv);
	elptic_mul( &signature->c, signer_point, &Temp2, &public_curve->crv);
	esum( &Temp1, &Temp2, &Verify, &public_curve->crv);
	
/*  convert x value of verify point to an integer and first signature value too  */

	field_to_int( &Verify.x, &x_value);
	field_to_int( &signature->c, &c_value);

/*  compute resultant message digest from original signature  */

	field_to_int( &public_curve->pnt_order, &point_order);
	int_sub( &c_value, &x_value, &temp);
	while( temp.hw[0] & 0x8000)			/* ensure positive result */
		int_add( &point_order, &temp, &temp);
	int_div( &temp, &point_order, &quotient, &check_value);

/*  generate hash of message and compare to original signature  */

	hash_to_int( Message, length, &temp);
	int_div( &temp, &point_order, &quotient, &hash_value);

	int_null(&temp);
	int_sub( &hash_value, &check_value, &temp);
	while( temp.hw[0] & 0x8000)		/*  ensure positive zero */
		int_add( &point_order, &temp, &temp);

/*  return error if result of subtraction is not zero  */

	INTLOOP(i) if (temp.hw[i]) return(0);  
	return(1);
}




/* Generate the base curve and point */
void makeBaseCurve(EC_PARAMETER* Base){
	BIGINT	prime_order,b1;

/*  compute curve order from Koblitz data  */
    ascii_to_bigint(&publicCurve, &prime_order);
	int_to_field( &prime_order, &Base->pnt_order);
	null( &Base->cofactor);
	Base->cofactor.e[NUMWORD] = 2;

/*  create Koblitz curve  */
	Base->crv.form = 1;
	one(&Base->crv.a2);
	one(&Base->crv.a6);

/*  create the base point with no cofactor  */
	ascii_to_bigint(&publicPoint_x,&b1);
	int_to_field(&b1,&Base->pnt.x);
	ascii_to_bigint(&publicPoint_y,&b1);
	int_to_field(&b1,&Base->pnt.y);
}


/* Generate a keypair */

void makeKeypair( EC_PARAMETER* Base, EC_KEYPAIR* Key) {
	/*  create a secret key for testing. Note that secret key must be less than order.
	The standard implies that the field size which can be used is one bit less than
	the length of the public base point order.
	*/
	makeSecretKey(Base, Key);
	ECKGP(Base, Key);
}

/* Generate lambda tables */
void init() {
	init_opt_math();
}

/* Diffie-Hellman */

void DH_gen(EC_PARAMETER *Base, EC_KEYPAIR *myKP) {

	// Create a public key using diffie-hellman
	DH_gen_send_key( &Base->pnt, &Base->crv, &myKP->prvt_key, &myKP->pblc_key);

}


void DH_recv(EC_PARAMETER *Base, EC_KEYPAIR *myKP, POINT* pub_pt, FIELD2N* secret) {

	// Determine the shared secret and return it in *secret
	DH_key_share( &Base->pnt, &Base->crv, pub_pt, &myKP->prvt_key, secret);

};



/* Conversion functions */

safeString *field2bin(FIELD2N* in) {
	safeString *ret;
	INDEX i;

	// Manual memory allocation of return string required for Python.
 	// This memory will be deallocated in the wrapper.
    ret = (safeString*) malloc(sizeof(safeString));
    ret->bytes = (char*)malloc(NUMBYTES);
    ret->sz = NUMBYTES;
	// Copy over the field
	SUMLOOP(i) memcpy(ret->bytes+(sizeof(long)*i), &in->e[i],sizeof(long));
	return ret;
}

FIELD2N* bin2field (char* in) {
	INDEX i;
	FIELD2N* ret;

	// Manual memory allocation of return string required for Python.
 	// This memory will be deallocated in the wrapper.
	ret = (FIELD2N*)malloc(sizeof(FIELD2N));

	/* Copy over the FIELD2N data */
	SUMLOOP(i) memcpy(&ret->e[i],in+(sizeof(long)*i),sizeof(long));
	return ret;
}

