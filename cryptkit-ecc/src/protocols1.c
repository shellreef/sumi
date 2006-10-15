/********************************************************************************
*																				*
*		Routines to implement protocols, Diffie-Hellman, Massey-Omura and 		*
*	ElGamal for elliptic curve analogs.  Data transfer routines not included.	*
*																				*
********************************************************************************/

#include <stdio.h>
#include "field2n.h"
#include "eliptic.h"
#include "protocols.h"

/*  random seed is accessable to everyone, not best way, but functional.  */

unsigned long random_seed;

/*  below is from Mother code, till end of mother.  Above is all my fault.  */

#include <string.h>

static short mother1[10];
static short mother2[10];
static short mStart=1;

#define m16Long 65536L                          /* 2^16 */
#define m16Mask 0xFFFF          /* mask for lower 16 bits */
#define m15Mask 0x7FFF                  /* mask for lower 15 bits */
#define m31Mask 0x7FFFFFFF     /* mask for 31 bits */
#define m32Double  4294967295.0  /* 2^32-1 */

/* Mother **************************************************************
|       George Marsaglia's The mother of all random number generators
|               producing uniformly distributed pseudo random 32 bit values with
|               period about 2^250.
|
|       The arrays mother1 and mother2 store carry values in their
|               first element, and random 16 bit numbers in elements 1 to 8.
|               These random numbers are moved to elements 2 to 9 and a new
|               carry and number are generated and placed in elements 0 and 1.
|       The arrays mother1 and mother2 are filled with random 16 bit values
|               on first call of Mother by another generator.  mStart is the switch.
|
|       Returns:
|       A 32 bit random number is obtained by combining the output of the
|               two generators and returned in *pSeed.  It is also scaled by
|               2^32-1 and returned as a double between 0 and 1
|
|       SEED:
|       The inital value of *pSeed may be any long value
|
|       Bob Wheeler 8/8/94
|
|	removed double return since I don't need it.  mgr
*/


void Mother(unsigned long *pSeed)
{
        unsigned long  number,
                       number1,
                       number2;
        short          n,
                       *p;
        unsigned short sNumber;

                /* Initialize motheri with 9 random values the first time */
        if (mStart) {
                sNumber= *pSeed&m16Mask;   /* The low 16 bits */
                number= *pSeed&m31Mask;   /* Only want 31 bits */

                p=mother1;
                for (n=18;n--;) {
                        number=30903*sNumber+(number>>16);   
				/* One line multiply-with-cary */
                        *p++=sNumber=number&m16Mask;
                        if (n==9)
                                p=mother2;
                }
                /* make cary 15 bits */
                mother1[0]&=m15Mask;
                mother2[0]&=m15Mask;
                mStart=0;
        }

                /* Move elements 1 to 8 to 2 to 9 */
        memmove(mother1+2,mother1+1,8*sizeof(short));
        memmove(mother2+2,mother2+1,8*sizeof(short));

                /* Put the carry values in numberi */
        number1=mother1[0];
        number2=mother2[0];

                /* Form the linear combinations */

number1+=1941*mother1[2]+1860*mother1[3]+1812*mother1[4]+1776*mother1[5]+
         1492*mother1[6]+1215*mother1[7]+1066*mother1[8]+12013*mother1[9];

number2+=1111*mother2[2]+2222*mother2[3]+3333*mother2[4]+4444*mother2[5]+
         5555*mother2[6]+6666*mother2[7]+7777*mother2[8]+9272*mother2[9];

                /* Save the high bits of numberi as the new carry */
        mother1[0]=number1/m16Long;
        mother2[0]=number2/m16Long;
                /* Put the low bits of numberi into motheri[1] */
        mother1[1]=m16Mask&number1;
        mother2[1]=m16Mask&number2;

                /* Combine the two 16 bit random numbers into one 32 bit */
        *pSeed=(((long)mother1[1])<<16)+(long)mother2[1];

                /* Return a double value between 0 and 1 
        return ((double)*pSeed)/m32Double;  */
}

/*  Generate a random bit pattern which fits in a FIELD2N size variable.
	Calls Mother as many times as needed to create the value.
*/

void random_field( value)
FIELD2N *value;
{
	INDEX	i;
	
	SUMLOOP(i)
	{
		Mother( &random_seed);
	 	value->e[i] = random_seed;
	}
	value->e[0] &= UPRMASK;
}

/*  embed data onto a curve.
	Enter with data, curve, ELEMENT offset to be used as increment, and
	which root (0 or 1).
	Returns with point having data as x and correct y value for curve.
	Will use y[0] for last bit of root clear, y[1] for last bit of root set.
	if ELEMENT offset is out of range, default is 0.
*/

void opt_embed( data, curv, incrmt, root, pnt)
FIELD2N	*data;
CURVE	*curv;
INDEX	incrmt, root;
POINT	*pnt;
{
	FIELD2N		f, y[2];
	INDEX		inc = incrmt;
	INDEX		i;
	
	if ( (inc < 0) || (inc > NUMWORD) ) inc = 0;
	copy( data, &pnt->x);
	fofx( &pnt->x, curv, &f);
	while (opt_quadratic( &pnt->x, &f, y))
	{
		pnt->x.e[inc]++;
		fofx( &pnt->x, curv, &f);
	}
	copy ( &y[root&1], &pnt->y);
}

/*  generate a random curve for a given field size.
	Enter with pointer to storage space for returned curve.
	Returns with curve.form = 0, curve.a2 = 0 and curve.a6
	as a random bit pattern.  This is for the equation
	
		y^2 + xy = x^3 + a_2x^2 + a_6
*/

void rand_curve ( curv)
CURVE *curv;
{
	curv->form = 0;
	random_field( &curv->a6);
	null( &curv->a2);
}

/*  generate a random point on a given curve.
	Enter with pointer to curve and one pointer 
	to storage space for returned point.  Returns 
	one of solutions to above equation. Negate point
	to get other solution.
*/

void rand_point( point, curve)
POINT	*point;
CURVE	*curve;
{
	FIELD2N	rf;

	random_field( &rf);
	opt_embed( &rf, curve, NUMWORD, rf.e[NUMWORD]&1, point);
}

/*  Compute a Diffie-Hellman key exchange.

	First routine computes senders public key.
	Enter with public point Base_point which sits on public curve E and
	senders private key my_private.
	Returns public key point My_public = my_private*Base_point to be sent 
	to other side.
*/

void DH_gen_send_key( Base_point, E, my_private, My_public)
POINT *Base_point, *My_public;
CURVE *E;
FIELD2N *my_private;
{
	elptic_mul( my_private, Base_point, My_public, E);
}

/*	Second routine computes shared secret that is same for sender and
	receiver.
	Enter with public point Base_point which sits on public curve E along with 
	senders public key their_public and receivers private key k.
	Returns shared_secret as x component of kP
*/

void DH_key_share(Base_point, E, their_public, my_private, shared_secret)
POINT *Base_point, *their_public;
CURVE *E;
FIELD2N *my_private, *shared_secret;
{
	POINT	temp;
	
	elptic_mul( my_private, their_public, &temp, E);
	copy (&temp.x, shared_secret);
}
