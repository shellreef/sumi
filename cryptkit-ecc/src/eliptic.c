/******   eliptic.c   *****/
/************************************************************************
*                                                                       *
*       Elliptic curves over Galois Fields.  These routines find points *
*  on a curve, add and double points for type 1 optimal normal bases.   *
*                                                                       *
*	For succint explanaition, see Menezes, page 92          	        *
*																		*
*		This file modified 6/23/97 to work with generalized ONB and 	*
*	tunable field sizes.  mgr											*
*                                                                       *
************************************************************************/

#include <stdio.h>
#include "field2n.h"
#include "eliptic.h"

/************************************************************************
*  Note that the following is obvious to mathematicians.  I thought it  *
*  was pretty cool when I discovered it myself, <sigh>.			*
*                                                                       *
*       Routine to solve quadradic equation.  Enter with coeficients    *
*  a and b and it returns solutions y[2]: y^2 + ay + b = 0.             *
*  If Tr(b/a^2) != 0, returns y=0 and error code 1.                     *
*  If Tr(b/a^2) == 0, returns y[2] and error code 0.                    *
*  If solution fails, returns y=0 and error code 2.                     *
*                                                                       *
*      Algorithm used based on normal basis GF math.  Since (a+b)^2 =   *
*  a^2 + b^2 it follows that (a+b)^.5 = a^.5 + b^.5.  Note that squaring*
*  is a left shift and rooting is a right shift in a normal basis.      *
*  Transforming the source equation with y = ax and dividing by a^2     *
*  gives:                                                               *
*               x^2 + x + b/a^2 = 0                                     *
*                                                                       *
*       or      x = x^.5 + (b/a^2)^.5                                   *
*                                                                       *
*  Let k_i = the ith significant bit of (b/a^2)^.5 and                  *
*      x_i = the ith significant bit of x.                              *
*  The above equation is equivelent to a bitwise representation as      *
*                                                                       *
*               x_i = x_(i+1) + k_i                                     *
*       or                                                              *
*               x(i+1) = x_i + k_i.                                     *
*                                                                       *
*  Since both x and x+1 are solutions, and 1 is represented by all      *
*  bits set in a normal basis, we can start with x_0 = 0 or 1 at our    *
*  pleasure and use the recursion relation to discover every bit of x.  *
*  The answer is then ax and ax+a returned in y[0] and y[1] respectively*
*  If the sum of x_(n-1) + k_(n-1) != x_0, returns error code 2 and     *
*  y = 0.                                                               *
*                                                                       *
*       error code                      returns                         *
*          0                    y[0] and y[1] values                    *
*          1                    y[0] = y[1] = 0                         *
*          2                    mathematicly impossible !!!!            *
*                                                                       *
************************************************************************/

int opt_quadratic(a, b, y)
FIELD2N *a, *b, *y;
{
        INDEX   i, l, bits;
        FIELD2N  x, k, a2;
        ELEMENT  r, t, mask;

/*  test for a=0. Return y = square root of b.  */

        r = 0;
        SUMLOOP(i) r |= a->e[i];
        if (!r) 
        {
			copy( b, &y[0]);
			rot_right( &y[0]);
			copy( &y[0], &y[1]);
           return(0);
        }

/*  find a^-2  */

        opt_inv( a, &a2);
        rot_left(&a2);

/*  find k=(b/a^2)^.5 */

        opt_mul( b, &a2, &k);
        rot_right(&k);
        r = 0;

/*  check that Tr(k) is zero.  Combine all words first. */

        SUMLOOP(i)  r ^= k.e[i];

/*  take trace of word, combining half of all the bits each time */

        mask = -1L;
        for (bits = WORDSIZE/2; bits > 0; bits >>= 1)
        {
        	mask >>= bits;
            r = ((r & mask) ^ (r >> bits));
        } 

/*  if not zero, return error code 1.  */

        if (r) 
        {
           null(&y[0]);
           null(&y[1]);
           return(1);
        }

/*  point is valid, proceed with solution.  mask points to bit i,
which is known, in x bits previously found and k (=b/a^2)^.5.  */

        null(&x);
        mask = 1;
        for (bits=0; bits < NUMBITS ; bits++) 
        {

/* source long word could be different than destination  */

           i = NUMWORD - bits/WORDSIZE;
           l = NUMWORD - (bits + 1)/WORDSIZE;

/*  use present bits to compute next one */

           r = k.e[i] & mask;
           t = x.e[i] & mask;
           r ^= t;

/*  same word, so just shift result up */

           if ( l == i ) 
           {
              r <<= 1;
              x.e[l] |= r;
              mask <<= 1;
           } 
           else 
           {

/*  different word, reset mask and use a 1 */

              mask = 1;
              if (r) x.e[l] = 1;
           }
        }

/*  test that last bit generates a zero */

        r = k.e[0] & UPRBIT;
        t = x.e[0] & UPRBIT;
        if ( r^t ) 
        {
           null(&y[0]);
           null(&y[1]);
           return(2);
        }

/*  convert solution back via y = ax */

        opt_mul(a, &x, &y[0]);

/*  and create complementary (z+1) solution y = ax + a */

		null (&y[1]);
        SUMLOOP(i) y[1].e[i] = y[0].e[i] ^ a->e[i];

/*  no errors, bye!  */

        return(0);
}

/*  compute R.H.S. f(x) = x^3 + a2*x^2 + a6  
    curv.form = 0 implies a2 = 0, so no extra multiply.  
    curv.form = 1 is the "twist" curve.
*/

void fofx(x, curv, f)
FIELD2N *x, *f;
CURVE *curv;
{

        FIELD2N x2,x3;
        INDEX i;

        copy(x, &x2);
        rot_left(&x2);
        opt_mul(x, &x2, &x3);
        if (curv->form) opt_mul(&x2, &curv->a2, f);
		else null(f);
        SUMLOOP(i)
             f->e[i] ^= (x3.e[i] ^ curv->a6.e[i]);
}

/****************************************************************************
*                                                                           *
*   Implement elliptic curve point addition for optimal normal basis form.  *
*  This follows R. Schroeppel, H. Orman, S. O'Mally, "Fast Key Exchange with*
*  Elliptic Curve Systems", CRYPTO '95, TR-95-03, Univ. of Arizona, Comp.   *
*  Science Dept.                                                            *
*                                                                           *
*   This version is faster for inversion processes requiring fewer          *
*  multiplies than projective math version.  For NUMBITS = 148 or 226 this  *
*  is the case because only 10 multiplies are required for inversion but    *
*  15 multiplies for projective math.  I leave it as a paper to be written  *
*  [HINT!!] to propagate TR-95-03 to normal basis inversion.  In that case  *
*  inversion will require order 2 multiplies and this method would be far   *
*  superior to projective coordinates.                                      *
****************************************************************************/

void esum (p1, p2, p3, curv)
POINT   *p1, *p2, *p3;
CURVE   *curv;
{
    INDEX   i;
    FIELD2N  x1, y1, theta, onex, theta2;

/*  compute theta = (y_1 + y_2)/(x_1 + x_2)  */

    null(&x1);
    null(&y1);
    SUMLOOP(i) 
    {
		x1.e[i] = p1->x.e[i] ^ p2->x.e[i];
		y1.e[i] = p1->y.e[i] ^ p2->y.e[i];
    }
    opt_inv( &x1, &onex);
    opt_mul( &onex, &y1, &theta);
    copy( &theta, &theta2);
    rot_left(&theta2);

/*  with theta and theta^2, compute x_3  */

    if (curv->form)
		SUMLOOP (i)
	    	p3->x.e[i] = theta.e[i] ^ theta2.e[i] ^ p1->x.e[i] ^ p2->x.e[i]
			 ^ curv->a2.e[i];
    else
		SUMLOOP (i)
	    	p3->x.e[i] = theta.e[i] ^ theta2.e[i] ^ p1->x.e[i] ^ p2->x.e[i];

/*  next find y_3  */

    SUMLOOP (i) x1.e[i] = p1->x.e[i] ^ p3->x.e[i];
    opt_mul( &x1, &theta, &theta2);
    SUMLOOP (i) p3->y.e[i] = theta2.e[i] ^ p3->x.e[i] ^ p1->y.e[i];
}

/*  elliptic curve doubling routine for Schroeppel's algorithm over normal
    basis.  Enter with p1, p3 as source and destination as well as curv
    to operate on.  Returns p3 = 2*p1.
*/

void edbl (p1, p3, curv)
POINT *p1, *p3;
CURVE *curv;
{
    FIELD2N  x1, y1, theta, theta2, t1;
    INDEX   i;

/*  first compute theta = x + y/x  */
    opt_inv( &p1->x, &x1);
    opt_mul( &x1, &p1->y, &y1);
    SUMLOOP (i) theta.e[i] = p1->x.e[i] ^ y1.e[i];

/*  next compute x_3  */
    copy( &theta, &theta2);
    rot_left(&theta2);
    if(curv->form)
		SUMLOOP (i) p3->x.e[i] = theta.e[i] ^ theta2.e[i] ^ curv->a2.e[i];
    else
		SUMLOOP (i) p3->x.e[i] = theta.e[i] ^ theta2.e[i];

/*  and lastly y_3  */
    one( &y1);
    SUMLOOP (i) y1.e[i] ^= theta.e[i];
    opt_mul( &y1, &p3->x, &t1);
    copy( &p1->x, &x1);
    rot_left( &x1);
    SUMLOOP (i) p3->y.e[i] = x1.e[i] ^ t1.e[i];
}

/*  subtract two points on a curve.  just negates p2 and does a sum.
    Returns p3 = p1 - p2 over curv.
*/

void esub (p1, p2, p3, curv)
POINT   *p1, *p2, *p3;
CURVE   *curv;
{
    POINT   negp;
    INDEX   i;

    copy ( &p2->x, &negp.x);
    null (&negp.y);
    SUMLOOP(i) negp.y.e[i] = p2->x.e[i] ^ p2->y.e[i];
    esum (p1, &negp, p3, curv);
}

/*  need to move points around, not just values.  Optimize later.  */

void copy_point (p1, p2)
POINT *p1, *p2;
{
	copy (&p1->x, &p2->x);
	copy (&p1->y, &p2->y);
}

/*  Routine to compute kP where k is an integer (base 2, not normal basis)
	and P is a point on an elliptic curve.  This routine assumes that K
	is representable in the same bit field as x, y or z values of P.
	This is for simplicity, larger or smaller fields can be independently 
	implemented.
    Enter with: integer k, source point P, curve to compute over (curv) and 
    Returns with: result point R.

  Reference: Koblitz, "CM-Curves with good Cryptografic Properties", 
	Springer-Verlag LNCS #576, p279 (pg 284 really), 1992
*/

void  elptic_mul(k, p, r, curv)
FIELD2N	*k;
POINT	*p, *r;
CURVE	*curv;
{
	char		blncd[NUMBITS+1];
	INDEX		bit_count, i;
	ELEMENT		notzero;
	FIELD2N		number;
	POINT		temp;

/*  make sure input multiplier k is not zero.
	Return point at infinity if it is.
*/
	copy( k, &number);
	notzero = 0;
	SUMLOOP (i) notzero |= number.e[i];
	if (!notzero)
	{
		null (&r->x);
		null (&r->y);
		return;
	}

/*  convert integer k (number) to balanced representation.
	Called non-adjacent form in "An Improved Algorithm for
	Arithmetic on a Family of Elliptic Curves", J. Solinas
	CRYPTO '97. This follows algorithm 2 in that paper.
*/
	bit_count = 0;
	while (notzero)
	{
	/*  if number odd, create 1 or -1 from last 2 bits  */
	
		if ( number.e[NUMWORD] & 1 )
		{
			blncd[bit_count] = 2 - (number.e[NUMWORD] & 3);
			
	/*  if -1, then add 1 and propagate carry if needed  */
			
			if ( blncd[bit_count] < 0 )
			{
				for (i=NUMWORD; i>=0; i--)
				{
					number.e[i]++;
					if (number.e[i]) break;
				}
			}
		}
		else
			blncd[bit_count] = 0;
	
	/*  divide number by 2, increment bit counter, and see if done  */
	
		number.e[NUMWORD] &= ~0 << 1;
		rot_right( &number);
		bit_count++;
		notzero = 0;
		SUMLOOP (i) notzero |= number.e[i];
	}
		
/*  now follow balanced representation and compute kP  */

	bit_count--;
	copy_point(p,r);		/* first bit always set */
	while (bit_count > 0) 
	{
	  edbl(r, &temp, curv);
	  bit_count--;
	  switch (blncd[bit_count]) 
	  {
	     case 1: esum (p, &temp, r, curv);
				 break;
	     case -1: esub (&temp, p, r, curv);
				  break;
	     case 0: copy_point (&temp, r);
	   }
	}
}

/*  One is not what it appears to be.  In any normal basis, "1" is the sum of
all powers of the generator.  So this routine puts ones to fill the number size
being used in the address of the FIELD2N supplied.  */

void one (place)
FIELD2N *place;
{
	INDEX i;

	SUMLOOP(i) place->e[i] = -1L;
	place->e[0] &= UPRMASK;
}

