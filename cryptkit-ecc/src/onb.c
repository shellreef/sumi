/************************************************************************************
*																					*
*		Alex project routines for generalized and variable length ONB mathematics.	*
*	copied from original source and modified with new math.  Must be optimized for	*
*	specific platforms later.  Specific implementations should remove C constructs	*
*   in favor of assembler for more speed.											*
*																					*
*									Author = mike rosing							*
*									 date  = June 7, 1997							*
************************************************************************************/

#include "field2n.h"

/*  globals initialized once and used for multiply and
	inversion routines.
*/

static	INDEX	Lambda[2][field_prime];
static	INDEX	lg2_m;
static	INDEX	log2[field_prime+1];
static	INDEX	two_inx[field_prime];
static	ELEMENT	two_bit[field_prime];
static unsigned char shift_by[256];
char		parity[256];

void rot_left(a)
FIELD2N *a;
{
        INDEX i;
        ELEMENT bit,temp;

        bit = (a->e[0] & UPRBIT) ? 1L : 0L;
        for (i=NUMWORD; i>=0; i--) {
           temp = (a->e[i] & MSB) ? 1L : 0L;
           a->e[i] = ( a->e[i] << 1) | bit;
           bit = temp;
        }
        a->e[0] &= UPRMASK;
}

void rot_right(a)
FIELD2N *a;
{
        INDEX i;
        ELEMENT bit,temp;

        bit = (a->e[NUMWORD] & 1) ? UPRBIT : 0L;
        SUMLOOP(i) {
           temp = ( a->e[i] >> 1)  | bit;
           bit = (a->e[i] & 1) ? MSB : 0L;
           a->e[i] = temp;
        }
        a->e[0] &= UPRMASK;
}

void null(a)
FIELD2N *a;
{
        INDEX i;

        SUMLOOP(i)  a->e[i] = 0;
}

void copy (a,b)
FIELD2N *a,*b;
{
        INDEX i;

        SUMLOOP(i)  b->e[i] = a->e[i];
}

void null_cust(a)
CUSTFIELD *a;
{
        register INDEX i;

	for (i=0; i<=LONGWORD; i++)  a->e[i] = 0;
}

void copy_cust (a,b)
CUSTFIELD *a,*b;
{
        register INDEX i;

	for (i=0; i<=LONGWORD; i++)  b->e[i] = a->e[i];
}

/*  binary search for most significant bit within word */

INDEX log_2( x)
ELEMENT x;
{
	INDEX	k, lg2;
	ELEMENT ebit, bitsave, bitmask;

	lg2 = 0;
	bitsave = x;				/* grab bits we're interested in.  */
	k = WORDSIZE/2;					/* first see if msb is in top half  */
	bitmask = -1L<<k;				/* of all bits  */
	while (k)
	{
		ebit = bitsave & bitmask;	/* did we hit a bit?  */
		if (ebit)					/* yes  */
		{
			lg2 += k;				/* increment degree by minimum possible offset  */
			bitsave = ebit;			/* and zero out non useful bits  */
		}
		k /= 2;
		bitmask ^= (bitmask >> k);
	}
	return( lg2);
}

/* create Lambda [i,j] table.  indexed by j, each entry contains the
value of i which satisfies 2^i + 2^j = 1 || 0 mod field_prime.  There are
two 16 bit entries per index j except for zero.  See references for
details.  Since 2^0 = 1 and 2^2n = 1, 2^n = -1 and the first entry would
be 2^0 + 2^n = 0.  Multiplying both sides by 2, it stays congruent to
zero.  So Half the table is unnecessary since multiplying exponents by
2 is the same as squaring is the same as rotation once.  Lambda[0] stores
n = (field_prime - 1)/2.  The terms congruent to one must be found via
lookup in the log table.  Since every entry for (i,j) also generates an
entry for (j,i), the whole 1D table can be built quickly.
*/

void genlambda()
{
        INDEX i, logof, n, index, twoexp;

        for (i=0; i<field_prime; i++) log2[i] = -1;

/*  build antilog table first  */

        twoexp = 1;
        for (i=0; i<field_prime; i++) 
        {
          log2[twoexp] = i;
          twoexp = (twoexp << 1) % field_prime;
        }

/*  compute n for easy reference */

        n = (field_prime - 1)/2;
        
/*  fill in first vector with indicies shifted by half table size  */

        Lambda[0][0] = n;
        for (i=1; i<field_prime; i++) 
        	Lambda[0][i] = (Lambda[0][i-1] + 1) % NUMBITS;

/*  initialize second vector with known values  */
        
        Lambda[1][0]= -1;		/*  never used  */
        Lambda[1][1] = n;
        Lambda[1][n] = 1;

/*  loop over result space.  Since we want 2^i + 2^j = 1 mod field_prime
        it's a ton easier to loop on 2^i and look up i then solve the silly
        equations.  Think about it, make a table, and it'll be obvious.  */

        for (i=2; i<=n; i++) {
          index = log2[i];
          logof = log2[field_prime - i + 1];
          Lambda[1][index] = logof;
          Lambda[1][logof] = index;
        }
/*  last term, it's the only one which equals itself.  See references.  */

        Lambda[1][log2[n+1]] = log2[n+1];

/*  find most significant bit of NUMBITS.  This is int(log_2(NUMBITS)).  
	Used in opt_inv to count number of bits.  */

	lg2_m = log_2((ELEMENT)(NUMBITS - 1));
	
}

/*  Type 2 ONB initialization.  Fills 2D Lambda matrix.  */

void genlambda2()
{
	INDEX	i, logof[4], n, j, k, twoexp;

/*  build log table first.  For the case where 2 generates the quadradic
	residues instead of the field, duplicate all the entries to ensure 
	positive and negative matches in the lookup table (that is, -k mod
	field_prime is congruent to entry field_prime + k).  */

	twoexp = 1;
	for (i=0; i<NUMBITS; i++)
	{
		log2[twoexp] = i;
		twoexp = (twoexp << 1) % field_prime;
	}
	if (twoexp == 1)		/*  if so, then deal with quadradic residues */
	{
		twoexp = 2*NUMBITS;
		for (i=0; i<NUMBITS; i++)
		{
			log2[twoexp] = i;
			twoexp = (twoexp << 1) % field_prime;
		}
	}
	else
	{
		for (i=NUMBITS; i<field_prime-1; i++)
		{
			log2[twoexp] = i;
			twoexp = (twoexp << 1) % field_prime;
		}
	}
		
/*  first element in vector 1 always = 1  */

	Lambda[0][0] = 1;
	Lambda[1][0] = -1;

/*  again compute n = (field_prime - 1)/2 but this time we use it to see if
	an equation applies  */
	
	n = (field_prime - 1)/2;

/*  as in genlambda for Type I we can loop over 2^index and look up index 
	from the log table previously built.  But we have to work with 4 
	equations instead of one and only two of those are useful.  Look up 
	all four solutions and put them into an array.  Use two counters, one
	called j to step thru the 4 solutions and the other called k to track
	the two valid ones.
	
	For the case when 2 generates quadradic residues only 2 equations are
	really needed.  But the same math works due to the way we filled the
	log2 table.
*/

	twoexp = 1;	
	for (i=1; i<n; i++)
	{
		twoexp = (twoexp<<1) % field_prime;
		logof[0] = log2[field_prime + 1 - twoexp];
		logof[1] = log2[field_prime - 1 - twoexp];
		logof[2] = log2[twoexp - 1];
		logof[3] = log2[twoexp + 1];
		k = 0;
		j = 0;
		while (k<2)
		{
			if (logof[j] < n)
			{
				Lambda[k][i] = logof[j];
				k++;
			}
			j++;
		}
	}

/*  find most significant bit of NUMBITS.  This is int(log_2(NUMBITS)).  
	Used in opt_inv to count number of bits.  */

	lg2_m = log_2((ELEMENT)(NUMBITS - 1));
}

static void init_two(void)
{
	INDEX n, i, j;

	j = 1;
        n = (field_prime-1)/2;
	for ( i=0; i<n; i++ ) {
	    two_inx[i] = LONGWORD-(j / WORDSIZE);
	    two_bit[i] = 1L << (j % WORDSIZE);
	    two_inx[i+n] = LONGWORD-((field_prime-j) / WORDSIZE);
            two_bit[i+n] = 1L << ((field_prime-j) % WORDSIZE);
            j = (j << 1) % field_prime;
	}
	two_inx[field_prime-1] = two_inx[0];
        two_bit[field_prime-1] = two_bit[0];

	for ( i=1; i<256; i++ )
	    shift_by[i] = 0;
	shift_by[0] = 1;
	for ( j=2; j<256; j+=j )
        for ( i=0; i<256; i+=j )
	    shift_by[i]++;

	for ( i=0; i<256; i++ )
	    parity[i] = 0;
	for ( j=1; j<256; j+=j )
	for ( i=j; i<256; i++ )
        if ( i & j )
	    parity[i] ^= 1;
}

/*  Generalized Optimal Normal Basis multiply.  Assumes two dimensional Lambda vector
	already initialized.  Will work for both type 1 and type 2 ONB.  Enter with pointers
	to FIELD2N a, b and result area c.  Returns with c = a*b over GF(2^NUMBITS).
*/

void opt_mul(a, b, c)
FIELD2N *a, *b, *c;
{
	INDEX i, j;
	INDEX 	zero_index, one_index;
	FIELD2N	amatrix[NUMBITS], copyb;
	
/*  clear result and copy b to protect original  */

	null(c);
	copy(b, &copyb);

/*  To perform the multiply we need two rotations of the input a.  Performing all
	the rotations once and then using the Lambda vector as an index into a table
	makes the multiply almost twice as fast.
*/

	copy( a, &amatrix[0]);
	for (i = 1; i < NUMBITS; i++)
	{
		copy( &amatrix[i-1], &amatrix[i]);
		rot_right( &amatrix[i]);
	}

/*  Lambda[1][0] is non existant, deal with Lambda[0][0] as speical case.  */

	zero_index = Lambda[0][0];
	SUMLOOP (i) c->e[i] = copyb.e[i] & amatrix[zero_index].e[i];

/*  main loop has two lookups for every position.  */

	for (j = 1; j<NUMBITS; j++)
	{
		rot_right( &copyb);
		zero_index = Lambda[0][j];
		one_index = Lambda[1][j];
		SUMLOOP (i) c->e[i] ^= copyb.e[i] &
					(amatrix[zero_index].e[i] ^ amatrix[one_index].e[i]);
	}
}

/* set b  = a * u^n, where n>0 and n <= field_prime */

void cus_times_u_to_n(CUSTFIELD *a, int n, CUSTFIELD *b)
{
#define SIZE	(2*LONGWORD+2)
	ELEMENT w, t[SIZE+1];
	INDEX	i, j, n1, n2, n3;

	if ( n == field_prime ) {
	    copy_cust(a, b);
	    return;
        }

	for ( j=0; j<=SIZE; j++ ) t[j] = 0;

	n1 = n / WORDSIZE;
	j = SIZE-n1;
	n2 = n & (WORDSIZE-1);
	if ( n2 ) {
	    n3 = WORDSIZE-n2;
	    for ( i=LONGWORD; i>=0; i-- ) {
		t[j--] |= a->e[i] << n2;
		t[j] |= a->e[i] >> n3;
	    }
	} else {
	    for ( i=LONGWORD; i>=0; i-- ) {
		t[j--] |= a->e[i];
	    }
	}

        n3 = LONGSHIFT+1;
	i = SIZE-LONGWORD;
	for ( j=SIZE; j>=SIZE-n1; j-- ) {
	    t[j] |= t[i--] >> n3;
	    t[j] |= t[i] << (WORDSIZE-n3);
	}

	w = t[SIZE-LONGWORD] & (1L << LONGSHIFT ) ? ~0 : 0;
	for ( i=0; i<=LONGWORD; i++ )
	    b->e[i] = t[i+SIZE-LONGWORD] ^ w;
	b->e[0] &= LONGMASK;

#undef SIZE
}

/* This algorithm is the Almost Inverse Algorithm of Schroeppel, et al. given
   in "Fast Key Exchange with Elliptic Curve Systems 
*/

void opt_inv(FIELD2N *a, FIELD2N *dest)
{
	CUSTFIELD	f, b, c, g;
	INDEX		i, j, k, m, n, f_top, c_top;
    ELEMENT		bits, t, mask;

	/* f, b, c, and g are not in optimal normal basis format: they are held
	    in 'customary format', i.e. a0 + a1*u^1 + a2^u^2 + ...; For the
	    comments in this routine, the polynomials are assumed to be
	    polynomials in u. */

	/* Set g to polynomial (u^p-1)/(u-1) */

	for ( i=1; i<=LONGWORD; i++ )
	    g.e[i] = ~0;
        g.e[0] = LONGMASK | (1L << LONGSHIFT);

	/* Convert a to 'customary format', putting answer in f */

	null_cust(&f);
        j = 0;
	for ( k=NUMWORD; k>=0; k-- ) {
	    bits = a->e[k];
	    m = k>0 ? WORDSIZE : UPRSHIFT;
	    for ( i=0; i<m; i++ ) {
		if ( bits & 1 ) {
		    f.e[two_inx[j]] |= two_bit[j];
#ifdef TYPE2
		    f.e[two_inx[j+NUMBITS]] |= two_bit[j+NUMBITS];
#endif
		}
		j++;
		bits >>= 1;
	    }
	}

	/* Set c to 0, b to 1, and n to 0 */

	null_cust(&c);
	null_cust(&b);
	b.e[LONGWORD] = 1;
	n = 0;

	/* Now find a polynomial b, such that a*b = u^n */

	/* f and g shrink, b and c grow.  The code takes advantage of this.
	c_top and f_top are the variables which control this behavior */

	c_top = LONGWORD;
	f_top = 0;
	do {
	    i = shift_by[f.e[LONGWORD] & 0xff];
	    n+=i;
    /* Shift f right i (divide by u^i) */
	    m = 0;
	    for ( j=f_top; j<=LONGWORD; j++ ) {
		bits = f.e[j];
		f.e[j] = (bits>>i) | ((ELEMENT)m << (WORDSIZE-i));
		m = bits;
	    }
	} while ( i == 8 && (f.e[LONGWORD] & 1) == 0 );
	for ( j=0; j<LONGWORD; j++ )
	    if ( f.e[j] ) break;
	if ( j<LONGWORD || f.e[LONGWORD] != 1 ) {
	/* There are two loops here: whenever we need to exchange f with g and
		b with c, jump to the other loop which has the names reversed! */
	    do {
	    /* Shorten f and g when possible */
		while ( f.e[f_top] == 0 && g.e[f_top] == 0 ) f_top++;
	    /* f needs to be bigger - if not, exchange f with g and b with c.
	       (Actually jump to the other loop instead of doing the exchange)
	       The published algorithm requires deg f >= deg g, but we don't
	       need to be so fine */
		if ( f.e[f_top] < g.e[f_top] ) goto loop2;
loop1:
	    /* f = f+g, making f divisible by u */
		for ( i=f_top; i<=LONGWORD; i++ )
		    f.e[i] ^= g.e[i];
	    /* b = b+c */
		for ( i=c_top; i<=LONGWORD; i++ )
		    b.e[i] ^= c.e[i];
		do {
		    i = shift_by[f.e[LONGWORD] & 0xff];
		    n+=i;
	    /* Shift c left i (multiply by u^i), lengthening it if needed */
		    m = 0;
		    for ( j=LONGWORD; j>=c_top; j-- ) {
			bits = c.e[j];
			c.e[j] = (bits<<i) | m;
			m = bits >> (WORDSIZE-i);
		    }
		    if ( m ) c.e[c_top=j] = m;

	    /* Shift f right i (divide by u^i) */
		    m = 0;
		    for ( j=f_top; j<=LONGWORD; j++ ) {
			bits = f.e[j];
			f.e[j] = (bits>>i) | ((ELEMENT)m << (WORDSIZE-i));
			m = bits;
		    }
		} while ( i == 8 && (f.e[LONGWORD] & 1) == 0 );
	    /* Check if we are done (f=1) */
		for ( j=f_top; j<LONGWORD; j++ )
		    if ( f.e[j] ) break;
	    } while ( j<LONGWORD || f.e[LONGWORD] != 1 );
	    if ( j>0 ) 
	    goto done;
	    do {
	    /* Shorten f and g when possible */
		while ( g.e[f_top] == 0 && f.e[f_top] == 0 ) f_top++;
	    /* g needs to be bigger - if not, exchange f with g and b with c.
	       (Actually jump to the other loop instead of doing the exchange)
	       The published algorithm requires deg g >= deg f, but we don't
	       need to be so fine */
		if ( g.e[f_top] < f.e[f_top] ) goto loop1;
loop2:
	    /* g = f+g, making g divisible by u */
		for ( i=f_top; i<=LONGWORD; i++ )
		    g.e[i] ^= f.e[i];
	    /* c = b+c */
		for ( i=c_top; i<=LONGWORD; i++ )
		    c.e[i] ^= b.e[i];
		do {
		    i = shift_by[g.e[LONGWORD] & 0xff];
		    n+=i;
	    /* Shift b left i (multiply by u^i), lengthening it if needed */
		    m = 0;
		    for ( j=LONGWORD; j>=c_top; j-- ) {
			bits = b.e[j];
			b.e[j] = (bits<<i) | m;
			m = bits >> (WORDSIZE-i);
		    }
		    if ( m ) b.e[c_top=j] = m;

	    /* Shift g right i (divide by u^i) */
		    m = 0;
		    for ( j=f_top; j<=LONGWORD; j++ ) {
			bits = g.e[j];
			g.e[j] = (bits>>i) | ((ELEMENT)m << (WORDSIZE-i));
			m = bits;
		    }
		} while ( i == 8 && (g.e[LONGWORD] & 1) == 0 );
	    /* Check if we are done (g=1) */
		for ( j=f_top; j<LONGWORD; j++ )
		    if ( g.e[j] ) break;
	    } while ( j<LONGWORD || g.e[LONGWORD] != 1 );
            copy_cust(&c, &b);
	}
done:
	/* Now b is a polynomial such that a*b = u^n, so multiply b by u^(-n) */
	cus_times_u_to_n(&b, field_prime - n % field_prime, &b);

        /* Convert b back to optimal normal basis form (into dest) */

	if ( b.e[LONGWORD] & 1 )
	    one(dest);
	else        	
	    null(dest);
	j = 0;
	for ( k=NUMWORD; k>=0; k-- ) {
	    bits = 0;
	    t = 1;
	    mask = k > 0 ? ~0 : UPRMASK;
	    do {
		if ( b.e[two_inx[j]] & two_bit[j] ) bits ^= t;
		j++;
		t <<= 1;
	    } while ( t&mask );
	    dest->e[k] ^= bits;
	}
         
} /* nu_inv */

/*  since I have more than one thing to do, create initialization
	routine.  Thanks Dave!
*/

void init_opt_math()
{

#ifdef TYPE2
	genlambda2();
#else
	genlambda();
#endif
	init_two();
}
