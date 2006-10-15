/*  These structures described in IEEE P1363 Nov. 1997  */

typedef struct
{
	CURVE	crv;
	POINT	pnt;
	FIELD2N	pnt_order;
	FIELD2N	cofactor;
} EC_PARAMETER;

typedef struct
{
	FIELD2N	prvt_key;
	POINT	pblc_key;
} EC_KEYPAIR;

typedef struct
{
	FIELD2N		c;
	FIELD2N		d;
} SIGNATURE;

/* Return string for Python */
typedef struct {
  int sz; //number of bytes
  char *bytes; //the bytes
} safeString;


/* prototypes */

void print_int();
INDEX int_onecmp();
void NR_Signature();
int NR_Verify();
void hash_to_int();

