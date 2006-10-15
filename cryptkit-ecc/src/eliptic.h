/******   eliptic.h   *****/
/****************************************************************
*                                                               *
*       These are structures used to create elliptic curve      *
*  points and parameters.  "form" is a just a fast way to check *
*  if a2 == 0.                                                  *
*               form            equation                        *
*                                                               *
*                0              y^2 + xy = x^3 + a_6            *
*                1              y^2 + xy = x^3 + a_2*x^2 + a_6  *
*                                                               *
****************************************************************/


typedef struct 
{
        INDEX   form;
        FIELD2N  a2;
        FIELD2N  a6;
} CURVE;

/*  coordinates for a point  */

typedef struct 
{
        FIELD2N  x;
        FIELD2N  y;
} POINT;

/* prototypes */

void rot_left();
void rot_right();
void null();
void copy();
void genlambda();
void genlambda2();
void opt_mul();
void opt_inv();
INDEX log_2();
int opt_quadratic();
void fofx();
void esum ();
void edbl ();
void esub ();
void copy_point ();
void elptic_mul();
void one(FIELD2N*);
void random_field();
void Mother();
void opt_embed();
void DH_gen_send_key();
void DH_key_share();
void send_elgamal();
void receive_elgamal();
void ECKGP();
void rand_curve ( );
void rand_point();
void print_field();
void print_point();
void print_curve();
void authen_secret();

//safeString* hex_field();

