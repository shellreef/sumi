/* Created:20050806
 * By Jeff Connelly
 *
 * In-place XOR routines for use within Python.
 *
 * $Id*
 */

/* Note: the fastest XOR in pure python I could manage is to 
   do a=list(s1), then XOR the list in-place using chr and ord, 
   looping over with xrange. I had a benchmark test suite in fastxor.py
   that compared various implementations but it was overwritten by SWIG. */

/* All functions have the same interface:
   char* a  destination: each bit will be XOR'd with a and b and written here
   char* b  source, not modified
   int len  common length, in bytes

   a and b must be the same length. Returns a.
*/
char* xor_byte(char* a, char* b, int len)
{
    do
        a[len] ^= b[len];
    while(len--);
    return a;
}

char* xor_int(char* a, char* b, int len)
{
    int* ai = (int*)a;
    int* bi = (int*)b;
    len /= sizeof(int);
    do
        ai[len] ^= bi[len];
    while(len--);
    return a;
}
