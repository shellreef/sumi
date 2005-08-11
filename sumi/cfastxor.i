%module cfastxor
%{
extern char* xor_byte(char* a, char* b, int len);
extern char* xor_int(char* a, char* b, int len);
%}
