# Created:20040110
# By Jeff Connelly

# Byte-compare two files and report differences.
# Used to verify a SUMI transfer.

open(A,"<lptest")||die;
open(B,"<tempout")||die;
binmode(A);
binmode(B);
$/=\1;
while(<A>)
{
$a=ord($_);
$b=ord(<B>);
print tell(A), ",$a,$b\n" if $a != $b;
}
close(A);close(B);

