# vi:noexpandtab:tw=0

# On amd64: need -fPIC, but takes up a register and impacts performance.
# The FreeBSD package (and port) doesn't build with -fPIC, and gcc can't
# build a -shared library without -fPIC. Not enforced on x86, but should be.
#ld -shared ctomcrypt_wrap.o -o _ctomcrypt.so -L/usr/local/lib -ltomcrypt -lgcc_pic 

build:
	swig -python ctomcrypt.i
	gcc -c ctomcrypt_wrap.c -I/usr/local/include/python2.4 -I/usr/local/include -L/usr/local/lib -fPIC
	ld -shared ctomcrypt_wrap.o -o _ctomcrypt.so -L/usr/local/lib -ltomcrypt -lgcc_pic
clean:
	rm -f _ctomcrypt.so
	rm -f *.o
	rm -f *.core

test_old:
	python test.py
test:
	python tomcrypt.py	
