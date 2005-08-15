# vi:noexpandtab:tw=0
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
