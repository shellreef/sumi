# SET YOUR PYTHON MODULE PATH HERE OR WHEREVER YOU WANT TO INSTALL
PYTHONPATH :=  /usr/lib/python2.1/

# SET YOUR PYTHON HEADER PATH HERE
PYTHONHEADERS := /usr/include/python2.1

all: deps swig
	ld -shared bigint.o ecc_wrap.o eliptic.o int_functions.o onb_integer.o onb.o protocols1.o sha.o -o ellipticcmodule.so

swig:
	swig -shadow -python ecc.i
	gcc -c ecc_wrap.c -DHAVE_CONFIG_H -I$(PYTHONHEADERS)

deps: *.h *.c
	gcc -c *.c -DHAVE_CONFIG_H -I$(PYTHONHEADERS)

clean:
	rm -f *.o core ~* *.pyc *.so

install:
	cp -f ecc.py elliptic.py ellipticcmodule.so $(PYTHONPATH)

