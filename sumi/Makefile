RLS="0.8.13"

all:: rawproxd

rawproxd:: rawproxd.c
	#gcc -static rawproxd.c -o rawproxd
	gcc -g hash/md5a.c rawproxd.c -o rawproxd_native

exe:
	python setup.py py2exe

package:
	cd /home/jeff/p2p/
	echo -n "archiving " 
	tar -hvcf sumi-${RLS}.tar --exclude sumi/build --exclude sumi/dist --exclude sumi/incoming --exclude sumi/share --exclude sumi/otp --exclude sumi/c++-obsolete/sender --exclude sumi/c++-obsolete/sumiserv --exclude sumi/hash/mddriver --exclude sumi/hash/test --exclude sumi/rawproxd --exclude sumi/\*.pyc --exclude sumi/build\* --exclude sumi/dist\* --exclude sumi/\*.exe --exclude \*CVS\* sumi/*

	echo -n "compressing "
	bzip2 -f sumi-${RLS}.tar
	echo 
	ls -lh sumi-${RLS}.tar.bz2
	cd sumi

clean::
	rm -f /home/jeff/p2p/sumi/incoming/*
	rm -f *.pyc
