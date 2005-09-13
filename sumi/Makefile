RLS="0.8.14"

all:: rawproxd

release: win32exe win32noinst
	

rawproxd:: rawproxd.c
	#gcc -static rawproxd.c -o rawproxd
	gcc -g hash/md5a.c rawproxd.c -o rawproxd_native

win32exe:
	python setup.py py2exe

win32noinst:
	rm -f ../sumi-win32-no_installer-${RLS}.zip
	cp config.txt.default dist/config.txt
	cp sumiserv.cfg.default dist/sumiserv.cfg
	cd dist && zip -r ../../sumi-win32-no_installer-${RLS}.zip *

package: clean
	cd /home/jeff/p2p/
	echo -n "archiving " 
	tar -hvcf sumi-${RLS}.tar --exclude sumi/build --exclude sumi/dist --exclude sumi/incoming --exclude sumi/share --exclude sumi/otp --exclude sumi/c++-obsolete/sender --exclude sumi/c++-obsolete/sumiserv --exclude sumi/hash/mddriver --exclude sumi/hash/test --exclude sumi/rawproxd --exclude sumi/\*.pyc --exclude sumi/build\* --exclude sumi/dist\* --exclude sumi/\*.exe --exclude .svn sumi/*

	echo -n "compressing "
	bzip2 -f sumi-${RLS}.tar
	echo 
	ls -lh sumi-${RLS}.tar.bz2
	cd sumi

clean::
	rm -f incoming/*
	rm -rf *.pyc
	rm -rf transport/*.pyc
	rm -rf cfastxor.o
	rm -rf cfastxor_wrap.o
	rm -rf cfastxor.so
	rm -rf _cfastxor.so
	rm -rf build
	rm -rf dist
	rm -rf buildsumigetw
	rm -rf distsumigetw
	rm -rf *.core

cfastxor::
	swig -python cfastxor.i
	gcc -c cfastxor.c cfastxor_wrap.c -I/usr/local/include/python2.3
	ld -shared cfastxor.o cfastxor_wrap.o -o _cfastxor.so

#backup-cvs::
#	fetch http://cvs.sourceforge.net/cvstarballs/sumi-cvsroot.tar.bz2

backup-svn:
	fetch http://svn.berlios.de/svndumps/sumi-repos.gz

backup-wiki:
	ssh jeffconnelly@shell.berlios.de ./dump > doc/wiki-`date +%Y%m%d`.sql
	chmod 000 doc/wiki-*.sql

test::
	python sumigetw.py tor 5mg27ujynvojkdpq.onion \#1

testc::
	python sumiget.py tor 5mg27ujynvojkdpq.onion \#1
