#!/bin/sh
RLS="0.7-20040722"

rm *.pyc
cd ..
echo -n "archiving " 
tar -cf sumi/sumi-${RLS}.tar sumi/* --exclude sumi/build --exclude sumi/dist --exclude sumi/incoming --exclude sumi/share --exclude sumi/otp --exclude sumi/c++-obsolete/sender --exclude sumi/c++-obsolete/sumiserv --exclude sumi/hash/mddriver --exclude sumi/hash/test --exclude sumi/rawproxd --exclude sumi/\*.pyc

echo -n "compressing "
bzip2 sumi/sumi-${RLS}.tar
echo 
ls -lh sumi/sumi-${RLS}.tar.bz2
cd sumi

