#!/bin/sh
# Exercise the hooks inside directory $1, then remove it.
# The loader runs this under the `watched` flag, so every command below
# (children, grandchildren) should be seen.
set -e
d="$1"
mkdir "$d"
cd "$d"
mkdir sub
echo hi > a.txt
cat a.txt > /dev/null
ln a.txt hard.txt
ln -s a.txt sym.txt
cat sym.txt > /dev/null
mv a.txt b.txt
echo again > b.txt
truncate -s 0 b.txt
mknod pipe p
awk 'BEGIN { print "x" > "awk.txt" }'
rm hard.txt sym.txt b.txt pipe awk.txt
rmdir sub
cd ..
rmdir "$d"
