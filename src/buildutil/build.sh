#!/bin/sh


if [ -e ./Makefile.inc ]; then
	mv Makefile.inc Makefile.inc.backup
fi

PCRE2_PRE=$(pcre2-config --prefix)
PCRE2_LOC=${PCRE2_PRE}/include

echo "PCRE2_PREFIX=${PCRE2_PRE}" >> Makefile.inc
echo "PCRE2_LOCATION=${PCRE2_LOC}" >> Makefile.inc
echo "PCRE2_LIB=-L${PCRE2_PRE}/lib" >> Makefile.inc
echo "PCRE2_INCLUDES=-I${PCRE2_LOC}" >> Makefile.inc

SYSTYPE=$(uname -s)
if [ "X${SYSTYPE}" = "XOpenBSD" ]; then
	cat ./OpenBSD.inc >> Makefile.inc
fi

