#!/bin/sh

INC=$(pg_config --includedir)
LIB=$(pg_config --libdir)

echo "PG_INCLUDES=-I${INC}" >> Makefile.inc
echo "PG_LIB=-L${LIB}" >> Makefile.inc
echo "DBD_DEFINES+=-DPGSQL_DATABASE_ENABLED" >> Makefile.inc

echo "DBD_INCLUDES:=-I../headers -I.. -I../os_xml -I../os_regex -I../config -I${INC}" >> Makefile.inc
echo "DBD_LIB:=-L${LIB}" >> Makefile.inc
echo "LIB_END+=-lpq -lpcre2-8" >> Makefile.inc

