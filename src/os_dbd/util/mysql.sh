#!/bin/sh

INC=$(mysql_config --include)
LIB=$(mysql_config --libs)

echo "DBD_DEFINES+=-DMYSQL_DATABASE_ENABLED" >> Makefile.inc

echo "DBD_INCLUDES:=-I./headers -I. -I./os_xml -I./os_regex -I./config ${INC}" >> Makefile.inc
echo "DBD_LIB:=${LIB}" >> Makefile.inc

echo "LIB_END+=-lmysqlclient -lpcre2-8" >> Makefile.inc

