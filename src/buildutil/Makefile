include ./Makefile.inc

EXTERNAL_JSON=external/cJSON/
EXTERNAL_LUA=external/lua-5.2.3/
EXTERNAL_ZLIB=external/zlib-1.2.11/
EXTERNAL_PCRE2=external/pcre2-10.32/
ZLIB_SYSTEM?=yes
PCRE2_SYSTEM?=yes
LUA_PLAT?=posix
LUA_ENABLE?=no
MAXAGENTS?=2048
REUSE_ID?=no
# XXX Becareful NO EXTRA Spaces here
PREFIX?=/var/ossec
PG_CONFIG?=pg_config
MY_CONFIG?=mysql_config
PRELUDE_CONFIG?=libprelude-config
OSSEC_GROUP?=ossec
OSSEC_USER?=ossec
OSSEC_USER_MAIL?=ossecm
OSSEC_USER_REM?=ossecr
H1_DEBUG?=yes

INSTALL_CMD?=install -m $(1) -o $(2) -g $(3)
INSTALL_LOCALTIME?=yes
INSTALL_RESOLVCONF?=yes

USE_PRELUDE?=no
USE_ZEROMQ?=no
USE_GEOIP?=no
USE_INOTIFY?=no
USE_PCRE2_JIT?=yes
USE_SYSTEMD?=yes
USE_SQLITE?=yes

CC?=cc
MAKE?=make

CFLAGS+=${OSSEC_CFLAGS}

all:
	@echo "TEST"

settings:
	@echo
	@echo "General settings:"
	@echo "    TARGET:	   ${TARGET}"
	@echo "    V:		${V}"
	@echo "    DEBUG:	    ${DEBUG}"
	@echo "    DEBUGAD:	  ${DEBUGAD}"
	@echo "    PREFIX:	   ${PREFIX}"
	@echo "    MAXAGENTS:	${MAXAGENTS}"
	@echo "    REUSE_ID:	 ${REUSE_ID}"
	@echo "    CLEANFULL:	${CLEANFULL}"
	@echo "User settings:"
	@echo "    OSSEC_GROUP:      ${OSSEC_GROUP}"
	@echo "    OSSEC_USER:       ${OSSEC_USER}"
	@echo "    OSSEC_USER_MAIL:  ${OSSEC_USER_MAIL}"
	@echo "    OSSEC_USER_REM:   ${OSSEC_USER_REM}"
	@echo "ZLIB settings:"
	@echo "    ZLIB_SYSTEM:      ${ZLIB_SYSTEM}"
	@echo "    ZLIB_INCLUDE:     ${ZLIB_INCLUDE}"
	@echo "    ZLIB_LIB:	 ${ZLIB_LIB}"
	@echo "PCRE2 settings:"
	@echo "    PCRE2_SYSTEM:     ${PCRE2_SYSTEM}"
	@echo "    PCRE2_INCLUDE:    ${PCRE2_INCLUDE}"
	@echo "USE settings:"
	@echo "    USE_ZEROMQ:       ${USE_ZEROMQ}"
	@echo "    USE_GEOIP:	${USE_GEOIP}"
	@echo "    USE_OPENSSL:      ${USE_OPENSSL}"
	@echo "    USE_INOTIFY:      ${USE_INOTIFY}"
	@echo "    USE_SQLITE:       ${USE_SQLITE}"
	@echo "    USE_PCRE2_JIT:    ${USE_PCRE2_JIT}"
	@echo "    USE_LIBTLS:       ${USE_LIBTLS}"
	@echo "    USE_SYSTEMD:      ${USE_SYSTEMD}"
	@echo "Defines:"
	@echo "    ${DEFINES}"
	@echo "Compiler:"
	@echo "    OSSEC_CFLAGS	  ${OSSEC_CFLAGS}"
	@echo "    CFLAGS	  ${CFLAGS}"
	@echo "    LDFLAGS	 ${OSSEC_LDFLAGS}"
	@echo "    CC	      ${CC}"
	@echo "    MAKE	    ${MAKE}"

shared:
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/agent_op.o ../shared/agent_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/custom_output_search_replace.o ../shared/custom_output_search_replace.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/debug_op.o ../shared/debug_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/dirtree_op.o ../shared/dirtree_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/file-queue.o ../shared/file-queue.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/file_op.o ../shared/file_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/fs_op.o ../shared/fs_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/hash_op.o ../shared/hash_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/help.o ../shared/help.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/list_op.o ../shared/list_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/math_op.o ../shared/math_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/mem_op.o ../shared/mem_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/mq_op.o ../shared/mq_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/privsep_op.o ../shared/privsep_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/pthreads_op.o ../shared/pthreads_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/randombytes.o ../shared/randombytes.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/read-agents.o ../shared/read-agents.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/read-alert.o ../shared/read-alert.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/regex_op.o ../shared/regex_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/rules_op.o ../shared/rules_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/sig_op.o ../shared/sig_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/store_op.o ../shared/store_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/string_op.o ../shared/string_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/validate_op.o ../shared/validate_op.c
	${CC} ${CFLAGS} -I../ -I../headers -c -o ../shared/wait_op.o ../shared/wait_op.c

osnet:
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_net/os_net.o ../os_net/os_net.c

osxml:
	echo "TEST"

osconfig:
	echo "TEST"

osregex:
	echo "TEST"

analysisd:
	echo "TEST"

clean:
	rm -f Makefile.inc ../shared/*.o ../os_net/*.o ../os_config/*.o ../os_xml/*.o ../os_regex/*.o ../analysisd/*.o
