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
DEBUG?=y

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
	@echo "    CFLAGS	  ${OSSEC_CFLAGS}"
	@echo "    LDFLAGS	 ${OSSEC_LDFLAGS}"
	@echo "    CC	      ${CC}"
	@echo "    MAKE	    ${MAKE}"
