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

JSON_FLAGS+=-I../external/cJSON
ANALYSISD_FLAGS+="-DARGV0=\"ossec-analysisd\""
ANALYSISD_FLAGS+= -I../analysisd -pthread

	
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

clean:
	rm -f Makefile.inc ../shared/*.o ../os_net/*.o ../os_config/*.o ../os_xml/*.o ../os_regex/*.o ../analysisd/*.o ../analysisd/alerts/*.o ../analysisd/cdb/*.o ../analysisd/compiled_rules/*.o ../analysisd/decoders/*.o ../analysisd/format/*.o ../analysisd/output/*.o ../config/*.o

testbuild:
	make clean
	./build.sh
	make shared osnet osxml osregex osconfig analysisd
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
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_xml/os_xml.o ../os_xml/os_xml.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_xml/os_xml_access.o ../os_xml/os_xml_access.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_xml/os_xml_node_access.o ../os_xml/os_xml_node_access.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_xml/os_xml_variables.o ../os_xml/os_xml_variables.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_xml/os_xml_writer.o ../os_xml/os_xml_writer.c
	
osconfig:
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../config/active-response.o ../config/active-response.c
	
osregex:
	echo "TEST"
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_converter.o ../os_regex/os_converter.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_match.o ../os_regex/os_match.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_match_compile.o ../os_regex/os_match_compile.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_match_execute.o ../os_regex/os_match_execute.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_match_free_pattern.o ../os_regex/os_match_free_pattern.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_pcre2.o ../os_regex/os_pcre2.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_pcre2_compile.o ../os_regex/os_pcre2_compile.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_pcre2_execute.o ../os_regex/os_pcre2_execute.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_pcre2_free_pattern.o ../os_regex/os_pcre2_free_pattern.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_pcre2_free_substrings.o ../os_regex/os_pcre2_free_substrings.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_regex.o ../os_regex/os_regex.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_regex_compile.o ../os_regex/os_regex_compile.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_regex_execute.o ../os_regex/os_regex_execute.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_regex_free_pattern.o ../os_regex/os_regex_free_pattern.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_regex_free_substrings.o ../os_regex/os_regex_free_substrings.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_regex_maps.o ../os_regex/os_regex_maps.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_regex_match.o ../os_regex/os_regex_match.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_regex_startswith.o ../os_regex/os_regex_startswith.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_regex_str.o ../os_regex/os_regex_str.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} -I../ -I../headers -c -o ../os_regex/os_regex_strbreak.o ../os_regex/os_regex_strbreak.c
	
analysisd:
	echo "TEST"
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/accumulator.o ../analysisd/accumulator.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/active-response.o ../analysisd/active-response.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/analysisd.o ../analysisd/analysisd.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/cleanevent.o ../analysisd/cleanevent.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/config.o ../analysisd/config.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/dodiff.o ../analysisd/dodiff.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/eventinfo.o ../analysisd/eventinfo.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/eventinfo_list.o ../analysisd/eventinfo_list.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/fts.o ../analysisd/fts.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/lists.o ../analysisd/lists.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/lists_list.o ../analysisd/lists_list.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/lists_make.o ../analysisd/lists_make.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/makelists.o ../analysisd/makelists.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/os_geoip.o ../analysisd/os_geoip.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/rules.o ../analysisd/rules.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/rules_list.o ../analysisd/rules_list.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/stats.o ../analysisd/stats.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -DTESTRULE -I../ -I../headers -c -o ../analysisd/testrule.o ../analysisd/testrule.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/alerts/exec.o ../analysisd/alerts/exec.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/alerts/getloglocation.o ../analysisd/alerts/getloglocation.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/alerts/log.o ../analysisd/alerts/log.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/cdb/cdb.o ../analysisd/cdb/cdb.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/cdb/cdb_hash.o ../analysisd/cdb/cdb_hash.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/cdb/cdb_make.o ../analysisd/cdb/cdb_make.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/cdb/uint32_pack.o ../analysisd/cdb/uint32_pack.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/cdb/uint32_unpack.o ../analysisd/cdb/uint32_unpack.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/decoders/decode-xml.o ../analysisd/decoders/decode-xml.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/decoders/decoder.o ../analysisd/decoders/decoder.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/decoders/decoders_list.o ../analysisd/decoders/decoders_list.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/decoders/geoip.o ../analysisd/decoders/geoip.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/decoders/hostinfo.o ../analysisd/decoders/hostinfo.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/decoders/plugin_decoders.o ../analysisd/decoders/plugin_decoders.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/decoders/rootcheck.o ../analysisd/decoders/rootcheck.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} -I../ -I../headers -c -o ../analysisd/decoders/syscheck.o ../analysisd/decoders/syscheck.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} ${JSON_FLAGS} -I../ -I../headers -c -o ../analysisd/format/json_extended.o ../analysisd/format/json_extended.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} ${JSON_FLAGS} -I../ -I../headers -c -o ../analysisd/format/to_json.o ../analysisd/format/to_json.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} ${JSON_FLAGS} -I../ -I../headers -c -o ../analysisd/output/jsonout.o ../analysisd/output/jsonout.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} ${JSON_FLAGS} -I../ -I../headers -c -o ../analysisd/output/prelude.o ../analysisd/output/prelude.c
	${CC} ${CFLAGS} ${LDFLAGS} ${PCRE2_INCLUDES} ${ANALYSISD_FLAGS} ${JSON_FLAGS} -I../ -I../headers -c -o ../analysisd/output/zeromq.o ../analysisd/output/zeromq.c
