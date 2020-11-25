scan-build:
	mkdir -p SCAN
	scan-build -o SCAN make postgresql

postgresql:
	/bin/sh ./util/pcre2.sh
	/bin/sh ./util/pg.sh
	make -f Makefile.build

mysql:
	/bin/sh ./util/pcre2.sh
	/bin/sh ./util/mysql.sh
	make -f Makefile.build

clean:
	rm -f shared/*.o ./*.o config/*.o os_regex/*.o os_xml/*.o Makefile.inc Makefile.inc.backup ossec-dbd

