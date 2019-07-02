debug:
	make collector CFLAGS=-DDEBUG=1

install: collector
	mkdir -p /usr/local/bin
	strip ./collector
	install -m 755 ./collector /usr/local/bin/collector

collector: collector.c
	gcc ${CFLAGS} hexdump.c collector.c -o collector $(shell pkg-config --cflags --libs libpq libuv)

sql: collector.sql
	cat collector.sql | psql -d billing --username=postgres --no-password --host=127.0.0.1
