CFLAGS=$(shell pkg-config --cflags --libs libpq libuv)

install: collector sql
	install --strip ./collector ../bin/collector

collector: collector.c
	gcc $(CFLAGS) hexdump.c collector.c -o collector

sql: collector.sql
	cat collector.sql | psql -d billing --username=postgres --no-password --host=127.0.0.1
