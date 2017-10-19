install: collector sql
	cp ./collector ../bin/collector

include ../deploy/postgres.mk

collector: collector.c
	gcc -luv -lpq  collector.c -o collector

sql: collector.sql
	cat collector.sql | psql -d billing --username=postgres --no-password --host=127.0.0.1
