CREATE UNLOGGED TABLE if not exists collector (
	"input" 	smallint NOT NULL,	--uint16_t input;
	"output"	smallint NOT NULL,	--uint16_t output;
	"pkts"  	int NOT NULL,	--uint32_t pkts;
	"octets"	int NOT NULL,	--uint32_t octets;
	"time"  	tsrange NOT NULL,	--uint32_t first;
	"sport" 	smallint NOT NULL,	--uint16_t sport;
	"dport" 	smallint NOT NULL,	--uint16_t dport;
	"prot"  	smallint NOT NULL,	--uint8_t prot;
	"sensor_port"	smallint NOT NULL,	--uint16_t sensor_port;
	"sequence"	int NOT NULL,	--uint32_t sequence;
	"sensor"	inet NOT NULL,	--uint32_t sensor;
	"srcaddr"	inet NOT NULL,	--uint32_t srcaddr;
	"dstaddr"	inet NOT NULL,	--uint32_t dstaddr;
	"nexthop"	inet NOT NULL,	--uint32_t nexthop;
	"srcmac"	macaddr NOT NULL,	--char[6] srcmac;
	"dstmac"	macaddr NOT NULL	--char[6] dstmac;
) WITH (
	OIDS=FALSE,
	fillfactor=100,
	autovacuum_enabled = false
);
