CREATE UNLOGGED TABLE if not exists collector (
	"srcaddr"	inet NOT NULL,	--uint32_t srcaddr;
	"dstaddr"	inet NOT NULL,	--uint32_t dstaddr;
	"nexthop"	inet NOT NULL,	--uint32_t nexthop;
	"input" 	smallserial NOT NULL,	--uint16_t input;
	"output"	smallserial NOT NULL,	--uint16_t output;
	"pkts"  	serial NOT NULL,	--uint32_t pkts;
	"octets"	serial NOT NULL,	--uint32_t octets;
	"first" 	serial NOT NULL,	--uint32_t first;
	"last"  	serial NOT NULL,	--uint32_t last;
	"sport" 	smallserial NOT NULL,	--uint16_t sport;
	"dport" 	smallserial NOT NULL,	--uint16_t dport;
	"prot"  	smallserial NOT NULL,	--uint8_t prot;
	"sensor"	inet NOT NULL,	--uint32_t sensor;
	"sensor_port"	smallserial NOT NULL,	--uint16_t sensor_port;
	"sequence"	serial NOT NULL,	--uint32_t sequence;
	"srcmac"	macaddr NULL,	--char[6] srcmac;
	"dstmac"	macaddr NULL	--char[6] dstmac;
) WITH (OIDS=FALSE, fillfactor=100);
