#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>

#include <uv.h>

#include <libpq-fe.h>

#define DEBUG
#define NETFLOW5 5
#define BUFFER_SIZE 1


#pragma pack(push,1)
typedef struct {
	char srcaddr[4];
	char dstaddr[4];
	char nexthop[4];
	char input[2];
	char output[2];
	char pkts[4];
	char octets[4];
	char first[4];
	char last[4];
	char sport[2];
	char dport[2];
	char prot;
	char sensor[4];
	char sensor_port[2];
	char sequence[4];
	char srcmac[6];
	char dstmac[6];
} flow_t;

typedef struct {
	uint16_t head;
	uint32_t tail;
} mac_t;


typedef struct {
	uint32_t srcaddr;
	uint32_t dstaddr;
	uint32_t nexthop;
	uint16_t input;
	uint16_t output;
	uint32_t pkts;
	uint32_t octets;
	uint64_t first;
	uint64_t last;
	uint16_t sport;
	uint16_t dport;
	uint8_t prot;
	uint32_t sensor;
	uint16_t sensor_port;
	uint32_t sequence;
	mac_t srcmac;
	mac_t dstmac;
} flow_uint_t;


typedef struct {
uint32_t p1;
	uint16_t input;
uint32_t p2;
	uint16_t output;
uint32_t p3;
	uint32_t pkts;
uint32_t p4;
	uint32_t octets;
char p5[9];
	uint64_t first;
char p6[4];
	uint64_t last;
uint32_t p7;
	uint16_t sport;
uint32_t p8;
	uint16_t dport;
uint32_t p9;
	uint8_t prot_pad;
	uint8_t prot;
uint32_t p10;
	uint16_t sensor_port;
uint32_t p11;
	uint32_t sequence;
uint32_t p12;
	uint8_t sensor_type;
	uint8_t sensor_mask;
	uint16_t sensor_version;
	uint32_t sensor;
uint32_t p13;
	uint8_t srcaddr_type;
	uint8_t srcaddr_mask;
	uint16_t srcaddr_version;
	uint32_t srcaddr;
uint32_t p14;
	uint8_t dstaddr_type;
	uint8_t dstaddr_mask;
	uint16_t dstaddr_version;
	uint32_t dstaddr;
uint32_t p15;
	uint8_t nexthop_type;
	uint8_t nexthop_mask;
	uint16_t nexthop_version;
	uint32_t nexthop;
uint32_t p16;
	mac_t srcmac;
uint32_t p17;
	mac_t dstmac;
} pgrow;

#pragma pack(pop)


static char COPY_HEAD[19] = {0x50, 0x47, 0x43, 0x4f, 0x50, 0x59, 0x0a, 0xff, 0x0d, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static char COPY_ROW[sizeof(pgrow)+2] = {
 0x00, 0x10,
 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,

 0x00, 0x00, 0x00, 0x19, 0x06,
 0x00, 0x00, 0x00, 0x08,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x08,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x08, 0x02, 0x20, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x08, 0x02, 0x20, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x08, 0x02, 0x20, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x08, 0x02, 0x20, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static char COPY_IP4[8] = {0, 0, 0, 0x08, 0x02, 0x20, 0, 0x04 };
static char COPY_NULL[4] = {0xff, 0xff, 0xff, 0xff};
static char COPY_END[2] = {0xff, 0xff};


flow_uint_t *flow_buffer;
uint16_t flow_in;

PGconn * postgres;


void hexDump (char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}


static void
exit_nicely(PGconn *conn)
{
	PQfinish(conn);
	exit(1);
}


void store() {
	PGresult *res;
	uint32_t size = 159*flow_in+19+2;

	//uv_buf_t buf;
	//buf = uv_buf_init(malloc(size), size);
	//memcpy ( buf.base, &flow_buffer, size);

	char *pgbuffer;
	pgbuffer = malloc(size);

	printf("buffer %d, size %d, count%d", pgbuffer,size,flow_in);

	char *p;
	p = pgbuffer;
	memcpy( pgbuffer,&COPY_HEAD,19);
	p += 19;

	for (uint16_t i=0; flow_in > i ;i++) {
		printf("%d - %d\n", i, sizeof(COPY_ROW));
		memcpy(p,&COPY_ROW,sizeof(COPY_ROW));
		p+=2;
		pgrow * row = (pgrow*)p;
		printf("row %d\n",row);


		row->input = flow_buffer[i].input;
		row->output = flow_buffer[i].output;
		row->pkts = flow_buffer[i].pkts;
		row->octets = flow_buffer[i].octets;
		row->first = flow_buffer[i].first;
		row->last = flow_buffer[i].last;
		row->sport = flow_buffer[i].sport;
		row->dport = flow_buffer[i].dport;
		row->prot = flow_buffer[i].prot;
		row->sensor_port = flow_buffer[i].sensor_port;
		row->sequence = flow_buffer[i].sequence;

		row->sensor = flow_buffer[i].sensor;
		row->dstaddr = flow_buffer[i].dstaddr;
		row->srcaddr = flow_buffer[i].srcaddr;

		row->srcmac = flow_buffer[i].srcmac;
		row->dstmac = flow_buffer[i].dstmac;

		hexDump("addr",row,157);

		p += 157;
		row = NULL;
	}
	flow_in=0;
	memcpy(p, &COPY_END, 2);
	p = NULL;

	hexDump("f", pgbuffer, size);
	res = PQexec(postgres, "COPY collector FROM STDIN WITH (FORMAT binary)");
	if (PQresultStatus(res) == PGRES_COPY_IN ) {
		PQputCopyData(postgres, pgbuffer, size);
		PQputCopyEnd(postgres, NULL);
	};
	PQendcopy(postgres);
	free(pgbuffer);
}



void alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
	*buf = uv_buf_init(malloc(size), size);
}


#define nf5header_size 24
#pragma pack(push,1)

struct nf5header {
	uint16_t version;
	uint16_t count;
	uint32_t uptime;
	uint32_t timestamp;
	uint32_t nanosecs;
	uint32_t sequence;
};

#define nf5data_size 48


struct nf5data {
	char srcaddr[4];
	uint32_t dstaddr;
	uint32_t nexthop;
	uint16_t input;
	uint16_t output;
	uint32_t dPkts;
	uint32_t dOctets;
	uint32_t first;
	uint32_t last;
	uint16_t srcport;
	uint16_t dstport;

	uint8_t pad1;

	uint8_t tcp_flags;
	uint8_t prot;
	uint8_t tos;
	uint16_t src_as;
	uint16_t dst_as;
	uint8_t src_mask;
	uint8_t dst_mask;

	uint16_t pad2;
};

#pragma pack(pop)

void parse_five(const struct uv_buf_t *buf, const struct sockaddr *addr) {


//	memcpy(head, buf->base,sizeof(nf5header));

	struct nf5header *nhead = (struct nf5header *) buf->base;
	uint64_t delta = ((uint64_t) ntohl(nhead->timestamp) - 946684800)*1000000
		+ ntohl(nhead->nanosecs)/1000
		- ((uint64_t) ntohl(nhead->uptime))*1000;

	fprintf(stderr, "%d\n",delta);

	for (uint16_t i=0; i<ntohs(nhead->count); i++) {
		struct nf5data *ndata = (struct nf5data *) (buf->base+nf5header_size+nf5data_size*i);
		struct sockaddr_in * sensor = (struct sockaddr_in*) addr;
		uint64_t first = htobe64( ( (uint64_t) ntohl(ndata->first)*1000+delta));
		uint64_t last = htobe64(( (uint64_t) ntohl(ndata->last)*1000+delta));
		uint32_t sequence = htonl(ntohl(nhead->sequence)+i);
		flow_uint_t flow;
		memcpy(&flow.srcaddr,&ndata->srcaddr,4);
		memcpy(&flow.dstaddr,&ndata->dstaddr,4);
		memcpy(&flow.nexthop,&ndata->nexthop,4);
		memcpy(&flow.input,&ndata->input,2);
		memcpy(&flow.output,&ndata->output,2);
		memcpy(&flow.pkts,&ndata->dPkts,4);
		memcpy(&flow.octets,&ndata->dOctets,4);
		memcpy(&flow.first,&first,8);
		memcpy(&flow.last, &last, 8);
		memcpy(&flow.sport,&ndata->srcport,2);
		memcpy(&flow.dport,&ndata->dstport,2);
		memcpy(&flow.prot,&ndata->prot,1);
		memcpy(&flow.sensor,&sensor->sin_addr.s_addr,4);
		memcpy(&flow.sensor_port,&sensor->sin_port,2);
		memcpy(&flow.sequence, &sequence, 4);
		memset(&flow.srcmac,0,6);
		memset(&flow.dstmac,0,6);
		flow_buffer[flow_in] = flow;
		if (++flow_in == BUFFER_SIZE)	store();
	};
}



void recv_cb(struct uv_udp_s *handle, long int nread, const struct uv_buf_t *buf, const struct sockaddr *addr, unsigned int flags)
{
	if (nread <= 0) {
		free(buf->base);
		return;
	};

#ifdef DEBUG
	char sender[17] = { 0 };
	uv_ip4_name((struct sockaddr_in*) addr, sender, 16);
#endif
	uint16_t *as_s = (uint16_t*)buf->base;
	uint16_t version =  ntohs( as_s[0]);
	switch(version) {
		case NETFLOW5 :
			parse_five(buf,addr);
			break;
	};
	free(buf->base);
}

int postgres_connect() {
	postgres = PQsetdbLogin("localhost","5432","","","billing","postgres","");
	if (PQstatus(postgres) != CONNECTION_OK)
	{
		fprintf(stderr, "Connection to database failed: %s", PQerrorMessage(postgres));
		PQfinish(postgres);
		return 1;
	}
	fprintf(stderr, "Connection to database OK\n");
	return 0;
}


int main(int argc, char **argv)
{
	while(postgres_connect()>0) sleep(1) ;
	flow_buffer = malloc(sizeof(flow_t)*BUFFER_SIZE);
	flow_in=0;
	uv_udp_t socket;
	struct sockaddr_in addr;
	uv_udp_init(uv_default_loop(), &socket);
	uv_ip4_addr("0.0.0.0", 2055, &addr);
	uv_udp_bind(&socket, (struct sockaddr *) &addr, 0);
	uv_udp_recv_start(&socket, alloc_cb, recv_cb);
	int r = uv_run(uv_default_loop(), UV_RUN_DEFAULT);
	free(flow_buffer);
	return r;
}
