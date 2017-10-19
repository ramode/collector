#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>

#include <libpq-fe.h>

#define DEBUG
#define NETFLOW5 5
#define BUFFER_SIZE 256

typedef struct {
	uint32_t srcaddr;
	uint32_t dstaddr;
	uint32_t nexthop;
	uint16_t input;
	uint16_t output;
	uint32_t pkts;
	uint32_t octets;
	uint32_t first;
	uint32_t last;
	uint16_t sport;
	uint16_t dport;
	uint8_t prot;
	uint32_t sensor;
	uint16_t sensor_port;
	uint32_t sequence;
	char srcmac[6];
	char dstmac[6];
} flow_t;


flow_t *flow_buffer;
uint16_t flow_in;

PGconn * postgres;

void store() {
	flow_in = 0;
	uint16_t size = sizeof(flow_t)*flow_in;
	uv_buf_t buf;
	buf = uv_buf_init(malloc(size), size);
	memcpy ( buf.base, &flow_buffer, size);

}

void save(flow_t *flow) {
	flow_buffer[flow_in] = *flow;
	if (++flow_in == BUFFER_SIZE)
		store();
}


void alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf)
{
    *buf = uv_buf_init(malloc(size), size);
}


#define nf5header_size 24

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
  uint32_t srcaddr;
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

void parse_five(const struct uv_buf_t *buf, const struct sockaddr *addr) {


//	memcpy(head, buf->base,sizeof(nf5header));

	struct nf5header *nhead = (struct nf5header *) buf->base;

	struct nf5header head = {
		.version = ntohs(nhead->version),
		.count = ntohs(nhead->count),
		.uptime = ntohl(nhead->uptime),
		.timestamp = ntohl(nhead->timestamp),
		.nanosecs = ntohl(nhead->nanosecs),
		.sequence = ntohl(nhead->sequence)
	};



#ifdef DEBUG
    fprintf(stderr, "nf %d %d %d %d %d\n", head.version, head.count, head.uptime, head.timestamp , head.sequence);
#endif

	for (uint16_t i=0; i<head.count; i++) {
		struct nf5data *ndata = (struct nf5data *) (buf->base+nf5header_size+nf5data_size*i);
		struct nf5data data = {
			.srcaddr=ntohl(ndata->srcaddr),
			.dstaddr=ntohl(ndata->dstaddr),
			.nexthop=ntohl(ndata->nexthop),
			.input=ntohs(ndata->input),
			.output=ntohs(ndata->output),
			.dPkts=ntohl(ndata->dPkts),
			.dOctets=ntohl(ndata->dOctets),
			.first=ntohl(ndata->first),
			.last=ntohl(ndata->last),
			.srcport=ntohs(ndata->srcport),
			.dstport=ntohs(ndata->dstport),

			.pad1=0,

			.tcp_flags=ndata->tcp_flags,
			.prot=ndata->prot,
			.tos=ndata->tos,
			.src_as=ntohs(ndata->src_as),
			.dst_as=ntohs(ndata->dst_as),
			.src_mask=ndata->src_mask,
			.dst_mask=ndata->dst_mask,

			.pad2=0
		};
		#ifdef DEBUG
    fprintf(stderr, "%d: %d\n", i, data.srcaddr);
		#endif


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
    fprintf(stderr, "Recv from %s ", sender);
#endif

    uint16_t *as_s = (uint16_t*)buf->base;
    uint16_t version =  ntohs( as_s[0]);


    switch(version) {
      case NETFLOW5 :
       parse_five(buf,addr);
       break;
    };

    free(buf->base);

//    uv_udp_send_t *req = malloc(sizeof(*req));
//    uv_buf_t ans = uv_buf_init("Hello world!", 13);
//    uv_udp_send(req, handle, &ans, 1, addr, send_cb);
}

int postgres_connect() {
	postgres = PQsetdbLogin("localhost","5432","","","billing","postgres","");
    if (PQstatus(conn) != CONNECTION_OK)
    {
        fprintf(stderr, "Connection to database failed: %s",
                PQerrorMessage(conn));
        exit_nicely(conn);
    }
	return 0;
}


int main(int argc, char **argv)
{
	postgres_connect();
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
