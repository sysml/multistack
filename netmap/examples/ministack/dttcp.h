#include "nm_util.h"
#include "tcplib.h"
#include <sys/stat.h>

enum {
	HTTP_TIMER_MONO = 0,
	HTTP_TIMER_BATCH,
	HTTP_TIMER_TCP,
};

enum {
	HTTP_TCP_PKT_SYN = 0,
	HTTP_TCP_PKT_DATA,
	HTTP_TCP_PKT_RST,
	HTTP_TCP_PKT_OOTB
};


extern int msstab[8];

TAILQ_HEAD(connbatch_list, conn_batch);
TAILQ_HEAD(batched_conns, httcp_cb);
struct conn_batch {
	TAILQ_ENTRY(conn_batch) next;
	/* connections leaves dynamically, so use TAILQ */
	struct batched_conns conns;
	uint32_t start_sec; /* 0 means free */
	int num_conns;
};

struct http_worker_args {
	u_int filelen;
	uint16_t port;
	int fd;
	struct netmap_ring *rxring;
	struct netmap_ring *txring;
	uint32_t timer_type;
};

int http_worker_body(struct http_worker_args *);

/* XXX */
enum {
	IOV_HTTP_HDR = 0,
	IOV_HTTP_DATA,
	IOV_HTTP_CNT,
};
#define MAX_HTTPHDR_LEN	256
#define HTTP_REQUEST_KEY_LEN	64
#define HTTP_NUM_KEYS	1
struct http_worker {
	char request_key[HTTP_REQUEST_KEY_LEN];
	int reqkey_len;
	char httphdr[MAX_HTTPHDR_LEN]; /* XXX should be malloced ? */
	size_t httphdrlen;
	struct iovec data[IOV_HTTP_CNT];
	int filefd;

	struct pcb_channel pcbc;
	u_int lastclock, completed, failed, accepted;
	int timer_type;
	struct connbatch_list batch_list;
	struct connbatch_list free_batches; /* NUM_TCBS */
	/* Cleaned every event loop */
	struct conn_batch *cur_batch[HTTP_NUM_KEYS];
	/* just a pool */
	struct conn_batch batches[TCP_DEFAULT_TCBS];
	/* point app's data */
};

/* XXX should this be cast-able to tcp_cb? */
/* In DTTCP nature, snd_nxt and snd_max is always same so seqno is reused */
struct httcp_cb {
	struct tcp_cb tcb;
	struct http_worker *worker;
	/* offset in the data mapped into worker */
	TAILQ_ENTRY(httcp_cb) batch_next; /* linked with a batch */
	struct conn_batch *mybatch;
};
