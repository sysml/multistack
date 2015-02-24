#include "tcplib.h"
#include "dttcp.h"

const char *httcp_default_content = "GET / HTTP/1.1\r\n Content-type: text/html\r\n<html><head><title>httcp_default_data</title></head><body><p>httcp_default_data</p></body></html>";
const char *httcp_default_path = "index.html";
const char *httcp_get_msg = "GET / HTTP/1.1";

#define	TAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = TAILQ_FIRST((head));				\
	    (var) && ((tvar) = TAILQ_NEXT((var), field), 1);		\
	    (var) = (tvar))

/* We expect buf is large enough (68 byte if the file size if 380 KB) */
static void
generate_httphdr(u_int content_length, char *buf)
{
	char *p = buf;
	/* From nginx */
	char *lines[8] = {"HTTP/1.1 200 OK\r\n",
		"Server: nginx/1.2.2\r\n",
		"Date: Thu, 10 Jan 2013 01:52:13 GMT\r\n",
		"Content-Type: text/html\r\n",
		"Content-Length: ",
		"Last-Modified: Wed, 19 Dec 2012 05:24:19 GMT\r\n",
		"Connection: keep-alive\r\n",
		"Accept-Ranges: bytes\r\n\r\n"};
	int l;

	strncat(p, lines[0], strlen(lines[0]));
	p += strlen(lines[0]);
	strncat(p, lines[1], strlen(lines[1]));
	p += strlen(lines[1]);
	strncat(p, lines[2], strlen(lines[2]));
	p += strlen(lines[2]);
	strncat(p, lines[3], strlen(lines[3]));
	p += strlen(lines[3]);
	strncat(p, lines[4], strlen(lines[4]));
	p += strlen(lines[4]);
	l = sprintf(p, "%u\r\n", content_length);
	p += l;

	strncat(p, lines[5], strlen(lines[5]));
	p += strlen(lines[5]);
	strncat(p, lines[6], strlen(lines[6]));
	p += strlen(lines[6]);
	strncat(p, lines[7], strlen(lines[7]));
	p += strlen(lines[7]);
}

/* Return the number of bytes of the file */
static int *
map_file(const char *path, size_t *size_p, int *fd_p, int max)
{
	struct stat sb;
	int *paddr;
	int fd;

	fd = open(path, O_RDONLY, 0);
	if (fd < 0) {
		perror("open");
		return NULL;
	}
	fstat(fd, &sb);
	paddr = mmap(0, min(sb.st_size, max), PROT_READ, MAP_SHARED | MAP_FILE, fd, 0);
	if (paddr == MAP_FAILED) {
		close(fd);
		return NULL;
	}
	*fd_p = fd;
	*size_p = min(sb.st_size, max);
	D("mapped %u bytes of %s", (u_int)*size_p, path);
	return paddr;
}

void
http_free_conn_batch(struct tcp_cb *tcb, struct http_worker *worker)
{
	struct conn_batch *batch;
	struct httcp_cb *hcb = (struct httcp_cb *)tcb;

	batch = hcb->mybatch;
	TAILQ_REMOVE(&batch->conns, hcb, batch_next);
	if (TAILQ_EMPTY(&batch->conns)) {
		TAILQ_REMOVE(&worker->batch_list, batch, next);
		TAILQ_INSERT_TAIL(&worker->free_batches, batch, next);
	}
	hcb->mybatch = NULL;
}

void
httcp_cb_release(struct tcp_cb *tcb)
{
	struct httcp_cb *hcb = (struct httcp_cb *)tcb;
	struct http_worker *worker = hcb->worker;

	if (worker->timer_type == HTTP_TIMER_BATCH)
		http_free_conn_batch(tcb, worker);
	tcp_release_tcb(tcb);
}

static int
http_valid_req(pkt_t *pkt, char *key, int keylen)
{
	if (strncmp(pkt->data, key, keylen)) {
		D("got an invalid request %s\n", pkt->data);
		return 0;
	}
	return 1;
}

/* We already know that there is at least one empty tcb */
static void
http_start_conn_batch(struct tcp_cb *tcb, struct http_worker *worker, int key)
{
	struct httcp_cb *hcb = (struct httcp_cb *)tcb;
	struct conn_batch *batch;

	/* Check whether this is the first batch */
	batch = worker->cur_batch[key];
	if (!batch) {
		/* never fail... */
		batch = TAILQ_FIRST(&worker->free_batches);
		TAILQ_REMOVE(&worker->free_batches, batch, next);
		TAILQ_INSERT_TAIL(&worker->batch_list, batch, next);
		worker->cur_batch[key] = batch;
		/* short cut */
		batch->start_sec = tcb->start_at.tv_sec;
		TAILQ_INIT(&batch->conns);
		batch->num_conns = 0;
	}
	batch->num_conns++;
	TAILQ_INSERT_TAIL(&batch->conns, hcb, batch_next);
	hcb->mybatch = batch; /* to be freed by hcb's activity */
}

/* entry of the cases of both pure-ack and data packet
 * We need at least two slots in txring */
static int
http_process_packet(pkt_t *pkt, struct http_worker *worker,
		struct netmap_ring *txring)
{
	struct tcp_cb *tcb;
	struct pcb_channel *pcbc = &worker->pcbc;
	uint16_t mss;
#ifdef TCP_PROFILE /* XXX */
	uint64_t start_seg;
	uint64_t start_find;
	uint64_t start_accept;
	struct clockstat *stat_seg = &pcbc->clstat[TCP_PROF_SEGMENT];
	struct clockstat *stat_find = &pcbc->clstat[TCP_PROF_FINDTCB];
	struct clockstat *stat_accept = &pcbc->clstat[TCP_PROF_ACCEPT];

	start_find = rdtsc();
#endif

	/* pure ack only searches the established list */
	tcb = tcp_find_established(pkt, pcbc);
#ifdef TCP_PROFILE
	add_to_current(stat_find, start_find);
#endif
	if (tcb) {
		int status = 0;
#ifdef TCP_PROFILE
		uint64_t start;
		struct clockstat *stat = &pcbc->clstat[TCP_PROF_ACKIN];

		start = rdtsc();
#endif
		tcp_input_established(tcb, pkt, txring, &status);
#ifdef TCP_PROFILE
		add_to_current(stat, start);
#endif
		switch (status) {
		case TCP_INPUT_DUPACK:
		case TCP_INPUT_RST:
		case TCP_INPUT_FINACK:
			httcp_cb_release(tcb);
		default:
			break;
		}
		if (status == TCP_INPUT_FINACK)
			worker->completed++;
		else if (status == TCP_INPUT_DUPACK)
			worker->failed++;
		return 0;
	}

	if (unlikely(pkt->th.tcph->th_flags & TH_RST))
		/* nothing to do for outbount RST */
		return 0;
	else if (unlikely(pkt->th.tcph->th_flags & TH_FIN)) {
		/* We might receive FIN or ACK to a stale destination */
		netmap_tcp_finack(pkt, txring);
		/* XXX we might reset connection (adopted in FBSD exp) */
//		tcp_ootb_netmap(pkt, txring);
		return 0;
	} else if (!pkt->datalen) /* Pure ACK */
		/* will be accepted or timeout later */
		return 0;

	/* Establish new connection? */
	if (!pcbc->num_avail) {
		netmap_tcp_ootb(pkt, txring); /* reset */
		return 0;
	}
	mss = tcp_v4_cookie_valid(pkt, pcbc->ts.tv_sec);
	if (!mss)
		return 0;
	/* Check validity of application-level payload */
	if (!http_valid_req(pkt, worker->request_key, worker->reqkey_len))
		return 0;
#ifdef TCP_PROFILE
	start_accept = rdtsc();
#endif
	tcb = tcp_v4_accept(pkt, &worker->pcbc, mss);
	tcp_attach_sendbuf(tcb, worker->data, IOV_HTTP_CNT);

	worker->accepted++;
	((struct httcp_cb *)tcb)->worker = worker;
	if (worker->timer_type == HTTP_TIMER_BATCH)
		http_start_conn_batch(tcb, worker, 0);
#ifdef TCP_PROFILE
	add_to_current(stat_accept, start_accept);
#endif

#ifdef TCP_PROFILE
	start_seg = rdtsc();
#endif
	netmap_tcp_output(tcb, &tcb->hint, &tcb->data, txring);
#ifdef TCP_PROFILE
	add_to_current(stat_seg, start_seg);
#endif
	return 0;
}

static void
http_destroy_worker(struct http_worker *worker)
{
	struct pcb_channel *pcbc = &worker->pcbc;
	struct iovec *p;

	tcp_free_tcbs(pcbc);
	p = &worker->data[IOV_HTTP_DATA];
	munmap(p->iov_base, p->iov_len);
	close(worker->filefd);
	free(worker);
}

static struct http_worker *
http_init_worker(uint16_t port, int fd, struct netmap_ring *rxring,
		struct netmap_ring *txring, int timer_type)
{
	struct http_worker *worker;
	struct pcb_channel *pcbc;
	int i;

	worker = (struct http_worker *)calloc(1, sizeof(*worker));
	if (!worker) {
		D("failed to allocate worker's structure");
		return NULL;
	}

	pcbc = &worker->pcbc;
	pcbc->sport = port;
	pcbc->fds[0].fd = fd;
	pcbc->fds[0].events = (POLLIN);
	pcbc->rxring = rxring;
	pcbc->txring = txring;
	pcbc->cpu_freq = get_cpufreq();
	if (!pcbc->cpu_freq) {
		D("failed to obtain cpu frequency");
		free(worker);
		return NULL;
	}

//	timer_type = 1;
	worker->timer_type = timer_type;

	/* pre-allocate TCBs */
	tcp_prealloc_tcbs(TCP_DEFAULT_TCBS, sizeof(struct httcp_cb), pcbc);

	if (timer_type == HTTP_TIMER_BATCH) {
		TAILQ_INIT(&worker->batch_list);
		TAILQ_INIT(&worker->free_batches);
		for (i = 0; i < TCP_DEFAULT_TCBS; i++) {
			TAILQ_INSERT_TAIL(&worker->free_batches,
					&worker->batches[i], next);
			worker->batches[i].num_conns = 0;
		}
		bzero(worker->cur_batch, sizeof(worker->cur_batch));
	}

	/* Profilers */
	bzero(pcbc->clstat, sizeof(struct clockstat) * TCP_PROF_END);

	return worker;
}

static __inline int
http_pkt_interest(pkt_t *pkt)
{
	unsigned char tcpflags = pkt->th.tcph->th_flags;

	if (tcpflags & TH_RST)
		return HTTP_TCP_PKT_RST;
	else if (tcpflags & TH_SYN && !(tcpflags & TH_ACK))
		return HTTP_TCP_PKT_SYN;
	else if (tcpflags & TH_ACK)
		return HTTP_TCP_PKT_DATA;
	return HTTP_TCP_PKT_OOTB;
}

#define DTTCP_TIMEOUT_SECSHIFT 1 // expires after 1-2 second
static void
http_clean_expired(struct http_worker *worker)
{
	struct pcb_channel *pcbc = &worker->pcbc;
	uint32_t s_shifted = pcbc->ts.tv_sec >> DTTCP_TIMEOUT_SECSHIFT;
	int i;
#ifdef TCP_PROFILE
	uint64_t start;
	struct clockstat *stat = &pcbc->clstat[TCP_PROF_CLEAN];
#endif

	if (s_shifted != worker->lastclock) {
		D("Accepted: %u completed: %u failed: %u",
			worker->accepted, worker->completed, worker->failed);
		worker->completed = 0;
		worker->failed = 0;
		worker->accepted = 0;
		worker->lastclock = s_shifted;
#ifdef TCP_PROFILE
		print_profiles(pcbc->clstat, TCP_PROF_END, pcbc->cpu_freq);
#endif /* TCP_PROFILE */
	}
#ifdef TCP_PROFILE
	start = rdtsc();
#endif
	if (worker->timer_type == HTTP_TIMER_BATCH) {
		struct conn_batch *b, *tmp_b;

		TAILQ_FOREACH_SAFE(b, &worker->batch_list, next, tmp_b) {
			struct httcp_cb *d, *tmp_d;

			if (b->start_sec >> DTTCP_TIMEOUT_SECSHIFT ==
			    s_shifted)
				continue;
			/* connections in this batch are expired */
			TAILQ_FOREACH_SAFE(d, &b->conns, batch_next, tmp_d) {
				netmap_tcp_tcbreset(&d->tcb, pcbc->txring);
				httcp_cb_release(&d->tcb);
				/* removed from both the established and this.
				 * batch is also removed and appended to the
				 * free list */
			}
		}
	}
	for (i = 0; i < TCP_TCBHASHSIZ; i++) {
		struct tcp_cb *tcb, *tmp;

#ifdef TCP_TCB_LIST
		LIST_FOREACH_SAFE(tcb, &pcbc->inuse_list[i], list_next, tmp) {
#else
		TAILQ_FOREACH_SAFE(tcb, &pcbc->inuse_tailq[i], tailq_next, tmp) {
#endif
			if (s_shifted !=
			    tcb->start_at.tv_sec >> DTTCP_TIMEOUT_SECSHIFT) {
				netmap_tcp_tcbreset(tcb, pcbc->txring);
				httcp_cb_release(tcb);
			}
		}
	}
#ifdef TCP_PROFILE
	add_to_current(stat, start);
#endif
}

#ifndef CLOCK_REALTIME_PRECISE
#define CLOCK_REALTIME_PRECISE CLOCK_REALTIME
#endif

/* Exposed to a main file */
int
http_worker_body(struct http_worker_args *args)
{
	pkt_t pkt;
	struct http_worker *worker;
	struct pcb_channel *pcbc;
	int err;
	int *paddr, filefd;
	size_t file_siz;
	struct netmap_ring *rxring = args->rxring;
	struct netmap_ring *txring = args->txring;

	paddr = map_file(httcp_default_path, &file_siz, &filefd, args->filelen);
	if (paddr == NULL)
		return -1;

	worker = http_init_worker(args->port, args->fd, args->rxring,
			args->txring, args->timer_type);
	if (!worker)
		return -1;
	D("initialized worker (timer %d)", worker->timer_type);
	pcbc = &worker->pcbc;

	/* set file pointer to the worker */
	worker->filefd = filefd;

	memcpy(worker->request_key, httcp_get_msg, strlen(httcp_get_msg));
	worker->reqkey_len = strlen(httcp_get_msg);
	worker->request_key[worker->reqkey_len] = '\0';
	generate_httphdr(file_siz, worker->httphdr);
	worker->httphdrlen = strlen(worker->httphdr);

	worker->data[IOV_HTTP_HDR].iov_base = worker->httphdr;
	worker->data[IOV_HTTP_HDR].iov_len = worker->httphdrlen;
	worker->data[IOV_HTTP_DATA].iov_base = (char *)paddr;
	worker->data[IOV_HTTP_DATA].iov_len = file_siz;

	D("HTTP hdr: %u byte Request key: %s",
			(u_int)worker->httphdrlen, worker->request_key);

	for (;;) {
#ifdef TCP_PROFILE
		uint64_t start;
		struct clockstat *stat = &pcbc->clstat[TCP_PROF_SYN];
#endif
		user_clock_gettime(&pcbc->ts, pcbc->cpu_freq);
		http_clean_expired(worker);
		err = poll(pcbc->fds, 1, 1000);
		if (unlikely(err < 0)) {
			D("poll error");
			break;
		} else if (err == 0)
			continue;
		while (rxring->avail) {
			uint32_t cur = rxring->cur;
			struct netmap_slot *slot = &rxring->slot[cur];
			char *buf = NETMAP_BUF(rxring, slot->buf_idx);

			if (unlikely(ipv4_tcp_pkt(buf, &pkt, 0)))
				goto consumed; /* Checksum error */
			switch (http_pkt_interest(&pkt)) {
			case HTTP_TCP_PKT_SYN:
				/* stateless processing, we don't need worker */
#ifdef TCP_PROFILE
				start = rdtsc();
#endif
				netmap_tcp_synack(&pkt, txring, pcbc->ts.tv_sec);
#ifdef TCP_PROFILE
				add_to_current(stat, start);
#endif
				break;
			case HTTP_TCP_PKT_OOTB:
				netmap_tcp_ootb(&pkt, txring);
				break;
			default:
				http_process_packet(&pkt, worker, txring);
				break;
			}
consumed:
			rxring->avail--;
			rxring->cur = NETMAP_RING_NEXT(rxring, cur);
			if (!txring->avail)
				ioctl(pcbc->fds[0].fd, NIOCTXSYNC, NULL);
			/* Otherwise poll() flushes packets later */
		}
		if (worker->timer_type == HTTP_TIMER_BATCH) {
//			if (worker->cur_batch[0])
//				D("batched %d conns", worker->cur_batch[0]->num_conns);
			bzero(worker->cur_batch, sizeof(worker->cur_batch));
		}
	}
	http_destroy_worker(worker);
	D("destroyed worker");
	return 0;
}
