#include <sys/types.h>
#include <sys/queue.h>
#include <pcap/pcap.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "tcplib.h"

int
pcap_send_segments(const char *ifname, struct mpkts_head *pkts, pcap_t **pd)
{
	pcap_t *npd = *pd;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct mpkts_entry *mp;
	int err, pd_alloc = 0, pkts_sent = 0;

	if (npd == NULL) {
		memset(errbuf, 0, sizeof(errbuf));
		npd = pcap_open_live(ifname, 65535, 1, 2000, errbuf);
		if (!npd) {
			perror("pcap_open_live");
			return -1;
		}
		pd_alloc = 1;
	}
	/* dltype = pcap_datalink(pd); */
	LIST_FOREACH(mp, pkts, next) {
		if (mp->pktlen == 0)
			break;
		err = pcap_inject(npd, mp->buf, mp->pktlen);
		if (err < 0) {
			pcap_close(npd);
			perror("pcap_inject");
			return -1;
		}
		pkts_sent++;
	}
	if (pd_alloc)
		pcap_close(npd);
	return pkts_sent;
}
