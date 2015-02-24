/*
 * Copyright (C) 2012 Luigi Rizzo. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * $Id$
 *
 * Some utilities to build netmap-based programs.
 */

#ifndef _NM_UTIL_H
#define _NM_UTIL_H
#include <errno.h>
#include <signal.h>	/* signal */
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>	/* PRI* macros */
#include <string.h>	/* strcmp */
#include <fcntl.h>	/* open */
#include <unistd.h>	/* close */
#include <ifaddrs.h>	/* getifaddrs */

#include <sys/mman.h>	/* PROT_* */
#include <sys/ioctl.h>	/* ioctl */
#include <sys/poll.h>
#include <sys/socket.h>	/* sockaddr.. */
#include <arpa/inet.h>	/* ntohs */
#include <sys/param.h>
#include <sys/sysctl.h>	/* sysctl */
#include <sys/time.h>	/* timersub */

#include <net/ethernet.h>
#include <net/if.h>	/* ifreq */

#ifdef linux
#define ifr_flagshigh  ifr_flags
#define ifr_curcap     ifr_flags
#define ifr_reqcap     ifr_flags
#define IFF_PPROMISC   IFF_PROMISC
#include <linux/ethtool.h>
#include <linux/sockios.h>
#endif /* linux */

#ifdef __APPLE__
#define ifr_flagshigh  ifr_flags	// XXX
#define IFF_PPROMISC   IFF_PROMISC
#endif /* __APPLE__ */

#ifdef __FreeBSD__
#include <sys/endian.h> /* le64toh */
#include <machine/param.h>
#endif /* __FreeBSD__ */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <net/netmap.h>
#include <net/netmap_user.h>
#ifndef MY_PCAP
#include <pcap/pcap.h> // XXX do we need it ?
#endif // XXX hack

#include <pthread.h>	/* pthread_* */

#if defined(__FreeBSD__)
#include <pthread_np.h> /* pthread w/ affinity */
#include <sys/cpuset.h> /* cpu_set */
#include <net/if_dl.h>  /* LLADDR */
#endif

#if defined(__APPLE__)
#include <net/if_dl.h>  /* LLADDR */
#define clock_gettime(a,b)	\
	do {struct timespec t0 = {0,0};	*(b) = t0; } while (0)
#endif

#ifdef linux
#define CLOCK_REALTIME_PRECISE CLOCK_REALTIME
#include <netinet/ether.h>      /* ether_aton */
#include <linux/if_packet.h>    /* sockaddr_ll */
#endif /* linux */

static inline int min(int a, int b) { return a < b ? a : b; }

/* debug support */
#define ND(format, ...)	do {} while(0)
#define D(format, ...)				\
	fprintf(stderr, "%s [%d] " format "\n",		\
	__FUNCTION__, __LINE__, ##__VA_ARGS__)

#ifndef EXPERIMENTAL
#define EXPERIMENTAL 0
#endif


// XXX does it work on 32-bit machines ?
static inline void prefetch (const void *x)
{
        __asm volatile("prefetcht0 %0" :: "m" (*(const unsigned long *)x));
}

// XXX only for multiples of 64 bytes, non overlapped.
static inline void
pkt_copy(const void *_src, void *_dst, int l)
{
	const uint64_t *src = _src;
	uint64_t *dst = _dst;
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)       __builtin_expect(!!(x), 0)
	if (unlikely(l >= 1024)) {
		bcopy(src, dst, l);
		return;
	}
	for (; l > 0; l-=64) {
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
		*dst++ = *src++;
	}
}

#if EXPERIMENTAL
/* Wrapper around `rdtsc' to take reliable timestamps flushing the pipeline */
#define netmap_rdtsc(t) \
	do { \
		u_int __regs[4];					\
		do_cpuid(0, __regs);					\
		(t) = rdtsc();						\
	} while (0)

static __inline void
do_cpuid(u_int ax, u_int *p)
{
	__asm __volatile("cpuid"
			 : "=a" (p[0]), "=b" (p[1]), "=c" (p[2]), "=d" (p[3])
			 :  "0" (ax));
}

static __inline uint64_t
rdtsc(void)
{
	uint64_t rv;

	__asm __volatile("rdtsc" : "=A" (rv));
	return (rv);
}
#endif /* EXPERIMENTAL */

//struct my_ring;
/*
 * info on a ring we handle
 */
struct my_ring {
        const char *ifname;
        int fd;
        char *mem;                      /* userspace mmap address */
        u_int memsize;
        u_int queueid;
        u_int begin, end;               /* first..last+1 rings to check */
        struct netmap_if *nifp;
        struct netmap_ring *tx, *rx;    /* shortcuts */

        uint32_t if_flags;
        uint32_t if_reqcap;
        uint32_t if_curcap;
};
int netmap_open(struct my_ring *me, int ringid, int promisc);
int netmap_close(struct my_ring *me);
int nm_do_ioctl(struct my_ring *me, int what, int subcmd);
#endif /* _NM_UTIL_H */
