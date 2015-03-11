#ifndef _BSD_GLUE_MULTISTACK_H
#define _BSD_GLUE_MULTISTACK_H

#define MS_RWLOCK_T	spinlock_t
#define	MS_RWINIT(_lock, _m)	spin_lock_init(_lock)
#define MS_WLOCK()	do {\
	spin_lock(&ms_global.lock); rcu_read_lock(); } while (0)
#define MS_WUNLOCK()	do {\
	rcu_read_unlock(); spin_unlock(&ms_global.lock); } while (0)
#define MS_RLOCK(_m)	rcu_read_lock()
#define MS_RUNLOCK(_m)	rcu_read_unlock()

#define MS_LIST_INIT(_head)	INIT_HLIST_HEAD(_head)
#define MS_LIST_ENTRY(_type)	struct hlist_node
#define MS_LIST_ADD(_head, _n, _pos) 	hlist_add_head_rcu(&((_n)->_pos), _head)
#define MS_LIST_DEL(_n, _pos)	hlist_del_init_rcu(&((_n)->_pos))
#define MS_LIST_FOREACH(_n, _head, _pos)		hlist_for_each_entry_rcu(_n, _head, _pos)
#define MS_LIST_FOREACH_SAFE(_n, _head, _pos, _tvar)	hlist_for_each_entry_rcu(_n, _head, _pos)
#define MS_ROUTE_LIST	struct hlist_head

#define MS_GET_VAR(lval)	rcu_dereference((lval))
#define MS_SET_VAR(lval, p)	rcu_assign_pointer((lval), (p))

#define INET6_ADDRSTRLEN 46

typedef uint32_t tcp_seq;

/* IPv6 address presentation (taken from FreeBSD) */

#define satosin(sa)	((struct sockaddr_in *)(sa))
#define satosin6(sa)	((struct sockaddr_in6 *)(sa))
#define IN6_ARE_ADDR_EQUAL(a, b) ipv6_addr_equal(a, b)
#define ETHER_HDR_LEN	ETH_HLEN
struct ip {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        u_char  ip_hl:4,                /* header length */
                ip_v:4;                 /* version */
#elif defined (__BIG_ENDIAN_BITFIELD)
        u_char  ip_v:4,                 /* version */
                ip_hl:4;                /* header length */
#endif
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
} __packed __aligned(4);

struct ip6_hdr {
        union {
                struct ip6_hdrctl {
                        u_int32_t ip6_un1_flow; /* 20 bits of flow-ID */
                        u_int16_t ip6_un1_plen; /* payload length */
                        u_int8_t  ip6_un1_nxt;  /* next header */
                        u_int8_t  ip6_un1_hlim; /* hop limit */
                } ip6_un1;
                u_int8_t ip6_un2_vfc;   /* 4 bits version, top 4 bits class */
        } ip6_ctlun;
        struct in6_addr ip6_src;        /* source address */
        struct in6_addr ip6_dst;        /* destination address */
} __packed;

#define	ETHER_ADDR_LEN		6
#define ip6_vfc         ip6_ctlun.ip6_un2_vfc
#define ip6_flow        ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen        ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt         ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim        ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops        ip6_ctlun.ip6_un1.ip6_un1_hlim

char *ip6_sprintf(char *, const struct in6_addr *);
/* From ethernet.h */
struct	ether_header {
	u_char	ether_dhost[ETHER_ADDR_LEN];
	u_char	ether_shost[ETHER_ADDR_LEN];
	u_short	ether_type;
};
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#define ETHERTYPE_ARP		0x0806	/* Addr. resolution protocol */
#define ETHERTYPE_IPV6		0x86dd	/* IPv6 */

#endif
