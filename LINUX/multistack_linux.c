#include <bsd_glue.h> /* from netmap-release */
#include <bsd_glue_multistack.h>
#include <contrib/multistack/multistack_kern.h>

#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/fdtable.h> /* for ms_pcb_clash() */

/* from FreeBSD in6.c */
/*
 * Convert IP6 address to printable (loggable) representation. Caller
 * has to make sure that ip6buf is at least INET6_ADDRSTRLEN long.
 */
static char digits[] = "0123456789abcdef";
char *
ip6_sprintf(char *ip6buf, const struct in6_addr *addr)
{
	int i, cnt = 0, maxcnt = 0, idx = 0, index = 0;
	char *cp;
	const u_int16_t *a = (const u_int16_t *)addr;
	const u_int8_t *d;
	int dcolon = 0, zero = 0;

	cp = ip6buf;

	for (i = 0; i < 8; i++) {
		if (*(a + i) == 0) {
			cnt++;
			if (cnt == 1)
				idx = i;
		}
		else if (maxcnt < cnt) {
			maxcnt = cnt;
			index = idx;
			cnt = 0;
		}
	}
	if (maxcnt < cnt) {
		maxcnt = cnt;
		index = idx;
	}

	for (i = 0; i < 8; i++) {
		if (dcolon == 1) {
			if (*a == 0) {
				if (i == 7)
					*cp++ = ':';
				a++;
				continue;
			} else
				dcolon = 2;
		}
		if (*a == 0) {
			if (dcolon == 0 && *(a + 1) == 0 && i == index) {
				if (i == 0)
					*cp++ = ':';
				*cp++ = ':';
				dcolon = 1;
			} else {
				*cp++ = '0';
				*cp++ = ':';
			}
			a++;
			continue;
		}
		d = (const u_char *)a;
		/* Try to eliminate leading zeros in printout like in :0001. */
		zero = 1;
		*cp = digits[*d >> 4];
		if (*cp != '0') {
			zero = 0;
			cp++;
		}
		*cp = digits[*d++ & 0xf];
		if (zero == 0 || (*cp != '0')) {
			zero = 0;
			cp++;
		}
		*cp = digits[*d >> 4];
		if (zero == 0 || (*cp != '0')) {
			zero = 0;
			cp++;
		}
		*cp++ = digits[*d & 0xf];
		*cp++ = ':';
		a++;
	}
	*--cp = '\0';
	return (ip6buf);
}

int
ms_getifname(struct sockaddr *sa, char *name)
{
	struct net_device *dev;
	int retval = 0;

	rcu_read_lock();
	for_each_netdev_rcu(&init_net, dev) {
		rcu_read_lock();
		if (sa->sa_family == AF_INET) {
			struct in_device *in_dev;
			struct in_ifaddr *ifa;
			struct sockaddr_in *sin = (struct sockaddr_in *)sa;

			if ((in_dev = __in_dev_get_rcu(dev)) == NULL) {
				rcu_read_unlock();
				continue;
			}
			for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
				if (ifa->ifa_local == sin->sin_addr.s_addr) {
					retval = 1;
					break;
				}
			}
			rcu_read_unlock();
		} else if (sa->sa_family == AF_INET6) {
			struct inet6_dev *in6_dev;
			struct inet6_ifaddr *ifa;
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

			rcu_read_lock();
			if ((in6_dev = __in6_dev_get(dev)) == NULL) {
				rcu_read_unlock();
				continue;
			}
			read_lock_bh(&in6_dev->lock);
			list_for_each_entry(ifa, &in6_dev->addr_list, if_list) {
				if (ipv6_addr_equal(&ifa->addr,
				    &sin6->sin6_addr)) {
					retval = 1;
					break;
				}
			}
			read_unlock_bh(&in6_dev->lock);
			rcu_read_unlock();
		}
		if (retval)
			break;
	}
	if (retval)
		strncpy(name, dev->name, IFNAMSIZ);
	rcu_read_unlock();
	return retval;
}

int
ms_pcb_clash(struct sockaddr *sa, uint8_t protocol)
{
	struct socket *so;
	int found = 0, i;
	struct files_struct *files;
	struct fdtable *files_table;
	int socktype = 0;

#if 0 /* we are not allowed to access inetsw... */
	spinlock_t *lock;
	struct list_head *head;
	struct inet_protosw *answer = NULL;

	if (sa->sa_family == AF_INET) {
		head = inetsw;
		lock = &inetsw_lock;
	}
#ifdef CONFIG_IPV6
	else if (sa->sa_family == AF_INET6) {
		head = inetsw6;
		lock = &inet6sw_lock;
	}
#endif
	else
		return ENOENT;

	spin_lock_bh(lock);
	for (i = 0; i < SOCK_MAX; i++) {
		list_for_each(lh, &head[i]) {
			answer = list_entry(lh, struct inet_protosw, list);
			if (answer->protocol == protocol) {
				found = 1;
				break;
			}
			answer = NULL:
		}
		if (found)
			break;
	}
	spin_unlock_bh(lock);
#endif /* 0 */
	if (protocol == IPPROTO_TCP || protocol == IPPROTO_SCTP)
		socktype = SOCK_STREAM;
	else if (protocol == IPPROTO_UDP)
		socktype = SOCK_DGRAM;
	else if (protocol == IPPROTO_DCCP)
		socktype = SOCK_DCCP;
	/* If success, the protocol is registered */
	if (sock_create_kern(sa->sa_family, socktype, protocol, &so) == 0) {
		found = 1;
		sock_release(so); /* don't need anymore */
	}

	if (!found) /* the protosw is not registered */
		return 0;

	/*
	 * Walking through PCBs in Linux is not trivial.
	 * We thus search in open files of the process.
	 */
	files = current->files;
	files_table = files_fdtable(files);
	for (i = 0, found = 0; files_table->fd[i] != NULL; i++) {
		struct inet_sock *isk;
		int err;
		
		so = sock_from_file(files_table->fd[i], &err);
		if (!so)
			continue;
		else if (so->sk->sk_protocol != protocol)
			continue;

		isk = inet_sk(so->sk);
		if (sa->sa_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)sa;

			if (isk->inet_sport != sin->sin_port)
				continue;
			if (isk->inet_rcv_saddr == 0 ||
			    isk->inet_rcv_saddr == sin->sin_addr.s_addr) {
				found = 1;
				break;
			}
		}
#ifdef CONFIG_IPV6
		else if (sa->sa_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

			if (isk->inet_sport != sin6->sin6_port)
				continue;
			if (ipv6_addr_any(&so->sk->sk_v6_rcv_saddr) ||
			    ipv6_addr_equal(&so->sk->sk_v6_rcv_saddr,
			    &sin6->sin6_addr)) {
				found = 1;
				break;
			}
		}
#endif
		if (found)
			break;
	}
	return found ? 0 : ENOENT;
}

static int linux_ms_init(void)
{
	return -ms_init();
}

static void linux_ms_fini(void)
{
	ms_fini();
}

module_init(linux_ms_init);
module_exit(linux_ms_fini);
MODULE_AUTHOR("Michio Honda");
MODULE_DESCRIPTION("MultiStack: isolated user-space stack support");
MODULE_LICENSE("Dual BSD/GPL");
