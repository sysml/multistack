/*
 * (C) 2012 Luigi Rizzo - Universita` di Pisa
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
 * glue code to build the netmap bsd code under linux.
 * Some of these tweaks are generic, some are specific for
 * character device drivers and network code/device drivers.
 */

#ifndef _BSD_GLUE_H
#define _BSD_GLUE_H

/* a set of headers used in netmap */
#include <linux/version.h>
#include <linux/if.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/miscdevice.h>
//#include <linux/log2.h>	// ilog2
#include <linux/etherdevice.h>	// eth_type_trans
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/virtio.h>	// virt_to_phys
#include <linux/ipv6.h>
#include <net/ipv6.h>

#define printf(fmt, arg...)	printk(KERN_ERR fmt, ##arg)
#define KASSERT(a, b)		BUG_ON(!(a))

/* Type redefinitions. XXX check them */
typedef	void *			bus_dma_tag_t;
typedef	void *			bus_dmamap_t;
typedef	int			bus_size_t;
typedef	int			bus_dma_segment_t;
typedef void *			bus_addr_t;
#define vm_paddr_t		phys_addr_t
/* XXX the 'off_t' on Linux corresponds to a 'long' */
#define vm_offset_t		uint32_t
struct thread;

/* endianness macros/functions */
#define le16toh			le16_to_cpu
#define le32toh			le32_to_cpu
#define le64toh			le64_to_cpu
#define be64toh			be64_to_cpu
#define htole32			cpu_to_le32
#define htole64			cpu_to_le64

#define bzero(a, len)		memset(a, 0, len)
#define bcopy(_s, _d, len)	memcpy(_d, _s, len)


// XXX maybe implement it as a proper function somewhere
// it is important to set s->len before the copy.
#define	m_devget(_buf, _len, _ofs, _dev, _fn)	( {		\
	struct sk_buff *s = netdev_alloc_skb(_dev, _len);	\
	if (s) {						\
		s->len += _len;					\
		skb_copy_to_linear_data_offset(s, _ofs, _buf, _len);	\
		s->protocol = eth_type_trans(s, _dev);		\
	}							\
	s; } )

#define	mbuf			sk_buff
#define	m_nextpkt		next			// chain of mbufs
#define m_freem(m)		dev_kfree_skb_any(m)	// free a sk_buff

/*
 * m_copydata() copies from mbuf to buffer following the mbuf chain.
 * XXX check which linux equivalent we should use to follow fragmented
 * skbufs.
 */

//#define m_copydata(m, o, l, b)	skb_copy_bits(m, o, b, l)
#define m_copydata(m, o, l, b)	skb_copy_from_linear_data_offset(m, o, b, l)

/*
 * struct ifnet is remapped into struct net_device on linux.
 * ifnet has an if_softc field pointing to the device-specific struct
 * (adapter).
 * On linux the ifnet/net_device is at the beginning of the device-specific
 * structure, so a pointer to the first field of the ifnet works.
 * We don't use this in netmap, though.
 *
 *	if_xname	name		device name
 *	if_capabilities	flags		// XXX not used
 *	if_capenable	priv_flags
 *		we would use "features" but it is all taken.
 *		XXX check for conflict in flags use.
 *
 *	if_bridge	atalk_ptr	struct nm_bridge (only for VALE ports)
 *
 * In netmap we use if_pspare[0] to point to the netmap_adapter,
 * in linux we have no spares so we overload ax25_ptr, and the detection
 * for netmap-capable is some magic in the area pointed by that.
 */
#define WNA(_ifp)		(_ifp)->ax25_ptr

#define ifnet			net_device      /* remap */
#define	if_xname		name		/* field ifnet-> net_device */
//#define	if_capabilities		flags		/* IFCAP_NETMAP */
#define	if_capenable		priv_flags	/* IFCAP_NETMAP */
#define	if_bridge		atalk_ptr	/* remap, only for VALE ports */
#define ifunit_ref(_x)		dev_get_by_name(&init_net, _x);
#define if_rele(ifp)		dev_put(ifp)
#define CURVNET_SET(x)
#define CURVNET_RESTORE(x)


/*
 * XXX Unclear whether we should use spin_lock_irq or spin_lock_bh.
 * I think the former is better as we may use the lock in the interrupt.
 */
//#define mtx			mutex      /* remap */
#define mtx_lock		spin_lock_irq
#define mtx_unlock		spin_unlock_irq
#define mtx_init(a, b, c, d)	spin_lock_init(a)
#define mtx_destroy(a)		// XXX spin_lock_destroy(a)
#define mtx_trylock(a)		spin_trylock(a)

/* use volatile to fix a probable compiler error on 2.6.25 */
#define malloc(_size, type, flags)                      \
        ({ volatile int _v = _size; kmalloc(_v, GFP_ATOMIC | __GFP_ZERO); })

#define free(a, t)	kfree(a)

// XXX do we need GPF_ZERO ?
// XXX do we need GFP_DMA for slots ?
// http://www.mjmwired.net/kernel/Documentation/DMA-API.txt

#define contigmalloc(sz, ty, flags, a, b, pgsz, c)		\
	(char *) __get_free_pages(GFP_KERNEL |  __GFP_ZERO,	\
		    ilog2(roundup_pow_of_two((sz)/PAGE_SIZE)))
#define contigfree(va, sz, ty)	free_pages((unsigned long)va,	\
		    ilog2(roundup_pow_of_two(sz)/PAGE_SIZE))

#define vtophys		virt_to_phys

/*--- selrecord and friends ---*/
/* wake_up() or wake_up_interruptible() ? */
#define	selwakeuppri(sw, pri)	wake_up(sw)
#define selrecord(x, y)		poll_wait((struct file *)x, y, pwait)
#define knlist_destroy(x)	// XXX todo

/* we use tsleep/wakeup to sleep a bit. */
#define	tsleep(a, b, c, t)	msleep(10)	// XXX
#define	wakeup(sw)				// XXX double check
#define microtime		do_gettimeofday


/*
 * The following trick is to map a struct cdev into a struct miscdevice
 */
#define	cdev			miscdevice


/*
 * XXX to complete - the dmamap interface
 */
#define	BUS_DMA_NOWAIT	0
#define	bus_dmamap_load(_1, _2, _3, _4, _5, _6, _7)
#define	bus_dmamap_unload(_1, _2)

typedef int (d_mmap_t)(struct file *f, struct vm_area_struct *vma);
typedef unsigned int (d_poll_t)(struct file * file, struct poll_table_struct *pwait);

/*
 * make_dev will set an error and return the first argument.
 * This relies on the availability of the 'error' local variable.
 */
#define make_dev(_cdev, _zero, _uid, _gid, _perm, _name)	\
	({error = misc_register(_cdev); _cdev; } )
#define destroy_dev(_cdev)	misc_deregister(_cdev)

/*--- sysctl API ----*/
/*
 * linux: sysctl are mapped into /sys/module/ipfw_mod parameters
 * windows: they are emulated via get/setsockopt
 */
#define CTLFLAG_RD              1
#define CTLFLAG_RW              2

struct sysctl_oid;
struct sysctl_req;


#define SYSCTL_DECL(_1)
#define SYSCTL_OID(_1, _2, _3, _4, _5, _6, _7, _8)
#define SYSCTL_NODE(_1, _2, _3, _4, _5, _6)
#define _SYSCTL_BASE(_name, _var, _ty, _perm)			\
		module_param_named(_name, *(_var), _ty,         \
			( (_perm) == CTLFLAG_RD) ? 0444: 0644 )

#define SYSCTL_PROC(_base, _oid, _name, _mode, _var, _val, _desc, _a, _b)

#define SYSCTL_INT(_base, _oid, _name, _mode, _var, _val, _desc)        \
        _SYSCTL_BASE(_name, _var, int, _mode)

#define SYSCTL_LONG(_base, _oid, _name, _mode, _var, _val, _desc)       \
        _SYSCTL_BASE(_name, _var, long, _mode)

#define SYSCTL_ULONG(_base, _oid, _name, _mode, _var, _val, _desc)      \
        _SYSCTL_BASE(_name, _var, ulong, _mode)

#define SYSCTL_UINT(_base, _oid, _name, _mode, _var, _val, _desc)       \
         _SYSCTL_BASE(_name, _var, uint, _mode)

#define TUNABLE_INT(_name, _ptr)

#define SYSCTL_VNET_PROC                SYSCTL_PROC
#define SYSCTL_VNET_INT                 SYSCTL_INT

#define SYSCTL_HANDLER_ARGS             \
        struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req
int sysctl_handle_int(SYSCTL_HANDLER_ARGS);
int sysctl_handle_long(SYSCTL_HANDLER_ARGS);

/*
 * List declarations.
 */
#define TRASHIT(x)
/* LIST_HEAD conflicts with Linux's one, so skip it */
#define	LIST_ENTRY(type)						\
struct {								\
	struct type *le_next;	/* next element */			\
	struct type **le_prev;	/* address of previous next element */	\
}

#define	QMD_LIST_CHECK_HEAD(head, field) do {				\
	if (LIST_FIRST((head)) != NULL &&				\
	    LIST_FIRST((head))->field.le_prev !=			\
	     &LIST_FIRST((head)))					\
		panic("Bad list head %p first->prev != head", (head));	\
} while (0)

#define	QMD_LIST_CHECK_NEXT(elm, field) do {				\
	if (LIST_NEXT((elm), field) != NULL &&				\
	    LIST_NEXT((elm), field)->field.le_prev !=			\
	     &((elm)->field.le_next))					\
		panic("Bad link elm %p next->prev != elm", (elm));	\
} while (0)

#define	QMD_LIST_CHECK_PREV(elm, field) do {				\
	if (*(elm)->field.le_prev != (elm))				\
		panic("Bad link elm %p prev->next != elm", (elm));	\
} while (0)

#define	LIST_EMPTY(head)	((head)->lh_first == NULL)

#define	LIST_FIRST(head)	((head)->lh_first)

#define	LIST_FOREACH(var, head, field)					\
	for ((var) = LIST_FIRST((head));				\
	    (var);							\
	    (var) = LIST_NEXT((var), field))

#define	LIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = LIST_FIRST((head));				\
	    (var) && ((tvar) = LIST_NEXT((var), field), 1);		\
	    (var) = (tvar))

#define	LIST_INIT(head) do {						\
	LIST_FIRST((head)) = NULL;					\
} while (0)

#define	LIST_INSERT_HEAD(head, elm, field) do {				\
	QMD_LIST_CHECK_HEAD((head), field);				\
	if ((LIST_NEXT((elm), field) = LIST_FIRST((head))) != NULL)	\
		LIST_FIRST((head))->field.le_prev = &LIST_NEXT((elm), field);\
	LIST_FIRST((head)) = (elm);					\
	(elm)->field.le_prev = &LIST_FIRST((head));			\
} while (0)

#define LIST_NEXT(elm, field)   ((elm)->field.le_next)

#define	LIST_REMOVE(elm, field) do {					\
	QMD_LIST_CHECK_NEXT(elm, field);				\
	QMD_LIST_CHECK_PREV(elm, field);				\
	if (LIST_NEXT((elm), field) != NULL)				\
		LIST_NEXT((elm), field)->field.le_prev =		\
		    (elm)->field.le_prev;				\
	*(elm)->field.le_prev = LIST_NEXT((elm), field);		\
	TRASHIT((elm)->field.le_next);					\
	TRASHIT((elm)->field.le_prev);					\
} while (0)

/*
 * Tail queue declarations.
 */
#define	QMD_TRACE_ELEM(elem)
#define	QMD_TRACE_HEAD(head)
#define	TRACEBUF
#define	TAILQ_HEAD(name, type)						\
struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type **tqh_last;	/* addr of last next element */		\
	TRACEBUF							\
}

#define	TAILQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).tqh_first }

#define	TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
	TRACEBUF							\
}

/*
 * Tail queue functions.
 */
#define	TAILQ_CONCAT(head1, head2, field) do {				\
	if (!TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->field.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		TAILQ_INIT((head2));					\
		QMD_TRACE_HEAD(head1);					\
		QMD_TRACE_HEAD(head2);					\
	}								\
} while (0)

#define	TAILQ_EMPTY(head)	((head)->tqh_first == NULL)

#define	TAILQ_FIRST(head)	((head)->tqh_first)

#define	TAILQ_FOREACH(var, head, field)					\
	for ((var) = TAILQ_FIRST((head));				\
	    (var);							\
	    (var) = TAILQ_NEXT((var), field))

#define	TAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = TAILQ_FIRST((head));				\
	    (var) && ((tvar) = TAILQ_NEXT((var), field), 1);		\
	    (var) = (tvar))

#define	TAILQ_FOREACH_REVERSE(var, head, headname, field)		\
	for ((var) = TAILQ_LAST((head), headname);			\
	    (var);							\
	    (var) = TAILQ_PREV((var), headname, field))

#define	TAILQ_FOREACH_REVERSE_SAFE(var, head, headname, field, tvar)	\
	for ((var) = TAILQ_LAST((head), headname);			\
	    (var) && ((tvar) = TAILQ_PREV((var), headname, field), 1);	\
	    (var) = (tvar))

#define	TAILQ_INIT(head) do {						\
	TAILQ_FIRST((head)) = NULL;					\
	(head)->tqh_last = &TAILQ_FIRST((head));			\
	QMD_TRACE_HEAD(head);						\
} while (0)

#define	TAILQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if ((TAILQ_NEXT((elm), field) = TAILQ_NEXT((listelm), field)) != NULL)\
		TAILQ_NEXT((elm), field)->field.tqe_prev =		\
		    &TAILQ_NEXT((elm), field);				\
	else {								\
		(head)->tqh_last = &TAILQ_NEXT((elm), field);		\
		QMD_TRACE_HEAD(head);					\
	}								\
	TAILQ_NEXT((listelm), field) = (elm);				\
	(elm)->field.tqe_prev = &TAILQ_NEXT((listelm), field);		\
	QMD_TRACE_ELEM(&(elm)->field);					\
	QMD_TRACE_ELEM(&listelm->field);				\
} while (0)

#define	TAILQ_INSERT_BEFORE(listelm, elm, field) do {			\
	(elm)->field.tqe_prev = (listelm)->field.tqe_prev;		\
	TAILQ_NEXT((elm), field) = (listelm);				\
	*(listelm)->field.tqe_prev = (elm);				\
	(listelm)->field.tqe_prev = &TAILQ_NEXT((elm), field);		\
	QMD_TRACE_ELEM(&(elm)->field);					\
	QMD_TRACE_ELEM(&listelm->field);				\
} while (0)

#define	TAILQ_INSERT_HEAD(head, elm, field) do {			\
	if ((TAILQ_NEXT((elm), field) = TAILQ_FIRST((head))) != NULL)	\
		TAILQ_FIRST((head))->field.tqe_prev =			\
		    &TAILQ_NEXT((elm), field);				\
	else								\
		(head)->tqh_last = &TAILQ_NEXT((elm), field);		\
	TAILQ_FIRST((head)) = (elm);					\
	(elm)->field.tqe_prev = &TAILQ_FIRST((head));			\
	QMD_TRACE_HEAD(head);						\
	QMD_TRACE_ELEM(&(elm)->field);					\
} while (0)

#define	TAILQ_INSERT_TAIL(head, elm, field) do {			\
	TAILQ_NEXT((elm), field) = NULL;				\
	(elm)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (elm);					\
	(head)->tqh_last = &TAILQ_NEXT((elm), field);			\
	QMD_TRACE_HEAD(head);						\
	QMD_TRACE_ELEM(&(elm)->field);					\
} while (0)

#define	TAILQ_LAST(head, headname)					\
	(*(((struct headname *)((head)->tqh_last))->tqh_last))

#define	TAILQ_NEXT(elm, field) ((elm)->field.tqe_next)

#define	TAILQ_PREV(elm, headname, field)				\
	(*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))

#define	TAILQ_REMOVE(head, elm, field) do {				\
	if ((TAILQ_NEXT((elm), field)) != NULL)				\
		TAILQ_NEXT((elm), field)->field.tqe_prev =		\
		    (elm)->field.tqe_prev;				\
	else {								\
		(head)->tqh_last = (elm)->field.tqe_prev;		\
		QMD_TRACE_HEAD(head);					\
	}								\
	*(elm)->field.tqe_prev = TAILQ_NEXT((elm), field);		\
	TRASHIT((elm)->field.tqe_next);					\
	TRASHIT((elm)->field.tqe_prev);					\
	QMD_TRACE_ELEM(&(elm)->field);					\
} while (0)

#define TAILQ_SWAP(head1, head2, type, field) do {                      \
	struct type *swap_first = (head1)->tqh_first;                   \
	struct type **swap_last = (head1)->tqh_last;                    \
	(head1)->tqh_first = (head2)->tqh_first;                        \
	(head1)->tqh_last = (head2)->tqh_last;                          \
	(head2)->tqh_first = swap_first;                                \
	(head2)->tqh_last = swap_last;                                  \
	if ((swap_first = (head1)->tqh_first) != NULL)                  \
		swap_first->field.tqe_prev = &(head1)->tqh_first;       \
	else                                                            \
		(head1)->tqh_last = &(head1)->tqh_first;                \
	if ((swap_first = (head2)->tqh_first) != NULL)                  \
		swap_first->field.tqe_prev = &(head2)->tqh_first;       \
	else                                                            \
		(head2)->tqh_last = &(head2)->tqh_first;                \
} while (0)

/*
 * Singly-linked Tail queue declarations.
 */
#define	STAILQ_HEAD(name, type)						\
struct name {								\
	struct type *stqh_first;/* first element */			\
	struct type **stqh_last;/* addr of last next element */		\
}

#define	STAILQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).stqh_first }

#define	STAILQ_ENTRY(type)						\
struct {								\
	struct type *stqe_next;	/* next element */			\
}
/*
 * Singly-linked Tail queue functions.
 */
#define	STAILQ_CONCAT(head1, head2) do {				\
	if (!STAILQ_EMPTY((head2))) {					\
		*(head1)->stqh_last = (head2)->stqh_first;		\
		(head1)->stqh_last = (head2)->stqh_last;		\
		STAILQ_INIT((head2));					\
	}								\
} while (0)

#define	STAILQ_EMPTY(head)	((head)->stqh_first == NULL)

#define	STAILQ_FIRST(head)	((head)->stqh_first)

#define	STAILQ_FOREACH(var, head, field)				\
	for((var) = STAILQ_FIRST((head));				\
	   (var);							\
	   (var) = STAILQ_NEXT((var), field))


#define	STAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = STAILQ_FIRST((head));				\
	    (var) && ((tvar) = STAILQ_NEXT((var), field), 1);		\
	    (var) = (tvar))

#define	STAILQ_INIT(head) do {						\
	STAILQ_FIRST((head)) = NULL;					\
	(head)->stqh_last = &STAILQ_FIRST((head));			\
} while (0)

#define	STAILQ_INSERT_AFTER(head, tqelm, elm, field) do {		\
	if ((STAILQ_NEXT((elm), field) = STAILQ_NEXT((tqelm), field)) == NULL)\
		(head)->stqh_last = &STAILQ_NEXT((elm), field);		\
	STAILQ_NEXT((tqelm), field) = (elm);				\
} while (0)

#define	STAILQ_INSERT_HEAD(head, elm, field) do {			\
	if ((STAILQ_NEXT((elm), field) = STAILQ_FIRST((head))) == NULL)	\
		(head)->stqh_last = &STAILQ_NEXT((elm), field);		\
	STAILQ_FIRST((head)) = (elm);					\
} while (0)

#define	STAILQ_INSERT_TAIL(head, elm, field) do {			\
	STAILQ_NEXT((elm), field) = NULL;				\
	*(head)->stqh_last = (elm);					\
	(head)->stqh_last = &STAILQ_NEXT((elm), field);			\
} while (0)

#define	STAILQ_LAST(head, type, field)					\
	(STAILQ_EMPTY((head)) ?						\
		NULL :							\
	        ((struct type *)(void *)				\
		((char *)((head)->stqh_last) - __offsetof(struct type, field))))

#define	STAILQ_NEXT(elm, field)	((elm)->field.stqe_next)

#define	STAILQ_REMOVE(head, elm, type, field) do {			\
	if (STAILQ_FIRST((head)) == (elm)) {				\
		STAILQ_REMOVE_HEAD((head), field);			\
	}								\
	else {								\
		struct type *curelm = STAILQ_FIRST((head));		\
		while (STAILQ_NEXT(curelm, field) != (elm))		\
			curelm = STAILQ_NEXT(curelm, field);		\
		STAILQ_REMOVE_AFTER(head, curelm, field);		\
	}								\
	TRASHIT((elm)->field.stqe_next);				\
} while (0)

#define	STAILQ_REMOVE_HEAD(head, field) do {				\
	if ((STAILQ_FIRST((head)) =					\
	     STAILQ_NEXT(STAILQ_FIRST((head)), field)) == NULL)		\
		(head)->stqh_last = &STAILQ_FIRST((head));		\
} while (0)

#define STAILQ_REMOVE_HEAD_UNTIL(head, elm, field) do {                 \
       if ((STAILQ_FIRST((head)) = STAILQ_NEXT((elm), field)) == NULL) \
               (head)->stqh_last = &STAILQ_FIRST((head));              \
} while (0)

#define STAILQ_REMOVE_AFTER(head, elm, field) do {			\
	if ((STAILQ_NEXT(elm, field) =					\
	     STAILQ_NEXT(STAILQ_NEXT(elm, field), field)) == NULL)	\
		(head)->stqh_last = &STAILQ_NEXT((elm), field);		\
} while (0)

#define STAILQ_SWAP(head1, head2, type) do {				\
	struct type *swap_first = STAILQ_FIRST(head1);			\
	struct type **swap_last = (head1)->stqh_last;			\
	STAILQ_FIRST(head1) = STAILQ_FIRST(head2);			\
	(head1)->stqh_last = (head2)->stqh_last;			\
	STAILQ_FIRST(head2) = swap_first;				\
	(head2)->stqh_last = swap_last;					\
	if (STAILQ_EMPTY(head1))					\
		(head1)->stqh_last = &STAILQ_FIRST(head1);		\
	if (STAILQ_EMPTY(head2))					\
		(head2)->stqh_last = &STAILQ_FIRST(head2);		\
} while (0)

#define atomic_add_int(addr, val)       atomic_add(val, (atomic_t *)addr)
#define atomic_subtract_int(addr, val) atomic_sub(val, (atomic_t *)addr)
#define atomic_fetchadd_int(addr, val) (atomic_add_return(val, (atomic_t *)addr) - val)

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

#define ip6_vfc         ip6_ctlun.ip6_un2_vfc
#define ip6_flow        ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen        ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt         ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim        ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops        ip6_ctlun.ip6_un1.ip6_un1_hlim

char *
ip6_sprintf(char *ip6buf, const struct in6_addr *addr)
{
        char digits[] = "0123456789abcdef";
        int i;
        char *cp;
        const u_int16_t *a = (const u_int16_t *)addr;
        const u_int8_t *d;
        int dcolon = 0, zero = 0;

        cp = ip6buf;

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
                        if (dcolon == 0 && *(a + 1) == 0) {
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

#endif /* _BSD_GLUE_H */
