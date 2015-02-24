/*
 * Copyright (C) 2012 Gaetano Catalli, Luigi Rizzo. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * BSD Copyright
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
 * $Id: if_e1000e_netmap.h 10670 2012-02-27 21:15:38Z luigi $
 *
 * netmap support for e1000e (em)
 * For details on netmap support please see ixgbe_netmap.h
 *
 * The driver supports 1 TX and 1 RX ring. Single lock.
 * tx buffer address only written on change.
 * Advanced descriptors ? Rx Crc stripping ?
 */


#include <bsd_glue.h>
#include <net/netmap.h>
#include <netmap/netmap_kern.h>
#define SOFTC_T	e1000_adapter


/*
 * Register/unregister, similar to e1000_reinit_safe()
 */
static int
e1000_netmap_reg(struct ifnet *ifp, int onoff)
{
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct netmap_adapter *na = NA(ifp);
	int error = 0;

	if (na == NULL)
		return EINVAL;

	if (!(ifp->flags & IFF_UP)) {
		/* e1000_open has not been called yet, so resources
		 * are not allocated */
		D("Interface is down!");
		return EINVAL;
	}

	while (test_and_set_bit(__E1000_RESETTING, &adapter->state))
		msleep(1);

	//rtnl_lock(); // XXX do we need it ?
	e1000e_down(adapter);

	if (onoff) { /* enable netmap mode */
		ifp->if_capenable |= IFCAP_NETMAP;
		na->if_transmit = (void *)ifp->netdev_ops;
		ifp->netdev_ops = &na->nm_ndo;
	} else {
		ifp->if_capenable &= ~IFCAP_NETMAP;
		ifp->netdev_ops = (void *)na->if_transmit;
	}

	e1000e_up(adapter);
	//rtnl_unlock(); // XXX do we need it ?
	clear_bit(__E1000_RESETTING, &adapter->state);
	return (error);
}


/*
 * Reconcile kernel and user view of the transmit ring.
 */
static int
e1000_netmap_txsync(struct ifnet *ifp, u_int ring_nr, int do_lock)
{
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct e1000_ring* txr = &adapter->tx_ring[ring_nr];
	struct netmap_adapter *na = NA(ifp);
	struct netmap_kring *kring = &na->tx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, k, l, n = 0, lim = kring->nkr_num_slots - 1;

	/* generate an interrupt approximately every half ring */
	int report_frequency = kring->nkr_num_slots >> 1;

	/* take a copy of ring->cur now, and never read it again */
	k = ring->cur;
	if (k > lim)
		return netmap_ring_reinit(kring);

	if (do_lock)
		mtx_lock(&kring->q_lock);
	rmb();
	/*
	 * Process new packets to send. j is the current index in the
	 * netmap ring, l is the corresponding index in the NIC ring.
	 */
	j = kring->nr_hwcur;
	if (j != k) {	/* we have new packets to send */
		l = netmap_idx_k2n(kring, j);
		for (n = 0; j != k; n++) {
			/* slot is the current slot in the netmap ring */
			struct netmap_slot *slot = &ring->slot[j];
			/* curr is the current slot in the nic ring */
			struct e1000_tx_desc *curr = E1000_TX_DESC(*txr, l);
			int flags = ((slot->flags & NS_REPORT) ||
				j == 0 || j == report_frequency) ?
					E1000_TXD_CMD_RS : 0;
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);
			u_int len = slot->len;

			if (addr == netmap_buffer_base || len > NETMAP_BUF_SIZE) {
				if (do_lock)
					mtx_unlock(&kring->q_lock);
				return netmap_ring_reinit(kring);
			}

			slot->flags &= ~NS_REPORT;
			if (slot->flags & NS_BUF_CHANGED) {
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr)
				curr->buffer_addr = htole64(paddr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->upper.data = 0;
			curr->lower.data = htole32(adapter->txd_cmd | len |
					(E1000_TXD_CMD_EOP | flags) );
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		kring->nr_hwcur = k; /* the saved ring->cur */
		kring->nr_hwavail -= n;

		wmb(); /* synchronize writes to the NIC ring */

		txr->next_to_use = l;
		writel(l, adapter->hw.hw_addr + txr->tail);
		mmiowb(); // XXX where do we need this ?
	}

	if (n == 0 || kring->nr_hwavail < 1) {
		int delta;

		/* record completed transmissions using TDH */
		l = readl(adapter->hw.hw_addr + txr->head);
		if (l >= kring->nkr_num_slots) { /* XXX can it happen ? */
			D("TDH wrap %d", l);
			l -= kring->nkr_num_slots;
		}
		delta = l - txr->next_to_clean;
		if (delta) {
			/* some tx completed, increment hwavail. */
			if (delta < 0)
				delta += kring->nkr_num_slots;
			txr->next_to_clean = l;
			kring->nr_hwavail += delta;
		}
	}
	/* update avail to what the kernel knows */
	ring->avail = kring->nr_hwavail;

	if (do_lock)
		mtx_unlock(&kring->q_lock);
	return 0;
}


/*
 * Reconcile kernel and user view of the receive ring.
 */
static int
e1000_netmap_rxsync(struct ifnet *ifp, u_int ring_nr, int do_lock)
{
	struct SOFTC_T *adapter = netdev_priv(ifp);
	struct netmap_adapter *na = NA(ifp);
	struct e1000_ring *rxr = &adapter->rx_ring[ring_nr];
	struct netmap_kring *kring = &na->rx_rings[ring_nr];
	struct netmap_ring *ring = kring->ring;
	u_int j, l, n, lim = kring->nkr_num_slots - 1;
	int force_update = do_lock || kring->nr_kflags & NKR_PENDINTR;
	int strip_crc = (adapter->flags2 & FLAG2_CRC_STRIPPING) ? 0 : 4;
	u_int k = ring->cur, resvd = ring->reserved;

	if (k > lim)
		return netmap_ring_reinit(kring);

	if (do_lock)
		mtx_lock(&kring->q_lock);
	rmb();
	/*
	 * Import newly received packets into the netmap ring.
	 * j is an index in the netmap ring, l in the NIC ring.
	 */
	l = rxr->next_to_clean;
	j = netmap_idx_n2k(kring, l);
	if (netmap_no_pendintr || force_update) {
		for (n = 0; ; n++) {
			struct e1000_rx_desc *curr = E1000_RX_DESC(*rxr, l);
			uint32_t staterr = le32toh(curr->status);

			if ((staterr & E1000_RXD_STAT_DD) == 0)
				break;
			ring->slot[j].len = le16toh(curr->length) - strip_crc;
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		if (n) { /* update the state variables */
			rxr->next_to_clean = l;
			kring->nr_hwavail += n;
		}
		kring->nr_kflags &= ~NKR_PENDINTR;
	}

	/* skip past packets that userspace has released */
	j = kring->nr_hwcur; /* netmap ring index */
	if (resvd > 0) {
		if (resvd + ring->avail >= lim + 1) {
			D("XXX invalid reserve/avail %d %d", resvd, ring->avail);
			ring->reserved = resvd = 0; // XXX panic...
		}
		k = (k >= resvd) ? k - resvd : k + lim + 1 - resvd;
	}
	if (j != k) { /* userspace has released some packets. */
		l = netmap_idx_k2n(kring, j); /* NIC ring index */
		for (n = 0; j != k; n++) {
			struct netmap_slot *slot = &ring->slot[j];
			struct e1000_rx_desc *curr = E1000_RX_DESC(*rxr, j);
			uint64_t paddr;
			void *addr = PNMB(slot, &paddr);

			if (addr == netmap_buffer_base) { /* bad buf */
				if (do_lock)
					mtx_unlock(&kring->q_lock);
				return netmap_ring_reinit(kring);
			}
			if (slot->flags & NS_BUF_CHANGED) {
				// netmap_reload_map(pdev, DMA_TO_DEVICE, old_paddr, addr)
				curr->buffer_addr = htole64(paddr);
				slot->flags &= ~NS_BUF_CHANGED;
			}
			curr->status = 0;
			j = (j == lim) ? 0 : j + 1;
			l = (l == lim) ? 0 : l + 1;
		}
		kring->nr_hwavail -= n;
		kring->nr_hwcur = k;
		wmb();
		rxr->next_to_use = l; // XXX not really used
		/*
		 * IMPORTANT: we must leave one free slot in the ring,
		 * so move l back by one unit
		 */
		l = (l == 0) ? lim : l - 1;
		writel(l, adapter->hw.hw_addr + rxr->tail);
	}
	/* tell userspace that there are new packets */
	ring->avail = kring->nr_hwavail - resvd;

	if (do_lock)
		mtx_unlock(&kring->q_lock);
	return 0;
}


/* diagnostic routine to catch errors */
static void e1000e_no_rx_alloc(struct SOFTC_T *a, int n)
{
	D("e1000->alloc_rx_buf should not be called");
}


/*
 * Make the tx and rx rings point to the netmap buffers.
 */
static int e1000e_netmap_init_buffers(struct SOFTC_T *adapter)
{
	struct ifnet *ifp = adapter->netdev;
	struct netmap_adapter* na = NA(ifp);
	struct netmap_slot* slot;
	struct e1000_ring *rxr = adapter->rx_ring;
	struct e1000_ring *txr = adapter->tx_ring;
	int i, si;
	uint64_t paddr;

	slot = netmap_reset(na, NR_RX, 0, 0);
	if (!slot)
		return 0;	// not in netmap mode

	adapter->alloc_rx_buf = (void*)e1000e_no_rx_alloc;
	for (i = 0; i < rxr->count; i++) {
		// XXX the skb check and cleanup can go away
		struct e1000_buffer *bi = &rxr->buffer_info[i];
		si = netmap_idx_n2k(&na->rx_rings[0], i);
		PNMB(slot + si, &paddr);
		if (bi->skb)
			D("rx buf %d was set", i);
		bi->skb = NULL; // XXX leak if set
		// netmap_load_map(...)
		E1000_RX_DESC(*rxr, i)->buffer_addr = htole64(paddr);
	}
	rxr->next_to_use = 0;
	/* preserve buffers already made available to clients */
	i = rxr->count - 1 - na->rx_rings[0].nr_hwavail;
	wmb();	/* Force memory writes to complete */
	writel(i, adapter->hw.hw_addr + rxr->tail);

	/* now initialize the tx ring */
	slot = netmap_reset(na, NR_TX, 0, 0);
	for (i = 0; i < na->num_tx_desc; i++) {
		si = netmap_idx_n2k(&na->tx_rings[0], i);
		PNMB(slot + si, &paddr);
		// netmap_load_map(...)
		E1000_TX_DESC(*txr, i)->buffer_addr = htole64(paddr);
	}
	return 1;
}


static void
e1000_netmap_attach(struct SOFTC_T *adapter)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = adapter->netdev;
	na.separate_locks = 0;
	na.num_tx_desc = adapter->tx_ring->count;
	na.num_rx_desc = adapter->rx_ring->count;
	na.nm_register = e1000_netmap_reg;
	na.nm_txsync = e1000_netmap_txsync;
	na.nm_rxsync = e1000_netmap_rxsync;
	netmap_attach(&na, 1);
}
/* end of file */
