/*
 * Glue code to implement netmap I/O for the userspace version of ipfw.
 */

#include <sys/types.h>
#ifdef _KERNEL
#undef _KERNEL
#endif
/* these headers need to be compiled without _KERNEL */
//#include <sys/select.h>
//#include <sys/socket.h>
//#define __NetBSD__	// XXX conflict in bpf_filter() between pcap.h and bpf.h
//#include <netinet/in.h>

#ifdef free
/* we are built in a pseudo-kernel env so malloc and free are redefined */
#undef free
#undef malloc
#endif

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

int verbose;

#include <stdio.h>
#include <unistd.h>	/* read() */
#include <errno.h>	/* EINVAL */

#include <sys/malloc.h>	/* M_NOWAIT */
#include <sys/mbuf.h>	/* mbuf */
#include <sys/cpuset.h> // FreeBSD
#include <net/pfil.h>	// PFIL_IN
#define _KERNEL

/* args for ipfw */
#include <netinet/ip_fw.h>
#include <netpfil/ipfw/ip_fw_private.h>

/*
 * A packet comes from either a netmap slot on the source,
 * or from an mbuf that must be freed.
 * slot != NULL means a netmap slot, otherwise use buf.
 * len == 0 means an empty slot.
 */
struct txq_entry {
	void *ring_or_mbuf;
	uint16_t slot_idx;	/* used if ring */
	uint16_t flags;			/* 0 if slot, len if mbuf */
#define	TXQ_IS_SLOT	0xc555
#define	TXQ_IS_MBUF	0xaacd
};

/*
 * the state associated to a netmap port:
 * (goes into the private field of my_ring)
 * XXX have an ifp at the beginning so we can use rcvif to store it.
 */
#define MY_TXQ_LEN	32
struct my_netmap_port {
	struct ifnet ifp;		/* contains if_xname */
	struct nm_desc 	*d;
	struct my_netmap_port *peer;	/* peer port */
	struct sess	*sess;		/* my session */

	u_int		allocator_id;	/* from nmreq.nr_arg2 */
	u_int		can_swap_bufs;	/* compute when peer is known, same allocator_id */
	u_int		cur_txq;	/* next txq slot to use for tx */
	struct txq_entry q[MY_TXQ_LEN];	/* slots are in the peer */
	/* followed by ifname */
};

/*
 * txq[] has a batch of n packets that possibly need to be forwarded.
 */
int
netmap_fwd(struct my_netmap_port *port)
{
	u_int dr; /* destination ring */
	u_int i = 0;
	const u_int n = port->cur_txq;	/* how many queued packets */
	struct txq_entry *x = port->q;
	int retry = 5;	/* max retries */
	struct nm_desc *dst = port->d;

	if (n == 0) {
		D("nothing to forward to %s", port->ifp.if_xname);
		return 0;
	}

 again:
	/* scan all output rings; dr is the destination ring index */
	for (dr = dst->first_tx_ring; i < n && dr <= dst->last_tx_ring; dr++) {
		struct netmap_ring *ring = NETMAP_TXRING(dst->nifp, dr);

		__builtin_prefetch(ring);
		if (nm_ring_empty(ring))
			continue;
		/*
		 * We have different ways to transfer from src->dst
		 *
		 * src	dst	Now		Eventually (not done)
		 *
		 * PHYS	PHYS	buf swap
		 * PHYS VIRT	NS_INDIRECT
		 * VIRT	PHYS	copy		NS_INDIRECT
		 * VIRT	VIRT	NS_INDIRECT
		 * MBUF	PHYS	copy		NS_INDIRECT
		 * MBUF	VIRT	NS_INDIRECT
		 *
		 * The "eventually" depends on implementing NS_INDIRECT
		 * on physical device drivers.
		 * Note we do not yet differentiate PHYS/VIRT.
		 */
		for  (; i < n && !nm_ring_empty(ring); i++) {
			struct netmap_slot *dst, *src;

			dst = &ring->slot[ring->cur];
			if (x[i].flags == TXQ_IS_SLOT) {
				struct netmap_ring *sr = x[i].ring_or_mbuf;

				src = &sr->slot[x[i].slot_idx];
				dst->len = src->len;

				if (port->can_swap_bufs) {
					ND("pkt %d len %d", i, src->len);
					u_int tmp = dst->buf_idx;
					dst->flags = src->flags = NS_BUF_CHANGED;
					dst->buf_idx = src->buf_idx;
					src->buf_idx = tmp;
				} else if (port->peer->allocator_id == 1) { // no indirect
					nm_pkt_copy(NETMAP_BUF(sr, src->buf_idx),
								NETMAP_BUF(ring, dst->buf_idx),
								dst->len);
				} else {
					dst->ptr = (uintptr_t)NETMAP_BUF(sr, src->buf_idx);
					dst->flags = NS_INDIRECT;
				}
			} else if (x[i].flags == TXQ_IS_MBUF) {
				struct mbuf *m = (void *)x[i].ring_or_mbuf;

				ND("copy from mbuf");
				dst->len = m->__m_extlen;
				nm_pkt_copy(m->__m_extbuf,
							NETMAP_BUF(ring, dst->buf_idx),
							dst->len);
				FREE_PKT(m);
			} else {
				panic("bad slot");
			}
			x[i].flags = 0;
			ring->head = ring->cur = nm_ring_next(ring, ring->cur);
		}
	}
	if (i < n) {
		if (retry-- > 0) {
			ioctl(port->d->fd, NIOCTXSYNC);
			goto again;
		}
		RD(1, "%d buffers leftover", n - i);
		for (;i < n; i++) {
			if (x[i].flags == TXQ_IS_MBUF) {
				FREE_PKT(x[i].ring_or_mbuf);
			}
		}
	}
	port->cur_txq = 0;
	return 0;
}

void
netmap_enqueue(struct mbuf *m, int proto)
{
	struct my_netmap_port *peer = m->__m_peer;
	struct txq_entry *x;


	if (peer == NULL) {
		D("error missing peer in %p", m);
		FREE_PKT(m);
	}
	ND(1, "start with %d packets", peer->cur_txq);
	if (peer->cur_txq >= MY_TXQ_LEN)
		netmap_fwd(peer);
	x = peer->q + peer->cur_txq;
	x->ring_or_mbuf = m;
	x->flags = TXQ_IS_MBUF;
	peer->cur_txq++;
	peer->sess->flags |= WANT_RUN;
	ND("end, queued %d on %s", peer->cur_txq, peer->ifname);
}

/*
 * Read packets from a port, invoke the firewall and possibly
 * pass them to the peer.
 * The firewall receives a fake mbuf on the stack that refers
 * to the netmap slot. In this case the mbuf has two extra fields,
 * indicating the original buffer and length (buf = NULL if no need
 * to copy).
 * We also need to pass the pointer to a peer, though we can use ifp for that.
 * If the result is accept, no need to copy
 * and we can just pass the slot to the destination interface.
 * Otherwise, we need to do an explicit copy.

 */
int
netmap_read(struct sess *sess, void *arg)
{
	struct my_netmap_port *port = arg;
	u_int si, hdrlen;
	struct mbuf dm, dm0;
	struct ip_fw_args args;
	struct my_netmap_port *peer = port->peer;
	struct nm_desc *srcp = port->d;

	bzero(&dm0, sizeof(dm0));
	bzero(&args, sizeof(args));

	/* scan all rings */
	for (si = srcp->first_rx_ring; si <= srcp->last_rx_ring; si++) {
	    struct netmap_ring *ring = NETMAP_RXRING(srcp->nifp, si);

	    __builtin_prefetch(ring);
	    if (nm_ring_empty(ring))
		    continue;
	    __builtin_prefetch(&ring->slot[ring->cur]);
	    while (!nm_ring_empty(ring)) {
			u_int src, idx, len;
			struct netmap_slot *slot;
			void *buf;

			/* make sure we have room before looking at the input */
			if (peer->cur_txq >= MY_TXQ_LEN) {
				netmap_fwd(peer);
				continue;
			}
			src = ring->cur;
			slot = &ring->slot[src];
			__builtin_prefetch (slot+1);
			idx = slot->buf_idx;
			buf = (u_char *)NETMAP_BUF(ring, idx);
			if (idx < 2) {
				D("%s bogus RX index at offset %d",
				  srcp->nifp->ni_name, src);
				sleep(2);
			}
			__builtin_prefetch(buf);
			ring->head = ring->cur = nm_ring_next(ring, src);

			/* prepare to invoke the firewall */
			dm = dm0;	// XXX clear all including tags
			args.m = &dm;
			len = slot->len;
			dm.m_flags = M_STACK;
			// remember original buf and peer
			dm.__m_extbuf = buf;
			dm.__m_extlen = len;
			dm.__m_peer = peer;
			/* the routine to call in netisr_dispatch */
			dm.__m_callback = netmap_enqueue;

			/* XXX can we use check_frame ? */
			if (1) { /* L2 */
				hdrlen = 0;
			} else {
				hdrlen = ((uint16_t *)buf)[6] == htons(0x8100) ? 18 : 14;
			}
			dm.m_pkthdr.rcvif = &port->ifp;
			ND(1, "hdrlen %d", hdrlen);
			dm.m_data = buf + hdrlen;	// skip mac + vlan hdr if any
			dm.m_len = dm.m_pkthdr.len = len - hdrlen;
			dm.__max_m_len = dm.m_len;
			ND("slot %d len %d", i, dm.m_len);
			// XXX ipfw_chk is slightly faster
			//ret = ipfw_chk(&args);
			if (hdrlen > 0) {
				ipfw_check_packet(NULL, &args.m, NULL, PFIL_IN, NULL);
			} else {
				ipfw_check_frame(NULL, &args.m, NULL, PFIL_IN, NULL);
			}

			if (args.m != NULL) {	// ok. forward
				/*
				 * XXX TODO remember to clean up any tags that
				 * ipfw may have allocated
				 */
				/*
				 * if peer has been modified, bounce back
				 * to the original
				 */
				struct my_netmap_port *d =
					(dm.__m_peer == peer) ? peer: port;
				u_int dst = d->cur_txq;
				struct txq_entry *x = d->q;
				if (d != peer)
					fprintf(stderr, "packet bounced back\n");
				x[dst].ring_or_mbuf = ring;
				x[dst].slot_idx = src;
				x[dst].flags = TXQ_IS_SLOT;
				d->cur_txq++;
			}
			ND("exit at slot %d", next_i);
	    }
	}
	/* process packets sent to the opposite queue */
	if (peer->cur_txq > 0)
		netmap_fwd(peer);
	if (port->cur_txq > 0) {		// WANT_RUN
		/* any traffic in this direction ? */
		netmap_fwd(port);
	}
	ND("done");
	return 0;
}

/*
 * add a netmap port. We add them in pairs, so forwarding occurs
 * between two of them.
 */
void
netmap_add_port(const char *dev)
{
	static struct sess *s1 = NULL;	// XXX stateful; bad!
	struct my_netmap_port *port;
	int l;
	struct sess *s2;

	D("opening netmap device %s", dev);
	l = strlen(dev) + 1;
	if (l >= IFNAMSIZ) {
		D("name %s too long, max %d", dev, IFNAMSIZ - 1);
		sleep(2);
		return;
	}
	port = calloc(1, sizeof(*port));
	port->d = nm_open(dev, NULL, 0, NULL);
	if (port->d == NULL) {
		D("error opening %s", dev);
		kern_free(port);	// XXX compat
		return;
	}
	strncpy(port->ifp.if_xname, dev, IFNAMSIZ-1);
	port->allocator_id = port->d->req.nr_arg2;
	D("--- mem_id %d", port->allocator_id);
	s2 = new_session(port->d->fd, netmap_read, port, WANT_READ);
	port->sess = s2;
	D("create sess %p my_netmap_port %p", s2, port);
	if (s1 == NULL) {       /* first of a pair */
		s1 = s2;
	} else {                /* second of a pair, cross link */
		struct my_netmap_port *peer = s1->arg;
		port->peer = peer;
		peer->peer = port;

		port->can_swap_bufs = peer->can_swap_bufs =
			(port->allocator_id == peer->allocator_id);
		D("%p %s %d <-> %p %s %d %s",
		  port, port->d->req.nr_name, port->allocator_id,
		  peer, peer->d->req.nr_name, peer->allocator_id,
		  port->can_swap_bufs ? "SWAP" : "COPY");
		s1 = NULL;
	}
}
