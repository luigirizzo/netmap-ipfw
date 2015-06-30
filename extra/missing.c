/*
 * $Id$
 *
 * Support to compile the kernel side of ipfw/dummynet in userland.
 * This file contains variables and functions that are not available in
 * userland. It is compiled in a kernel-like environment, so
 * it has _KERNEL defined, together with malloc() and free().
 * They must be redefined here as we build the real thing.
 */

#include "glue.h"	/* normally comes from the command line */
#include "missing.h"	/* normally comes from the command line */
#undef _KERNEL
#include <sys/types.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/time.h>	/* timersub */
#define _KERNEL

#include <sys/types.h>
#include <sys/taskqueue.h>

#include <sys/mbuf.h>
#undef malloc
#undef free

#include <stdlib.h>	// calloc

#include <netinet/in.h>         /* struct sockaddr, route, sockopt... */
#include <netinet/in_systm.h>

#if 0
#define         IF_NAMESIZE     16              /* ip_fw.h */
#define         IFNAMSIZ        IF_NAMESIZE     /* ip_fw.h */
#endif


/*
 * Global bariables in the kernel
 */
int ticks;		/* kernel ticks counter */
int hz = 5000;		/* default clock time */
long tick = 0;	/* XXX is this 100000/hz ? */
int bootverbose = 0;
time_t time_uptime = 0;
struct timeval boottime;

int	max_protohdr = 14 + 4 + 20 + 20; /* mac, vlan, ip, tcp */
int     max_linkhdr;
int     ip_defttl;
u_long  in_ifaddrhmask;                         /* mask for hash table */
struct  in_ifaddrhashhead *in_ifaddrhashtbl;    /* inet addr hash table  */

u_int rt_numfibs = RT_NUMFIBS;

void
module_register_init(const void *foo)
{
	D("start for %p", foo);
}

/* defined as assert */
#include <assert.h>
void
panic(const char *fmt, ...)
{
        assert(1);
}

void
getmicrouptime(struct timeval *tv)
{
	gettimeofday(tv, NULL);
}

/*
 * pfil hook support.
 * We make pfil_head_get return a non-null pointer, which is then ignored
 * in our 'add-hook' routines.
 */
struct pfil_head;
typedef int (pfil_hook_t)
	(void *, struct mbuf **, struct ifnet *, int, struct inpcb *);

struct pfil_head *
pfil_head_get(int proto, u_long flags)
{
	static int dummy;
	D("called");
	return (struct pfil_head *)(void *)&dummy;
}
 
int
pfil_add_hook(pfil_hook_t *func, void *arg, int dir, struct pfil_head *h)
{
	D("called");
	return 0;
}

int
pfil_remove_hook(pfil_hook_t *func, void *arg, int dir, struct pfil_head *h)
{
	D("called");
	return 0;
}

/* from sys/netinet/ip_output.c */
int
ip_output(struct mbuf *m, struct mbuf *opt, struct route *ro, int flags,
    struct ip_moptions *imo, struct inpcb *inp)
{
	D("unimplemented");
	return 0;
}

struct tags_freelist tags_freelist;
int tags_minlen = 64;
int tags_freelist_count = 0;
static int tags_freelist_max = 0;

struct mbuf *mbuf_freelist;

void
m_freem(struct mbuf *m)
{
	struct m_tag *t;

	/* free the m_tag chain */
	while ( (t = SLIST_FIRST(&m->m_pkthdr.tags) ) ) {
		ND("free tag %p", &m->m_pkthdr.tags);
		SLIST_REMOVE_HEAD(&m->m_pkthdr.tags, m_tag_link);
		SLIST_INSERT_HEAD(&tags_freelist, t, m_tag_link);
		tags_freelist_count++;
		if (tags_freelist_count > tags_freelist_max) {
			static int pr=0;
			if ((pr++ % 1000) == 0)
				D("new max %d", tags_freelist_count);
			tags_freelist_max = tags_freelist_count;
		}
	}
	if (m->m_flags & M_STACK) {
		ND("free invalid mbuf %p", m);
		return;
	}
	/* free the mbuf */
	ND("free(m = %p, M_IPFW);", m);
	m->m_next = mbuf_freelist;
	mbuf_freelist = m;
}

/* from net/netisr.c */
int
netisr_dispatch(u_int proto, struct mbuf *m)
{
	if ((int)proto < 0)
		m_freem(m);
	else if (m->__m_callback)
		m->__m_callback(m, proto);
	else
		D("unimplemented proto %d mbuf %p", proto, m);
	return 0;
}

/* define empty body for kernel function */
int
priv_check(struct thread *td, int priv)
{
	/* once connected, always allow */
	ND("called");
	return 0;
}

int
securelevel_ge(struct ucred *cr, int level)
{
	/* we are always secure... */
	ND("called");
	return 0;
}

int
sysctl_handle_int(SYSCTL_HANDLER_ARGS)
{
	int tmp;

	ND("called");
	if (!req || !req->oldptr || req->oldlen != sizeof(int))
		return EINVAL;
	tmp = arg1 ? *(int *)arg1 : arg2;
	bcopy(&tmp, req->oldptr, sizeof(int));
	/* XXX check the SET routine */
	if (req->newptr && arg1)
		bcopy(req->newptr, arg1, sizeof(int));
	return 0;
}

int
sysctl_handle_long(SYSCTL_HANDLER_ARGS)
{
	ND("called");
	sysctl_handle_int(oidp, arg1, arg2, req);
	return 0;
}

void
ether_demux(struct ifnet *ifp, struct mbuf *m)
{
	if (m->__m_callback)
		m->__m_callback(m, 0);
	else
		D("missing callback mbuf %p", m);
	return;
}

int
ether_output_frame(struct ifnet *ifp, struct mbuf *m)
{
	D("incomplete");
	return 0;
}

void
in_rtalloc_ign(struct route *ro, u_long ignflags, u_int fibnum)
{
	D("called");
	return;
}

void
icmp_error(struct mbuf *n, int type, int code, n_long dest, int mtu)
{
	D("called");
	return;
}

void
rtfree(struct rtentry *rt)
{
	D("called");
	return;
}

u_short
in_cksum_skip(struct mbuf *m, int len, int skip)
{
	D("called");
	return 0;
}

u_short
in_cksum_hdr(struct ip *ip)
{
	D("called");
	return 0;
}


struct mbuf *
ip_reass(struct mbuf *clone)
{
	D("called");
	return clone;
}
#ifdef INP_LOCK_ASSERT
#undef INP_LOCK_ASSERT
#define INP_LOCK_ASSERT(a)
#endif

int
jailed(struct ucred *cred)
{
	D("called");
	return 0;
}

/*
* Return 1 if an internet address is for a ``local'' host
* (one to which we have a connection).  If subnetsarelocal
* is true, this includes other subnets of the local net.
* Otherwise, it includes only the directly-connected (sub)nets.
*/
int
in_localaddr(struct in_addr in)
{
	D("called");
	return 1;
}

#if 0
int ipfw_chg_hook(SYSCTL_HANDLER_ARGS)
{
	return 1;
}
#endif

/*
 * Procedures for the callout interface
 *
 * callout_init() initializes a descriptor,
 * callout_reset() starts a timer
 * callout_stop() stops a timer
 *
 * Internally we hold a list of callout entries etc etc.
 */

struct callout_tailq callout_head;

#include <sys/systm.h>
void
callout_init(struct callout *c, int mpsafe)
{
	D("c %p mpsafe %d", c, mpsafe);
	bzero(c, sizeof(*c));
}

int
callout_reset_on(struct callout *c, int due_ticks, void (*func)(void *), void *arg, int p)
{
	return callout_reset(c, due_ticks, func, arg);
}

int
callout_reset(struct callout *c, int due_ticks, void (*func)(void *), void *arg)
{
	struct callout *cur;

	ND("c %p ticks %d f %p(%p)", c, due_ticks, func, arg);
	if (c->c_flags & CALLOUT_ACTIVE) {
		D(" --- callout was already active");
		return -1;
	}
	c->c_time = ticks + due_ticks;	 /* XXX not the original meaning */
	c->c_func = func;
	c->c_arg = arg;
	c->c_flags |= CALLOUT_ACTIVE;
	TAILQ_FOREACH(cur, &callout_head, c_links.tqe) {
		if ( (c->c_time - cur->c_time) < 0)
			break;
	}
	if (cur)
		TAILQ_INSERT_BEFORE(cur, c, c_links.tqe);
	else
		TAILQ_INSERT_TAIL(&callout_head, c, c_links.tqe);
	return 0;	/* no error */
}

int
_callout_stop_safe(struct callout *c, int safe)
{
	D("c %p safe %d", c, safe);
	TAILQ_REMOVE(&callout_head, c, c_links.tqe);
	return 0;
}

int
callout_drain(struct callout *c)
{
	_callout_stop_safe(c, 1);
	return 0;
}

void
callout_startup(void)
{
	D("start");
	TAILQ_INIT( &callout_head);
}

void
callout_run(void)
{
	struct callout *cur, *tmp;

	ND("Run pending callouts tick %d", ticks);
	TAILQ_FOREACH_SAFE(cur, &callout_head, c_links.tqe, tmp) {
		int delta = ticks - cur->c_time;
		if (delta < 0) {	// early ?
			//fprintf(stderr, "c %p due at %d\n", cur, cur->c_time);
			continue;
		}
		if (delta > 100)
			RD(1,"running %p due at %d now %d", cur, cur->c_time, ticks);
		TAILQ_REMOVE(&callout_head, cur, c_links.tqe);
		cur->c_flags &= ~CALLOUT_ACTIVE;
		cur->c_func(cur->c_arg);
	}
}

/*
 * the taskqueue type is actually opaque
 */
struct taskqueue {
        STAILQ_ENTRY(taskqueue) tq_link;
        STAILQ_HEAD(, task)     tq_queue;
        const char              *tq_name;
        taskqueue_enqueue_fn    tq_enqueue;
        void                    *tq_context;
        struct task             *tq_running;
        int                     tq_pcount;
        int                     tq_spin;
        int                     tq_flags;
};

#if 0
/*
 * instead of enqueueing, we run this immediately.
 */
int
taskqueue_enqueue(struct taskqueue *queue, struct task *task)
{
	task->ta_func(task->ta_context, 1);
	return 0;
}
#endif

void
taskqueue_thread_enqueue(void *context)
{
	D("ctx %p", context);
}

struct taskqueue *
taskqueue_create_fast(const char *name, int mflags,
	taskqueue_enqueue_fn enqueue, void *context)
{
	struct taskqueue *tq;

	tq = calloc(1, sizeof(*tq));
	if (tq == NULL)
		return NULL;
	D("start %s fn %p ctx %p", name, enqueue, context);
	return tq;
}

int
taskqueue_start_threads(struct taskqueue **tqp, int count, int pri,
                        const char *name, ...)
{
	D("tqp %p count %d (dummy)", tqp, count);
	return 0;
}

void
taskqueue_drain(struct taskqueue *queue, struct task *task)
{
	D("q %p task %p", queue, task);
}

void
taskqueue_free(struct taskqueue *queue)
{
	D("q %p", queue);
	free(queue);
}

void *
kern_malloc(int sz)
{
	return calloc(sz, 1); /* most of the time we want zeroed memory */
}

void
kern_free(void *p)
{
	free(p);
}

#ifdef linux
size_t
strlcpy(char *dst, const char *src, size_t siz)
{
        char *d = dst;
        const char *s = src;
        size_t n = siz;

        /* Copy as many bytes as will fit */
        if (n != 0 && --n != 0) {
                do {
                        if ((*d++ = *s++) == 0)
                                break;
                } while (--n != 0);
        }

        /* Not enough room in dst, add NUL and traverse rest of src */
        if (n == 0) {
                if (siz != 0)
                        *d = '\0';              /* NUL-terminate dst */
                while (*s++)
                        ;
        }
 
        return(s - src - 1);    /* count does not include NUL */
}
#endif // linux

#ifdef EMULATE_SYSCTL
/*
 * Support for sysctl emulation.
 * We transfer options as part of the IP_DUMMYNET3 sockopt emulation,
 * so we need to include ip_fw.h and ip_dummynet.h
 */

#include <netinet/ip_fw.h>                      /* struct ip_fw_args */
#include <netinet/ip_dummynet.h>		/* struct dn_id */
static struct sysctltable GST;

int
kesysctl_emu_get(struct sockopt* sopt)
{
	struct dn_id* oid = sopt->sopt_val;
	struct sysctlhead* entry;
	int sizeneeded = sizeof(struct dn_id) + GST.totalsize +
		sizeof(struct sysctlhead);
	unsigned char* pstring;
	unsigned char* pdata;
	int i;
	
	if (sopt->sopt_valsize < sizeneeded) {
		// this is a probe to retrieve the space needed for
		// a dump of the sysctl table
		oid->id = sizeneeded;
		sopt->sopt_valsize = sizeof(struct dn_id);
		return 0;
	}
	
	entry = (struct sysctlhead*)(oid+1);
	/* [entry][data(datalen)][name(namelen)] */
	ND("copying values");
	for( i=0; i<GST.count; i++) {
		ND("entry %d %s flags 0x%x",
			i, GST.entry[i].name, GST.entry[i].head.flags);
		entry->blocklen = GST.entry[i].head.blocklen;
		entry->namelen = GST.entry[i].head.namelen;
		entry->flags = GST.entry[i].head.flags;
		entry->datalen = GST.entry[i].head.datalen;
		pdata = (unsigned char*)(entry+1);
		pstring = pdata+GST.entry[i].head.datalen;
		if  (entry->flags & SYSCTLTYPE_PROC) {
			//int (*f)(SYSCTL_HANDLER_ARGS);
			sysctl_h_fn_t *f;
			int tmp = 0, ret;
			struct sysctl_req req;

			bzero(&req, sizeof(req));
			req.oldlen = req.newlen = sizeof(int);
			req.oldptr = &tmp;
			f = GST.entry[i].fn;
			ND("-- %s is a proc -- at %p", GST.entry[i].name, f);
			ret = f(NULL, NULL, (int)(intptr_t)(GST.entry[i].data), &req);
			ND("-- %s returns %d", GST.entry[i].name, ret);
			bcopy(&tmp, pdata, sizeof(tmp));
		} else {
			bcopy(GST.entry[i].data, pdata, GST.entry[i].head.datalen);
		}
		bcopy(GST.entry[i].name, pstring, GST.entry[i].head.namelen);
		entry = (struct sysctlhead*)
			((unsigned char*)(entry) + GST.entry[i].head.blocklen);
	}
	sopt->sopt_valsize = sizeneeded;
	return 0;
}

int
kesysctl_emu_set(void* p, int l)
{
	struct sysctlhead* entry;
	unsigned char* pdata;
	unsigned char* pstring;
	int i = 0;
	
	entry = (struct sysctlhead*)(((struct dn_id*)p)+1);
	pdata = (unsigned char*)(entry+1);
	pstring = pdata + entry->datalen;
	
	for (i=0; i<GST.count; i++) {
		if (strcmp(GST.entry[i].name, (char *)pstring) != 0)
			continue;
		ND("%s: match found! %s\n",__FUNCTION__,pstring);
		//sanity check on len, not really useful now since
		//we only accept int32
		if (entry->datalen != GST.entry[i].head.datalen) {
			printf("%s: len mismatch, user %d vs kernel %d\n",
				__FUNCTION__, entry->datalen,
				GST.entry[i].head.datalen);
			return -1;
		}
		// check access (at the moment flags handles only the R/W rights
		//later on will be type + access
		if( (GST.entry[i].head.flags & 3) == CTLFLAG_RD) {
			printf("%s: the entry %s is read only\n",
				__FUNCTION__,GST.entry[i].name);
			return -1;
		}
		if  (GST.entry[i].head.flags & SYSCTLTYPE_PROC) {
			int (*f)(SYSCTL_HANDLER_ARGS);
			int tmp = 0, ret;
			struct sysctl_req req;

			bzero(&req, sizeof(req));
			req.oldlen = req.newlen = sizeof(int);
			req.oldptr = &tmp;
			req.newptr = pdata;
			f = GST.entry[i].fn;
			ND("-- %s is a proc -- at %p", GST.entry[i].name, f);
			ret = f(NULL, NULL, (int)(intptr_t)(GST.entry[i].data), &req);
			ND("-- %s returns %d", GST.entry[i].name, ret);
		} else {
			bcopy(pdata, GST.entry[i].data, GST.entry[i].head.datalen);
		}
		return 0;
	}
	D("%s: match not found\n",__FUNCTION__);
	return 0;
}

/* convert all _ to . until the first . */
static void
underscoretopoint(char* s)
{
	for (; *s && *s != '.'; s++)
		if (*s == '_')
			*s = '.';
}

static int
formatnames(void)
{
	int i;
	int size=0;
	char* name;

	for (i=0; i<GST.count; i++)
		size += GST.entry[i].head.namelen;
	GST.namebuffer = malloc(size);
	if (GST.namebuffer == NULL)
		return -1;
	name = GST.namebuffer;
	for (i=0; i<GST.count; i++) {
		bcopy(GST.entry[i].name, name, GST.entry[i].head.namelen);
		underscoretopoint(name);
		GST.entry[i].name = name;
		name += GST.entry[i].head.namelen;
	}
	return 0;
}

static void
dumpGST(void)
{
	int i;

	for (i=0; i<GST.count; i++) {
		printf("SYSCTL: entry %i\n", i);
		printf("name %s\n", GST.entry[i].name);
		printf("namelen %i\n", GST.entry[i].head.namelen);
		printf("type %i access %i\n",
			GST.entry[i].head.flags >> 2,
			GST.entry[i].head.flags & 0x00000003);
		printf("data %i\n", *(int*)(GST.entry[i].data));
		printf("datalen %i\n", GST.entry[i].head.datalen);
		printf("blocklen %i\n", GST.entry[i].head.blocklen);
	}
}

void sysctl_addgroup_f1(void);
void sysctl_addgroup_f2(void);
void sysctl_addgroup_f3(void);
void sysctl_addgroup_f4(void);

void
keinit_GST(void)
{
	int ret;

	sysctl_addgroup_f1();
	sysctl_addgroup_f2();
	sysctl_addgroup_f3();
	sysctl_addgroup_f4();
	ret = formatnames();
	if (ret != 0)
		printf("conversion of names failed for some reason\n");
	if (0)
		dumpGST();	// XXX debugging
	printf("*** Global Sysctl Table entries = %i, total size = %i ***\n",
		GST.count, GST.totalsize);
}

void
keexit_GST(void)
{
	if (GST.namebuffer != NULL)
		free(GST.namebuffer);
	bzero(&GST, sizeof(GST));
}

void
sysctl_pushback(char* name, int flags, int datalen, void* data, sysctl_h_fn_t *fn)
{
	if (GST.count >= GST_HARD_LIMIT) {
		printf("WARNING: global sysctl table full, this entry will not be added,"
				"please recompile the module increasing the table size\n");
		return;
	}
	GST.entry[GST.count].head.namelen = strlen(name)+1; //add space for '\0'
	GST.entry[GST.count].name = name;
	GST.entry[GST.count].head.flags = flags;
	GST.entry[GST.count].data = data;
	GST.entry[GST.count].fn = fn;
	GST.entry[GST.count].head.datalen = datalen;
	GST.entry[GST.count].head.blocklen =
		((sizeof(struct sysctlhead) + GST.entry[GST.count].head.namelen +
			GST.entry[GST.count].head.datalen)+3) & ~3;
	GST.totalsize += GST.entry[GST.count].head.blocklen;
	GST.count++;
}
#endif /* EMULATE_SYSCTL */

extern int mainloop(int argc, char *argv[]);

/*
 * main program for ipfw kernel side when running an userspace emulation:
 * open a socket on which we receive requests from userland,
 * another socket for calls from the 'kernel' (simulating packet
 * arrivals etc), and then periodically run the tick handler.
 */
int
main(int argc, char *argv[])
{
	tick = 1000000/hz;
	D("initializing tick to %ld", tick);
	return mainloop(argc, argv);
}
