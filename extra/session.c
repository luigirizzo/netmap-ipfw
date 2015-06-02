/*
 * Session handler to simulate soopt* and network communication
 * over a TCP socket, and also run the callbacks.
 */

#ifdef _KERNEL
#undef _KERNEL
#endif
/* these headers need to be compiled without _KERNEL */
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>	// TCP_NODELAY
#include <sys/cpuset.h> // freebsd, used in rmlock
#include <net/pfil.h>	// PFIL_IN
#include <sys/errno.h>
extern int errno;


#ifdef free
/* we are built in a pseudo-kernel env so malloc and free are redefined */
#undef free
#undef malloc
#endif /* free */

#include <stdio.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/time.h>	/* timersub */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>	/* read() */

#include <sys/mbuf.h>	/* mbuf */
#define _KERNEL

/* args for ipfw */
#include <netinet/ip_fw.h>
#include <netpfil/ipfw/ip_fw_private.h>

/*
 * Global variables need to be somewhere...
 */
void ip_dn_init(void);
int ipfw_init(void);
void ipfw_destroy(void);

extern int (*ip_fw_ctl_ptr)(struct sockopt *);
extern int (*ip_dn_ctl_ptr)(struct sockopt *);
extern struct ip_fw *ip_fw_default_rule;

extern int ticks;	/* kernel ticks counter */

int callout_startup(void);
int callout_run(void);

/*
 * generic handler for sockopt functions
 */
static int
ctl_handler(struct sockopt *sopt)
{
	int error = EINVAL;

	ND("called, level %d", sopt->sopt_level);
	if (sopt->sopt_level != IPPROTO_IP)
		return (EINVAL);
	switch (sopt->sopt_name) {
	default:
		D("command not recognised %d", sopt->sopt_name);
		break;
	case IP_FW3: // XXX untested
	case IP_FW_ADD: /* ADD actually returns the body... */
	case IP_FW_GET:
	case IP_FW_DEL:
	case IP_FW_TABLE_GETSIZE:
	case IP_FW_TABLE_LIST:
	case IP_FW_NAT_GET_CONFIG:
	case IP_FW_NAT_GET_LOG:
	case IP_FW_FLUSH:
	case IP_FW_ZERO:
	case IP_FW_RESETLOG:
	case IP_FW_TABLE_ADD:
	case IP_FW_TABLE_DEL:
	case IP_FW_TABLE_FLUSH:
	case IP_FW_NAT_CFG:
	case IP_FW_NAT_DEL:
		if (ip_fw_ctl_ptr != NULL)
			error = ip_fw_ctl_ptr(sopt);
		else {
			D("ipfw not enabled");
			error = ENOPROTOOPT;
		}
		break;
			
	case IP_DUMMYNET_GET:
	case IP_DUMMYNET_CONFIGURE:
	case IP_DUMMYNET_DEL:
	case IP_DUMMYNET_FLUSH:
	case IP_DUMMYNET3:
		if (ip_dn_ctl_ptr != NULL)
			error = ip_dn_ctl_ptr(sopt);
		else
			error = ENOPROTOOPT;
		break ;
	}
	ND("returning error %d", error);
	return error;
}

/*
 * copy data back to userland
 */
int
sooptcopyout(struct sockopt *sopt, const void *buf, size_t len)
{
	size_t valsize = sopt->sopt_valsize;

	ND("data len %d sopt_len %d", (int)len, (int)valsize);
	if (len < valsize)
		sopt->sopt_valsize = valsize = len;
	bcopy(buf, sopt->sopt_val, valsize);
	return 0;
}

int
copyout(const void *kaddr, void *uaddr, size_t len)
{
	bcopy(kaddr, uaddr, len);
	return 0; /* no fault */
}

/*
 * copy data from userland to kernel
 */
int
sooptcopyin(struct sockopt *sopt, void *buf, size_t len, size_t minlen)
{
	size_t valsize = sopt->sopt_valsize;

	ND("have %d len %d minlen %d", (int)valsize, (int)len, (int)minlen);
	if (valsize < minlen)
		return EINVAL;
	if (valsize > len)
		sopt->sopt_valsize = valsize = len;
	bcopy(sopt->sopt_val, buf, valsize);
	return 0;
}

/*
 * session description for event-based programming
 */
/* event-based session support */

#define SOCK_QLEN 5     /* listen lenght for incoming connection */

static struct sess *all_sessions, *new_sessions;

struct sess *
new_session(int fd, handler_t *func, void *arg, enum flags_t flags)
{
	struct sess *desc;
	desc = calloc(1, sizeof(*desc));
	if (desc == NULL)
		return NULL;
	desc->fd = fd;
	desc->func = func;
	desc->arg = arg;
	desc->flags = flags;
	desc->next = new_sessions;
	new_sessions = desc;
	return desc;
}

/* remove deleted sessions, merge with new ones */
static void
merge_sessions(void)
{
	struct sess *cur, *prev, *tmp;

	for (prev = NULL, cur = all_sessions; cur; prev = cur, cur = tmp) {
		tmp = cur->next;
		if ( (cur->flags & WANT_DELETE) == 0)
			continue;
		if (prev)
			prev->next = cur->next;
		else
			all_sessions = cur->next;
		memset(cur, 0, sizeof(*cur));
		free(cur);
		cur = prev;
	}
	if (prev)
		prev->next = new_sessions;
	else
		all_sessions = new_sessions;
	new_sessions = NULL;
}

/* set the fdset, return the fdmax+1 for select() */
int
set_sessions(fd_set *r, fd_set *w)
{
	struct sess *cur;
	int fd_max = -1;
	int count = 0,ready = 0;

	FD_ZERO(r);
	FD_ZERO(w);
	merge_sessions();
	for (cur = all_sessions; cur; cur = cur->next) {
		count++;
		if (cur->flags & WANT_RUN) {
			ND("WANT_RUN on session %p", cur);
			cur->flags &= ~WANT_RUN;
			cur->func(cur, cur->arg);
		}
		if (cur->flags & WANT_READ)
			FD_SET(cur->fd, r);
		if (cur->flags & WANT_WRITE)
			FD_SET(cur->fd, w);
		if (cur->flags & (WANT_WRITE|WANT_READ)) {
			ready ++;
			if (cur->fd > fd_max)
				fd_max = cur->fd;
		}
	}
	ND("%d session %d waiting", count, ready);
	return fd_max + 1;
}

int
run_sessions(fd_set *r, fd_set *w)
{
	struct sess *cur;

	for (cur = all_sessions; cur; cur = cur->next) {
		int fd = cur->fd;
		// fprintf(stderr, "%s sess %p\n", __FUNCTION__, cur);
		if (FD_ISSET(fd, r) || FD_ISSET(fd, w))
			cur->func(cur, cur->arg);
	}
	return 0;
}

struct sess_buf {
	int len;	/* allocation length */
	int used;	/* bytes used */
	int start;	/* start position for next write */
	char data[0];
};

struct sess_buf *
get_buf(int size, struct sess_buf *old)
{
	struct sess_buf *p = old;

	if (!p) {
		ND("new buffer size %d", size);
		p = calloc(1, sizeof(*p) + size);
	} else if (p->len >= size) {
		return p;
	} else {
		ND("calling realloc %p %d", old, size);
		p = realloc(old, sizeof(*p) + size);
	}
	if (!p) {
		if (old)
			free(old);
	} else {
		p->len = size;
	}
	return p;
}

/*
 * do a non-blocking read into the buffer, reallocating if space
 * is needed.
 */
static struct sess_buf *
get_data(int fd, struct sess_buf *buf, int want)
{
	int l;

	buf = get_buf(want, buf);
	if (buf == NULL)
		return buf;
	l = read(fd, buf->data + buf->used, want - buf->used);
	if (l > 0)
		buf->used += l;
	return buf;
}

/*
 * Handler for a request coming from the control socket.
 */
enum sockopt_state {
	READING = 0, WRITING = 1
};

struct sockopt_desc {
	int state;	/* internal state */
	struct sess_buf *rd;
	struct sess_buf *wr;
};

/* header prepended to data in all transactions */
struct rx_hdr {
	uint32_t optlen;	/* data len */
	uint32_t level;		/* or error ? */
	uint32_t optname;	/* or desired len ? */
	uint32_t dir;		/* in or out */
};

/*
 * Return the number of remainig bytes from the buffer.
 * The meessage is int optname; [int optlen; int data]
 * where the second part is present or not depending on the
 * message type.
 */
int
get_want(struct sess_buf *rd, struct rx_hdr *r)
{
	struct rx_hdr _r;
	int l = sizeof(_r);

	if (r == NULL)
		r = &_r;
	if (!rd || rd->used < l) {
		ND("short buffer (%d), return %d to bootstrap",
			rd ? rd->used : -1, l);
		return l;
	}
	bcopy(rd->data, r, l);
	/* header fields are in network format, convert to host fmt */
	r->optlen = ntohl(r->optlen);
	r->level = ntohl(r->level);
	r->optname = ntohl(r->optname);
	r->dir = ntohl(r->dir);
	l += r->optlen;
	return l;
}

/*
 * The sockopt commands are sent in network format (at least the header)
 */
int
sockopt_handler(struct sess *sess, void *arg)
{
	struct sockopt_desc *d;
	int error = 1;

	ND("sess %p arg %p", sess, arg);
	if (sess->private == NULL)
		sess->private = calloc(1, sizeof(struct sockopt_desc));
	d = sess->private;
	if (d == NULL)
		goto done;
	if (sess->flags & WANT_READ) {
		int l, want, prev;
		struct rx_hdr r;
		struct sockopt sopt;
		struct thread dummy;

		want = get_want(d->rd, &r);
		prev = d->rd ? d->rd->used : 0;
		ND("total message size is %d (prev %d)", want, prev);

		d->rd = get_data(sess->fd, d->rd, want);
		l = d->rd ? d->rd->used : 0;
		ND("read %d prev %d want %d", l, prev, want);
		if (l == prev) /* no data -> error */
			goto done;
		want = get_want(d->rd, &r);
		ND("again, want %d l %d", want, l);
		if (l < want) /* must read more data */
			return 0;
		sopt.sopt_dir = r.dir;
		sopt.sopt_level = r.level;
		sopt.sopt_name = r.optname;
		sopt.sopt_val =
			(l <= sizeof(r)) ? NULL : d->rd->data + sizeof(r);
		sopt.sopt_valsize = r.optlen;
		sopt.sopt_td = &dummy;
		ND("dir 0x%x lev %d opt %d optval %p optlen %d",
			sopt.sopt_dir,
			sopt.sopt_level,
			sopt.sopt_name,
			sopt.sopt_val,
			(int)sopt.sopt_valsize);

		/* now call the handler */
		r.level = htonl(ctl_handler(&sopt));
		ND("handler returns %d", ntohl(r.level));
		r.optlen = htonl(0);	/* default len */
		r.dir = htonl(sopt.sopt_dir);
		/* prepare the buffer for writing */
		if (d->wr != NULL) { /* previous write buffer */
			free(d->wr);
		}
		d->wr = d->rd;
		d->rd = NULL;
		d->wr->used = sopt.sopt_valsize + sizeof(r);
		d->wr->start = 0;
		/* now update the header */
		if (sopt.sopt_dir == SOPT_GET)
			r.optlen = htonl(sopt.sopt_valsize);
		
		bcopy(&r, d->wr->data, sizeof(r));

		sess->flags = WANT_WRITE;
		return 0;
	}
	if (sess->flags & WANT_WRITE) {
		struct sess_buf *wr = d->wr;

		int l = write(sess->fd, wr->data + wr->start,
				wr->used - wr->start);
		ND("written %d bytes out of %d", l,
			wr->used - wr->start);
		if (l <= 0) {
			if (errno == EAGAIN)
				return 0;
			goto done;	/* error */
		}
		wr->start += l;
		if (wr->start < wr->used)
			return 0;
		// prepare for another rpc
		sess->flags = WANT_READ;
		return 0;
		//goto done;
	}
done:
	ND("closing session");
	if (d) {
		if (sess->fd >= 0)
			close(sess->fd);
		if (d->rd)
			free(d->rd);
		if (d->wr)
			free(d->wr);
		d->rd = d->wr = NULL;
		free(d); /* private data */
		sess->flags = WANT_DELETE;
	}
	return error;
}


/*
 * testing code when reading fake packets from socket 5556.
 * Turns out that ipfw_check_hook() is a lot slower than ipfw_chk()
 * XXX new ipfw uses ipfw_check_frame or ipfw_check_packet
 */
int
packet_handler(struct sess *sess, void *arg)
{
	char fake_buf[2048];
	struct mbuf dm;
	int i;

	bzero(&dm, sizeof(dm));
	dm.m_data = fake_buf + 14;	/* skip mac hdr */
	dm.m_len = dm.m_pkthdr.len = 128;
	fake_buf[14] = 0x45; // ip
	*(uint16_t *)(fake_buf+16) = htons(64); // bytes
	*(uint32_t *)(fake_buf+26) = htonl(0x01020304); // src
	*(uint32_t *)(fake_buf+30) = htonl(0x05060708); // dst
	{
#if 0
	struct ip_fw_args args;
	bzero(&args, sizeof(args));
	args.m = &dm;
	for (i = 0; i < 1000; i++)
		ipfw_chk(&args);
#else
	struct ifnet *ifp = NULL;
	struct inpcb *inp = NULL;
	struct mbuf *m = &dm;
	ND("sess %p arg %p", sess, arg);
	for (i = 0; i < 1000; i++)
		ipfw_check_packet(NULL, &m, ifp, PFIL_IN, inp);
#endif
	}
	return 0;
}


/*
 * This task accepts a new connection and creates a new session.
 */
static int
listener(struct sess *sess, void *arg)
{
	int fd;

	ND("sess %p arg %p", sess, arg);
	fd = accept(sess->fd, NULL, NULL);
	if (fd < 0)
		return -1;
	fcntl(fd, F_SETFL, O_NONBLOCK);
#ifdef setsockopt /* make sure we don't redefine it */
#error cannot compile this
#endif
	{
		int on = 1, ret;
		ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
		ND("TCP_NODELAY returns %d", ret);
	}
	new_session(fd, sess->arg ? sockopt_handler: packet_handler,
		sess->arg, WANT_READ);
	return 0;
}

/*
 * listen on a socket,
 * return the listen fd or -1 on error.
 */
static int
do_server(const char *addr, int port)
{
	int fd = -1, on;
	struct sockaddr_in server;
	
	/* open the listen socket */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror( "socket" );
		return -1;
	}

	on = 1;
#ifdef SO_REUSEADDR
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
		perror("SO_REUSEADDR failed(non fatal)");
#endif
#ifdef SO_REUSEPORT
	on = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) == -1)
		perror("SO_REUSEPORT failed(non fatal)");
#endif

	/* fill the server struct */
	bzero(&server, sizeof(server));
        server.sin_family = AF_INET;
        inet_aton(addr, &server.sin_addr);
        server.sin_port = htons(port);

	/* bind the local address */
        if (bind(fd, (struct sockaddr*) &server, sizeof(server)) < 0) {
		perror( "bind" );
		return -1;
	}
	D("+++ listening tcp %s:%d",
	    inet_ntoa(server.sin_addr), ntohs(server.sin_port));

	/* listen for incoming connection */
	if (listen(fd, SOCK_QLEN) < 0) {
		perror( "listen" );
		return -1;
	}
	return fd;
}

extern int ipfw_module_init(void);

/*
 * main program for ipfw kernel side when running an userspace emulation:
 * open a socket on which we receive requests from userland,
 * another socket for calls from the 'kernel' (simulating packet
 * arrivals etc), and then periodically run the tick handler.
 */
int
mainloop(int argc, char *argv[])
{
	int listen_fd;
	struct timeval t0;
	const char *s, *addr = LOCALADDR;
	int port = IPFW_PORT;
	int i;
	int old_ticks;
	uint64_t callouts = 0, skipped = 0;

	gettimeofday(&t0, NULL);
	old_ticks = ticks = 0;
	callout_startup();

	ipfw_module_init();

	/* override the host if set in the environment */
        s = getenv("IPFW_HOST");
        if (s)
		addr = s;
        s = getenv("IPFW_PORT");
        if (s && atoi(s) > 0)
                port = atoi(s);
	/* start the server */
	listen_fd = do_server(addr, port);
	if (listen_fd < 0) {
		printf("Error starting server\n");
		return -1;
        }
	new_session(listen_fd, listener, (void *)1, WANT_READ);

#ifdef WITH_NETMAP
	for (i = 1; i < argc; i++) {
		netmap_add_port(argv[i]);
	}
#endif /* WITH_NETMAP */

#if 0 // test code: a telnet on 5556 becomes an infinite source
	{
		int net_fd = do_server(addr, port+1);
		if (net_fd >= 0)
			new_session(net_fd, listener, NULL, WANT_READ);
	}
#endif

	for (;;) {
		struct timeval now, delta = { 0, tick} ;
		int n;
		fd_set r, w;

		n = set_sessions(&r, &w);
		select(n, &r, &w, NULL, &delta);
		run_sessions(&r, &w);
		gettimeofday(&now, 0);
		timersub(&now, &t0, &delta);
		/* compute absolute ticks. */
		ticks = (delta.tv_sec * hz) + (delta.tv_usec * hz) / 1000000;
		if (old_ticks != ticks) {
			callouts++;
			callout_run();
			old_ticks = ticks;
		} else {
			skipped++;
		}
		RD(1, "callouts %lu skipped %lu", (u_long)callouts, (u_long)skipped);
	}
	ipfw_destroy();
	return 0;
}
