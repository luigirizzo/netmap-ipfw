#ifndef __LINUX_DEFS_
#define __LINUX_DEFS_

/* define, includes and functions missing in linux */

#ifdef __linux__
/* include and define */
#include <arpa/inet.h>		/* inet_ntoa */
#include <netinet/tcp.h>

#include <linux/errno.h>	/* error define */
#include <stdint.h>		/* u_int32_t */
#include <stdio.h>		/* snprintf */

typedef struct mtx spinlock_t;
typedef struct mtx rwlock_t;

/*
 * some network structure can be defined in the bsd way
 * by using the _FAVOR_BSD definition. This is not true
 * for icmp structure.
 * XXX struct icmp contains bsd names in 
 * /usr/include/netinet/ip_icmp.h
 */
#define icmp_code code
#define icmp_type type

/* linux in6_addr has no member __u6_addr
 * replace the whole structure ?
 */
#define __u6_addr       __in6_u
// #define __u6_addr32     u6_addr32

/* defined in linux/sctp.h with no bsd definition */
struct sctphdr {
        uint16_t src_port;      /* source port */
        uint16_t dest_port;     /* destination port */
        uint32_t v_tag;         /* verification tag of packet */
        uint32_t checksum;      /* Adler32 C-Sum */
        /* chunks follow... */
}       SCTP_PACKED;

/* missing definition */
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_ACK  0x10

#define RTF_CLONING	0x100		/* generate new routes on use */

#define IPPROTO_OSPFIGP         89              /* OSPFIGP */
#define IPPROTO_CARP            112             /* CARP */
#define IPPROTO_IPV4            IPPROTO_IPIP    /* for compatibility */

#define	CARP_VERSION		2
#define	CARP_ADVERTISEMENT	0x01

#define PRIV_NETINET_IPFW       491     /* Administer IPFW firewall. */
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)	/* linux/stdlib */

#define IP_FORWARDING           0x1             /* most of ip header exists */

#define NETISR_IP       2               /* same as AF_INET */

#define PRIV_NETINET_DUMMYNET   494     /* Administer DUMMYNET. */

extern int securelevel;

struct carp_header {
#if BYTE_ORDER == LITTLE_ENDIAN
        u_int8_t        carp_type:4,
                        carp_version:4;
#endif
#if BYTE_ORDER == BIG_ENDIAN
        u_int8_t        carp_version:4,
                        carp_type:4;
#endif
};

struct pim {
};

struct route {
	struct  rtentry *ro_rt;
	struct  sockaddr ro_dst;
};


#if 0 // already in main header
struct ifaltq {
	void *ifq_head;
};

struct ifnet {
	char    if_xname[IFNAMSIZ];     /* external name (name + unit) */
        struct ifaltq if_snd;          /* output queue (includes altq) */
};

/* involves mbufs */
int in_cksum(struct mbuf *m, int len);
#define divert_cookie(mtag) 0
#define divert_info(mtag) 0
#define INADDR_TO_IFP(a, b) b = NULL
#define pf_find_mtag(a) NULL
#define pf_get_mtag(a) NULL
#define AF_LINK AF_ASH	/* ? linux/socket.h */

struct pf_mtag {
	void            *hdr;           /* saved hdr pos in mbuf, for ECN */
	sa_family_t      af;            /* for ECN */
        u_int32_t        qid;           /* queue id */
};
#endif

/* radix related */

#if 0
struct radix_node {
	caddr_t rn_key;         /* object of search */
	caddr_t rn_mask;        /* netmask, if present */
};
#endif


/* missing functions */

/* from bsd sys/queue.h */
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                      \
        for ((var) = TAILQ_FIRST((head));                               \
            (var) && ((tvar) = TAILQ_NEXT((var), field), 1);            \
            (var) = (tvar))

#define SLIST_FOREACH_SAFE(var, head, field, tvar)                      \
        for ((var) = SLIST_FIRST((head));                               \
            (var) && ((tvar) = SLIST_NEXT((var), field), 1);            \
            (var) = (tvar))

/* depending of linux version */
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6          0x86dd          /* IP protocol version 6 */
#endif

#endif /* __linux__ */
#endif /* !__LINUX_DEFS_ */
