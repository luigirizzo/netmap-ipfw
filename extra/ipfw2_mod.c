/*
 * Copyright (C) 2009 Luigi Rizzo, Marta Carbone, Universita` di Pisa
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
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
 * $Id: ipfw2_mod.c 7787 2010-11-19 21:15:50Z marta $
 *
 * The main interface to build ipfw+dummynet as a linux module.
 * (and possibly as a windows module as well, though that part
 * is not complete yet).
 *
 * The control interface uses the sockopt mechanism
 * on a socket(AF_INET, SOCK_RAW, IPPROTO_RAW).
 *
 * The data interface uses the netfilter interface, at the moment
 * hooked to the PRE_ROUTING and POST_ROUTING hooks.
 * Unfortunately the netfilter interface is a moving target,
 * so we need a set of macros to adapt to the various cases.
 *
 * In the netfilter hook we just mark packet as 'QUEUE' and then
 * let the queue handler to do the whole work (filtering and
 * possibly emulation).
 * As we receive packets, we wrap them with an mbuf descriptor
 * so the existing ipfw+dummynet code runs unmodified.
 */

#include <sys/cdefs.h>
#include <sys/mbuf.h>			/* sizeof struct mbuf */
#include <sys/param.h>			/* NGROUPS */
#include <netinet/in.h>			/* in_addr */
#include <netinet/ip_fw.h>		/* ip_fw_ctl_t, ip_fw_chk_t */
#include <netinet/ip_dummynet.h>	/* ip_dn_ctl_t, ip_dn_io_t */
#include <net/pfil.h>			/* PFIL_IN, PFIL_OUT */
#include <net/route.h>			/* inet_iif */

#include <netpfil/ipfw/ip_fw_private.h>		/* ip_fw_ctl_t, ip_fw_chk_t */

/*
 * Here we allocate some global variables used in the firewall.
 */
//ip_dn_ctl_t    *ip_dn_ctl_ptr;
int (*ip_dn_ctl_ptr)(struct sockopt *);

ip_fw_ctl_t    *ip_fw_ctl_ptr;

int	(*ip_dn_io_ptr)(struct mbuf **m, int dir, struct ip_fw_args *fwa);

void		(*bridge_dn_p)(struct mbuf *, struct ifnet *);

/* Divert hooks. */
void (*ip_divert_ptr)(struct mbuf *m, int incoming);

/* ng_ipfw hooks. */
ng_ipfw_input_t *ng_ipfw_input_p = NULL;


/*---
 * Control hooks:
 * ipfw_ctl_h() is a wrapper for linux to FreeBSD sockopt call convention.
 * then call the ipfw handler in order to manage requests.
 * In turn this is called by the linux set/get handlers.
 */
static int
ipfw_ctl_h(struct sockopt *s, int cmd, int dir, int len, void __user *user)
{
	struct thread t;
	int ret = EINVAL;

	memset(s, 0, sizeof(*s));
	s->sopt_name = cmd;
	s->sopt_dir = dir;
	s->sopt_valsize = len;
	s->sopt_val = user;

	/* sopt_td is not used but it is referenced */
	memset(&t, 0, sizeof(t));
	s->sopt_td = &t;
	
	if (ip_fw_ctl_ptr && cmd != IP_DUMMYNET3 && (cmd == IP_FW3 ||
												 cmd < IP_DUMMYNET_CONFIGURE))
		ret = ip_fw_ctl_ptr(s);
	else if (ip_dn_ctl_ptr && (cmd == IP_DUMMYNET3 ||
							   cmd >= IP_DUMMYNET_CONFIGURE))
		ret = ip_dn_ctl_ptr(s);
	
	return -ret;	/* errors are < 0 on linux */
}



/*
 * setsockopt hook has no return value other than the error code.
 */
int
do_ipfw_set_ctl(void *sk, int cmd,
	void __user *user, unsigned int len)
{
	struct sockopt s;	/* pass arguments */
	return ipfw_ctl_h(&s, cmd, SOPT_SET, len, user);
}

/*
 * getsockopt can can return a block of data in response.
 */
int
do_ipfw_get_ctl(void *sk,
	int cmd, void __user *user, int *len)
{
	struct sockopt s;	/* pass arguments */
	int ret = ipfw_ctl_h(&s, cmd, SOPT_GET, *len, user);

	*len = s.sopt_valsize;	/* return lenght back to the caller */
	return ret;
}


/*
 * Module glue - init and exit function.
 */
#include <sys/module.h>
/* descriptors for the children, until i find a way for the
 * linker to produce them
 */
extern moduledata_t *moddesc_ipfw;
extern moduledata_t *moddesc_dummynet;
extern moduledata_t *moddesc_dn_fifo;
extern moduledata_t *moddesc_dn_wf2qp;
extern moduledata_t *moddesc_dn_rr;
extern moduledata_t *moddesc_dn_qfq;
extern moduledata_t *moddesc_dn_prio;
extern int (*sysinit_ipfw_init)(void *);
extern int (*sysuninit_ipfw_destroy)(void *);
extern int (*sysinit_vnet_ipfw_init)(void *);
extern int (*sysuninit_vnet_ipfw_uninit)(void *);

/*---
 * Glue code to implement the registration of children with the parent.
 * Each child should call my_mod_register() when linking, so that
 * module_init() and module_exit() can call init_children() and
 * fini_children() to provide the necessary initialization.
 * We use the same mechanism for MODULE_ and SYSINIT_.
 * The former only get a pointer to the moduledata,
 * the latter have two function pointers (init/uninit)
 */
#include <sys/module.h>
struct mod_args {
	const char *name;
	int order;
	struct moduledata *mod;
	int (*init)(void *);
	int (*uninit)(void *);
};

static unsigned int mod_idx;
static struct mod_args mods[10];        /* hard limit to 10 modules */

int
my_mod_register(const char *name, int order,
				struct moduledata *mod, int (*init)(void *), int (*uninit)(void *));
/*
 * my_mod_register should be called automatically as the init
 * functions in the submodules. Unfortunately this compiler/linker
 * trick is not supported yet so we call it manually.
 */
int
my_mod_register(const char *name, int order,
				struct moduledata *mod, int (*init)(void *), int (*uninit)(void *))
{
	struct mod_args m;
 
	m.name = name;
	m.order = order;
	m.mod = mod;
	m.init = init;
	m.uninit = uninit;

	ND("called for %s", name);
	if (mod_idx < sizeof(mods) / sizeof(mods[0]))
		mods[mod_idx++] = m;
	return 0;
}

static void
init_children(void)
{
	unsigned int i;

	/* Call the functions registered at init time. */
	printf("%s mod_idx value %d\n", __FUNCTION__, mod_idx);
	for (i = 0; i < mod_idx; i++) {
		struct mod_args *m = &mods[i];
		printf("+++ start module %d %s %s at %p order 0x%x\n",
			   i, m->name, m->mod ? m->mod->name : "SYSINIT",
			   m->mod, m->order);
		if (m->mod && m->mod->evhand)
			m->mod->evhand(NULL, MOD_LOAD, m->mod->priv);
		else if (m->init)
			m->init(NULL);
	}
}

static void
fini_children(void)
{
	int i;

	/* Call the functions registered at init time. */
	for (i = mod_idx - 1; i >= 0; i--) {
		struct mod_args *m = &mods[i];
		printf("+++ end module %d %s %s at %p order 0x%x\n",
			   i, m->name, m->mod ? m->mod->name : "SYSINIT",
			   m->mod, m->order);
		if (m->mod && m->mod->evhand)
			m->mod->evhand(NULL, MOD_UNLOAD, m->mod->priv);
		else if (m->uninit)
			m->uninit(NULL);
	}
}
/*--- end of module binding helper functions ---*/

int
ipfw_module_init(void)
{
	int ret = 0;

	my_mod_register("ipfw",  1, moddesc_ipfw, NULL, NULL);
	my_mod_register("sy_ipfw",  2, NULL,
					sysinit_ipfw_init, sysuninit_ipfw_destroy);
	my_mod_register("sy_Vnet_ipfw",  3, NULL,
					sysinit_vnet_ipfw_init, sysuninit_vnet_ipfw_uninit);
	my_mod_register("dummynet",  4, moddesc_dummynet, NULL, NULL);
	my_mod_register("dn_fifo",  5, moddesc_dn_fifo, NULL, NULL);
	my_mod_register("dn_wf2qp",  6, moddesc_dn_wf2qp, NULL, NULL);
	my_mod_register("dn_rr",  7, moddesc_dn_rr, NULL, NULL);
	my_mod_register("dn_qfq",  8, moddesc_dn_qfq, NULL, NULL);
	my_mod_register("dn_prio",  9, moddesc_dn_prio, NULL, NULL);
	init_children();

#ifdef EMULATE_SYSCTL
	keinit_GST();
#endif 

	return ret;
}

/* module shutdown */
void
ipfw_module_exit(void)
{
#ifdef EMULATE_SYSCTL
	keexit_GST();
#endif

	fini_children();

	printf("%s unloaded\n", __FUNCTION__);
}
