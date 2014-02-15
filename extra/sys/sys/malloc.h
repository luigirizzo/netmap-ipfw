/*
 * $Id$
 * replacement for sys/malloc.h to compile kernel in userspace
 */

#ifndef _SYS_MALLOC_H_
#define _SYS_MALLOC_H_

#define M_WAITOK        0x0000          /* can block */
#define M_NOWAIT        0x0001          /* do not block */
#define M_ZERO          0x0100          /* bzero the allocation */
#endif /* _SYS_MALLOC_H_ */

