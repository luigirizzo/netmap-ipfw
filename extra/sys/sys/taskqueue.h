#ifndef _SYS_TASKQUEUE_H_
#define _SYS_TASKQUEUE_H_

/*
 * Remap taskqueue to direct calls
 */

#ifdef _WIN32
struct task {
	void (*func)(void*, int);
};
#define taskqueue_enqueue_fast(tq, ta)	(ta)->func(NULL,1)
#define TASK_INIT(a,b,c,d) do { 				\
	(a)->func = (c); } while (0)
#else
struct task {
	void (*func)(void);
};
#define taskqueue_enqueue_fast(tq, ta)	(ta)->func()
#define TASK_INIT(a,b,c,d) do { 				\
	(a)->func = (void (*)(void))c; } while (0)


#endif
typedef void (*taskqueue_enqueue_fn)(void *context);

// #define taskqueue_create(_a, _b, _c, _d)	NULL
struct taskqueue *taskqueue_create_fast(const char *name, int mflags,
                                    taskqueue_enqueue_fn enqueue,
                                    void *context);
void    taskqueue_thread_enqueue(void *context);


// #define taskqueue_create_fast(_a, _b, _c, _d)	NULL
int     taskqueue_start_threads(struct taskqueue **tqp, int count, int pri,
                                const char *name, ...) __printflike(4, 5);


// #define	taskqueue_drain(_a, _b)	/* XXX to be completed */
// #define	taskqueue_free(_a)	/* XXX to be completed */
void    taskqueue_drain(struct taskqueue *queue, struct task *task);
void    taskqueue_free(struct taskqueue *queue);


#define PRI_MIN                 (0)             /* Highest priority. */
#define PRI_MIN_ITHD            (PRI_MIN)
#ifndef __FreeBSD__
#define PI_NET                  (PRI_MIN_ITHD + 16)
#endif

#endif /* !_SYS_TASKQUEUE_H_ */
