#ifndef _PTHREAD_H
#define _PTHREAD_H

#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 1

//move to kernel in future
#define PTHREAD_CANCEL_DISABLE  0
#define PTHREAD_CANCEL_ENABLE   1

#define pthread_cleanup_push(routine,arg)                     \                                                                                              
	{ struct _pthread_cleanup_buffer _buffer;                 \
      _pthread_cleanup_push (&_buffer, (routine), (arg));

#define pthread_cleanup_pop(execute)                          \
    _pthread_cleanup_pop (&_buffer, (execute)); }

typedef struct _pthread_attr_t_{
	int detached;
}pthread_attr_t;

struct _pthread_cleanup_buffer {                                                                                                                             
	void (*routine) __P ((void *));   /* Function to call.  */
	void *arg;                /* Its argument.  */
	int canceltype;           /* Saved cancellation type. */
	struct _pthread_cleanup_buffer *prev; /* Chaining of cleanup functions.  */
};

typedef struct _pthread *pthread_t;

int pthread_attr_init(pthread_attr_t *attr);
int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate);
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg);
void pthread_exit(void *retval);
int pthread_cancel(pthread_t thread);
int pthread_setcancelstate(int state, int *oldstate);
void pthread_cleanup_push(void (*routine)(void *), void *arg);
void pthread_cleanup_pop(int execute);
void pthread_testcancel(void);

#endif /* _PTHREAD_H */
