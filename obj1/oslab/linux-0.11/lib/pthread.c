#include <stdio.h>
#include <pthread.h>

struct _pthread {
	pthread_t p_nextlive, p_prevlive; /* Double chaining of active threads */
    pthread_t p_nextwaiting;      /* Next element in the queue holding the thr */
	int p_pid;                    /* PID of Unix process */
    int p_spinlock;               /* Spinlock for synchronized accesses */
  	int p_signal;                 /* last signal received */
    sigjmp_buf * p_signal_jmp;    /* where to siglongjmp on a signal or NULL */
	sigjmp_buf * p_cancel_jmp;    /* where to siglongjmp on a cancel or NULL */
    char p_terminated;            /* true if terminated e.g. by pthread_exit */
  	char p_detached;              /* true if detached */
    char p_exited;                /* true if the assoc. process terminated */
  	void * p_retval;              /* placeholder for return value */
    int p_retcode;                /* placeholder for return code */
	pthread_t p_joining;          /* thread joining on that thread or NULL */
    struct _pthread_cleanup_buffer * p_cleanup; /* cleanup functions */
  	char p_cancelstate;           /* cancellation state */
  	char p_canceled;              /* cancellation request pending */
    int p_errno;                  /* error returned by last system call */
  	int p_h_errno;                /* error returned by last netdb function */
    void *(*p_initial_fn)(void *); /* function to call on thread start */
  	void *p_initial_fn_arg;   /* argument to give that function */
    sigset_t p_initial_mask;  /* signal mask on thread start */
	void * p_specific[PTHREAD_KEYS_MAX]; /* thread-specific data */
};


static inline pthread_t thread_self (void)
{
#ifdef THREAD_KERNEL
	THREAD_SELF
#else
    char *sp = CURRENT_STACK_FRAME;
	if (sp >= __pthread_initial_thread_bos)
		return &__pthread_initial_thread;
	else if (sp >= __pthread_manager_thread_bos 
				&& sp < __pthread_manager_thread_tos)
		return &__pthread_manager_thread;
	else
		return (pthread_t) (((unsigned long int) sp | (STACK_SIZE - 1)) + 1) - 1;
#endif
}

static void pthread_perform_cleanup(void)
{
	pthread_t self = thread_self();
	struct _pthread_cleanup_buffer * c;
	
	for (c = self->p_cleanup; c != NULL; c = c->prev)
		c->routine(c->arg); 
} 

int pthread_attr_init(pthread_attr_t *attr)
{
	attr->detached = PTHREAD_CREATE_JOINABLE;
	
	return 0; 
}

int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate)
{
	attr->detached = detachstate;

	return 0; 
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg)
{
	pthread_t self = thread_self();
	struct pthread_request request;
	if (__pthread_manager_request < 0) {
		if (pthread_initialize_manager() < 0) 
			return EAGAIN;
	}
	request.req_thread = self;
	request.req_kind = REQ_CREATE;
	request.req_args.create.attr = attr;
	request.req_args.create.fn = start_routine;
	request.req_args.create.arg = arg;
	sigprocmask(SIG_SETMASK, (const sigset_t *) NULL,
	             &request.req_args.create.mask);
	_libc_write(__pthread_manager_request, (char *) &request, sizeof(request));
	suspend(self);
	if (self->p_retcode == 0) 
		*thread = (pthread_t) self->p_retval;
	return self->p_retcode;
}

void pthread_exit(void *retval)
{
	pthread_perform_cleanup();
}

int pthread_join(pthread_t thread, void **value_ptr)
{

}

int pthread_cancel(pthread_t thread)
{
	thread->p_canceled = 1;

	return 0;
}

int pthread_setcancelstate(int state, int *oldstate)
{
	pthread_t self = thread_self();

	if ((state != PTHREAD_CANCEL_ENABLE) && 
		(state != PTHREAD_CANCEL_DISABLE))
		return EINVAL;
	if (oldstate != NULL) 
		*oldstate = self->p_cancelstate;
	
	self->p_cancelstate = state;
	
	if (self->p_canceled &&
		self->p_cancelstate == PTHREAD_CANCEL_ENABLE)
		pthread_exit(PTHREAD_CANCELED);
	
	return 0;
}

void _pthread_cleanup_push(struct _pthread_cleanup_buffer *buffer, void (*routine)(void *), void *arg)
{
	pthread_t self = thread_self();
	
	buffer->routine = routine;
    buffer->arg = arg;
	
	buffer->prev = self->p_cleanup;
	self->p_cleanup = buffer;
}

void _pthread_cleanup_pop(struct _pthread_cleanup_buffer *buffer, int execute)
{
	pthread_t self = thread_self();
	
	if (execute) 
		buffer->routine(buffer->arg);
	self->p_cleanup = buffer->prev;
}

void pthread_testcancel(void)
{
	pthread_t self = thread_self();
	
	if (self->p_canceled &&
		self->p_cancelstate == PTHREAD_CANCEL_ENABLE)
		pthread_exit(PTHREAD_CANCELED);
}
