#include "pthread.h"
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

struct _pthread {
	pthread_t p_nextlive, p_prevlive; /* Double chaining of active threads */
    	pthread_t p_nextwaiting;      /* Next element in the queue holding the thr */
	int p_pid;                    /* PID of Unix process */
   	int p_spinlock;               /* Spinlock for synchronized accesses */
  	int p_signal;                 /* last signal received */
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

static int pthread_initialize_manager(void)
{
	int manager_pipe[2];

	/* Setup stack for thread manager */
	__pthread_manager_thread_bos = malloc(THREAD_MANAGER_STACK_SIZE);
	if (__pthread_manager_thread_bos == NULL) 
		return -1;
	
	pthread_manager_thread_tos =
		__pthread_manager_thread_bos + THREAD_MANAGER_STACK_SIZE;
    /* Setup pipe to communicate with thread manager */
	if (pipe(manager_pipe) == -1) {
		free(__pthread_manager_thread_bos);
		return -1;
    }
	__pthread_manager_request = manager_pipe[1]; /* writing end */
	__pthread_manager_reader = manager_pipe[0]; /* reading end */
	/* Start the thread manager */
	if (__clone(__pthread_manager,
	          	__pthread_manager_thread_tos,
				CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND,
				(void *)(long)manager_pipe[0]) == -1) {
		free(__pthread_manager_thread_bos);
		__libc_close(manager_pipe[0]);
    	__libc_close(manager_pipe[1]);
	    __pthread_manager_request = -1;
		return -1;
	}
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
	pthread_t self = thread_self();
	pthread_t joining;
	struct pthread_request request;
	
	/* Reset the cancellation flag to avoid looping if the cleanup handlers
		contain cancellation points */
	self->p_canceled = 0;
	
	/* Call cleanup functions and destroy the thread-specific data */
	pthread_perform_cleanup();
	__pthread_destroy_specifics();
	
	/* Store return value */
   	self->p_retval = retval;
	
	/* Say that we've terminated */
   	self->p_terminated = 1;
	
	/* See if someone is joining on us */
   	joining = self->p_joining;
	
	/* Restart joining thread if any */
   	if (joining != NULL) 
		restart(joining);
	
	/* If this is the initial thread, block until all threads have terminated.
		If another thread calls exit, we'll be terminated from our signal
		handler. */
	if (self == __pthread_main_thread && __pthread_manager_request >= 0) {
		request.req_thread = self;
		request.req_kind = REQ_MAIN_THREAD_EXIT;
		__libc_write(__pthread_manager_request, (char *)&request, sizeof(request));
		suspend(self);
	}
	
	/* Exit the process (but don't flush stdio streams, and don't run
		atexit functions). */
	exit(0);
}

int pthread_join(pthread_t th, void **thread_return)
{
	volatile pthread_t self = thread_self();
	struct pthread_request request;

	if (th == self) 
		return EDEADLK;
	
	/* If detached or already joined, error */
	if (th->p_detached || th->p_joining != NULL) {
		return EINVAL;
	}
	
	/* If not terminated yet, suspend ourselves. */
	if (! th->p_terminated) {
		th->p_joining = self;
		suspend(self);
	}

	/* Get return value */
	if (thread_return != NULL) 
		*thread_return = th->p_retval;
	
	/* Send notification to thread manager */
	if (__pthread_manager_request >= 0) {
		request.req_thread = self;
		request.req_kind = REQ_FREE;
		request.req_args.free.thread = th;
		__libc_write(__pthread_manager_request,
			(char *) &request, sizeof(request));
	}
	
	return 0;
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
