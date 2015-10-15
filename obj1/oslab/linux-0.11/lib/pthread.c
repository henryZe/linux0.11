#include <stdio.h>
#include <pthread.h>

//move to kernel in future
#define PTHREAD_CANSIG_NOTYET   0
#define PTHREAD_CANSIG_CATCHED  1

int pthread_attr_init(pthread_attr_t *attr)
{
	//move to kernel in future
	attr->cancel_state = PTHREAD_CANCEL_DISABLE;
	attr->cancel_sign = PTHREAD_CANSIG_NOTYET;

	attr->detached = PTHREAD_CREATE_JOINABLE;
	
	return (0); 
}

int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate)
{
	attr->detached = detachstate;

	return (0); 
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start_routine) (void *), void *arg)
{

}

void pthread_exit(void *retval)
{

}


int pthread_cancel(pthread_t thread)
{
	
}

int pthread_setcancelstate(int state, int *oldstate)
{
	*oldstate = attr->cancel_state;
	attr->cancel_state = state;

	return 0;
}

void pthread_cleanup_push(void (*routine)(void *), void *arg)
{

}

void pthread_cleanup_pop(int execute)
{

}

void pthread_testcancel(void)
{
	if(attr->cancel_state == PTHREAD_CANCEL_ENABLE){
		if(attr->cancel_sign == PTHREAD_CANSIG_CATCHED){
			pthread_exit(NULL);
		}
	}
}


