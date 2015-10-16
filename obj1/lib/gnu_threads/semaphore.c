/* Linuxthreads - a simple clone()-based implementation of Posix        */
/* threads for Linux.                                                   */
/* Copyright (C) 1996 Xavier Leroy (Xavier.Leroy@inria.fr)              */
/*                                                                      */
/* This program is free software; you can redistribute it and/or        */
/* modify it under the terms of the GNU Library General Public License  */
/* as published by the Free Software Foundation; either version 2       */
/* of the License, or (at your option) any later version.               */
/*                                                                      */
/* This program is distributed in the hope that it will be useful,      */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU Library General Public License for more details.                 */

/* Semaphores a la POSIX 1003.1b */

#include "pthread.h"
#include "semaphore.h"
#include "internals.h"
#include "restart.h"


#ifndef HAS_COMPARE_AND_SWAP
/* If we have no atomic compare and swap, fake it using an extra spinlock.  */

#include "spinlock.h"
static inline int compare_and_swap(sem_t *sem, long oldval, long newval)
{
  int ret;
  acquire(&sem->sem_spinlock);
  if ((ret = sem->sem_status == oldval) != 0)
    sem->sem_status = newval;
  release(&sem->sem_spinlock);
  return ret;
}

#else
/* But if we do have an atomic compare and swap, use it!  */

#define compare_and_swap(sem,old,new) \
  __compare_and_swap(&(sem)->sem_status, (old), (new))

#endif


/* The state of a semaphore is represented by a long int encoding
   either the semaphore count if >= 0 and no thread is waiting on it,
   or the head of the list of threads waiting for the semaphore.
   To distinguish the two cases, we encode the semaphore count N
   as 2N+1, so that it has the lowest bit set.

   A sequence of sem_wait operations on a semaphore initialized to N
   result in the following successive states:
     2N+1, 2N-1, ..., 3, 1, &first_waiting_thread, &second_waiting_thread, ...
*/

int sem_init(sem_t *sem, int pshared, unsigned int value)
{
  if (value > SEM_VALUE_MAX) {
    errno = EINVAL;
    return -1;
  }
  if (pshared) {
    errno = ENOSYS;
    return -1;
  }
  sem->sem_status = ((long)value << 1) + 1;
  return 0;
}

int sem_wait(sem_t * sem)
{
  long oldstatus, newstatus;
  volatile pthread_t self = thread_self();
  pthread_t * th;

  while (1) {
    do {
      oldstatus = sem->sem_status;
      if ((oldstatus & 1) && (oldstatus != 1))
        newstatus = oldstatus - 2;
      else {
        newstatus = (long) self;
        self->p_nextwaiting = (pthread_t) oldstatus;
      }
    }
    while (! compare_and_swap(sem, oldstatus, newstatus));
    if (newstatus & 1)
      /* We got the semaphore. */
      return 0;
    /* Wait for sem_post or cancellation */
    suspend_with_cancellation(self);
    /* This is a cancellation point */
    if (self->p_canceled && self->p_cancelstate == PTHREAD_CANCEL_ENABLE) {
      /* Remove ourselves from the waiting list if we're still on it */
      /* First check if we're at the head of the list. */
      do {
        oldstatus = sem->sem_status;
        if (oldstatus != (long) self) break;
        newstatus = (long) self->p_nextwaiting;
      }
      while (! compare_and_swap(sem, oldstatus, newstatus));
      /* Now, check if we're somewhere in the list.
         There's a race condition with sem_post here, but it does not matter:
         the net result is that at the time pthread_exit is called,
         self is no longer reachable from sem->sem_status. */
      if (oldstatus != (long) self && (oldstatus & 1) == 0) {
        th = &(((pthread_t) oldstatus)->p_nextwaiting);
        while (*th != (pthread_t) 1 && *th != NULL) {
          if (*th == self) {
            *th = self->p_nextwaiting;
            break;
          }
          th = &((*th)->p_nextwaiting);
        }
      }
      pthread_exit(PTHREAD_CANCELED);
    }
  }
}

int sem_trywait(sem_t * sem)
{
  long oldstatus, newstatus;

  do {
    oldstatus = sem->sem_status;
    if ((oldstatus & 1) == 0 || (oldstatus == 1)) {
      errno = EAGAIN;
      return -1;
    }
    newstatus = oldstatus - 2;
  }
  while (! compare_and_swap(sem, oldstatus, newstatus));
  return 0;
}

int sem_post(sem_t * sem)
{
  long oldstatus, newstatus;
  pthread_t th, next_th;

  do {
    oldstatus = sem->sem_status;
    if ((oldstatus & 1) == 0)
      newstatus = 3;
    else {
      if (oldstatus >= SEM_VALUE_MAX) {
        /* Overflow */
        errno = ERANGE;
        return -1;
      }
      newstatus = oldstatus + 2;
    }
  }
  while (! compare_and_swap(sem, oldstatus, newstatus));
  if ((oldstatus & 1) == 0) {
    th = (pthread_t) oldstatus;
    do {
      next_th = th->p_nextwaiting;
      th->p_nextwaiting = NULL;
      restart(th);
      th = next_th;
    } while(th != (pthread_t) 1);
  }
  return 0;
}

int sem_getvalue(sem_t * sem, int * sval)
{
  long status = sem->sem_status;
  if (status & 1)
    *sval = (int)((unsigned long) status >> 1);
  else
    *sval = 0;
  return 0;
}

int sem_destroy(sem_t * sem)
{
  if ((sem->sem_status & 1) == 0) {
    errno = EBUSY;
    return -1;
  }
  return 0;
}
