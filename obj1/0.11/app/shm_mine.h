#ifndef _SHM_MINE_H
#define _SHM_MINE_H

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <assert.h>
#include <shm.h>
#define __LIBRARY__
#include <unistd.h>

#define SHM_SIZE	1024
#define PROJ_ID		0
#define MAX 		500
#define BUFFER_SIZE	10

_syscall2(int, sem_open, char *, name, unsigned int, value);
_syscall1(int, sem_wait, int, sd);
_syscall1(int, sem_post, int, sd);
_syscall1(int, sem_unlink, const char *, name);

_syscall3(int, shmget, key_t, key, size_t, size, int, shmflg);
_syscall1(int, shmdt, void *, shmaddr);
_syscall2(int, shmctl, int, shmid, int, cmd);
void *shmat(int shmid, void *shmaddr, int shmflg)
{
	long __res; \
	__asm__ volatile ("int $0x80" \
		: "=a" (__res) \
		: "0" (__NR_shmat),"b" ((long)(shmid)),"c" ((long)(shmaddr)),"d" ((long)(shmflg))); \
		if (__res>=0) \
			return (void *)__res; \
		errno=-__res; \
		return (void *)-1;
}

#endif
