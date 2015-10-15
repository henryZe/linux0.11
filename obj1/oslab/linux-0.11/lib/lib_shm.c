/*
 *  linux/lib/lib_shm.c
 *
 *  (C) 1991  Linus Torvalds
 */

#define __LIBRARY__
#include <unistd.h>

_syscall3(int, shmget, key_t, key, size_t, size, int, shmflg);
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
_syscall1(int, shmdt, void *, shmaddr);
_syscall2(int, shmctl, int, shmid, int, cmd);
