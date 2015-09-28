/*
 *  linux/lib/lib_sem.c
 *
 *  (C) 1991  Linus Torvalds
 */

#define __LIBRARY__
#include <unistd.h>

_syscall2(int, sem_open, char *, name, unsigned int, value);
_syscall1(int, sem_wait, int, sd);
_syscall1(int, sem_post, int, sd);
_syscall1(int, sem_unlink, const char *, name);
