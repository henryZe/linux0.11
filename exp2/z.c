/*
 * Compile: "gcc z.c"
 * Run: "./a.out"
 */

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#define __LIBRARY__
#include <unistd.h>

_syscall2(int, whoami,char*,name,unsigned int,size);
_syscall1(int, iam, const char*, name);


int main(void)
{
	int ret;
	char name[50];

	ret = iam("123456789012345678");	
	printf("iam:ret = %d\n", ret);
	if(ret == -1)
	{
		printf("errno = %d\n", errno);
	}

	ret = whoami(name, sizeof(name));
	printf("whoami:ret = %d\n", ret);
	if(ret == -1)
	{
		printf("errno = %d\n", errno);
	}

	return 0;
}
