#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#define __LIBRARY__
#include <unistd.h>

_syscall2(int, whoami,char*,name,unsigned int,size);

int main(void)
{
	int ret;
	char name[50];

	ret = whoami(name, sizeof(name));
	if(ret >= 0) printf("%s\n", name);

	return 0;
}