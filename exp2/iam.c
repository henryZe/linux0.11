#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#define __LIBRARY__
#include <unistd.h>

_syscall1(int, iam, const char*, name);

int main(int argc, char **argv)
{
	iam(argv[1]);
	
	return 0;
}