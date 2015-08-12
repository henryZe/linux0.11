#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>

int main()
{
	if(!fork())
	{
		while(1){
			printf("A\n");
			sleep(1);
		}
	}
	if(!fork())
	{
		while(1){
			printf("B\n");
			sleep(1);
		}
	}
	
	wait(NULL);
	return 0;
}
