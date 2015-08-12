#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#define __LIBRARY__
#include <unistd.h>

#define MAX 		500
#define BUFFER_SIZE	10

_syscall2(int, sem_open, char *, name, unsigned int, value);
_syscall1(int, sem_wait, int, sd);
_syscall1(int, sem_post, int, sd);
_syscall1(int, sem_unlink, const char *, name);

int producer(int fd, int mutex, int full, int empty)
{
	int i, ret;

	for(i=1; i<MAX+1; i++){
		ret = sem_wait(empty);
		ret = sem_wait(mutex);
/*		printf("P sem_wait:mutex ret=%d\n", ret);
		fflush(stdout);
*/		
		lseek(fd, 0, SEEK_END);
		write(fd, (char *)&i, sizeof(i));
/*		printf("write:i = %d\n", i);
		fflush(stdout);
*/		
		ret = sem_post(mutex);
		ret = sem_post(full);
/*		printf("P sem_post:full ret=%d\n", ret);
		fflush(stdout);
*/	}
	
	return 0;
}

int consumer(int fd, int mutex, int full, int empty)
{
	int j, ret, read_num;
	int num[10];
	
	while(1){
		ret = sem_wait(full); 
		ret = sem_wait(mutex);
/*		printf("C sem_wait:mutex ret=%d\n", ret);
		fflush(stdout);
*/		
		read_num = lseek(fd, 0, SEEK_END);
		lseek(fd, 0, SEEK_SET);
		ret = read(fd, (char *)num, read_num);
		if(ret){
/*			printf("out %d:", getpid());
			for(j=0; j<(ret/4); j++){
				printf("%d", num[j]);
			}
			printf("\n");
*/			printf("out %d:%d\n", getpid(), num[0]);
			fflush(stdout);
			
			if(num[0] == MAX){
				break;
			}
			else{
				system(">buffer");
				lseek(fd, 0, SEEK_SET);
				write(fd, (char *)(num+1), ret-4);
			}
		}
		else{
			printf("out %d: the queue is nothing!\n", getpid());
			fflush(stdout);
		}
		
		ret = sem_post(mutex);
		ret = sem_post(empty);
/*		printf("C sem_post:empty ret=%d\n", ret);
		fflush(stdout);
*/	}
	
	return 0;
}

int main()
{
	int j;
	int fd;

	int mutex, full, empty;

	int ret;	

	mutex = sem_open("mutex", 1);
	if(mutex<0){
		printf("mutex:errno=%d\n", errno);
		return -1;
	}
	full = sem_open("full", 0);
	if(full<0){
		printf("full:errno=%d\n", errno);
		return -1;
	}
	empty = sem_open("empty", BUFFER_SIZE);
	if(empty<0){
		printf("empty:errno=%d\n", errno);
		return -1;
	}

	fd = open("./buffer", O_CREAT|O_RDWR|O_TRUNC, 0666);
	if(fd<0){
		printf("open buffer fail\n");
		perror(NULL);
		exit(-1);
	}
	
	if(!fork()){
		producer(fd, mutex, full, empty);
		exit(0);
	}
	
	for(j=0; j<10; j++){
		if(!fork()){
			printf("create C pid:%d\n", getpid());
			fflush(stdout);
			consumer(fd, mutex, full, empty);
			exit(0);
		}
	}

	for(j=0; j<2; j++){
		wait(NULL);
	}

	ret = sem_unlink("mutex");
	printf("mutex unlink ret=%d\n", ret);
	ret = sem_unlink("full");
	printf("full unlink ret=%d\n", ret);
	ret = sem_unlink("empty");
	printf("empty unlink ret=%d\n", ret);
	fflush(stdout);
	
	return 0;
}

