#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <semaphore.h>

#define MAX 		500+1
#define BUFFER_SIZE 10

int fd;

sem_t mutex;
sem_t full;
sem_t empty;

void *producer()
{
	int i, ret;

	for(i=1; i<MAX; i++){
		
		sem_wait(&empty);
		sem_wait(&mutex);
//		printf("%s sem_wait:mutex\n", __func__);

		ret = lseek(fd, 0, SEEK_END);
		write(fd, (char *)&i, sizeof(i));
		printf("write:i = %d\n", i);
		fflush(stdout);
		
		sem_post(&mutex);
		sem_post(&full);
	}
	
	pthread_exit(NULL);
}

void *consumer()
{
	int ret, i, read_num, j;
	int num[500];
	
	while(1){
		
		sem_wait(&full); 
		sem_wait(&mutex);
//		printf("%s sem_wait:mutex\n", __func__);
		
		read_num = lseek(fd, 0, SEEK_END);
		lseek(fd, 0, SEEK_SET);
		ret = read(fd, (char *)num, read_num);
//		printf("read_ret = %d\n", ret);
		if(ret){
			printf("out:");
			for(j=0; j<(ret/4); j++){
				printf("%d", num[j]);
			}
			printf("\n");
			fflush(stdout);
			
//			printf("out:%d\n", num[0]);
			if(num[0] == MAX){
				break;
			}
			else{
				system(">buffer");
				lseek(fd, 0, SEEK_SET);
				//printf("read->write:%d\n", num+4);
				write(fd, (char *)(num+1), ret-4);
			}
		}
		else{
			printf("out: the queue is nothing!\n");
			fflush(stdout);
		}
		
		sem_post(&mutex);
		sem_post(&empty);
	}
	
	pthread_exit(NULL);
}


int main()
{
	int j;
	pthread_t tid_c, tid_p;
	
	sem_init(&mutex, 0, 1);
	sem_init(&full, 0, 0);
	sem_init(&empty, 0, BUFFER_SIZE);
	
//	fd = open("./buffer", O_CREAT|O_RDWR, 0666);
	fd = open("./buffer", O_CREAT|O_RDWR|O_TRUNC, 0666);
	if(fd<0){
		printf("%s open buffer fail\n", __func__);
		perror(NULL);
		exit(-1);
	}
	
	pthread_create(&tid_p, NULL, producer, NULL);
			
	for(j=0; j<10; j++){
		pthread_create(&tid_c, NULL, consumer, NULL);
	}

//	pthread_join(tid_p ,NULL);
	while(1);
	return 0;
}

