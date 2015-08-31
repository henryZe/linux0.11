#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include "shm_mine.h"

int main()
{
	int j, ret, read_num;
	int *p;
	int num[10];
	int fd,id;
	key_t key;
	key_t key2;
	int semid = -1;
	
	for(j=0; j<9; j++){
		if(!fork()) break;
	}

	key = ftok(PATH_NAME,PROJ_ID);
	key2 = ftok(PATH_NAME,PROJ_ID+1);

	while(semid == -1)
	{
		semid = semget(key2, 3, 0666);	
	}
	
	id = shmget(key,SHM_SIZE,IPC_CREAT|IPC_EXCL|0666);
	if(id == -1){
		id = shmget(key,SHM_SIZE,0666);
	}
/*	printf("%d shmid = %d\n", getpid(), id);
*/	p = (int *)shmat(id,NULL,0);
	
	while(1){
		ret = sem_P(semid,full);
		if(ret == -1) exit(0);
		ret = sem_P(semid,mutex);
/*		printf("C sem_wait:mutex ret=%d\n", ret);
		fflush(stdout);
*/			
		memset(num, 0, sizeof(num));
	
		printf("out %d:", getpid());
		for(j=0; j<BUFFER_SIZE; j++){
			if(!p[j]) break;
			num[j] = p[j];
			printf("%d ", num[j]);
		}
		printf("\n");
//		printf("out:%d\n", num[0]);
		fflush(stdout);
		
		for(j=1; j<BUFFER_SIZE; j++){
			if(!num[j]) break;
			p[j-1] = num[j];
		}
		p[j-1]=0;
		
		ret = sem_V(semid,mutex);
		ret = sem_V(semid,empty);
/*		printf("C sem_post:empty ret=%d\n", ret);
		fflush(stdout);
*/	
		if(num[0] == MAX){
			break;
		}
	}

	shmdt(p);
	
	semctl(semid,mutex,IPC_RMID,NULL);			//删除信号量0,否则仍将存在,破坏P/V操作
	semctl(semid,full,IPC_RMID,NULL);
	semctl(semid,empty,IPC_RMID,NULL);
	shmctl(id,IPC_RMID,NULL);

	return 0;
}

