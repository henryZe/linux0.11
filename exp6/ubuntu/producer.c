#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include "shm_mine.h"

int main()
{
	int i,j;
	int fd;
	int ret;	
	int id;
	int *p;
	key_t key;
	key_t key2;
	int semid;
	union semun a;

	key = ftok(PATH_NAME,PROJ_ID);
	key2 = ftok(PATH_NAME,PROJ_ID+1);

	semid = semget(key2, 3, IPC_CREAT|IPC_EXCL|0666);
	if(semid == -1){
		semid = semget(key2,3,0666);	
	}

	a.val = 1;
	semctl(semid,mutex,SETVAL,a);
	a.val = 0;
	semctl(semid,full,SETVAL,a);
	a.val = BUFFER_SIZE;
	semctl(semid,empty,SETVAL,a);
	
	id = shmget(key,SHM_SIZE,IPC_CREAT|IPC_EXCL|0666);
	if(id == -1){
		id = shmget(key,SHM_SIZE,0666);
	}
	p = (int *)shmat(id,NULL,0);
	memset(p, 0, SHM_SIZE);
	
	for(i=1; i<MAX+1; i++){
		sem_P(semid,empty);
		sem_P(semid,mutex);
/*		printf("P sem_wait:mutex ret=%d\n", ret);
		fflush(stdout);
*/		
		for(j=0; p[j]; j++);
		p[j] = i;
		printf("set:p[%d]=%d\n", j, i);
		fflush(stdout);
		
		sem_V(semid,mutex);
		sem_V(semid,full);
/*		printf("P sem_post:full ret=%d\n", ret);
		fflush(stdout);
*/	}
	
	shmdt(p);
	
	return 0;
}

