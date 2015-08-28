#include "shm_mine.h"

int main()
{
	int j, ret, read_num;
	int *p;
	int num[10];
	int fd,id;
	int mutex, full, empty;
	key_t key = PROJ_ID;
	key_t key2 = PROJ_ID+1;
	
	
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

	for(j=0; j<9; j++){
		if(!fork()) break;
	}

	id = shmget(key,SHM_SIZE,0);
	if(id == -1){
		id = shmget(key,SHM_SIZE,0);
	}
/*	printf("%d shmid = %d\n", getpid(), id);
*/	p = (int *)shmat(id,NULL,0);
	
	while(1){
		/* sys_sem_open */
/*		printf("C:mutex=%d full=%d empty=%d\n", mutex, full, empty);
*/		ret = sem_wait(full); 
		printf("C sem_wait:full=%d ret=%d\n", full, ret);
		if(ret == -1) exit(0);
		ret = sem_wait(mutex);
		printf("C sem_wait:mutex=%d ret=%d\n", mutex, ret);
		fflush(stdout);
			
		memset(num, 0, sizeof(num));
	
		printf("out %d:", getpid());
		for(j=0; j<BUFFER_SIZE; j++){
			if(!p[j]) break;
			num[j] = p[j];
			printf("%d ", num[j]);
		}
		printf("\n");
/*		printf("out:%d\n", num[0]);
*/		fflush(stdout);
		
		for(j=1; j<BUFFER_SIZE; j++){
			if(!num[j]) break;
			p[j-1] = num[j];
		}
		p[j-1]=0;
		
		ret = sem_post(mutex);
		ret = sem_post(empty);
/*		printf("C sem_post:empty ret=%d\n", ret);
		fflush(stdout);
*/	
		if(num[0] == MAX){
			break;
		}
	}
	
	shmdt(p);
	shmctl(id,IPC_RMID);
	
	ret = sem_unlink("mutex");
	printf("mutex unlink ret=%d\n", ret);
	ret = sem_unlink("full");
	printf("full unlink ret=%d\n", ret);
	ret = sem_unlink("empty");
	printf("empty unlink ret=%d\n", ret);
	fflush(stdout);
	
	return 0;
}

