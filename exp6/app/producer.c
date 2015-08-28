#include "shm_mine.h"

int main()
{
	int i,j;
	int fd;
	int ret;	
	int id;
	int *p;
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
	printf("P:mutex=%d full=%d empty=%d\n", mutex, full, empty);

	/* sys_shmget */	
	id = shmget(key,SHM_SIZE,0);
	if(id == -1){
		printf("shmget_errno = %d\n", errno);
		return -1;
	}
	printf("shm_id = %d\n", id);

	/* sys_shmat */	
	p = (int *)shmat(id,NULL,0);
	if((int)p == -1){
		printf("shmat_errno = %d\n", errno);
		return -1;
	}

	memset(p, 0, SHM_SIZE);
	
	for(i=1; i<MAX+1; i++){
		ret = sem_wait(empty);
		ret = sem_wait(mutex);
/*		printf("P sem_wait:mutex ret=%d\n", ret);
		fflush(stdout);
*/			
		for(j=0; p[j]; j++); /*{printf("p[%d] = %d\n", j, p[j]);}*/
		p[j] = i;
	/*	printf("set:p[%d]=%d\n", j, i);
		fflush(stdout);
	*/	
		ret = sem_post(mutex);
		ret = sem_post(full);
/*		printf("P sem_post:full ret=%d\n", ret);
		fflush(stdout);
*/	}
	
	shmdt(p);
	
	return 0;
}

