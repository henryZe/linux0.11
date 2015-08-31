#include "shm_mine.h"

int main()
{
	int j, ret, read_num;
	int *p;
	int num[10];
	int fd,id;
	int mutex, full, empty;
	key_t key = PROJ_ID;
	
	
	/* sys_sem_open */
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

/*	printf("source %d\n", getpid());
*/	for(j=0; j<9; j++){
		if(!fork()) break;
	}
/*	printf("c %d\n", getpid());
*/
	/* sys_shmget */
	id = shmget(key,SHM_SIZE,0);
	if(id == -1){
		printf("shmget_errno = %d\n", errno);
		return -1;
	}
/*	printf("%d id = %d\n", getpid(), id);
*/	p = (int *)shmat(id,NULL,0);
	if((int)p == -1){
		printf("shmat_errno = %d\n", errno);
		return -1;
	}
	
	while(1){
/*		printf("C %d:wait full\t", getpid());
*/		
		/* sys_sem_wait */
		ret = sem_wait(full); 
		
/*		printf("C %d:wait mutex\t", getpid());
*/		ret = sem_wait(mutex);
/*		printf("C sem_wait:mutex=%d ret=%d\n", mutex, ret);
		fflush(stdout);
*/			
		memset(num, 0, sizeof(num));
	
/*		printf("out %d:", getpid());
*/		for(j=0; j<BUFFER_SIZE; j++){
			if(!p[j]) break;
			num[j] = p[j];
/*			printf("%d ", num[j]);
*/		}
/*		printf("\n");
*/		printf("out %d:%d\n", getpid(), num[0]);
		fflush(stdout);
		
		for(j=1; j<BUFFER_SIZE; j++){
			if(!num[j]) break;
			p[j-1] = num[j];
		}
		p[j-1]=0;
		
		ret = sem_post(mutex);
		ret = sem_post(empty);
/*		printf("C %d:post\n", getpid());
		fflush(stdout);
*/	
		if(num[0] == MAX){
/*			printf("pid:%d break\n", getpid());
*/			break;
		}
	}
/*	printf("\n");
*/
	/* sys_shmdt */	
/*	p[0] = 1000;
	printf("before test:p[0]=%d\n", p[0]);
*/	ret = shmdt(p);
	if(ret == -1){
		printf("shmdt error = %d\n", errno);
	}
	
/*	printf("A test:p[0]=%d\n", p[0]);
	p = (int *)shmat(id,NULL,0);
	printf("B test:p[0]=%d\n", p[0]);
*/	
	/* sys_shmctl */
	ret = shmctl(id,IPC_RMID);
	if(ret == -1){
		printf("shmctl error = %d\n", errno);
	}
/*	printf("ctl test:p[0]=%d\n", p[0]);
*/
	
	/* sys_sem_unlink */	
	ret = sem_unlink("mutex");
	ret = sem_unlink("full");
	ret = sem_unlink("empty");
	fflush(stdout);
	
	return 0;			/* all processes quit */
}

