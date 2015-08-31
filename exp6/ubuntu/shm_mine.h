#ifndef _SHM_MINE_H
#define _SHM_MINE_H

#define SHM_SIZE	1024
#define PATH_NAME	"."
#define PROJ_ID		1
#define MAX 		500
#define BUFFER_SIZE	10
#define mutex		0
#define full		1
#define empty		2

union semun 
{
	int val;
	struct semid_ds *buf;
	unsigned short *array;
	struct seminfo *__buf;
};

int sem_P(int semid,int numsem)
{
	struct sembuf a;
	
	a.sem_num = numsem;
	a.sem_op = -1;
	a.sem_flg = 0;

	return semop(semid,&a,1);
}

int sem_V(int semid,int numsem)
{
	struct sembuf a;

	a.sem_num = numsem;
	a.sem_op = 1;
	a.sem_flg = 0;

	return semop(semid,&a,1);
}

#endif
