/*
 *  linux/kernel/sem.c
 *
 *  henry
 */

#include <unistd.h>
#include <errno.h>
#include <asm/segment.h>
#include <asm/system.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <string.h>
#include <sys/stat.h>

#define SIZE_NAM 20
#define SIZE_SEM 20

typedef struct 
{
	char name[SIZE_NAM];
	int value;
	int used;
	struct task_struct *head;
}sem_t;

static sem_t semtable[SIZE_SEM];

static int init_semtable = 1;

int sys_sem_open(char *name, unsigned int value)
{
	int i=0, j;
	char k_name[SIZE_NAM];
	
	if(init_semtable){
		init_semtable = 0;
		for(i=0; i<SIZE_SEM; i++){
			semtable[i].used = 0;
		}
		i=0;
	}

	memset(k_name, 0, sizeof(k_name));
	while(get_fs_byte(name+i) != '\0'){
		k_name[i] = get_fs_byte(name+i);
		i++;
	}
	//printk("k_name[%d] = %d\n", i, k_name[i]);

	if(i>=SIZE_NAM){
		return -EINVAL;
	}

	for(i=0; i<SIZE_SEM; i++){
		if(semtable[i].used){
			if(!strcmp(semtable[i].name, k_name)) break;
		}
	}
	
	if(i>=SIZE_SEM){
		for(j=0; j<SIZE_SEM; j++){
			if(!semtable[j].used){
				semtable[j].used = 1;
				semtable[j].value = value;
				semtable[j].head = NULL;
				strcpy(semtable[j].name, k_name);
				break;
	           	}
	    	}

		if(j>=SIZE_SEM) return -E2BIG;
		
//		printk("sys_sem.c: new sem %s\n", semtable[j].name);
		i=j;
	}
	
	return i;
}

int sys_sem_wait(int sd)
{
	if(!semtable[sd].used)
		return -EINVAL;
	
	cli();
	//printk("bw %d %d %d ", sd, semtable[sd].value, current->pid);
	while(semtable[sd].value<=0)
	{
		sleep_on(&semtable[sd].head);
	}
	semtable[sd].value--;
	sti();

	return 0; 
}

int sys_sem_post(int sd)
{
	if(!semtable[sd].used)
		return -EINVAL;
	
	cli();
	semtable[sd].value++;
	//printk("fp %d %d %d ", sd, semtable[sd].value, current->pid);
	wake_up(&semtable[sd].head);
	sti();

	return 0; 
}

int sys_sem_unlink(char *name)
{
	int i = 0;
	char k_name[SIZE_NAM];
	
	while(get_fs_byte(name+i) != '\0'){
		k_name[i] = get_fs_byte(name+i);
		i++;
	} 
	k_name[i] = 0;

	if(i>=SIZE_NAM){
		return -ENOMEM;
	}

	for(i=0; i<SIZE_SEM; i++){
		if(semtable[i].used){
			if(!strcmp(semtable[i].name, k_name)){
//				printk("sem_unlink %d\n", i);	
				semtable[i].used=0;
				if(semtable[i].head != NULL){
					sys_sem_post(i);
				}

				return 0;
			}
		}
	}
	
	return -EINVAL;	
}

