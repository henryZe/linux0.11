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

struct semwait_q
{
	struct task_struct *task;
	struct semwait_q *next;
};

typedef struct 
{
	char name[SIZE_NAM];
	int value;
	int used;
	struct semwait_q *head;
}sem_t;

static sem_t semtable[SIZE_SEM];

struct semwait_q *create_list(void)
{
	struct semwait_q *node;
	node = (struct semwait_q *)malloc(sizeof(struct semwait_q));
	node->task = NULL;
	node->next = NULL;
	
	return node;	
}

int list_add(struct task_struct *new_task, struct semwait_q *head)
{
	struct semwait_q *new = (struct semwait_q *)malloc(sizeof(struct semwait_q));
	new->task = new_task;
	new->next = head->next;
	head->next = new;

	return 0;
}

struct semwait_q *list_del(struct semwait_q *head)
{
	struct semwait_q *node = head->next;
	head->next = node->next;
	node->next = NULL;
	
	return node;
}

static int init_semtable = 1;

int sys_sem_open(char *name, unsigned int value)
{
	int i=0,j;
	char k_name[SIZE_NAM];
	
	if(init_semtable){
		init_semtable = 0;
		for(i=0; i<SIZE_SEM; i++){
			semtable[i].used = 0;
		}
		i=0;
	}

	while(get_fs_byte(name+i) != '\0'){
		k_name[i] = get_fs_byte(name+i);
		i++;
	}
	k_name[i] = 0;

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
//			printk("%d used=%d\n", j, semtable[j].used);
			if(!semtable[j].used){
				semtable[j].used = 1;
				semtable[j].value = value;
				semtable[j].head = create_list();
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
	int schd=0;

	cli();
	semtable[sd].value--;
	//printk("fw %d %d %d ", sd, semtable[sd].value, current->pid);
	if(semtable[sd].value < 0){
		current->state = TASK_INTERRUPTIBLE;
		list_add(current, semtable[sd].head);
		schd = 1;
	}
	sti();

	if(schd)
		schedule();

	return 0; 
}

int sys_sem_post(int sd)
{
	struct semwait_q *node;

	cli();
	semtable[sd].value++;
	//printk("fp %d %d %d ", sd, semtable[sd].value, current->pid);
	if(semtable[sd].value<=0){
		node = list_del(semtable[sd].head);
		node->task->state = TASK_RUNNING;
		free(node);
	}
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
		return -EINVAL;
	}

	for(i=0; i<SIZE_SEM; i++){
		if(semtable[i].used){
			if(!strcmp(semtable[i].name, k_name)){
				semtable[i].used=0;
				while(semtable[i].head->next != NULL){
					sys_sem_post(i);
				}
				free(semtable[i].head);

				return 0;
			}
		}
	}
	
	return -ENOMEM;	
}

