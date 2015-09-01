#include <linux/kernel.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <a.out.h>
#include <linux/sched.h>

#define SHM_NUM		20

typedef struct 
{
	unsigned long phy_addr;
	unsigned int size;
	int shmid;
}shm_struct;

static shm_struct shmid_arr[SHM_NUM];
static int init_shm_struct = 1;

int sys_shmget(key_t key, size_t size, int shmflg)
{
	if(init_shm_struct){
		memset(shmid_arr, 0, sizeof(shmid_arr));
		init_shm_struct = 0;
	}

	if(size > PAGE_SIZE)
		return -EINVAL;

	if(shmid_arr[key%SHM_NUM].shmid)
		return shmid_arr[key%SHM_NUM].shmid;

	shmid_arr[key%SHM_NUM].phy_addr = get_free_page();
	if(shmid_arr[key%SHM_NUM].phy_addr)
		return -ENOMEM;

	shmid_arr[key%SHM_NUM].shmid = key%SHM_NUM;
	shmid_arr[key%SHM_NUM].size = size;
		
	return shmid_arr[key%SHM_NUM].shmid;
}

void *sys_shmat(int shmid, void *shmaddr, int shmflg)
{
	if(!shmid_arr[shmid].shmid)
		return (void *)-EINVAL;
	
	unsigned long data_base, vir_addr;

	data_base = get_base(current->ldt[2]);	
	vir_addr = data_base + current->brk;	
	put_page(shmid_arr[shmid].phy_addr, vir_addr);		//建立线性地址和物理地址的映射
	
	current->brk += PAGE_SIZE;
		
	return (void *)vir_addr;
}

int sys_shmdt(void *shmaddr)
{
	unsigned long data_base, vir_addr;
	
	data_base = get_base(current->ldt[2]);	
	vir_addr = data_base + current->brk - PAGE_SIZE;	
	if(((unsigned long)shmaddr<=vir_addr) && ((unsigned long)shmaddr>data_base)){
		free_page_tables((unsigned long)shmaddr, PAGE_SIZE);	
		current->brk -= PAGE_SIZE;
		
		return 0;
	}
		
	return -EINVAL;	
}

int sys_shmctl(int shmid, int cmd)
{
	if(cmd != IPC_RMID)
		return -EINVAL;

	free_page(shmid_arr[shmid].phy_addr);
	
	shmid_arr[shmid].shmid = 0;
	shmid_arr[shmid].size = 0;	
	shmid_arr[shmid].phy_addr = 0;
		
	return 0;
}

