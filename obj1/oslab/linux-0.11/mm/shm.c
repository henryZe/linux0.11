#include <linux/kernel.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <a.out.h>
#include <linux/sched.h>

#define SHM_NUM		20
#define IPC_RMID	0

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
	if(!shmid_arr[key%SHM_NUM].phy_addr)
		return -ENOMEM;

	shmid_arr[key%SHM_NUM].shmid = key%SHM_NUM+1;
	shmid_arr[key%SHM_NUM].size = size;
	
//	printk("%d shmid_arr[%d].phy_addr = %x\n", current->pid, key%SHM_NUM, shmid_arr[key%SHM_NUM].phy_addr);
			
	return shmid_arr[key%SHM_NUM].shmid;
}

void *sys_shmat(int shmid, void *shmaddr, int shmflg)
{
	if(shmid<=0)
		return (void *)-EINVAL;
	if(!shmid_arr[shmid-1].shmid)
		return (void *)-EINVAL;
	
	unsigned long data_base, seg_addr;

	data_base = get_base(current->ldt[2]);
	seg_addr = data_base + current->brk;			//equel to virtual address
	if(!put_page(shmid_arr[shmid-1].phy_addr, seg_addr))	//map physics addr to virtual addr
		return (void *)-ENOMEM;
	
	current->brk += PAGE_SIZE;
	//printk("new brk = %x\n", current->brk);
	
	return (void *)(seg_addr-data_base);			//return the address in the special segment
}

int remove_page(unsigned long vir_addr)				//on the basis of put_page
{
	unsigned long * page_table;
	
	page_table = (unsigned long *)((vir_addr>>20)&0xffc);	//gain the directory's address
	if((*page_table)&1){					//if the directory is exist, then gain the directory first page's address
		page_table = (unsigned long *)((*page_table)&0xfffff000);
	}

	page_table[(vir_addr>>12)&0x3ff] = 0;			//clean the phy_addr of this page (two level page table mechanism)
	
	return 0;
}

int sys_shmdt(void *shmaddr)
{
	unsigned long data_base, seg_addr, vir_addr;
	
	data_base = get_base(current->ldt[2]);	
	seg_addr = current->brk - PAGE_SIZE;
	if((unsigned long)shmaddr<=seg_addr){
		vir_addr = (unsigned long)shmaddr+data_base;
//		free_page_tables(vir_addr&0xffc00000, PAGE_SIZE);	//include free_page, inadequacy
		remove_page(vir_addr);
		current->brk -= PAGE_SIZE;
		
		return 0;
	}
		
	return -EINVAL;	
}

int sys_shmctl(int shmid, int cmd)
{
	if(cmd != IPC_RMID)
		return -EINVAL;
	if(shmid<=0)
		return -EINVAL;
	if(!shmid_arr[shmid-1].shmid)
		return -ENOMEM;
	if(!shmid_arr[shmid-1].phy_addr)
		return -EINVAL;
		
	free_page(shmid_arr[shmid-1].phy_addr);
	
	shmid_arr[shmid-1].shmid = 0;
	shmid_arr[shmid-1].size = 0;	
	shmid_arr[shmid-1].phy_addr = 0;
		
	return 0;
}

