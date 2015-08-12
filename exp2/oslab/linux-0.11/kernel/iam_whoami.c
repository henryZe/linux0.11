/*
 *  linux/kernel/iam_whoami.c
 *
 *  henry
 */

#include <unistd.h>
#include <errno.h>
#include <asm/segment.h>
#include <linux/kernel.h>
#include <string.h>


static char name_g[24] = {0};

int sys_iam(const char *name)
{
	int i = 0;

	while(get_fs_byte(name+i) != '\0')
	{
		i++;
		if(i>=sizeof(name_g))
		{
			return -EINVAL;
		}
	}

	memset(name_g, 0, sizeof(name_g));
	i=0;

	while(get_fs_byte(name+i) != '\0')
	{
		name_g[i] = get_fs_byte(name+i);
		i++;
	}
	
//	printk("has recv %s\n", name_g);
	
	return strlen(name_g);
}

int sys_whoami(char* name, unsigned int size)
{	
	int i = 0;

	if(size<strlen(name_g))
	{
		return -EINVAL;
	}
	
//	printk("the name is %s.\n", name_g);
	while(name_g[i] != '\0')
	{
		put_fs_byte(name_g[i], name+i);
		i++;
	}

	return i;
}

