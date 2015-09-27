#include <linux/kernel.h>
#include <F12_func.h>

unsigned char F12_mask = 0;

void my_func(void)
{
	F12_mask = !F12_mask;
//	printk("F12 func %d\n", F12_mask);
}

void printk_F12(void)
{
	printk("F12=%d\n", F12_mask);
}

