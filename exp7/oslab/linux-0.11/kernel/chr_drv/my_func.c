#include <linux/kernel.h>
#include <F12_func.h>

unsigned char F11_mask = 0;
unsigned char F12_mask = 0;

void my_func_F11(void)
{
	F11_mask = !F11_mask;
	printk("F11=%d\n", F11_mask);
}

void my_func_F12(void)
{
	F12_mask = !F12_mask;
//	printk("F12=%d\n", F12_mask);
}
