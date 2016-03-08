#include ""


int main(void)
{
	/* phys page allocator */
	kinit1(end, P2V(4*1024*1024));

	/* kernel page table */
	kvmalloc();

	/* collect info about this machine */
	mpinit();

	lapicinit();

	/* set up segments */
	seginit();

	cprintf("\ncpu%d: starting xv6\n\n", cpu->id);

	/* interrupt controller */
	picinit();

	/* another interrupt controller */
	ioapicinit();

	/* I/O devices & their interrupts */
	consoleinit();

	/* serial port */
	uartinit();

	/* process table */
	pinit();

	/* trap vectors */
	tvinit();

	/* buffer cache */
	binit();

	/* file table */
	fileinit();

	/* inode cache */
	iinit();

	/* disk */
	ideinit();

}
