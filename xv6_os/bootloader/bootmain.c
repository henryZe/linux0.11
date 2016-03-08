/*	Boot loader.

	Part of the boot sector, along with bootasm.S, which calls bootmain().
	bootasm.S has put the processor into protected 32-bit mode.
	bootmain() loads an ELF kernel image from the disk starting at
	sector 1 and then jumps to the kernel entry routine.
*/

#include <types.h>
#include <elf.h>
#include <x86.h>
#include <memlayout.h>

#define SECTSIZE	512

void readseg(uchar *, uint, uint);

void bootmain(void)
{
	struct elfhdr *elf;



	return 0;
}






