SYSSIZE = 0x3000
ROOT_DEV = 0x306


.globl begtext, begdata, begbss, endtext, enddata, endbss
.text
begtext:
.data
begdata:
.bss
begbss:
.text

SETUPLEN = 1				! nr of setup-sectors
BOOTSEG  = 0x07c0			! original address of boot-sector
INITSEG  = 0x9000			! we move boot here - out of the way
SETUPSEG = 0x9020			! setup starts here
SYSSEG   = 0x1000			! system loaded at 0x10000 (65536).
ENDSEG   = SYSSEG + SYSSIZE		! where to stop loading

entry _start
_start:
! Prepare es Register to Print

	mov	ax,#SETUPSEG
	mov	es,ax
	jmpi	go,SETUPSEG

go:	
! Print some inane message

	mov	ah,#0x03		! read cursor pos
	xor	bh,bh
	int	0x10
	
	mov	cx,#78
	mov	bx,#0x0007		! page 0, attribute 7 (normal)
	mov	bp,#msg1
	mov	ax,#0x1301		! write string, move cursor
	int	0x10

jmp_setup:
	jmp	jmp_setup

sectors:
	.word 0

msg1:
	.byte 13,10,13,10
	.ascii "======================"
	.byte 13,10
	.ascii "  Now is in Setup ... "
	.byte 13,10
	.ascii "======================"
	.byte 13,10,13,10

.org 508
root_dev:
        .word ROOT_DEV
boot_flag:
	.word 0xAA55

.text
endtext:
.data
enddata:
.bss
endbss:
