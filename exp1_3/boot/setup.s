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

SETUPLEN = 4				! nr of setup-sectors
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
	
! Print some inane message

	mov	ah,#0x03		! read cursor pos
	xor	bh,bh
	int	0x10
	
	mov	cx,#78
	mov	bx,#0x0007		! page 0, attribute 7 (normal)
	mov	bp,#msg1
	mov	ax,#0x1301		! write string, move cursor
	int	0x10

gain_argu:
	mov    ax,#INITSEG    
	mov    ds,ax 			!设置ds=0x9000
	mov    ah,#0x03    		!读入光标位置
	xor    bh,bh
	int    0x10        		!调用0x10中断
	mov    [0],dx        		!ds:0x0 将光标位置写入0x90000


	!读入内存大小位置
	mov    ah,#0x88
	int    0x15
	mov    [2],ax			!ds:0x2

	!从0x41处拷贝16个字节（磁盘参数表）
        mov    ax,#0x0000
        mov    ds,ax
        lds    si,[4*0x41]

        mov    ax,#INITSEG
        mov    es,ax
        mov    di,#4
        mov    cx,#0x10                 ! 重复16次
        rep				! ds:[si]=>es:[di]
        movsb

	! Prepare for printing
	mov     ax,#SETUPSEG
        mov     es,ax	

try:
	mov     ah,#0x03                ! read cursor pos
        xor     bh,bh
        int     0x10

print_pos:
        mov     cx,#11
        mov     bx,#0x0008              ! page 0, attribute 7 (normal)
        mov     bp,#msg2
        mov     ax,#0x1301              ! write string, move cursor
        int     0x10

! Prepare ss:bp value to print_hex
	mov	ax,#INITSEG	
	mov	ss,ax

	mov	bp,#0
	mov	ax,#print_pos_end	! &print_pos_end
	push	ax
	jmp	print_hex

print_pos_end:
	mov     ah,#0x03                ! read cursor pos
        xor     bh,bh
        int     0x10

        mov     cx,#14
        mov     bx,#0x0009              ! page 0, attribute 7 (normal)
        mov     bp,#msg3
        mov     ax,#0x1301              ! write string, move cursor
        int     0x10

	mov	bp,#2
	mov	ax,#print_size_end
	push	ax
	jmp	print_hex


print_size_end:
	mov     ah,#0x03                ! read cursor pos
        xor     bh,bh
        int     0x10

        mov     cx,#12
        mov     bx,#0x000a              ! page 0, attribute 7 (normal)
        mov     bp,#msg4
        mov     ax,#0x1301              ! write string, move cursor
        int     0x10

        mov     bp,#4
        mov     ax,#print_disk_1_end
        push    ax
        jmp     print_hex

print_disk_1_end:
	mov     ah,#0x03                ! read cursor pos
        xor     bh,bh
        int     0x10

        mov     cx,#8
        mov     bx,#0x000b              ! page 0, attribute 7 (normal)
        mov     bp,#msg5
        mov     ax,#0x1301              ! write string, move cursor
        int     0x10

        mov     bp,#6
        mov     ax,#print_disk_2_end
        push    ax
        jmp     print_hex

print_disk_2_end:
	mov     ah,#0x03                ! read cursor pos
        xor     bh,bh
        int     0x10

        mov     cx,#10
        mov     bx,#0x000c              ! page 0, attribute 7 (normal)
        mov     bp,#msg6
        mov     ax,#0x1301              ! write string, move cursor
        int     0x10

        mov     bp,#4+0x0E
        mov     ax,#jmp_loop
        push    ax
        jmp     print_hex


					!以16进制方式打印栈顶的16位数
print_hex:
	mov    cx,#4         		! 4个十六进制数字
	mov    dx,(bp)     		! 将(bp)所指的值放入dx中，如果bp是指向栈顶的话

print_digit:
	rol    dx,#4        		! 循环以使低4比特用上 !! 取dx的高4比特移到低4比特处。
	mov    ax,#0xe0f     		! ah = 请求的功能值，al = 半字节(4个比特)掩码。
	and    al,dl        		! 取dl的低4比特值。
	add    al,#0x30     		! 给al数字加上十六进制0x30
	cmp    al,#0x3a
	jl	outp        		!是一个不大于十的数字
	add    al,#0x07      		!是a～f，要多加7
outp: 
	int    0x10
    	loop	print_digit

    	ret

print_nl:
	mov    ax,#0xe0d  		! CR
	int    0x10
	mov    al,#0xa     		! LF
	int    0x10
    	ret


jmp_loop:
	jmp	jmp_loop

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

msg2:
	.byte 13,10
	.ascii "Position:"

msg3:
	.byte 13,10
	.ascii "Memory_size:"

msg4:
	.byte 13,10
	.ascii "Cylinders:"

msg5:
	.byte 13,10
	.ascii "Heads:"

msg6:
	.byte 13,10
	.ascii "Sectors:"


.text
endtext:
.data
enddata:
.bss
endbss:
