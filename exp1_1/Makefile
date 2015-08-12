all: 
	as86 -0 -a -o bootsect.o bootsect.s
	ld86 -0 -s -o bootsect bootsect.o
	dd bs=1 if=bootsect of=Image skip=32
	cp Image /home/henry/oslab/linux-0.11

clean:
	rm bootsect.o bootsect Image
