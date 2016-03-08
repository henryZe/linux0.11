CC=gcc

BINDIR=./hdc/usr/bin

TARGET=cat sh

FLAG=-I../include

all:$(TARGET)

%:%.c
	$(CC) $< $(FLAG) -o $@
	cp $@ $(BINDIR)

.PHONY:clean
clean:
	-rm $(OBJ)
