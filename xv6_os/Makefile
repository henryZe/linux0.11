CC=gcc

BINDIR=./hdc/usr/bin

SRC=$(wildcard usr/*.c)
TARGET=$(patsubst %.c,%,$(SRC))

FLAG=-I./include

all:$(TARGET)

%:%.c
	$(CC) $< $(FLAG) -o $@
	cp $@ $(BINDIR)

.PHONY:clean

clean:
	-rm $(TARGET)
