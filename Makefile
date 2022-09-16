src = $(wildcard *.c)
obj = $(src:.c=.o)

LDFLAGS = -lz -lm

CC = gcc

myprog: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) myprog