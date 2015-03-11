PROGS = pkt-gen test_bind
CLEANFILES = $(PROGS) *.o
CFLAGS = -O2 -pipe
CFLAGS += -Werror -Wall -Wextra
CFLAGS += -I ../sys
CFLAGS += -DMULTISTACK
LDFLAGS = -lpcap -lrt -lpthread

all: $(PROGS)
pkt-gen: pkt-gen.o
	$(CC) $(CFLAGS) -o pkt-gen pkt-gen.o $(LDFLAGS)
test_bind: test_bind.c
	$(CC) $(CFLAGS) -o test_bind test_bind.c
clean:
	-@rm -rf $(CLEANFILES)

