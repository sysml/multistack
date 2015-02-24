PROGS = pkt-gen
CLEANFILES = $(PROGS) *.o
CFLAGS = -O2 -pipe
CFLAGS = -Werror -Wall -Wunused-function
CFLAGS = -I../sys
LDFLAGS = -lpthread -lrt -lpcap
all: $(PROGS)

pkt-gen: pkt-gen.o
	$(CC) $(CFLAGS) -o pkt-gen pkt-gen.o $(LDFLAGS)
clean:
	-@rm -rf $(CLEANFILES)
