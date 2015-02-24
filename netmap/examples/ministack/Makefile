CFLAGS += -Werror -Wall -O3
LDFLAGS += -lpthread -lpcap
LDFLAGS += -lrt # for clock_gettime()
PROG = pkt-gen-prot
OBJS = pkt-gen-prot.o tcpsrlib.o tcplib.o dttcp.o
#OPT = -DMSTACK -DTCPLIB_NETMAP
OPT = -DMSTACK -DTCPLIB_NETMAP -DTCP_PROFILE

all: $(PROG)

pkt-gen-prot: pkt-gen-prot.o tcpsrlib.o tcplib.o dttcp.o
	$(CC) $(CFLAGS) -o pkt-gen-prot pkt-gen-prot.o tcpsrlib.o tcplib.o dttcp.o $(LDFLAGS)
pkt-gen-prot.o: pkt-gen-prot.c dttcp.c tcplib.c tcplib.h dttcp.h
	$(CC) $(CFLAGS) $(OPT) -c pkt-gen-prot.c
dttcp.o: dttcp.c tcplib.c dttcp.h tcplib.h
	$(CC) $(CFLAGS) $(OPT) -c dttcp.c
tcpsrlib.o: tcpsrlib.c tcplib.h
	$(CC) $(CFLAGS) -c tcpsrlib.c
tcplib.o: tcplib.c tcplib.h
	$(CC) $(CFLAGS) $(OPT) -c tcplib.c

clean:
	-@rm -f $(PROG) $(OBJS)
