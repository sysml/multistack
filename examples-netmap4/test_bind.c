#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/netmap.h>
#include <net/multistack.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define DEFAULT_VPORT	"valem:mp0"

int
main(int argc, char **argv)
{
	int fd, nfd;
	struct sockaddr_storage ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
	struct nmreq nmr;
	int mmap_size;
	char *mmap_addr;
	struct msreq msr;

	if (argc != 3) {
		fprintf(stderr, "Usage: ./test_bind addr port\n");
		return 1;
	}
	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (!fd) {
		perror("socket");
		return 0;
	}
	sin->sin_family = AF_INET;
	sin->sin_port = htons(atoi(argv[2]));
	if (inet_pton(AF_INET, argv[1], &sin->sin_addr) != 1) {
		perror("inet_pton");
		close(fd);
		return 0;
	}
	printf("binding %s %u\n", argv[1], atoi(argv[2]));
	if (bind(fd, (struct sockaddr *)sin, sizeof(*sin))) {
		perror("bind");
		close(fd);
		return 0;
	}

	nfd = open("/dev/netmap", O_RDWR);
	if (nfd < 0) {
		perror("open");
		close(fd);
		return 0;
	}
	bzero(&nmr, sizeof(nmr));
	nmr.nr_version = NETMAP_API;
	strncpy(nmr.nr_name, DEFAULT_VPORT, strlen(DEFAULT_VPORT));
	if (ioctl(nfd, NIOCREGIF, &nmr)) {
		perror("ioctl");
		close(nfd);
		close(fd);
		return 0;
	}
	bzero(&nmr, sizeof(nmr));
	nmr.nr_version = NETMAP_API;
	strncpy(nmr.nr_name, DEFAULT_VPORT, strlen(DEFAULT_VPORT));
	if (ioctl(nfd, NIOCGINFO, &nmr)) {
		perror("ioctl");
		close(fd);
		close(nfd);
		return 0;
	}
	printf("mmapping\n");
	mmap_size = nmr.nr_memsize;
	mmap_addr = (char *) mmap(0, nmr.nr_memsize, PROT_WRITE | PROT_READ,
				MAP_SHARED, nfd, 0);
	if (mmap_addr == MAP_FAILED) {
		perror("mmap");
		close(fd);
		close(nfd);
		return 0;
	}
	bzero(&nmr, sizeof(nmr));
	nmr.nr_version = NETMAP_API;
	strncpy(nmr.nr_name, DEFAULT_VPORT, strlen(DEFAULT_VPORT));
	if (ioctl(nfd, NIOCREGIF, &nmr)) {
		perror("ioctl");
		munmap(mmap_addr, mmap_size);
		close(nfd);
		close(fd);
		return 0;
	}

	sin->sin_port = htons(atoi(argv[2]));
	strncpy(msr.mr_name, nmr.nr_name, sizeof(msr.mr_name));
	msr.mr_cmd = MSTACK_BIND;
	msr.mr_sin = *sin;
	msr.mr_proto = IPPROTO_TCP;

	if (ioctl(nfd, NIOCCONFIG, &msr)) {
		perror("ioctl");
	}

	msr.mr_cmd = MSTACK_UNBIND;
	if (ioctl(nfd, NIOCCONFIG, &msr)) {
		perror("ioctl");
	}

	munmap(mmap_addr, mmap_size);
	close(nfd);
	close(fd);
	return 0;
}
