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
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <net/multistack.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define DEFAULT_VPORT	"valem:mp0"
#define TEST_TIME	2

int
main(int argc, char **argv)
{
	int fd;
	struct sockaddr_storage ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
	struct msreq msr;
	struct nm_desc *nmd;
	int i;
	uint16_t lport;

	if (argc != 3) {
		fprintf(stderr, "Usage: ./test_bind addr port\n");
		return 1;
	}
       	lport = (uint16_t)atoi(argv[2]);
	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (!fd) {
		perror("socket");
		return 0;
	}
	sin->sin_family = AF_INET;
	sin->sin_port = htons(lport);
	if (inet_pton(AF_INET, argv[1], &sin->sin_addr) != 1) {
		perror("inet_pton");
		close(fd);
		return 0;
	}
	printf("bind()ing %s %u\n", argv[1], lport);
	if (bind(fd, (struct sockaddr *)sin, sizeof(*sin))) {
		perror("bind");
		close(fd);
		return 0;
	}

	nmd = nm_open(DEFAULT_VPORT, NULL, 0, NULL);
	if (nmd == NULL) {
		fprintf(stderr, "Unable to open %s\n", DEFAULT_VPORT);
		close(fd);
		return -1;
	}

	strncpy(msr.mr_name, nmd->req.nr_name, sizeof(msr.mr_name));
	for (i = 0; i < TEST_TIME; i++) {
		printf("MultiStack-bind()ing %s %u\n", argv[1], lport + i);
		sin->sin_port = htons(lport + i);
		msr.mr_cmd = MULTISTACK_BIND;
		msr.mr_sin = *sin;
		msr.mr_proto = IPPROTO_TCP;

		if (ioctl(nmd->fd, NIOCCONFIG, &msr)) {
			perror("ioctl");
			continue;
		}
		printf("success for port %d\n", lport + i);

		msr.mr_cmd = MULTISTACK_UNBIND;
		if (ioctl(nmd->fd, NIOCCONFIG, &msr)) {
			perror("ioctl");
		}
	}

	munmap(nmd->mem, nmd->req.nr_memsize);
	close(nmd->fd);
	close(fd);
	/*
	munmap(mmap_addr, mmap_size);
	close(nfd);
	close(fd);
	*/
	return 0;
}
