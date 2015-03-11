#if defined(linux) && defined(__KERNEL__)
#include <linux/in.h>
#else
#include <netinet/in.h>
#endif

#define MULTISTACK_BIND	1
#define MULTISTACK_UNBIND	2

struct msaddr {
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr sa;
	};
	uint8_t protocol;
};

struct msreq {
	char mr_name[IFNAMSIZ];
	union {
		struct msaddr mr_addr;
	} mr_ifru;
	int mr_cmd;
};
#define  mr_sin6	mr_ifru.mr_addr.sin6
#define  mr_sin		mr_ifru.mr_addr.sin
#define  mr_sa		mr_ifru.mr_addr.sa
#define  mr_proto	mr_ifru.mr_addr.protocol

