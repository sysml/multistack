.PATH: .
KMOD=	multistack
SRCS=	multistack.c
SRCS+=	opt_inet.h opt_inet6.h opt_sctp.h opt_compat.h opt_ipsec.h
TARGET!=	uname -m
IDENT!=		uname -i
CFLAGS+= -I$(KSRC)
CFLAGS+= -I../../../sys/
CFLAGS+= -I$(KSRC)/sys/$(TARGET)/compile/$(IDENT)
CFLAGS+= $(NMVER)

.include <bsd.kmod.mk>
