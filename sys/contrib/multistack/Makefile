.PATH: .
KMOD=	multistack
SRCS=	multistack.c
TARGET!=	uname -m
IDENT!=		uname -i
CFLAGS+= -I$(KSRC)
CFLAGS+= -I../../../sys/
CFLAGS+= -I$(KSRC)/sys/$(TARGET)/compile/$(IDENT)
CFLAGS+= $(NMVER)

.include <bsd.kmod.mk>
