.PATH:${.CURDIR}/../common

PROG=	aprsd
SRCS=	aprs.c aprsd.c gps.c log.c parse.y ax25.c
MAN=	aprsd.conf.5 aprsd.8

CPPFLAGS=-I${.CURDIR} -I${.CURDIR}/../common

.include <bsd.prog.mk>
