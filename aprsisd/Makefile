.PATH:${.CURDIR}/../common

PROG=	aprsisd
SRCS=	aprsisd.c log.c tnc2.c ax25.c
MAN=	aprsis-filter.7 aprsisd.8

CPPFLAGS=-I${.CURDIR} -I${.CURDIR}/../common

LDFLAGS=-ltls

.include <bsd.prog.mk>
