# $OpenBSD: Makefile,v 1.5 2019/06/17 13:13:03 claudio Exp $

.PATH:		${.CURDIR}/../../../aprsisd ${.CURDIR}/../../../common

PROGS += ax25_to_tnc2_test

.  for p in ${PROGS}
REGRESS_TARGETS += run-regress-$p
.endfor

CFLAGS+= -I${.CURDIR} -I${.CURDIR}/../../../aprsisd -I${.CURDIR}/../../../common
LDADD= -lutil
DPADD+= ${LIBUTIL}

SRCS_ax25_to_tnc2_test=	ax25_to_tnc2_test.c ax25.c tnc2.c
run-regress-ax25_to_tnc2_test: ax25_to_tnc2_test
	./ax25_to_tnc2_test

.include <bsd.regress.mk>
