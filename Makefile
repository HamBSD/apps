SUBDIR = aprsisd aprsd tncd

.if make(regress) || make(obj) || make(clean)
SUBDIR += regress
.endif

.include <bsd.subdir.mk>
