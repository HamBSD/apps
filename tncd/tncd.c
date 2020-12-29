#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <vis.h>

#include <sys/event.h>

#include "log.h"

/* KISS special characters */
#define KISSFEND 0xC0 /* frame end */
#define KISSFESC 0xDB /* frame escape */
#define KISSTFEND 0xDC /* transposed frame end */
#define KISSTFESC 0xDD /* transposed frame escape */

/* KISS commands */
#define KISSCMD_DATA  0x00
#define KISSCMD_TXDELAY  0x01 /* in 10 ms units */
#define KISSCMD_PERSIST  0x02 /* used for CSMA */
#define KISSCMD_SLOTTIME 0x03 /* in 10 ms units */
#define KISSCMD_TXTAIL  0x04 /* in 10 ms units */
#define KISSCMD_FULLDUPLEX 0x05 /* 0=half, anything else=full */
#define KISSCMD_SETHARDWARE 0x06 /* this is not implemented anywhere here */
#define KISSCMD_RETURN  0xFF /* on all ports */

int tfd, nfd; /* KISS TNC and network pd file descriptors */

void ether_output(unsigned char *, int);

static __dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-Dv] callsign\n", __progname);
	exit(1);
}

void ether_input(unsigned char *buffer, int len)
{
	unsigned char *c;
	write(tfd, "\xC0\x00", 2);
	/* Strip Ethernet and BPQ header. */
	/* TODO: Check destination address and Ethertype. */
	buffer += 16;
	len -= 16;
	for (c = buffer; c < buffer + len; ++c) {
		switch (*c) {
		case KISSFESC:
			write(tfd, "\xDB\xDD", 2);
			break;
		case KISSFEND:
			write(tfd, "\xDB\xDC", 2);
			break;
		default:
			write(tfd, c, 1);
		}
	}
	write(tfd, "\xC0", 1);
}

int
kiss_decode(unsigned char *dst, unsigned char *src, int len)
{
	int i, j;
	for (i = j = 0; i < len; i++) {
		if (src[i] == KISSFESC) {
			switch (src[++i]) {
			case KISSTFESC:
				dst[j++] = KISSFESC;
				break;
			case KISSTFEND:
				dst[j++] = KISSFEND;
				break;
			}
		} else {
			dst[j++] = src[i];
		}
	}
	return j;
}

void kiss_input(unsigned char *rawbuf, int rawlen)
{
	static ssize_t framelen = -2;
	static unsigned char framebuf[255];
	unsigned char debugbuf[1021];
	int i;
	if (rawlen == -1) {
		log_debug("kiss_input: reset");
		framelen = -2;
		return;
	}
	log_debug("kiss_input: %d bytes", rawlen);
	for (i = 0; i < rawlen; i++) {
		switch (framelen) {
		case -2:
			if (rawbuf[i] == KISSFEND) {
				framelen = -1;
				log_debug("kiss_input: first frame end received, ready for command");
			}
			break;
		case -1:
			if (rawbuf[i] == KISSFEND) {
				log_debug("kiss_input: another frame end, no state change");
				continue;
			}
			if (rawbuf[i] == KISSCMD_DATA) {
				framelen = 0;
				log_debug("kiss_input: received data command");
			} else {
				framelen = -2;
				log_debug("kiss_input: received unknown command %d", rawbuf[i]);
			}
			break;
		default:
			switch (rawbuf[i]) {
			case KISSFEND:
				if (framelen > 14) {
					strvisx(debugbuf, framebuf, framelen, VIS_WHITE | VIS_OCTAL);
					log_debug("kiss_input: frame: %s", debugbuf);
					ether_output(framebuf, framelen);
				} else {
					log_debug("kiss_input: dropped frame less than 14 bytes");
				}
				framelen = -1;
				log_debug("kiss_input: ready for command");
				break;
			default:
				framebuf[framelen++] = rawbuf[i];
				break;
			}
			break;
		}
	}
}

void ether_output(unsigned char *framebuf, int framelen) {
	unsigned char etherbuf[1500];
	memcpy(etherbuf, "\x01\x42\x50\x51\x00\x00", 6); /* BPQ Multicast */
	memcpy(&etherbuf[6], "\x00\x00\x00\x00\x00\x00", 6); /* Source Address */
	memcpy(&etherbuf[12], "\x08\xff\x00\x00", 4); /* BPQ Ethernet EtherType */
	framelen = kiss_decode(&etherbuf[16], framebuf, framelen);
	write(nfd, etherbuf, 16 + framelen);
}

static void
tnc_loop(void)
{
	struct kevent chlist[2];
	struct kevent evlist[2];
	int evi, kq, nbytes, nev;
	unsigned char buffer[255];

	log_debug("looping now");

	if ((kq = kqueue()) == -1)
		fatal("kqueue");

	EV_SET(&chlist[0], tfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
	EV_SET(&chlist[1], nfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);

	while ((nev = kevent(kq, chlist, 2, evlist, 2, NULL)) > 0)
	{
		for (evi = 0; evi < nev; evi++) {
			if (evlist[evi].ident == tfd) {
				nbytes = read(tfd, buffer, sizeof(buffer));
				kiss_input(buffer, nbytes);
			} else if (evlist[evi].ident == nfd) {
				nbytes = read(nfd, buffer, sizeof(buffer));
				ether_input(buffer, nbytes);
			}
		}
		log_debug("looped");
	}
}

int
main(int argc, char **argv)
{
	struct termios options;
	int debug, verbose;
	char ch;

	debug = 0; /* stay in foreground */
	verbose = 0; /* debug level logging */

	while ((ch = getopt(argc, argv, "Dv")) != -1) {
		switch (ch) {
		case 'D':
			debug = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	log_debug("log init");

	/* Check for root privileges. */
	if (geteuid())
		fatalx("need root privileges");

	/* Open the TNC port. */
	if ((tfd = open(argv[0], O_RDWR | O_NOCTTY | O_NDELAY)) == -1)
		fatal("could not open port: %s", argv[0]);
	if (fcntl(tfd, F_SETFL, 0) == -1)
		fatal("fcntl");

	/* Set terminal options for raw I/O. */
	tcgetattr(tfd, &options);
	/* These values come from the Serial Programming Guide but perhaps
	 * cfmakeraw() does exactly this and would reduce the hardcoded
         * values here. */
	options.c_cflag |= (CLOCAL | CREAD);
	options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
	options.c_oflag &= ~OPOST;
	options.c_cc[VMIN] = 0;
	options.c_cc[VTIME] = 10;
	if (tcsetattr(tfd, TCSANOW, &options) == -1)
		fatal("tcsetattr");

	/* Open the tap device. */
	nfd = open("/dev/tap0", O_RDWR);

	/* TODO: Should look up MAC address to use here. */

	tnc_loop();
}
