/* $Id: pxy.h,v 1.8 2004/05/27 14:18:43 mjt Exp $
 * open proxy checker, common definitions.
 * Michael Tokarev  <mjt@corpit.ru>.
 * This code may be freely used and distributed according to
 * the terms of General Public License (GPL) version 2 or later.
 */

#ifndef _PXY_H
#define _PXY_H

#include "event.h"

#if !defined(__GNUC__) && !defined(__attribute__)
# define __attribute__(c)
#endif
#ifndef UNUSED
# define UNUSED __attribute__((unused))
#endif
#ifndef PRINTFLIKE
# define PRINTFLIKE(f,v) __attribute__((format(printf,f,v)))
#endif

typedef struct pxyconn pxyconn_t;

typedef unsigned short ipport_t;

typedef struct {
  unsigned len;	/* current length in buffer */
  char buf[128-3*sizeof(unsigned)]; /* the buffer itself */
} pxybuf_t;

extern char pxybuf[8193];

/* Proxy protocol definition. */
typedef struct {
  const char *name;	/* "canonical" name of a protocol */
  const char *aname;	/* alternative name */
  const char *transport;/* http */
  const char *fullname;	/* HTTP CONNECT */
  int family;		/* internal code: "family" of proto, HTTP, FTP, etc */
  void (*handler)(pxyconn_t *, int); /* protocol handler */
  int (*check)(pxyconn_t *c, char *buf, int l);
} pxyproto_t;

extern const pxyproto_t pxyprotos[]; /* array of all supported protocols */

typedef struct {
  const pxyproto_t *proto;
  const ipport_t *ports;
  int advanced;
} pxyprobe_t;

extern const pxyprobe_t pxyprobes[];

/* Active proxy connection structure.
 * There aren't many of those: upper limit is the
 * number of open files.
 * The structure supposed to be "embedded" into another
 * structure with additional data for higher-level protocol
 * handled by hlcbck routine.
 */
struct pxyconn {
  int fd;			/* filedescriptor */
  struct in_addr pxyaddr;	/* address of a proxy */
  struct in_addr dstaddr;	/* address of destination */
  ipport_t pxyport;		/* port number of a proxy */
  ipport_t dstport;		/* port number of destination */
  const pxyproto_t *proto;	/* proxy protocol description */
  pxybuf_t *buf;		/* buffer holding data read from net */
  int pxystate;			/* current proxy protocol state */
  int appstate;			/* current application protocol state */
  int nread;			/* number of bytes read so far */
  void *data;			/* app-supplied data */
  char *detail;			/* strdup'ed additional info if any */
  struct ev_tm timer;		/* I/O timer */
  pxyconn_t *next;		/* for linked lists, app usage */
};

extern int pxytimeout;

/* almost all routines returns > 0 on ok and 0 on error;
 * in error case, pxyaction will be called automatically. */

/* allocate new connection structure */
pxyconn_t *pxynew();

/* free connection resources, timers etc */
void pxyfree(pxyconn_t *c);

/* start new connection attempt */
int pxystart(pxyconn_t *c, int fd);

/* renew a timer; if tmo==0, use pxytimeout */
int pxyrenew(pxyconn_t *c, int tmo, void (*tmfn)(pxyconn_t*));

int pxyreqio(pxyconn_t *c, int e, void(*fn)(pxyconn_t*,int));

int
pxyreqiot(pxyconn_t *c, int e, void(*iofn)(pxyconn_t*,int),
          int tmo, void(*tmfn)(pxyconn_t*));

/* read bytes from connection, return number of bytes read (>=0)
   or call pxyaction and return -1.  In case of EAGAIN, returns 0
   if minlen == 0, or -1 as error */
int pxyread(pxyconn_t *c, char *buf, int l, int minlen, int loglevel);

/* read next chunk of bytes into pxybuf[] together with saved data,
   return number of bytes available (>0) or call pxyaction and
   return 0 */
int pxyreadnext(pxyconn_t *c, int minlen, int *tlen, int loglevel);

/* save data from buf of len `len', at most max bytes, within
   connection structure.  Calls pxyaction on error */
int pxysave(pxyconn_t *c, char *buf, unsigned len, unsigned max);

/* write something from buf of length len to the remote, with logging */
int pxywrite(pxyconn_t *c, const char *buf, int len, int loglevel);
int pxyprintf(pxyconn_t *c, int loglevel, const char *fmt, ...)
	PRINTFLIKE(3,4);

/* app-supplied: */
void pxyinfo(const pxyconn_t *c, int level, const char *fmt, ...)
	PRINTFLIKE(3,4);
void pxyaction(pxyconn_t *c, int result);
 /* 0 - connected, 1 - done, 2 - definitely not open, -1 - err.
  * Should free connection in case result != 0, or change event
  * callback if == 0. */
int pxygetdata(pxyconn_t *c);
 /* fills in pxybuf[] with app-data for one-shot proxies and
  * returns length of it */
void pxycheckdata(pxyconn_t *c);
 /* all-in-once result check */

/* log the raw io: direction is 0 for read and 1 for write */
void pxyvio(pxyconn_t *c, int loglevel, int direction,
	    const char *buf, int bufl);

#endif
