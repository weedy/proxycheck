/* $Id: pxy.c,v 1.19 2004/05/27 14:18:43 mjt Exp $
 * open proxy checker, proxy protocol routines.
 * Michael Tokarev  <mjt@corpit.ru>.
 * This code may be freely used and distributed according to
 * the terms of General Public License (GPL) version 2 or later.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "event.h"
#include "pxy.h"

int pxytimeout = 30000; /* 30 sec */
char pxybuf[8193];

static void
timedout(pxyconn_t *c) {
  errno = ETIMEDOUT;
  pxyaction(c, -1);
}

int pxyrenew(pxyconn_t *c, int tmo, void (*tmfn)(pxyconn_t *)) {
  if (!tmfn) tmfn = timedout;
  ev_tm_del(0, &c->timer);
  if (ev_tm_add(0, &c->timer, tmo ? tmo : pxytimeout, (ev_tm_cbck_f*)tmfn, c) != NULL)
    return 1;
  else {
    pxyaction(c, -1);
    return 0;
  }
}

pxyconn_t *pxynew() {
  pxyconn_t *c = (pxyconn_t *)malloc(sizeof(pxyconn_t));
  if (c)
    memset(c, 0, sizeof(*c));
  return c;
}

void pxyfree(pxyconn_t *c) {
  ev_tm_del(0, &c->timer);
  if (c->fd >= 0)
    ev_io_del(0, c->fd);
  if (c->detail)
    free(c->detail);
  if (c->buf) {
    free(c->buf);
    c->buf = NULL;
  }
  free(c);
}

int
pxyreqio(pxyconn_t *c, int e, void(*iofn)(pxyconn_t*,int)) {
  if (ev_io_mod(0, c->fd, e, (ev_io_cbck_f*)iofn, c) == 0)
    return 1;
  else {
    pxyaction(c, -1);
    return 0;
  }
}

int
pxyreqiot(pxyconn_t *c, int e, void(*iofn)(pxyconn_t*,int),
          int tmo, void(*tmfn)(pxyconn_t*)) {
  return pxyreqio(c, e, iofn) && pxyrenew(c, tmo, tmfn);
}

int pxywrite(pxyconn_t *c, const char *buf, int len, int level) {
  int r;
  if ((r = write(c->fd, buf, len)) <= 0) {
    pxyaction(c, r < 0 ? -1 : 1);
    return 0;
  }
  else {
    pxyvio(c, level, 1, buf, len);
    return 1;
  }
}

int pxyprintf(pxyconn_t *c, int loglevel, const char *fmt, ...) {
  va_list ap;
  int l;
  va_start(ap, fmt);
  l = vsprintf(pxybuf, fmt, ap);
  va_end(ap);
  return pxywrite(c, pxybuf, l, loglevel);
}

int pxystart(pxyconn_t *c, int fd) {
  c->fd = fd;
  if (ev_io_add(0, fd, EV_OUT, (ev_io_cbck_f*)c->proto->handler, c) != 0) {
    pxyaction(c, -1);
    return 0;
  }
  else
    return pxyrenew(c, pxytimeout/2, NULL);
}

int pxyread(pxyconn_t *c, char *buf, int l, int minlen, int level) {
  l = read(c->fd, buf, l);
  if (l > 0) {
    pxyvio(c, level, 0, buf, l);
    c->nread += l;
  }
  else if (l < 0) {
    if (minlen || errno != EAGAIN) {
      pxyaction(c, -1);
      return -1;
    }
    else
      l = 0;
  }
  else {
    errno = 0;
    pxyaction(c, -1);
    return -1;
  }
  buf[l] = '\0';
  return l;
}

int pxyreadnext(pxyconn_t *c, int minlen, int *tlen, int loglevel) {
  int l, r;
  if (c->buf && (l = c->buf->len) != 0)
    memcpy(pxybuf, c->buf->buf, l);
  else
    l = 0;
  r = pxyread(c, pxybuf + l, sizeof(pxybuf) - l - 1, minlen, loglevel);
  if (r >= 0 && tlen)
    *tlen = r + l;
  return r;
}

int pxysave(pxyconn_t *c, char *buf, unsigned len, unsigned max) {
  if (c->nread > 2048) {
    pxyinfo(c, 2, "too much input");
    pxyaction(c, 2);
    return 0;
  }
  if (buf && len > 0) {
    if (!c->buf && !(c->buf = (pxybuf_t*)malloc(sizeof(pxybuf_t)))) {
      errno = ENOMEM;
      pxyaction(c, -1);
      return 0;
    }
    if (len > sizeof(c->buf->buf)) {
      buf += len - sizeof(c->buf->buf);
      len = sizeof(c->buf->buf);
    }
    if (max && len > max) {
      buf += len - max;
      len = max;
    }
    memcpy(c->buf->buf, buf, len);
    c->buf->len = len;
  }
  else if (c->buf)
    c->buf->len = 0;
  return 1;
}

/* find the string `str' in memory block, case-insensitive
 * (`str' should be lowercased) */
char *memcfind(const char *buf, int l, const char *str) {
  const char *s, *b, *e;
  for (e = buf + l - strlen(str); buf <= e; ++buf) {
#define lc(c) (((c) >= 'A' && (c) <= 'Z') ? (c) - 'A' + 'a' : (c))
    if (lc(*buf) != *str) continue;
    s = str + 1; b = buf + 1;
    for(;;) {
      if (!*s) return (char*)buf;
      if (*s != lc(*b)) break;
      ++s; ++b;
    }
  }
  return NULL;
}

/* parse HTTP headers */
static int httpheaders(pxyconn_t *c, char *buf, int l) {
  char *a;
  int r;
  if (memcmp(buf, "HTTP/", 5) != 0 ||
      !(a = strchr(buf, ' ')) ||
      a > buf + 8 ||
      a[1] < '1' || a[1] > '9' ||
      a[2] < '0' || a[2] > '9' ||
      a[3] < '0' || a[3] > '9' ||
      a[4] != ' ')
    return 0;
  r = (a[1] - '0') * 100 + (a[2] - '0') * 10 + (a[3] - '0');

  /* find Proxy-agent:, Via: headers */
  if ((a = memcfind(buf, l, "\nproxy-agent: ")) ||
      (a = memcfind(buf, l, "\nvia: "))) {
    int via;
    char *e;
    ++a;
    a += (via = *a == 'V' || *a == 'v') ? 5 : 13;
    while(*a == ' ') ++a;
    if (via) {
      while(*a > ' ') ++a;
      while(*a == ' ') ++a;
    }
    e = a;
    while((unsigned char)*e >= ' ' && *e != 0x7f) ++e;
    if (e != a) {
      if (e - a > 60) a[65] = '\0';
      else *e = '\0';
      c->detail = strdup(a);
      pxyinfo(c, 2, "Proxy-agent: %s", a);
    }
  }

  if (r / 100 != 2) {
    /*XX determine whenever this is a permanent or temp error */
    pxyinfo(c, 2, "HTTP request refused or failed (%d)", r);
    /* too bad some proxies return 403 or 404 errors on temp errors */
    if (r == 407 ||
        /* r == 404 || */
        /* r == 403 || */
        r == 400 ||
        r == 302)
      pxyaction(c, 2);
    else
      pxyaction(c, 1);
    return -1;
  }

  return r;
}

static int hcc(pxyconn_t *c, char *buf, int l) {
  int r;
  /* todo:
   *  - headers may come in separate packets;
   *  - detect e.g. "Out of buffers" errors seen from wingate-3.0 (1182)
   *  - detect redirects (status=3xx)
   */
  if (c->pxystate > 1)
    return 0;
  c->pxystate = 2;
  if (memcfind(buf, l, "hwarang/"))
    pxyinfo(c, 2, "probably HwaRang \"lazy\" proxy");
  r = httpheaders(c, buf, l);
  if (!r) return 0;
  if (r < 0) return 1;
  /* 2xx result */
  /*if (r / 100 == 2)*/ {
    if (memcfind(buf, l, "content-length:")
        /* some STUPID software... || memcfind(buf, l, "content-type:") */) {
      pxyinfo(c, 2, "HTTP CONNECT answered with a page (code %d)", r);
      pxyaction(c, 1); /* maybe temp. error message */
      return 1;
    }
    else {
      pxyinfo(c, 2, "HTTP request successeful (%d)", r);
      return 0;
    }
  }
}

static void hch(pxyconn_t *c, int UNUSED e) {
  /* HTTP CONNECT.
   * state:
   *  1 - request sent, want reply
   */
  if (c->pxystate == 0) {
    /* some proxies requires \r\n in separate packet - doh */
    if (pxyprintf(c, 3, "CONNECT %s:%d HTTP/1.0\r\n",
                  inet_ntoa(c->dstaddr), c->dstport) &&
        pxywrite(c, "\r\n", 2, 3) &&
        pxyreqiot(c, EV_IN, hch, 0, NULL))
      c->pxystate = 1;
  }
  else
  /* todo: read headers if any here.
   * requires some logic change: upper-level protocol
   * routines should deal with already read data */
    pxyaction(c, 0);
}

/* HTTP POST/PUT methods */

static int
hxc(pxyconn_t *c, char *buf, int l) {
  int r;
  if (c->pxystate > 2) return 0;
  c->pxystate = 2;
  r = httpheaders(c, buf, l);
  if (!r) return 0;
  if (r < 0) return 1;
  /*if (r / 100 == 2)*/ {
    pxyinfo(c, 2, "HTTP request successeful (%d)", r);
    return 0;
  }
}

static void hxh(pxyconn_t *c, int UNUSED e) {
  if (!c->pxystate) {
    int dl = pxygetdata(c);
    char *b = pxybuf + dl + 1;
    int l = sprintf(b,
"%s http://%s:%d/ HTTP/1.0\r\n"
"Content-length: %d\r\n"
"Connection: close\r\n"
"\r\n",
      strchr(c->proto->fullname, ' ') + 1,
      inet_ntoa(c->dstaddr), c->dstport, dl);
    if (pxywrite(c, b, l, 3)) {
      c->pxystate = 1;
      pxyinfo(c, 3, "sending data");
      if (pxywrite(c, pxybuf, dl, 6))
        pxyreqiot(c, EV_IN, hxh, 0, NULL);
    }
  }
  else
    pxycheckdata(c);
}

static void s5h(pxyconn_t *c, int UNUSED e) {
  /* SOCKS5
   * state:
   *  1 - auth request sent, want reply
   *  2 - connect request sent, want reply
   */
  int l;
  if (!c->pxystate) {
    pxybuf[0] = 5; /* socks version */
    pxybuf[1] = 1; /* nmethods */
    pxybuf[2] = 0; /* no auth reqd */
    if (pxywrite(c, pxybuf, 3, 4) &&
        pxyreqiot(c, EV_IN, s5h, pxytimeout / 2, NULL))
      c->pxystate = 1;
  }
  else if (c->pxystate == 1) {
    if ((l = pxyread(c, pxybuf, 4, 2, 4)) <= 0)
      ;
    else if (pxybuf[1] != 0) {
      pxyinfo(c, 2, "auth rejected (v=%d c=%d%s)",
              (unsigned char)pxybuf[0], (unsigned char)pxybuf[1],
              pxybuf[0] == 0 && pxybuf[1] == 91 ?
                ", socks4-only server" : "");
      pxyaction(c, 2);
    }
    else if (l > 2) {
      pxyinfo(c, 2, "too much socks5 data v=%d c=%d %d %d",
              (unsigned char)pxybuf[0], (unsigned char)pxybuf[1],
              (unsigned char)pxybuf[2], (unsigned char)pxybuf[3]);
      pxyaction(c, 2);
    }
    else {
      ipport_t p = htons(c->dstport);
      pxyinfo(c, 3, "auth accepted");
      pxybuf[0] = 5; /* version */
      pxybuf[1] = 1; /* connect cmd */
      pxybuf[2] = 0; /* reserved */
      pxybuf[3] = 1; /* ipv4 addrtype */
      memcpy(pxybuf+4, &c->dstaddr.s_addr, 4);
      memcpy(pxybuf+8, &p, 2);
      if (pxywrite(c, pxybuf, 10, 4) && pxyrenew(c, 0, NULL))
        c->pxystate = 2;
    }
  }
  else if ((l = pxyread(c, pxybuf, 10, 2, 4)) <= 0)
    ;
  else if (pxybuf[1] == 0) {
    pxyinfo(c, 2, "request granted (v=%d c=%d l=%d)",
            (unsigned char)pxybuf[0], (unsigned char)pxybuf[1], l);
    pxyaction(c, 0);
  }
  else {
    char *s;
    switch(pxybuf[1]) {
    case 1: s = "general server failure"; l = 1; break;
    case 2: s = "connection not allowed by ruleset"; l = 2; break;
    case 3: s = "network unreachable"; l = 1; break;
    case 4: s = "host unreachable"; l = 1; break;
    case 5: s = "connection refused"; l = 1; break;
    case 6: s = "TTL expired"; l = 1; break;
    case 7: s = "command not supported"; l = 2; break;
    case 8: s = "address type not supported"; l = 2; break;
    default: s = "unexpected response"; l = 1; break;
    }
    pxyinfo(c, 2, "%s (v=%d c=%d)", s,
            (unsigned char)pxybuf[0], (unsigned char)pxybuf[1]);
    pxyaction(c, l);
  }
}

static void s4h(pxyconn_t *c, int UNUSED e) {
  /* SOCKS4.
   * state:
   *  1 - connect request sent, want reply
   */
  int l;
  if (!c->pxystate) {
    ipport_t p = htons(c->dstport);
    pxybuf[0] = 4; /* socks version */
    pxybuf[1] = 1; /* request: connect */
    memcpy(pxybuf+2, &p, 2);
    memcpy(pxybuf+4, &c->dstaddr.s_addr, 4);
    pxybuf[8] = 0; /* empty/null username */
    if (pxywrite(c, pxybuf, 9, 4) && pxyreqiot(c, EV_IN, s4h, 0, NULL))
      c->pxystate = 1;
  }
  else if ((l = pxyread(c, pxybuf, 8, 8, 4)) <= 0)
    ;
  else if (pxybuf[1] == 90) {
    pxyinfo(c, 2, "request granted (v=%d c=%d)",
            (unsigned char)pxybuf[0], (unsigned char)pxybuf[1]);
    pxyaction(c, 0);
  }
  else {
    char *s;
    switch(pxybuf[1]) {
    case 91: s = "request rejected or failed"; break;
    case 92: s = "identd required"; break;
    case 93: s = "identd info mismatch"; break;
    case 1:
      if (pxybuf[0] == 5) {
        pxyinfo(c, 2, "request rejected (v=5 c=1, socks5-only server)");
        pxyaction(c, 2);
        return;
      }
    default: s = "unexpected response"; break;
    }
    pxyinfo(c, 2, "%s (v=%d c=%d)", s,
            (unsigned char)pxybuf[0], (unsigned char)pxybuf[1]);
    pxyaction(c, 1);
  }
}

static int
checklist(const char *buf, int l, const char *const lp[]) {
  const char *const *sp = lp;
  while(*sp)
    if (memmem(buf, l, *sp, strlen(*sp)))
      return sp - lp;
    else
      ++sp;
  return -1;
}

static int
wgc(pxyconn_t *c, char *buf, int l) {
  /* look at Password:/etc strings */
  static const char *const wgabort[] = {
   "sername",
   "ogin:",
   "assword:",
   NULL
  };
  if (checklist(buf, l, wgabort) < 0)
    return 0;
  pxyaction(c, 2);
  return 1;
}

static void wgh(pxyconn_t *c, int e);

static void wgh_tmo(pxyconn_t *c) {
  wgh(c, -1);
}

static void wgh(pxyconn_t *c, int e) {
  /* WINGATE/telnet.
   * state:
   *  1 - wait for a prompt, interpret Username:/Login: and similar;
   *   we're waiting for a small timeout here, if not found - go to
   *   next state
   *  2 - connection request sent, wait for reply
   */
  int l;
  if (!c->pxystate) {
    if (pxyreadnext(c, 0, &l, 3) < 0)
      return;
    c->pxystate = 1;
    if (!pxyreqiot(c, EV_IN, wgh, pxytimeout / 8, wgh_tmo) ||
        !l || !pxysave(c, pxybuf, l, 0))
      return;
  }
  if (c->pxystate == 1) {
    if (e < 0) {
      /*XX try to recognize whenever to use telnet or "plain" wingate */
      l = sprintf(pxybuf, "%s:%d\r\n", inet_ntoa(c->dstaddr), c->dstport);
      if (c->pxyport == 23)
        l += sprintf(pxybuf + l, "telnet %s %d\r\n",
                     inet_ntoa(c->dstaddr), c->dstport);
      if (pxywrite(c, pxybuf, l, 3) && pxyrenew(c, 0, NULL))
        c->pxystate = 2;
    }
    else if (pxyreadnext(c, 0, &l, 3) < 0 || wgc(c, pxybuf, l))
      return;
    else {
      static const char *const wggo[] = {
       "cisco>", /*0 wingate-3.0 1181 */
       "MNGTR>", /*1 wingate-3.0 1181 */
       "WinGate>", /*2 wingate 23 */
       "host[:port]:", /*3 telnet 23 */
       "host_name:port", /*4 TelNet Gateway 23*/
       "SpoonProxy>", /*5 host port 23 */
       "tn-gw",  /*6 telnet gateways 23 */
       "telnet>", /*7*/
       "CCProxy Telnet>", /*8 open host port 23 */
       NULL
      };
      const char *d;
      switch(checklist(pxybuf, l, wggo)) {
      case 0:
      case 1:
      case 2:
        if (!pxyprintf(c, 3, "%s:%d\r\n", inet_ntoa(c->dstaddr), c->dstport))
          return;
        d = "host:port (wingate)";
        break;
      case 3:
      case 4:
        if (!pxyprintf(c, 3, "%s:%d\r\n", inet_ntoa(c->dstaddr), c->dstport))
          return;
        d = "host:port (telnet gateway)";
        break;
      case 5:
        if (!pxyprintf(c, 3, "%s %d\r\n",
                       inet_ntoa(c->dstaddr), c->dstport))
          return;
        d = "host port (SpoonProxy)";
        break;
      case 6:
      case 7:
        if (!pxyprintf(c, 3, "telnet %s %d\r\n",
                       inet_ntoa(c->dstaddr), c->dstport))
          return;
        d = "telnet host port (telnet gateway)";
        break;
      case 8:
        if (!pxyprintf(c, 3, "open %s %d\r\n",
                       inet_ntoa(c->dstaddr), c->dstport))
          return;
        d = "open host port (CCProxy)";
        break;
      default:
        return;
      }
      if (pxysave(c, pxybuf, l, 0) && pxyrenew(c, 0, NULL))
        c->pxystate = 2;
      c->detail = strdup(d);
    }
  }
  else
    pxyaction(c, 0);
}

static void fuh(pxyconn_t *c, int UNUSED e) {
  /* FTP proxy.  Wait for initial FTP greething and
   * issue a command:
   *   USER dummy@targethost:targetport\r\n
   * After this, target receives
   *   USER dummy
   * and transparent connection begun.
   * There is no way to use such proxy with protocols
   * dependant on first line from client (e.g. http).
   */
  int l;
  if (!c->pxystate) {
    if (pxyreadnext(c, 0, &l, 3) < 0) /* check if established */
      return;
    c->pxystate = 1;
    if (!pxyreqiot(c, EV_IN, fuh, pxytimeout / 2, NULL) ||
        !l || !pxysave(c, pxybuf, l, 0))
      return;
  }
  if (c->pxystate == 1) {
    if (pxyreadnext(c, 1, &l, 3) > 0 && l > 4) {
      if (memcmp(pxybuf, "220 ", 4) == 0) {
        char *a, *e;
	pxybuf[l] = '\0';
	a = pxybuf + 4;
	if (!(*a >= 'A' && *a <= 'Z') && !(*a >= 'a' && *a <= 'z')) {
	  while(*a && *a != ' ' && *a != '\n' && *a != '\r') ++a;
	  while(*a == ' ') ++a;
	}
	e = a;
	while(*e && *e >= ' ' && *e != 0x7f) ++e;
	if (a != e) {
          if (e - a > 6 && memcmp(e - 6, " ready", 6) == 0)
	    e -= 6;
	  if (e - a > 70) a[65] = '\0';
	  else *e = '\0';
	  pxyinfo(c, 2, "Proxy-agent: %s", a);
	  c->detail = strdup(a);
	}
        pxysave(c, NULL, 0, 0);
        if (pxyprintf(c, 3, "USER dummy@%s:%d\r\n",
                      inet_ntoa(c->dstaddr), c->dstport))
          pxyaction(c, 0);
      }
      else {
        pxyinfo(c, 2, "seems not to be FTP proxy");
        /*XXX handle temp errors? */
        pxyaction(c, 2);
      }
    }
  }
}

enum pxyfamily { pfSOCKS, pfHTTP, pfWG, pfFTP };

const pxyproto_t pxyprotos[] = {
/* name       aname   transport  fullname        family   hdl  chk */
 { "socks5",      "s5", "socks5",  "SOCKS5",       pfSOCKS, s5h, NULL },
#define S5P (pxyprotos+0)
 { "socks4",      "s4", "socks4",  "SOCKS4",       pfSOCKS, s4h, NULL },
#define S4P (pxyprotos+1)
 { "wingate",     "wg", "wingate", "WINGATE",      pfWG,    wgh, wgc },
#define WGP (pxyprotos+2)
 { "http-connect","hc", "http",    "HTTP CONNECT", pfHTTP,  hch, hcc },
#define HCP (pxyprotos+3)
 { "http-post",   "ho", "http",    "HTTP POST",    pfHTTP,  hxh, hxc },
#define HOP (pxyprotos+4)
 { "http-put",    "hu", "http",    "HTTP PUT",     pfHTTP,  hxh, hxc },
#define HUP (pxyprotos+5)
 { "ftp-user",    "fu", "ftp",     "FTP USER",     pfFTP,   fuh, NULL },
#define FUP (pxyprotos+6)
 {0,0,0,0,0,0,0}
};

static const ipport_t
 htc[] = {80,81,1075,3128,4480,6588,7856,8000,8080,8081,8090,0},
 hta[] = {7033,8085,8095,8100,8105,8110,0},
 htaa[] = {/*rizon*/1039,1050,1080,1098,11055,1200,19991,3332,3382,35233,443,444,4471,4480,5000,5490,5634,5800,63000,63809,65506,6588,6654,6661,6663,6664,6665,6667,6668,7070,7868,808,8085,8082,8118,8888,9000,9090,9988,0},
 spp[] = {1080,1075,0},
 spa[] = {/*rizon*/10000,10080,10099,10130,10242,10777,1025,1026,1027,1028,1029,1030,1031,1032,1033,1039,1050,1066,1081,1098,11011,11022,11033,11055,11171,1122,11225,1180,1182,1200,1202,1212,1234,12654,1337,14841,16591,17327,1813,18888,1978,1979,19991,2000,21421,22277,2280,24971,24973,25552,25839,26905,28882,29992,3127,3128,32167,3330,3380,34610,3801,3867,40,4044,41080,41379,43073,43341,443,44548,4471,43371,44765,4914,49699,5353,559,58,6000,62385,63808,6551,6561,6664,6748,6969,7007,7080,8002,8009,8020,8080,8085,8111,8278,8751,8888,9090,9100,9988,9999,59175,0},
 wgp[] = {23,2323,0},
 fup[] = {21,2121,0},
 p1813[] = {1813,0}, /* skk proxy, socks5 only */
 p5490[] = {5490,0}  /* NONAME/1.4, probably trojan - http connect only */
;

const pxyprobe_t pxyprobes[] = {
/* keep this list sorted by 3rd column (level)! */
/* pro ports adv */
 { S5P, spp,   0 }, /* socks5 basic */
 { S4P, spp,   0 }, /* socks4 basic */ 
 { HCP, htc,   0 }, /* HTTP CONNECT basic */
 { HCP, p5490, 0 }, /* NONAME/1.4, http connect only */
 { HCP, hta,   1 }, /* HTTP CONNECT extended ports */
 { HOP, htc,   1 }, /* HTTP POST basic */
 { HUP, htc,   2 }, /* HTTP PUT basic */
 { WGP, wgp,   2 }, /* wingate/telnet */
 { HOP, hta,   2 }, /* HTTP POST extended ports */
 { S5P, p1813, 2 }, /* SKK proxy (socks5) */
 { S5P, spa,   3 }, /* socks5 extended */
 { S4P, spa,   3 }, /* socks4 extended */
 { FUP, fup,   3 }, /* FTP */
 { HUP, hta,   3 }, /* HTTP PUT extended ports */
 { HUP, htaa,  4 }, /* HTTP PUT really extended ports */
 { HOP, htaa,  4 }, /* HTTP POST really extended ports */
 { HCP, htaa,  4 }, /* HTTP CONNECT really extended ports */
 {0,0,0}
};
