/* $Id: proxycheck.c,v 1.23 2004/05/27 21:27:37 mjt Exp $
 * open proxy checker, main program.
 * Michael Tokarev  <mjt@corpit.ru>.
 * This code may be freely used and distributed according to
 * the terms of General Public License (GPL) version 2 or later.
 */

#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include "event.h"
#include "pxy.h"

typedef struct {
  const pxyproto_t *proto;	/* proxy protocol to use */
  ipport_t port;		/* port to connect to */
} pxyprotoport_t;

typedef struct pxyhost {
  struct in_addr addr;		/* IP address of proxy */
  pxyprotoport_t *pps;		/* array of proto:ports to test */
  pxyprotoport_t *cpp;		/* next proto:port to test */
  int nopen;			/* numbef of open ports found */
  int nactive;			/* number of active connections */
  struct pxyhost *next;		/* next host to test */
} pxyhost_t;

static char *progname;
static int verbose;		/* verbosity level */
static int maxconn;		/* max number of connections */
static int maxhconn;		/* max number of connection to one host */
static int stopfound;		/* stop searching on first open port */
struct sockaddr_in baddr;	/* bind address */
static pxyhost_t *hosts;	/* host list */
static int nhosts;		/* number of hosts to check */
static pxyhost_t *chost;	/* current host */
static pxyprotoport_t *pps;	/* default array of protos:ports */
static int ntodo;		/* number of hosts and total ports */
static int nactive;		/* number of active connections */
static int nhopen, npopen;	/* number of open proxies found (hosts/ports) */
static long nread;		/* number of bytes read */
static char *dstspec;		/* destination specification */
static struct in_addr dstaddr;	/* destination address */
static ipport_t dstport;	/* destination port number */
static int printclosed;		/* print a line about closed proxies */
static int extinfo;		/* print extended info */
static int advanced;		/* use advanced protos as well */

typedef struct {
  char *name;
  void (*connh)(pxyconn_t *c, int e);
  int (*getdata)(pxyconn_t *c);
  void (*exph)(pxyconn_t *c, int e);
  int (*init)(char *arg);
  char *arg;
  char *descr;
} pxycheck_t;
extern const pxycheck_t checks[];
static const pxycheck_t *check;

static void PRINTFLIKE(2,3)
err(int errnum, const char *fmt, ...) {
  char buf[1024];
  int l = sprintf(buf, "%s: ", progname);
  va_list ap;
  va_start(ap, fmt);
  l += vsprintf(buf + l, fmt, ap);
  va_end(ap);
  if (errnum)
    l += sprintf(buf + l, ": %s\n", strerror(errno));
  else
    buf[l++] = '\n';
  write(2, buf, l);
  exit(1);
}

void PRINTFLIKE(3,4)
pxyinfo(const pxyconn_t *c, int level, const char *fmt, ...) {
  if (level <= verbose) {
    char buf[512];
    int len;
    va_list ap;
    if (c)
      len = sprintf(buf, "%s:%s:%d: ",
                    inet_ntoa(c->pxyaddr), c->proto->aname, c->pxyport);
    else
      len = 0;
    va_start(ap, fmt);
    len += vsprintf(buf + len, fmt, ap);
    va_end(ap);
    buf[len++] = '\n';
    write(2, buf, len);
  }
}

void pxyvio(pxyconn_t *c, int level, int direction,
            const char *s, int len) {
  if (level <= verbose) {
    char buf[90];
    char *bs, *bp;
    const char *e = s + len;
    char *const be = buf + sizeof(buf) - 1 - 4;
    bs = buf + sprintf(buf, "%s:%s:%d: %s ",
                       inet_ntoa(c->pxyaddr), c->proto->aname, c->pxyport,
                       direction > 0 ? ">>" : "<<");
    bp = bs;
#define flushb() \
   do { *bp++ = '\n'; write(2, buf, bp - buf); bp = bs; } while(0)
    while(s < e) {
      if (bp >= be)
        flushb();
      switch(*s) {
      case '\n': *bp++ = '\\'; *bp++ = 'n'; break;
      case '\r': *bp++ = '\\'; *bp++ = 'r'; break;
      case '\t': *bp++ = '\\'; *bp++ = 't'; break;
      case '\\': *bp++ = '\\'; *bp++ = '\\'; break;
      default:
        if (*s < ' ' || *s >= 0177)
          bp += sprintf(bp, "\\%o", (unsigned char)*s);
        else
          *bp++ = *s;
      }
      if (*s == '\n')
        flushb();
      ++s;
    }
    if (bp > bs)
      flushb();
  }
#undef flushb
}

void *emalloc(unsigned size) {
  void *ptr = malloc(size);
  if (!ptr)
    err(0, "out of memory (%d bytes)", size);
  return ptr;
}

void *erealloc(void *ptr, unsigned size) {
  ptr = realloc(ptr, size);
  if (!ptr)
    err(0, "out of memory (%d bytes)", size);
  return ptr;
}

static int
satoi(const char *s) {
  int c = 0;
  if (*s < '0' || *s > '9') return -1;
  do
    c = c * 10 + (*s++ - '0');
  while (*s >= '0' && *s <= '9');
  return *s ? -1 : c;
}

static int
hostaddr(const char *s, struct in_addr *a) {
  if (!inet_aton(s, a)) {
    struct hostent *he = gethostbyname(s);
    if (!he) return 0;
    if (he->h_addrtype != AF_INET ||
        he->h_length != 4)
      return 0;
    memcpy(&a->s_addr, he->h_addr_list[0], 4);
  }
  return 1;
}

static ipport_t
portnum(const char *s) {
  int p = satoi(s);
  return p < 1 || p > 0xffff ? 0 : (ipport_t)p;
}

static pxyhost_t *
findhost(register struct in_addr addr) {
  register pxyhost_t *h;
  for (h = hosts; h; h = h->next)
    if (h->addr.s_addr == addr.s_addr)
      return h;
  h = (pxyhost_t*) emalloc(sizeof(*h));
  memset(h, 0, sizeof(*h));
  h->addr = addr;
  h->next = hosts;
  hosts = h;
  return h;
}

static void
donehost(pxyhost_t *h) {
  pxyhost_t *hp;
  pxyinfo(NULL, 4, "%s: done, numopen=%d", inet_ntoa(h->addr), h->nopen);
  if (h->pps != pps)
    free(h->pps);
  if (h == hosts)
    hosts = h->next;
  else {
    hp = hosts;
    while(hp->next != h)
      hp = hp->next;
    hp->next = h->next;
  }
  hp = h->next;
  if (chost == h)
    chost = hp ? hp : hosts;
  free(h);
  --nhosts;
}

static void PRINTFLIKE(1,2)
usage(const char *fmt, ...) {
  char buf[256];
  int l = sprintf(buf, "%s: ", progname);
  va_list ap;
  va_start(ap, fmt);
  l += vsprintf(buf + l, fmt, ap);
  va_end(ap);
  l += sprintf(buf + l, "\n%s: `%s -h' for help\n", progname, progname);
  write(2, buf, l);
  exit(1);
}

/* parse list of proto/ports */

static pxyprotoport_t *
addprotoport(pxyprotoport_t *pp, ipport_t port, const pxyproto_t *proto) {
  pxyprotoport_t *p;
  if (!pp) {
    pp = (pxyprotoport_t*)emalloc(sizeof(*pp) * 5);
    p = pp;
  }
  else {
    int n;
    for (n = 0; pp[n].port; ++n)
      if (pp[n].port == port && pp[n].proto == proto)
        return pp;
    if (!(n & 3))
      pp = (pxyprotoport_t*)erealloc(pp, sizeof(*pp) * (n + 5));
    p = pp + n;
  }
  p->port = port;
  p->proto = proto;
  p[1].port = 0;
  p[1].proto = NULL;
  return pp;
}

static pxyprotoport_t *
parseprotoport(pxyprotoport_t *pp, char *s) {
  char *p;
  const pxyprobe_t *probe;
  const ipport_t *portp;
  ipport_t port;
  int n, found;
  static const char *delims = ",|/; \t";
  if ((p = strchr(s, ':')) != NULL) {
    const pxyproto_t *proto;
    *p = '\0';
    proto = pxyprotos;
    while(strcmp(proto->name, s) != 0 && strcmp(proto->aname, s) != 0)
      if (!(++proto)->name)
        usage("invalid protocol `%s'", s);
    *p++ = ':';
    found = 0;
    while(*p) {
      if (strchr(delims, *p)) { ++p; continue; }
      s = p;
      n = 0;
      while(*p >= '0' && *p <= '9' && p < s + 5)
        n = n * 10 + (*p++ - '0');
      if (!n || n > 0xffff)
        usage("invalid port specification near `%s'", s);
      ++found;
      pp = addprotoport(pp, n, proto);
    }
    if (!found) {
      probe = pxyprobes;
      while(probe->proto) {
        if (probe->proto == proto) {
          for(portp = probe->ports; *portp; ++portp)
            pp = addprotoport(pp, *portp, proto);
          if (probe->advanced >= advanced)
            break;
        }
        ++probe;
      }
    }
  }
  else { /* no protocol specified */
    p = s;
    while(*p) {
      if (strchr(delims, *p)) { ++p; continue; }
      s = p;
      n = 0;
      while(*p >= '0' && *p <= '9' && p < s + 5)
        n = n * 10 + (*p++ - '0');
      if (!n || n > 0xffff)
        usage("invalid port specification near `%s'", s);
      port = n;
      found = 0;
      probe = pxyprobes;
      while(probe->proto && (!found || probe->advanced <= advanced)) {
        for(portp = probe->ports; *portp; ++portp)
          if (*portp == port) {
            pp = addprotoport(pp, port, probe->proto);
            found = 1;
            break;
          }
        ++probe;
      }
      if (!found)
        for (probe = pxyprobes; probe->proto; ++probe)
          if (probe->advanced <= advanced)
            pp = addprotoport(pp, port, probe->proto);
    }
  }
  return pp;
}

static int
numprotoports(const pxyprotoport_t *pp) {
  const pxyprotoport_t *ppp = pp;
  while(ppp->port) ++ppp;
  return ppp - pp;
}

static void addent(char *p) {
  char *n = p;
  struct in_addr addr;
  pxyhost_t *h;
  if ((p = strchr(n, ':'))) *p = '\0';
  if (!hostaddr(n, &addr))
    usage("invalid IP address `%s'", n);
  h = findhost(addr);
  if (p) {
    *p++ = ':';
    if (*p)
      h->pps = parseprotoport(h->pps, p);
    else
      h->nopen = 1; /* remember to add std pps */
  }
  else
    h->nopen = 1; /* remember to add std pps */
}

static void
init(int argc, char **argv) {
  int c;
  int timeout = 0;
  pxyhost_t *h;
  const pxyproto_t *proto;
  const pxyprobe_t *probe;
  const ipport_t *portp;
  pxyprotoport_t *pp;
  char *p;
  int npps;
  const char *readin = NULL;
  int add_defaults = 0;
  char *check_arg = NULL;

  if ((progname = strrchr(argv[0], '/')) != NULL)
    argv[0] = ++progname;
  else
    progname = argv[0];

  while((c = getopt(argc, argv, "vd:c:p:Db:t:m:M:i:nasxh")) != EOF)

    switch(c) {

    case 'v':
      ++verbose;
      break;

    case 'p':
      pps = parseprotoport(pps, optarg);
      break;

    case 'd':
      dstspec = optarg;
      break;

    case 'D':
      ++add_defaults;
      break;

    case 'c':
      if ((p = strchr(optarg, ':')) != NULL)
        *p = '\0';
      for(check = checks; ; ++check)
        if (!check->name)
          usage("unknown check `%s'", optarg);
        else if (strcmp(optarg, check->name) == 0)
          break;
      if (p)
        check_arg = p + 1, *p = ':';
      else
        check_arg = NULL;
      break;

    case 'b':
      if (!hostaddr(optarg, &baddr.sin_addr))
        usage("unknown host `%s'", optarg);
      baddr.sin_family = AF_INET;
      break;

    case 't':
      if ((timeout = satoi(optarg)) < 1 || timeout > 1000)
        usage("invalid timeout `%s'", optarg);
      break;

    case 'm':
      if ((maxconn = satoi(optarg)) < 1)
        usage("invalid maximum number of connections `%s'", optarg);
      break;

    case 'M':
      if ((maxhconn = satoi(optarg)) < 0)
        usage("invalid maximum number of connections to one host `%s'",
              optarg);
      break;

    case 'i':
      readin = optarg;
      break;

    case 'n':
      printclosed = 1;
      break;

    case 'a':
      ++advanced;
      break;

    case 's':
      ++stopfound;
      break;

    case 'x':
      extinfo = 1;
      break;

    case 'h':
      printf(
"%s: Open proxy checker version " VERSION_STR "\n"
"Usage is: `%s options host[:proto_port_spec]...'\n"
"where options are:\n"
" -h - print this help and exit\n"
" -d dsthost:dstport - destination to connect to (required)\n"
" -c check[:params] - method to check proxy (required, see below)\n"
" -p proto_port_spec - proxy port/protocol specification\n"
"   (may be used more than once) - see below\n"
" -D - do not reset default portlist in case -p option specified\n"
" -a - use \"advanced\" protocols too (more -a's means more advanced)\n"
" -t timeout - general timeout in secounds, default %d\n"
" -m maxconn - maximum number of parallel connections\n"
" -M maxhconn - maximum number of parallel connections to one host\n"
" -s - stop probing a host after first found open proxy\n"
" -b bindaddr - bind to specified address\n"
" -x - print extended info (proxy software etc) if known\n"
" -n - also print a line about definitely closed proxies\n"
"\n"
"proto_port_spec is in the form [proto:][port,port,...].\n"
"If portlist is omitted, default ports for given protocols\n"
"will be tried; if proto is omitted, either all protocols will\n"
"be tried (if port is not known), or the protocols which are\n"
"assotiated with this port.\n"
"\n"
"The following protocols are recognized:\n"
, progname, progname, pxytimeout / 1000);
      for(proto = pxyprotos; proto->name; ++proto)
        printf(" %s (%s, %s, %s)\n",
               proto->aname, proto->name, proto->transport, proto->fullname);
      printf("\nThe following probes are made (level cf. -a):\n");
      for(probe = pxyprobes; probe->proto; ++probe) {
        printf(" %s (level %d): ", probe->proto->aname, probe->advanced);
        for(portp = probe->ports;; ) {
          printf("%d", *portp++);
          putchar(*portp ? ',' : '\n');
          if (!*portp) break;
        }
      }
      printf("\nThe following checks are available:\n");
      for(check = checks; check->name; ++check)
        printf(" %s%s - %s", check->name,
               check->arg ? check->arg : "",
               check->descr);
      exit(0);

    default:
      err(0, "`%s -h' for help", progname);
    }

  argc -= optind; argv += optind;
  if (!*argv && !readin)
    usage("no host(s) to check specified");

  if (!check)
    usage("no action (-c) specified");

  while(*argv)
    addent(*argv++);
  if (readin) {
    FILE *f;
    char buf[8192];
    if (readin[0] == '-' && readin[1] == '\0')
      f = stdin;
    else if ((f = fopen(readin, "r")) == NULL)
      err(errno, "unable to open %s", readin);
    while(fgets(buf, sizeof(buf), f)) {
      char *p = buf;
      char *e;
      while(*p == ' ' || *p == '\t')
       ++p;
      if (*p == '#' || *p == '\n' || !*p)
        continue;
      if ((e = strchr(p, '\n')) != NULL)
        *e = '\0';
      addent(p);
    }
    if (f != stdin)
      fclose(f);
  }

  if (getuid() == 0 || geteuid() == 0)
    pxyinfo(NULL, 0, "warning: do not run this program as root");

  check->init(check_arg);

  if (!dstspec) /* dstspec may be set in check->init() */
    usage("no destination (-d) specified");

  if (!(p = strchr(dstspec, ':')))
    usage("destination port missing in `%s'", dstspec);
  *p = '\0';
  if (!hostaddr(dstspec, &dstaddr))
    usage("unknown destination host `%s'", dstspec);
  if (!(dstport = portnum(p+1)))
    usage("invalid destination port `%s'", p+1);
  *p = ':';


  if (!pps || add_defaults) { /* no explicit ports given, pick up defaults */
    for (probe = pxyprobes; probe->proto; ++probe)
      if (probe->advanced <= advanced)
        for (portp = probe->ports; *portp; ++portp)
          pps = addprotoport(pps, *portp, probe->proto);
  }
  npps = numprotoports(pps);

  for (h = hosts; h; h = h->next) {
    ++nhosts;
    if (!h->pps)
      h->pps = pps, ntodo += npps;
    else {
      if (h->nopen) {
        for (pp = pps; pp->port; ++pp)
          h->pps = addprotoport(h->pps, pp->port, pp->proto);
      }
      ntodo += numprotoports(h->pps);
    }
    h->nopen = 0;
    h->cpp = h->pps;
#if 0
    if (verbose) {
      pxyprotoport_t *pp;
      printf("%s:", inet_ntoa(h->addr));
      for(pp = h->pps; pp->port; ++pp)
        printf(" %s:%d", pp->proto->name, pp->port);
      putchar('\n');
    }
#endif
  }
  pxyinfo(NULL, 1,
          "To check: hosts=%d, proto:ports=%d, host:proto:ports=%d",
          nhosts, npps, ntodo);

  if (timeout)
    pxytimeout = timeout * 1000;
  chost = hosts;

  signal(SIGPIPE, SIG_IGN);
}

static int
nextconn(void) {
  pxyconn_t *c;
  pxyprotoport_t *pp;
  pxyhost_t *h;
  int fd;
  struct sockaddr_in sin;

  if (!ntodo)
    return 0;

  if (maxconn && nactive >= maxconn)
    return 0;

  /* find next host to connect to */
  h = chost; fd = 0;
  do {
    if (h->cpp->port && (!maxhconn || h->nactive < maxhconn)) {
      fd = 1;
      break;
    }
    if (!(h = h->next))
      h = hosts;
  } while (h != chost);
  if (!fd)
    return 0;

  fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) {
    if (errno != EMFILE)
      err(errno, "unable to create socket");
    if (!maxconn || maxconn > nactive) {
      pxyinfo(NULL, 1, "limiting max number of connections to %d",
              nactive);
      maxconn = nactive;
    }
    return 0;
  }

  pp = h->cpp++;
  if (!(chost = h->next))	/* move to next host to distribute load */
    chost = hosts;
  --ntodo;

  if (baddr.sin_addr.s_addr &&
      bind(fd, (struct sockaddr*)&baddr, sizeof(baddr)) < 0)
    err(errno, "unable to bind to %s", inet_ntoa(baddr.sin_addr));
  if (fcntl(fd, F_SETFL, O_NONBLOCK|O_RDWR) < 0)
    /*fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)*/
    err(errno, "unable to set socket flags");

  c = pxynew();
  if (!c)
    abort();

  c->pxyaddr = h->addr;
  c->pxyport = pp->port;
  c->proto = pp->proto;
  c->dstaddr = dstaddr;
  c->dstport = dstport;
  c->data = h;

  ++h->nactive; ++nactive;

  /* from now on, we should expect to be called recursively:
   * do not touch chost and pp anymore */

  if (!pxystart(c, fd))
    err(errno, "unable to enqueue testing request");

  sin.sin_family = AF_INET;
  sin.sin_addr = h->addr;
  sin.sin_port = htons(pp->port);
  if (connect(fd, (struct sockaddr*)&sin, sizeof(sin)) != 0 &&
      errno != EINPROGRESS)
    pxyaction(c, -1);

  return 1;
}

static void
freeconn(pxyconn_t *c) {
  int fd = c->fd;
  pxyhost_t *h = (pxyhost_t *)c->data;
  nread += c->nread;
  --h->nactive;
  --nactive;
  pxyinfo(c, 5, "done, nactive=%d ntodo=%d", nactive, ntodo);
  pxyfree(c);
  close(fd);
  if (stopfound && h->nopen && h->cpp->port) {
    /*XXX abort active connections: need a list of
     * all connections for this host, and a state of
     * each: in case of e.g. dsbl, connection may be
     * in final stage and it isn't a good idea to simple
     * abort connection in this case.
     * Here, we just will not do any more *new* connections.
     */
    int skip = 0;
    do {
      ++h->cpp;
      ++skip;
    } while(h->cpp->port);
    ntodo -= skip;
    pxyinfo(NULL, 3, "%s: skipping %d other probes for this host (%d active)",
            inet_ntoa(h->addr), skip, h->nactive);
  }
  if (!h->nactive && !h->cpp->port)
    donehost(h);
  while(nextconn())
    ;
}

static void
isopen(pxyconn_t *c, int is_open, const char *info) {
  pxyhost_t *h = (pxyhost_t *)c->data;
  if (is_open || printclosed) {
    char buf[8192]; /* do not use pxybuf due to info pointing to it */
    int l = sprintf(buf, "%s %s:%d ",
                    inet_ntoa(c->pxyaddr), c->proto->aname, c->pxyport);
    if (is_open) {
      l += sprintf(buf + l, "open");
      if (info)
        l += sprintf(buf + l, " %s", info);
    }
    else
      l += sprintf(buf + l, "closed");
    if (extinfo && c->detail)
      l += sprintf(buf + l, " [%s]", c->detail);
    buf[l++] = '\n';
    write(1, buf, l);
  }
  if (is_open) {
    if (!(h->nopen++))
      ++nhopen;
    ++npopen;
  }
  freeconn(c);
}

void pxyaction(pxyconn_t *c, int result) {
  if (!result) {
    if (pxyreqiot(c, EV_IN, check->connh, 0, NULL))
      check->connh(c, EV_IN);
  }
  else {
    if (result < 0)
      pxyinfo(c, c->pxystate ? 3 : 4, c->pxystate ? "%s" : "connect: %s",
              errno ? strerror(errno) : "EOF");
    else if (result > 1) {
      isopen(c, 0, NULL);
      return;
    }
    /*else
      pxyinfo(c, 3, "seems not to be open");*/
    freeconn(c);
  }
}

void pxycheckdata(pxyconn_t *c) {
  if (pxyreqio(c, EV_IN, check->exph))
    check->exph(c, EV_IN);
}

int pxygetdata(pxyconn_t *c) {
  return check->getdata(c);
}
int main(int argc, char **argv) {
  time_t start;

  init(argc, argv);
  if (ev_init(0, EV_ADVANCED|EV_SELECT) != 0)
    err(errno, "ev_init");

  start = time(NULL);

  while(nextconn())
    ;

  while(nactive)
    if (ev_wait(0, -1) < 0 && errno != EINTR)
      err(errno, "ev_wait");

  pxyinfo(NULL, 1, "NumOpen=%d(%d) NRead=%ld Time=%d",
          nhopen, npopen, nread, (int)(time(NULL) - start));

  return nhopen ? 100 : 0;
}

static char *findip(pxyconn_t *c, char *buf) {
 /* look at possible IP address in a form [ip.add.re.ss] */
  unsigned o1,o2,o3,o4;
  int l;
  while(*buf >= ' ' && *buf != '[') ++buf;
  if (*buf == '[' &&
      sscanf(++buf, "%3u.%3u.%3u.%3u%n]", &o1,&o2,&o3,&o4, &l) == 4 &&
      o1 && o1 < 256 && o2 < 256 && o3 < 256 && o4 < 256 &&
      ((o1<<24)|(o2<<16)|(o3<<8)|o4) != ntohl(c->pxyaddr.s_addr)) {
    buf[l] = '\0';
    return buf;
  }
  return NULL;
}

static char *sendstr;		/* send this string... */
static char *expstr;		/* and expect this */
static unsigned explen;		/* length of expstr */

static int expectd(pxyconn_t *c) {
  return sendstr ?
    sprintf(pxybuf, "%s\r\n", sendstr) :
    sprintf(pxybuf, "%s:%s:%d\r\n",
            c->proto->aname, inet_ntoa(c->pxyaddr), c->pxyport);
}

static void
expectw(pxyconn_t *c, int UNUSED e) {
  int l;
  char *p;
  if (pxyreadnext(c, 1, &l, 3) <= 0)
    ;
  else if (c->proto->check && c->proto->check(c, pxybuf, l)) return;
  else if ((p = (char*)memmem(pxybuf, l, expstr, explen)) != NULL)
    /* look at possible IP address after the expect string */
    isopen(c, 1, findip(c, p + explen));
  else /* if (!c->proto->check || !c->proto->check(c, pxybuf, l)) */
    pxysave(c, pxybuf, l, explen);
}

static void
expecth(pxyconn_t *c, int UNUSED e) {
  if (pxywrite(c, pxybuf, expectd(c), 3))
    pxyreqio(c, EV_IN, expectw);
}

static int expecti(char *arg) {
  char *p = strchr(arg, ':');
  if (!p || !p[1])
    usage("send:expect strings expected");
  if (p != arg) {
    sendstr = arg;
    *p++ = '\0';
    arg = p;
  }
  else
    ++arg;
  if (!(expstr = arg) || !(explen = strlen(arg)))
    usage("specify a string to expect");
  else if (explen >= sizeof(((pxybuf_t*)0)->buf))
    usage("expect string is too long");
  return 0;
}

#define DSBL_COOKIE_PORT 200
#define DSBL_COOKIE_LEN 32
static char dsblcookie[DSBL_COOKIE_LEN+1];
static char *dsbluser, *dsblpass, *dsblrcpt, *dsblfrom;

static int dsblmsg(char *buf, pxyconn_t *c) {
  char pxyaddr[sizeof("255.255.255.255")];
  int l;
  strcpy(pxyaddr, inet_ntoa(c->pxyaddr));
  l = sprintf(buf,
"Message-ID: <%s@%s>\r\n"
"To: <%s>\r\n"
"Subject: Open %s Proxy test message\r\n"
"\r\n"
"DSBL LISTME: %s [%s]:%d\r\n"
"%s\r\n"
"Connect to %s:%d\r\n",
              dsblcookie, dsblfrom, /* Message-ID */
              dsblrcpt, /* To: */
              c->proto->fullname, /* Subj */
              c->proto->name, pxyaddr, c->pxyport, /* dsbl listme */
              dsblcookie, /* dsbl cookie */
              inet_ntoa(c->dstaddr), c->dstport);
  if (c->detail)
    l += sprintf(buf + l, "Proxy info: %s\r\n", c->detail);
  l += sprintf(buf + l, "DSBL END\r\n\r\n.\r\n");
  return l;
}

static int dsbld(pxyconn_t *c) {
  int l = sprintf(pxybuf,
"HELO [%s]\r\n"
"MAIL FROM:<%s>\r\n"
"RCPT TO:<%s>\r\n"
"DATA\r\n",
              inet_ntoa(c->pxyaddr),
              dsblfrom,
              dsblrcpt);
  l += dsblmsg(pxybuf + l, c);
  l += sprintf(pxybuf + l, "QUIT\r\n");
  return l;
}

static void
dsblo(pxyconn_t *c, char *line) {
  isopen(c, 1, memcmp(line, "250 listed [", 12) ? NULL : findip(c, line + 11));
}

static void
dsble(pxyconn_t *c, int UNUSED e) {
  int l;
  char *s;
  /* state:
   * 0 - connected, 2xx helo
   * 1 - 2xx mail from
   * 2 - 2xx rcpt to
   * 3 - 3xx data
   * 4 - 2xx ok
   */
  if (pxyreadnext(c, 1, &l, 3) <= 0) return;
  if (c->proto->check && c->proto->check(c, pxybuf, l)) return;
  s = pxybuf;
  for(;;) {
    char *n = (char*)memmem(s, l, c->appstate == 3 ? "\r\n3" : "\r\n2", 3);
    if (!n) break;
    n += 2;
    l -= n - s;
    s = n;
    if (c->appstate++ == 4) {
      dsblo(c, n);
      return;
    }
  }
  pxysave(c, s, l, 0);
}

static void
dsblh(pxyconn_t *c, int UNUSED e) {
  /* state:
   * 0 - connected, send helo
   * 1 - wait for initial 2xx reply, send MAIL FROM
   * 2 - wait for 2xx to MAIL FROM, send RCPT TO
   * 3 - wait for 2xx to RCPT TO, send DATA
   * 4 - wait for 3xx to DATA, send message
   * 5 - wait for final 2xx reply
   */
  int l;
  char *p;

  switch(c->appstate) {
  case 0: /* connected, send helo */
    if (pxyprintf(c, 3, "HELO [%s]\r\n", inet_ntoa(c->pxyaddr)))
      c->appstate = 1;
    break;

  case 1: /* wait reply to HELO, send MAIL FROM */
  case 2: /* wait reply to MAIL, send RCPT TO */
  case 3: /* wait reply to RCPT, send DATA */
    if (pxyreadnext(c, 1, &l, 3) <= 0)
      ;
    else if ((p = (char*)memmem(pxybuf, l, "\r\n2", 3)) /*&& p[5] == ' '*/) {
      l = c->appstate == 1 ? sprintf(pxybuf, "MAIL FROM:<%s>\r\n", dsblfrom) :
          c->appstate == 2 ? sprintf(pxybuf, "RCPT TO:<%s>\r\n", dsblrcpt) :
          sprintf(pxybuf, "DATA\r\n");
      if (pxysave(c, pxybuf, l, 10) &&
          pxywrite(c, pxybuf, l, 3) &&
          pxyrenew(c, pxytimeout/2, NULL))
        c->appstate += 1;
    }
    else if (c->appstate != 1 ||
             !c->proto->check || !c->proto->check(c, pxybuf, l))
      pxysave(c, pxybuf, l, 10);
    break;

  case 4: /* wait reply to DATA, send message */
    if (pxyreadnext(c, 1, &l, 3) <= 0)
      ;
    else if ((p = (char*)memmem(pxybuf, l, "\r\n3", 3)) /*&& p[3] == ' '*/) {
      if (verbose < 6) pxyinfo(c, 2, "sending message");
      if (pxywrite(c, pxybuf, dsblmsg(pxybuf, c), 6) &&
          pxywrite(c, "QUIT\r\n", 6, 3) &&
          pxysave(c, NULL, 0, 0) && pxyrenew(c, 0, NULL))
        c->appstate = 5;
    }
    else
      pxysave(c, pxybuf, l, 10);
    break;

  default: /* wait final data ack */
    if (pxyreadnext(c, 1, &l, 3) <= 0)
      ;
    else if (pxybuf[0] == '2' && pxybuf[3] == ' ')
      dsblo(c, pxybuf);
    else
      pxysave(c, pxybuf, l, 10);
  }
}

static char *egetenv(const char *name, char *def) {
  char *v = getenv(name);
  return v ? v : def;
}

static void dsbl_cookie_alarm(int UNUSED sig) {
  err(0, "unable to obtain cookie: timeout");
}

static int
dsbli(char *arg) {
  if (!dstspec)
    dstspec = (arg && *arg) ? arg : egetenv("DSBL_SMTP", "mx.listme.dsbl.org");
  if (!strchr(dstspec, ':')) {
    sprintf(pxybuf, "%s:25", dstspec);
    dstspec = strdup(pxybuf);
  }

  dsbluser = egetenv("DSBL_USER", "anonimous");
  dsblpass = egetenv("DSBL_PASS", "");
  dsblfrom = egetenv("DSBL_FROM", dsbluser);
  dsblrcpt = egetenv("DSBL_RCPT", "listme@listme.dsbl.org");
  if (!(arg = getenv("DSBL_COOKIE"))) {
    char *chost = egetenv("DSBL_COOKIE_HOST", "cookie.dsbl.org");
    struct sockaddr_in sin;
    int fd;
    int l;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(DSBL_COOKIE_PORT);
    if (!hostaddr(chost, &sin.sin_addr))
      err(0, "unknown DSBL cookie host %s", chost);
    signal(SIGALRM, dsbl_cookie_alarm);
    alarm(3*60);
    if ((fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0 ||
        connect(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0)
      err(errno, "unable to connect to cookie server");
    l = sprintf(pxybuf, "%s\n%s\n", dsbluser, dsblpass);
    if (send(fd, pxybuf, l, 0) < 0 ||
        recv(fd, dsblcookie, DSBL_COOKIE_LEN, 0) != DSBL_COOKIE_LEN)
      err(errno, "unable to obtain cookie");
    alarm(0);
    close(fd);
    dsblcookie[DSBL_COOKIE_LEN] = 0;
  }
  else if (strlen(arg) != DSBL_COOKIE_LEN)
    usage("invalid dsbl cookie `%s'", arg);
  else
    strcpy(dsblcookie, arg);
  pxyinfo(NULL, 4, "dsbl cookie: %s", dsblcookie);
  return 0;
}

const pxycheck_t checks[] = {
  { "chat", expecth, expectd, expectw, expecti, ":sendstr:expectstr",
    "perform a little chat: send `sendstr'\n"
    "   to the remote system  and assume proxy is open is `expectstr'\n"
    "   is returned.  `sendstr' defaults to proto:ip:port\n"
  },
  { "dsbl", dsblh, dsbld, dsble, dsbli, "[:smtpserver[:port]]",
    "attempt to submit proxy to DSBL-like system\n"
    "   DSBL settings are expected to be in environment:\n"
    "\t$DSBL_USER - username (anonimous)\n"
    "\t$DSBL_PASS - password (default is empty)\n"
    "\t$DSBL_COOKIE_HOST - cookie server (cookie.dsbl.org)\n"
    "\t$DSBL_COOKIE - already obtained DSBL cookie\n"
    "\t$DSBL_RCPT - recipient (listme@listme.dsbl.org)\n"
    "\t$DSBL_FROM - sender address (nobody)\n"
    "\t$DSBL_SMTP - smtp server if -d not given (mx.listme.dsbl.org)\n"
  },
  {0,0,0,0,0,0,0}
};
