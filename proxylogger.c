/* $Id: proxylogger.c,v 1.4 2004/05/27 21:27:37 mjt Exp $
 * A trivial program (should be invoked by inetd) that
 * writes out a string "550 ESMTP_unwelcome [peer.ip.add.ress]"
 * to the network and optionally waits for a string in form
 *    [junk]protocol:ip.add.re.ss:port\n
 * from the remote system.  May be used as a destination for
 * proxycheck program.  All connections (together with the
 * information in the above form, if given) are optionally
 * logged to a specified file.
 * Options:
 *   -n - do not wait for a proxy connection info
 *   -t timeout - timeout in secs
 *   -l logfile - where to log proxy/connection info
 *   -s say - what to say
 *   -S saylast - what to say when correct proxy parameters are seen
 */

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef INADDR_NONE
# define INADDR_NONE ((in_addr_t)-1)
#endif

struct sockaddr_in peer;
struct in_addr pxyaddr;
unsigned short pxyport;
char *logfile;
char *say = "550 open proxy cheking service";
char *saylast = "550 ESMTP_unwelcome";
char buf[2048];

static struct proto {
  const char *see;
  int len;
  const char *say;
} protos[] = {
 { "hc", 2, "hc" },
 { "http", 4, "hc" },
 { "http-connect", 12, "hc" },
/* { "hg", 2, "hg" },
 { "http-get", 8, "hg" },*/
 { "ho", 2, "ho" },
 { "http-post", 9, "ho" },
 { "hu", 2, "hu" },
 { "http-put", 8, "hu" },
 { "wg", 2, "wg" },
 { "wingate", 7, "wg" },
 { "s4", 2, "s4" },
 { "socks4", 6, "s4" },
 { "s5", 2, "s5" },
 { "socks5", 6, "s5" },
 { "fu", 2, "fu" },
 { "ftp", 3, "fu" },
 { "cisco", 5, "ci" },
 { "ci", 2, "ci" },
 { NULL, 0, NULL }
};

void info(const char *proto) {
  int logfd;
  if (logfile && (logfd = open(logfile, O_CREAT|O_WRONLY|O_APPEND, 0644)) > 0) {
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    int l = sprintf(buf, "%04d-%02d-%02d %02d:%02d:%02d %s",
       tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
       tm->tm_hour, tm->tm_min, tm->tm_sec,
       inet_ntoa(peer.sin_addr));
    if (proto)
      l += sprintf(buf + l, " %s:%s:%d", proto, inet_ntoa(pxyaddr), pxyport);
    buf[l++] = '\n';
    write(logfd, buf, l);
    close(logfd);
  }
  if (proto) {
    int l = sprintf(buf, "%s [%s]\r\n", saylast, inet_ntoa(peer.sin_addr));
    write(1, buf, l);
  }
  exit(0);
}

void timedout(int sig) {
  sig = sig;
  info(NULL);
}

void findproxyinfo(char *b, char *be) {
  const struct proto *pr;
  char *p;

  *be = '\0';

  while(b < be) {
    for(pr = protos; pr->see; ++pr)
      if (*b == pr->see[0] &&
          b + pr->len < be &&
          b[pr->len] == ':' &&
	  memcmp(pr->see, b, pr->len) == 0)
        break;
    if (!pr->see) {
      ++b;
      continue;
    }
    b += pr->len + 1;
    if ((p = strchr(b, ':')) == NULL) continue;
    *p = '\0';
    pxyaddr.s_addr = inet_addr(b);
    *p++ = ':';
    if (pxyaddr.s_addr == INADDR_NONE) continue;
    b = p;
    pxyport = 0;
    while(*b >= '0' && *b <= '9' && b - p < 6)
      pxyport = pxyport * 10 + (*b++ - '0');
    if (!(*b >= 'a' && *b <= 'z') && !(*b >= 'A' && *b <= 'Z')
        && !(*b >= '0' && *b <= '9'))
      info(pr->say);
  }
}

int main(int argc, char **argv) {
  int timeout = 30;
  int nowait = 0;
  int l, r, wl;
  char *w;

  while((l = getopt(argc, argv, "t:l:s:S:n")) != EOF)
    switch(l) {
    case 't': timeout = atoi(optarg); break;
    case 'l': logfile = optarg; break;
    case 's': say = optarg; break;
    case 'S': saylast = optarg; break;
    case 'n': nowait = 1; break;
    default: return 1;
    }

  l = sizeof(peer);
  if (getpeername(0, (struct sockaddr*)&peer, &l) < 0 ||
      l != sizeof(peer) || peer.sin_family != AF_INET)
    return 1;

  signal(SIGALRM, timedout);
  signal(SIGPIPE, SIG_IGN);
  alarm(timeout);

  /* print some easily recognizeable string */
  wl = sprintf(buf, "%s [%s]\r\n", say, inet_ntoa(peer.sin_addr));
  w = (char*)malloc(wl);
  memcpy(w, buf, wl);
  write(0, w, wl);

  if (nowait || !logfile)
    info(NULL);

  /* read data from the network.
   * try to recognize:
   *  junk space proto:ipaddr:port space
   */
  l = 0;
  while((r = read(0, buf + l, sizeof(buf) - l - 1)) > 0) {
    char *e;
    char *s = buf + l - 30;
    if (s < buf) s = buf;
    r += l;
    e = buf + r;
    findproxyinfo(s, e);
    for(s = buf + l; s < e; ++s)
      if (*s == '\n')
        if (write(1, w, wl) < 0)
          info(NULL);
  }
  info(NULL);
  return 0;
}
