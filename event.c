/* $Id: event.c,v 1.17 2004/05/29 14:32:32 mjt Exp $
 * Timer and I/O Event core
 * Author: Michael Tokarev, <mjt@corpit.ru>
 * License: LGPL.
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <signal.h>

#include "event.h"

#if HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif
#if HAVE_EPOLL
# include <sys/epoll.h>
# ifdef HAVE_POLL
#  undef HAVE_POLL
# endif
# define HAVE_POLL 1
#endif
#if HAVE_DEVPOLL
# include <fcntl.h>
# include <sys/poll.h>
# include <sys/devpoll.h>
# include <sys/ioctl.h>
#endif
#if HAVE_KQUEUE
# include <sys/event.h>
#endif
#if HAVE_POLL
# include <sys/poll.h>
#endif

#define ARR_ROUND(x) ((x) < 64 ? ((x) & ~3) + 4 : ((x) & ~31) + 32)

struct ev_fd {	/* information about a filedescriptor */
  short events;		/* bitmask: events of interest */
  short revents;	/* bitmask: events ready */
#if HAVE_POLL
  int pfdi;		/* index in ct.pfd[] array */
#endif
  ev_io_cbck_f *cbck;	/* application callback routine */
  void *data;		/* application data */
  struct ev_fd *next;	/* next in ready list */
};

struct ev_method;

#if 0
struct ev_sig {
  struct ev_ct *ct;
  ev_sig_cbck_f *cbck;
  void *data;
  int raised;
  struct ev_sig *next;
};
#endif

struct ev_ct {	/* the event context */

  struct ev_tm *tmhead, *tmtail;	/* list of timers */
  int tmcnt;		/* current number of timers */
  ev_time_t tmsum;	/* sum of `when' values of all timers */

  int loop;		/* reenterancy protection */

  /* common fields */
  struct ev_fd *efd;	/* array of FD structures (dynalloc), index by fd */
  int aefd;		/* number of entries allocated in efd */

  int maxfd;		/* max FD number so far */
  int nfd;		/* total number of FDs monitored */

  const struct ev_method *method;	/* current I/O method */

  int sigpipe[2];
  int sigcnt;

  /* method-specific data */
  int qfd;		/* fd for epoll, kqueue, devpoll */

#if HAVE_POLL
  struct pollfd *pfd;	/* array of pollfd structures (dynalloc) */
  int apfd;		/* number of entries in pfd (allocated so far) */
#endif /* HAVE_POLL */

  fd_set rfdset, wfdset, xfdset;

};

#if HAVE_EPOLL	/***************************************/

#if IMPLEMENT_LINUX_EPOLL
#include <linux/unistd.h>
#ifndef __NR_epoll_create
#define __NR_epoll_create       254
#define __NR_epoll_ctl          255
#define __NR_epoll_wait         256
#endif
_syscall1(int, epoll_create, int, size)
_syscall4(int, epoll_ctl, int, epfd, int, op, int, fd,
          struct epoll_event *, event)
_syscall4(int, epoll_wait, int, epfd, struct epoll_event *, pevents,
          int, maxevents, int, timeout)
#endif

static int evio_epoll_init(struct ev_ct *ct, int maxfd) {
  int epfd = epoll_create(maxfd);
  assert(EPOLLIN == EV_IN && EPOLLOUT == EV_OUT && EPOLLPRI == EV_PRI);
  if (epfd < 0)
    return -1;
  ct->qfd = epfd;
  return 0;
}

static int evio_epoll_ctl(struct ev_ct *ct, int func, int fd, int events) {
  struct epoll_event ev;
  ev.events = events;
  ev.data.fd = fd;
  return epoll_ctl(ct->qfd, func, fd, &ev);
}

static int evio_epoll_add(struct ev_ct *ct, int fd, int events) {
  return evio_epoll_ctl(ct, EPOLL_CTL_ADD, fd, events);
}

static int evio_epoll_mod(struct ev_ct *ct, int fd, int events) {
  return evio_epoll_ctl(ct, EPOLL_CTL_MOD, fd, events);
}

static int evio_epoll_del(struct ev_ct *ct, int fd) {
  return evio_epoll_ctl(ct, EPOLL_CTL_DEL, fd, 0);
}

static int
evio_epoll_wait(struct ev_ct *ct, int timeout, struct ev_fd **efdp) {
#define EPOLL_CHUNK 200
  struct epoll_event epev[EPOLL_CHUNK];
  int ready;

  /* wait for events */
  ready = epoll_wait(ct->qfd, epev, EPOLL_CHUNK, timeout < 0 ? -1 : timeout);
  if (ready > 0) {
    /* initialize list of ready fds */
    struct epoll_event *ep = epev, *epe = epev + ready;
    do {
      struct ev_fd *efd = ct->efd + ep->data.fd;
      assert(ep->data.fd >= 0 && ep->data.fd <= ct->maxfd);
      assert(efd->cbck != NULL);
      assert(efd->next == NULL);
      assert(efd->revents == 0);
      efd->revents = ep->events;
      *efdp = efd;
      efdp = &efd->next;
    } while (++ep < epe);
  }
  *efdp = NULL;
  return ready;
}

#endif /* HAVE_EPOLL */


#if HAVE_DEVPOLL /***************************************/

static int evio_devpoll_init(struct ev_ct *ct, int maxfd) {
  int dpfd = open("/dev/poll", O_RDWR);
  if (dpfd < 0)
    return -1;
  ct->qfd = dpfd;
  maxfd = maxfd;
  return 0;
}

static int evio_devpoll_mod(struct ev_ct *ct, int fd, int events) {
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = events;
  pfd.revents = 0;
  return write(ct->qfd, &pfd, sizeof(pfd)) < 0 ? -1 : 0;
}

static int evio_devpoll_add(struct ev_ct *ct, int fd, int events) {
  assert(POLLIN == EV_IN && POLLOUT == EV_OUT && POLLPRI == EV_PRI);
  return evio_devpoll_mod(ct, fd, events);
}

static int evio_devpoll_del(struct ev_ct *ct, int fd) {
  return evio_devpoll_mod(ct, fd, POLLREMOVE);
}

static int
evio_devpoll_wait(struct ev_ct *ct, int timeout, struct ev_fd **efdp) {
#define DEVPOLL_CHUNK 100
  struct pollfd pfda[DEVPOLL_CHUNK];
  struct pollfd *pfd, *pfde;
  dvpoll_t dvp;
  int ready;

  /* wait for events */
  dvp.dp_timeout = timeout;
  dvp.dp_nfds = DEVPOLL_CHUNK;
  dvp.dp_fds = pfd = pfda;
  ready = ioctl(ct->qfd, DP_POLL, &dvp);
  if (ready > 0) {
    /* initialize list of ready fds */
    for (pfde = pfd + ready; pfd < pfde; ++pfd) {
      struct ev_fd *efd = ct->efd + pfd->fd;
      assert(pfd->fd >= 0 && pfd->fd <= ct->maxfd);
      assert(efd->cbck != NULL);
      assert(efd->revents == 0);
      efd->revents = pfd->revents;
      *efdp = efd;
      efdp = &efd->next;
    }
  }
  *efdp = NULL;
  return ready;
}

#endif /* HAVE_DEVPOLL */


#if HAVE_KQUEUE /***************************************/

static int evio_kqueue_init(struct ev_ct *ct, int maxfd) {
  int kqfd = kqueue();
  if (kqfd < 0)
    return -1;
  ct->qfd = kqfd;
  maxfd = maxfd;
  return 0;
}

static int evio_kqueue_mod(struct ev_ct *ct, int fd, int events) {
  struct kevent kev;
  struct ev_fd *efd = ct->efd + fd;
  static struct timespec zero_ts;
  if ((efd->events & EV_IN) && !(events & EV_IN)) {
    EV_SET(&kev, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    if (kevent(ct->qfd, &kev, 1, 0, 0, &zero_ts))
      return -1;
    efd->events &= ~EV_IN;
  }
  else if (!(efd->events & EV_IN) && (events & EV_IN)) {
    EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(ct->qfd, &kev, 1, 0, 0, &zero_ts) < 0)
      return -1;
    efd->events |= EV_IN;
  }
  if ((efd->events & EV_OUT) && !(events & EV_OUT)) {
    EV_SET(&kev, fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    if (kevent(ct->qfd, &kev, 1, 0, 0, &zero_ts))
      return -1;
    efd->events &= ~EV_OUT;
  }
  else if (!(efd->events & EV_OUT) && (events & EV_OUT)) {
    EV_SET(&kev, fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
    if (kevent(ct->qfd, &kev, 1, 0, 0, &zero_ts) < 0)
      return -1;
    efd->events |= EV_OUT;
  }
  return 0;
}

static int evio_kqueue_add(struct ev_ct *ct, int fd, int events) {
  return evio_kqueue_mod(ct, fd, events);
}

static int evio_kqueue_del(struct ev_ct *ct, int fd) {
  return evio_kqueue_mod(ct, fd, 0);
}

static int
evio_kqueue_wait(struct ev_ct *ct, int timeout, struct ev_fd **efdp) {
#define KQUEUE_CHUNK 200
  struct kevent keva[KQUEUE_CHUNK];
  struct kevent *kev, *keve;
  int ready;
  struct timespec ts, *tsp;

  /* wait for events */
  if (timeout < 0)
    tsp = NULL;
  else {
    ts.tv_sec = timeout / 1000;
    ts.tv_nsec = (timeout % 1000) * 1000000;
    tsp = &ts;
  }
  kev = keva;
  ready = kevent(ct->qfd, 0, 0, kev, KQUEUE_CHUNK, tsp);
  if (ready > 0) {
    /* initialize list of ready fds */
    for (keve = kev + ready; kev < keve; ++kev) {
      short ev;
      struct ev_fd *efd = ct->efd + kev->ident;
      assert(kev->ident <= (unsigned)ct->maxfd);
      assert(efd->cbck != NULL);
      if (kev->filter == EVFILT_READ) ev = EV_IN;
      else if (kev->filter == EVFILT_WRITE) ev = EV_OUT;
      else continue;
      if (!efd->revents) {
        *efdp = efd;
        efdp = &efd->next;
      }
      efd->revents |= ev;
    }
  }
  *efdp = NULL;
  return ready;
}

#endif /* HAVE_KQUEUE */


#if HAVE_POLL /***************************************/

static int evio_poll_init(struct ev_ct *ct, int maxfd) {
  struct pollfd *pfd;
  assert(POLLIN == EV_IN && POLLOUT == EV_OUT && POLLPRI == EV_PRI);
  maxfd = ARR_ROUND(maxfd);
  pfd = (struct pollfd *)calloc(maxfd, sizeof(struct pollfd));
  if (!pfd)
    return errno = ENOMEM, -1;
  ct->pfd = pfd;
  ct->apfd = maxfd;
  return 0;
}

static int evio_poll_add(struct ev_ct *ct, int fd, int events) {
  struct pollfd *pfd;
  int pfdi = ct->nfd;
  if (pfdi >= ct->apfd) {
    int apfd = ARR_ROUND(pfdi+1);
    struct pollfd *pfdp, *pfde;
    pfd = (struct pollfd *)realloc(ct->pfd, sizeof(struct pollfd) * apfd);
    if (!pfd)
      return errno = ENOMEM, -1;
    for(pfdp = pfd + pfdi, pfde = pfd + apfd; pfdp < pfde; ++pfdp)
      pfdp->fd = -1;
    ct->pfd = pfd;
    ct->apfd = apfd;
  }
  pfd = ct->pfd + pfdi;
  assert(pfd->events == 0);
  pfd->fd = fd;
  pfd->events = events;
  pfd->revents = 0;
  assert(ct->efd[fd].pfdi < 0);
  ct->efd[fd].pfdi = pfdi;
  return 0;
}

static int evio_poll_mod(struct ev_ct *ct, int fd, int events) {
  struct ev_fd *efd = ct->efd + fd;
  int pfdi = efd->pfdi;
  assert(pfdi >= 0 && pfdi <= ct->nfd);
  assert(ct->pfd[pfdi].fd == fd);
  ct->pfd[pfdi].events = events;
  return 0;
}

static int evio_poll_del(struct ev_ct *ct, int fd) {
  struct ev_fd *efd = ct->efd + fd;
  int pfdi = efd->pfdi;
  int lastfd;
  assert(pfdi >= 0 && pfdi <= ct->nfd);
  assert(ct->pfd[pfdi].fd == fd);
  ct->pfd[pfdi].fd = -1;
  efd->pfdi = -1;
  lastfd = ct->nfd - 1;
  if (lastfd != pfdi) {
    /* move last pfd to pfdi'th position */
    ct->pfd[pfdi] = ct->pfd[lastfd];
    ct->efd[ct->pfd[pfdi].fd].pfdi = pfdi;
  }
  ct->pfd[lastfd].fd = -1;
  efd->pfdi = -1;
  return 0;
}

static int evio_poll_wait(struct ev_ct *ct, int timeout, struct ev_fd **efdp)
{
  struct pollfd *pfd, *pfde;
  struct ev_fd *efd;
  int ready, cnt;

  /* wait for events */
  pfd = ct->pfd;
  ready = poll(pfd, ct->nfd, timeout);
  if (ready > 0) {

    /* initialize list of ready fds */
    for (pfde = pfd + ct->nfd, cnt = ready; pfd < pfde; ++pfd) {
      assert(pfd->fd >= 0 && pfd->fd <= ct->maxfd);
      efd = ct->efd + pfd->fd;
      assert(efd->pfdi == pfd - ct->pfd);
      assert(efd->cbck != NULL);
      if (pfd->revents) {
        efd->revents =
          (pfd->revents & POLLERR) ? EV_IN|EV_OUT|EV_PRI : pfd->revents;
        *efdp = efd;
        efdp = &efd->next;
        if (--cnt)
          break;
      }
    }
  }

  *efdp = NULL;
  return ready;
}

#endif /* HAVE_POLL */


/* SELECT is always present */ /***************************************/

static int evio_select_init(struct ev_ct *ct, int maxfd) {
  FD_ZERO(&ct->rfdset);
  FD_ZERO(&ct->wfdset);
  FD_ZERO(&ct->xfdset);
  maxfd = maxfd;
  return 0;
}

static int evio_select_add(struct ev_ct *ct, int fd, int events) {
  assert(fd < FD_SETSIZE);
  if (events & EV_IN)  FD_SET(fd, &ct->rfdset);
  if (events & EV_OUT) FD_SET(fd, &ct->wfdset);
  if (events & EV_PRI) FD_SET(fd, &ct->xfdset);
  return 0;
}

static int evio_select_mod(struct ev_ct *ct, int fd, int events) {
  if (events & EV_IN)  FD_SET(fd, &ct->rfdset);
  else FD_CLR(fd, &ct->rfdset);
  if (events & EV_OUT) FD_SET(fd, &ct->wfdset);
  else FD_CLR(fd, &ct->wfdset);
  if (events & EV_PRI) FD_SET(fd, &ct->xfdset);
  else FD_CLR(fd, &ct->xfdset);
  return 0;
}

static int evio_select_del(struct ev_ct *ct, int fd) {
  FD_CLR(fd, &ct->rfdset);
  FD_CLR(fd, &ct->wfdset);
  FD_CLR(fd, &ct->xfdset);
  return 0;
}

static int
evio_select_wait(struct ev_ct *ct, int timeout, struct ev_fd **efdp) {
  int ready, cur, fd;
  fd_set fdr = ct->rfdset;
  fd_set fdw = ct->wfdset;
  fd_set fdx = ct->xfdset;
  struct timeval tv, *tvp;

  if (timeout < 0)
    tvp = NULL;
  else {
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;
    tvp = &tv;
  }

  /* wait for events */
  ready = select(ct->maxfd + 1, &fdr, &fdw, &fdx, tvp);
  if (ready > 0) {
    /* initialize list of ready fds */
    for(fd = 0, cur = ready; fd <= ct->maxfd; ++fd) {
      int revents = 0;
      struct ev_fd *efd = ct->efd + fd;
      if (!efd->cbck) continue;
      if (FD_ISSET(fd, &fdr)) revents |= EV_IN;
      if (FD_ISSET(fd, &fdw)) revents |= EV_OUT;
      if (FD_ISSET(fd, &fdx)) revents |= EV_PRI;
      if (!revents) continue;
      assert(!efd->next);
      assert(!efd->revents);
      efd->revents = revents;
      *efdp = efd;
      efdp = &efd->next;
      if (!--cur) break;
    }
  }

  *efdp = NULL;
  return ready;
}


static struct ev_ct *ev_defct;
#define GETCTX(ct) if (!ct) ct = ev_defct

ev_time_t ev_now;
time_t ev_time;

ev_time_t ev_gettime(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  ev_time = tv.tv_sec;
  ev_now = (ev_time_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
  return ev_now;
}

int ev_fdlimit(void) {
  struct rlimit rlim;
  getrlimit(RLIMIT_NOFILE, &rlim);
  return rlim.rlim_cur;
}


struct ev_method {
  const char *name;
  int type;
  int (*init)(struct ev_ct *ct, int maxfd);
  int (*wait)(struct ev_ct *ct, int tmo, struct ev_fd **pefd);
  int (*add)(struct ev_ct *ct, int fd, int events);
  int (*mod)(struct ev_ct *ct, int fd, int events);
  int (*del)(struct ev_ct *ct, int fd);
  int maxfd;
};

static const struct ev_method methods[] = {
#define EVIO_METHOD(name,type,maxfd) \
  { #name, type, evio_##name##_init, evio_##name##_wait, \
    evio_##name##_add, evio_##name##_mod, evio_##name##_del, maxfd }

#if HAVE_EPOLL
  EVIO_METHOD(epoll,EV_EPOLL,0),
#endif
#if HAVE_DEVPOLL
  EVIO_METHOD(devpoll,EV_DEVPOLL,0),
#endif
#if HAVE_KQUEUE
  EVIO_METHOD(kqueue,EV_KQUEUE,0),
#endif
#if HAVE_POLL
  EVIO_METHOD(poll,EV_POLL,0),
#endif
  EVIO_METHOD(select,EV_SELECT,FD_SETSIZE-1)
};

struct ev_ct *ev_ct_new(int maxfdhint, int type) {
  unsigned i;
  struct ev_ct *ct;
  const struct ev_method *em;
  int maxfd;
  const char *method;

  ev_gettime();
  ct = (struct ev_ct *)calloc(1, sizeof(struct ev_ct));
  if (!ct)
    return errno = ENOMEM, (struct ev_ct*)0;
  ct->qfd = -1;
  i = 0;
  if (maxfdhint <= 0)
    maxfdhint = ev_fdlimit();
  maxfdhint = ARR_ROUND(maxfdhint);
  method = getenv("EV_METHOD");
  if (method || !type)
    type = 0xffff;
#ifdef ENOTSUP
  errno = ENOTSUP;
#else
  errno = ENOENT;
#endif
  for(;;) {
    em = &methods[i];
    if ((em->type & type) && (!method || strcmp(method, em->name) == 0)) {
      maxfd = em->maxfd && em->maxfd < maxfdhint ?
        em->maxfd : maxfdhint;
      if (em->init(ct, maxfd) == 0)
        break;
    }
    if (++i < sizeof(methods)/sizeof(methods[0]))
      continue;
    free(ct);
    return NULL;
  }

  ct->efd = (struct ev_fd *)calloc(maxfd, sizeof(struct ev_fd));
  if (!ct->efd) {
    if (ct->qfd >= 0) close(ct->qfd);
#if HAVE_POLL
    if (ct->pfd) free(ct->pfd);
#endif
    free(ct);
    errno = ENOMEM;
    return NULL;
  }
#if HAVE_POLL
  { struct ev_fd *efd, *efde;
    for(efd = ct->efd, efde = efd + maxfd; efd < efde; ++efd)
      efd->pfdi = -1;
  }
#endif
  ct->aefd = maxfd;
  ct->method = em;
  ct->maxfd = -1;
  return ct;
}

void ev_ct_free(struct ev_ct *ct) {
  GETCTX(ct);
  if (ct->qfd >= 0) close(ct->qfd);
#if HAVE_POLL
  if (ct->pfd) free(ct->pfd);
#endif
  free(ct->efd);
  free(ct);
  if (ct == ev_defct)
    ev_defct = NULL;
}

const char *ev_method_name(const struct ev_ct *ct) {
  GETCTX(ct);
  return ct->method->name;
}

int ev_method(const struct ev_ct *ct) {
  GETCTX(ct);
  return ct->method->type;
}

int ev_init(int maxfdhint, int type) {
  if (!ev_defct && !(ev_defct = ev_ct_new(maxfdhint, type)))
    return -1;
  return 0;
}

void ev_free(void) {
  if (ev_defct)
    ev_ct_free(ev_defct);
}

#define CHKFD(ct,fd,err) \
  if (fd < 0) return errno = EINVAL, err
#define GETFD(ct,fd,efd,err) \
  CHKFD(ct,fd,err); \
  if (fd > ct->maxfd) return errno = ENOENT, err; \
  efd = ct->efd + fd; \
  if (!efd->cbck) return errno = ENOENT, err

int ev_io_add(struct ev_ct *ct, int fd, int events,
              ev_io_cbck_f *cb, void *data) {
  int r;
  struct ev_fd *efd;
  GETCTX(ct);
  CHKFD(ct, fd, -1);
  if (!cb)
    return errno = EFAULT, -1;
  if (ct->method->maxfd && fd > ct->method->maxfd)
    return errno = EMFILE, -1;
  if (fd >= ct->aefd) {
    r = ARR_ROUND(fd);
    efd = (struct ev_fd *)realloc(ct->efd, sizeof(struct ev_fd) * r);
    if (!efd)
      return errno = ENOMEM, -1;
    memset(efd, 0, sizeof(struct ev_fd) * (r - ct->aefd));
#if HAVE_POLL
    { struct ev_fd *efdp, *efde;
      for(efdp = efd + ct->aefd, efde = efd + r; efdp < efde; ++efdp)
        efdp->pfdi = -1;
    }
#endif
    ct->efd = efd;
    ct->aefd = r;
  }
  efd = ct->efd + fd;
  if (efd->cbck)
    return errno = EEXIST, -1;
  r = ct->method->add(ct, fd, events);
  if (r != 0)
    return r;
  efd->cbck = cb;
  efd->data = data;
  if (ct->maxfd < fd)
    ct->maxfd = fd;
  ++ct->nfd;
  return 0;
}

/* modify parameters for existing FD */
int ev_io_mod(struct ev_ct *ct, int fd, int events,
              ev_io_cbck_f *cb, void *data) {
  int r;
  struct ev_fd *efd;
  GETCTX(ct);
  GETFD(ct, fd, efd, -1);
  if (!cb)
    return errno = EFAULT, -1;
  r = ct->method->mod(ct, fd, events);
  if (r != 0)
    return r;
  efd->cbck = cb;
  efd->data = data;
  efd->events = events;
  efd->revents = 0;
  return 0;
}

/* deregister an FD */
int ev_io_del(struct ev_ct *ct, int fd) {
  struct ev_fd *efd;
  GETCTX(ct);
  GETFD(ct, fd, efd, -1);
  ct->method->del(ct, fd);	/* ignore errors */
  efd->cbck = NULL;
  efd->data = NULL;
  efd->events = efd->revents = 0;
  if (ct->maxfd == fd) {
    do --fd;
    while(fd >= 0 && ct->efd[fd].cbck == NULL);
    ct->maxfd = fd;
  }
  --ct->nfd;
  return 0;
}

int ev_io_count(const struct ev_ct *ct) {
  GETCTX(ct);
  return ct->nfd;
}

/* create new timer to be fired at the time specified by `when',
 * and insert it into the list appropriately.
 */
static struct ev_tm *
ev_tm_new(struct ev_ct *ct, struct ev_tm *tmr,
          ev_time_t when, ev_tm_cbck_f *cbck, void *data) {
  GETCTX(ct);
  if (!cbck)
    return errno = EFAULT, (struct ev_tm*)0;
  if (tmr)
    assert(!tmr->evtm_prev && !tmr->evtm_next && !tmr->evtm_when);
  else if ((tmr = (struct ev_tm *)malloc(sizeof(struct ev_tm))) == NULL)
    return errno = ENOMEM, (struct ev_tm*)0;
  tmr->evtm_when = when;
  tmr->evtm_cbck = cbck;
  tmr->evtm_data = data;

  if (!ct->tmhead) {
    /* no other timers are registered, just create empty list */
    assert(!ct->tmtail && !ct->tmcnt && !ct->tmsum);
    ct->tmhead = ct->tmtail = tmr;
    tmr->evtm_next = tmr->evtm_prev = NULL;
  }
  else if (when >= ct->tmtail->evtm_when) {
    /* add after the tail */
    ct->tmtail->evtm_next = tmr;
    tmr->evtm_prev = ct->tmtail;
    ct->tmtail = tmr;
    tmr->evtm_next = NULL;
  }
  else if (when < ct->tmhead->evtm_when) {
    /* add before the head */
    ct->tmhead->evtm_prev = tmr;
    tmr->evtm_next = ct->tmhead;
    ct->tmhead = tmr;
    tmr->evtm_prev = NULL;
  }
  else if (ct->tmsum <= when * ct->tmcnt) {
    /* add into the middle, going from the tail */
    struct ev_tm *prev = ct->tmtail;
    while(prev->evtm_when > when) {
      assert(prev->evtm_prev && prev->evtm_when >= prev->evtm_prev->evtm_when);
      prev = prev->evtm_prev;
    }
    tmr->evtm_prev = prev;
    tmr->evtm_next = prev->evtm_next;
    prev->evtm_next->evtm_prev = tmr;
    prev->evtm_next = tmr;
  }
  else {
    /* add into the middle, going from the head */
    struct ev_tm *next = ct->tmhead;
    while(next->evtm_when <= when) {
      assert(next->evtm_next && next->evtm_when <= next->evtm_next->evtm_when);
      next = next->evtm_next;
    }
    tmr->evtm_next = next;
    tmr->evtm_prev = next->evtm_prev;
    next->evtm_prev->evtm_next = tmr;
    next->evtm_prev = tmr;
  }
  ct->tmcnt += 1;
  ct->tmsum += when;
  return tmr;
}

struct ev_tm *
ev_tm_add(struct ev_ct *ct, struct ev_tm *tmr,
          int mstimeout, ev_tm_cbck_f *cbck, void *data) {
  if (mstimeout < 0)
    return errno = EINVAL, (struct ev_tm*)0;
  else
    return ev_tm_new(ct, tmr, ev_now + mstimeout, cbck, data);
}

struct ev_tm *
ev_ts_add(struct ev_ct *ct, struct ev_tm *tmr,
          int stimeout, ev_tm_cbck_f *cbck, void *data) {
  if (stimeout < 0)
    return errno = EINVAL, (struct ev_tm*)0;
  else
    return ev_tm_new(ct, tmr, ((ev_now + 500) / 1000 + stimeout) * 1000,
                     cbck, data);
}

int ev_tm_del(struct ev_ct *ct, struct ev_tm *tmr) {
  int mstimeout;
  GETCTX(ct);
  if (!tmr->evtm_when) {
    assert(tmr->evtm_prev == NULL && tmr->evtm_next == NULL);
    return errno = ENOENT, -1;
  }
  assert(tmr->evtm_prev != NULL || ct->tmhead == tmr);
  assert(tmr->evtm_next != NULL || ct->tmtail == tmr);
  if (tmr->evtm_prev)
    tmr->evtm_prev->evtm_next = tmr->evtm_next;
  else
    ct->tmhead = tmr->evtm_next;
  if (tmr->evtm_next)
    tmr->evtm_next->evtm_prev = tmr->evtm_prev;
  else
    ct->tmtail = tmr->evtm_prev;
  ct->tmcnt -= 1;
  ct->tmsum -= tmr->evtm_when;
  mstimeout = tmr->evtm_when < ev_now ? 0 : tmr->evtm_when - ev_now;
  tmr->evtm_prev = tmr->evtm_next = NULL;
  tmr->evtm_when = 0;
  return mstimeout;
}

/* return the time when first timer will be fired */
ev_time_t ev_tm_first(const struct ev_ct *ct) {
  GETCTX(ct);
  return ct->tmhead ? ct->tmhead->evtm_when : 0;
}

/* return the time from now to the first timer to be fired
 * or -1 if no timer is set */
int ev_tm_timeout(const struct ev_ct *ct) {
  GETCTX(ct);
  if (!ct->tmhead) return -1;
  if (ct->tmhead->evtm_when > ev_now) return 0;
  return ct->tmhead->evtm_when - ev_now;
}

int ev_tm_count(const struct ev_ct *ct) {
  GETCTX(ct);
  return ct->tmcnt;
}

/* wait and dispatch any events, single */
int ev_wait(struct ev_ct *ct, int timeout) {
  struct ev_tm *tmr;
  struct ev_fd *efdl;
  int r;
  int saved_errno = 0;
  GETCTX(ct);
  if (ct->loop)
    return errno = EAGAIN, -1;
  ct->loop = 1;
  if (timeout && ct->tmhead) {
    r = ct->tmhead->evtm_when - ev_now;
    if (r < 0)
      timeout = 0;
    else if (timeout < 0 || r < timeout)
      timeout = r;
  }
  r = ct->method->wait(ct, timeout, &efdl);
  if (r < 0)
    saved_errno = errno;
  ev_gettime();
  while((tmr = ct->tmhead) != NULL && tmr->evtm_when <= ev_now) {
    if ((ct->tmhead = tmr->evtm_next) != NULL)
      tmr->evtm_next->evtm_prev = NULL;
    else
      ct->tmtail = NULL;
    ct->tmcnt -= 1;
    ct->tmsum -= tmr->evtm_when;
    tmr->evtm_prev = tmr->evtm_next = NULL;
    tmr->evtm_when = 0;
    tmr->evtm_cbck(tmr->evtm_data, tmr, ct);
  }
  while(efdl) {
    struct ev_fd *efd = efdl;
    int revents = efd->revents;
    efdl = efd->next;
    efd->revents = 0;
    efd->next = NULL;
    if (revents)
      efd->cbck(efd->data, revents, efd - ct->efd, ct);
  }
  ct->loop = 0;
  if (r < 0)
    errno = saved_errno;
  return r;
}

#if TEST

#include <stdio.h>

#define delay 3000

static void pc(struct ev_ct *ct, struct ev_tm *tmr, void *data) {
  char *t = (char*)data;
  write(1, t, 1);
  if (*t >= 'a' && *t <= 'z') *t = *t - 'a' + 'A';
  else if (*t >= 'A' && *t <= 'Z') *t = *t - 'A' + 'a';
  ev_tm_add(ct, tmr, delay, pc, data);
}

static void rt(struct ev_ct *ct, int fd, int events, void *data) {
  char buf[10];
  int l = read(fd, buf, sizeof(buf));
  if (l <= 0) {
    ev_ct_free(ct);
    exit(l < 0 ? 1 : 0);
  }
  write(1, "input: ", 7); write(1, buf, l);
  ev_io_del(0, 0);
  ev_io_add(0, 0, EV_IN, rt, 0);
}

int main() {
  static char text[] = "\rdingDONG";
  char *p;

  if (ev_init(1, 0) != 0) {
    perror("ev_init");
    return 1;
  }
  printf("evio method: %s\n", ev_method_name(0));

  for(p = text; *p; ++p)
    ev_tm_add(0, 0, delay, pc, p);

  ev_io_add(0, 0, EV_IN, rt, 0);
  while(1)
    ev_wait(0, -1);
  return 1;
}

#endif /* TEST */
