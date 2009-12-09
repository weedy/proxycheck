/* $Id: event.h,v 1.7 2004/05/29 14:26:24 mjt Exp $
 * Timer and I/O Event header
 * Author: Michael Tokarev <mjt@corpit.ru>
 * Licence: LGPL.
 */

#ifndef _EVENT_H
#define _EVENT_H

#include <sys/types.h>

struct ev_ct;
struct ev_tm;

typedef long long ev_time_t;

#define EV_SELECT	0x01
#define EV_POLL		0x02
#define EV_EPOLL	0x04
#define EV_KQUEUE	0x08
#define EV_DEVPOLL	0x10
#define EV_ADVANCED	(EV_EPOLL|EV_KQUEUE|EV_DEVPOLL)

int ev_init(int maxfdhint, int type);
void ev_free(void);

struct ev_ct *ev_ct_new(int maxfdhint, int type);
void ev_ct_free(struct ev_ct *ct);

const char *ev_method_name(const struct ev_ct *ct);
int ev_method(const struct ev_ct *ct);

int ev_wait(struct ev_ct *ct, int timeout);

ev_time_t ev_gettime(void);
extern ev_time_t ev_now;
extern time_t ev_time;

int ev_fdlimit(void);

/* waiting for I/O */

#define EV_IN	0x01
#define EV_PRI	0x02
#define EV_OUT	0x04

typedef void ev_io_cbck_f(void *data, int revents, int fd, struct ev_ct *ct);

int ev_io_add(struct ev_ct *ct, int fd, int events,
              ev_io_cbck_f *cb, void *data);
int ev_io_mod(struct ev_ct *ct, int fd, int events,
              ev_io_cbck_f *cb, void *data);
int ev_io_del(struct ev_ct *ct, int fd);
int ev_io_count(const struct ev_ct *ct);

/* timers */
typedef void ev_tm_cbck_f(void *data, struct ev_tm *tmr, struct ev_ct *ct);

struct ev_tm {
  struct ev_tm *evtm_prev, *evtm_next;
  ev_time_t evtm_when;
  ev_tm_cbck_f *evtm_cbck;
  void *evtm_data;
};

struct ev_tm *
ev_tm_add(struct ev_ct *ct, struct ev_tm *tmr,
          int mstimeout, ev_tm_cbck_f *cb, void *data);
struct ev_tm *
ev_ts_add(struct ev_ct *ct, struct ev_tm *tmr,
          int stimeout, ev_tm_cbck_f *cb, void *data);
int ev_tm_del(struct ev_ct *ct, struct ev_tm *tmr);
int ev_tm_count(const struct ev_ct *ct);
ev_time_t ev_tm_first(const struct ev_ct *ct);
int ev_tm_timeout(const struct ev_ct *ct);

#if 0
typedef void ev_sig_cbck_f(void *data, int sig, struct ev_ct *ct);
int ev_sig_add(struct ev_ct *ct, int sig, ev_sig_cbck_f *cbck, void *data);
int ev_sig_mod(struct ev_ct *ct, int sig, ev_sig_cbck_f *cbck, void *data);
int ev_sig_del(struct ev_ct *ct, int sig);
int ev_sig_count(const struct ev_ct *ct);
#endif

#endif /* include guard */
