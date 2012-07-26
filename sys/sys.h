#ifndef __SYS_H__
#define __SYS_H__

#ifdef __linux__
#include <sys/time.h>
#include "linux/thread.h"

#define sys_thread_init_global thread_init_global
#define sys_thread_init_local thread_init_local
#define sys_thread_init_wait_complete thread_init_wait_complete
#define sys_thread_id_get thread_id_get
#define sys_thread_fini_global thread_fini_global
#define sys_thread_fini_local thread_fini_local

typedef struct timeval sys_time_t;
#define sys_get_time(time) gettimeofday(time, NULL)
#define sys_time_diff(time1, time2) (time2.tv_sec - time1.tv_sec)

#else
#error "Not implement yet!"
#endif

#endif
