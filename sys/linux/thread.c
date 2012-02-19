#include <pthread.h>
#include <stdio.h>
#include "common.h"
#include "thread.h"
#include "lock.h"

static pthread_key_t key;
static uint32_t core_num;
static uint32_t core_id[MAX_WORKER_THREAD];
static spinlock_t lock;

uint32_t thread_init_global()
{
    pthread_key_create(&key, NULL);
    spin_init(&lock, 0);
    return 0;
}


uint32_t thread_init_local()
{
    uint32_t my_id;
    spin_lock(&lock);
    core_id[core_num] = core_num;
    my_id = core_num;
    core_num++;
    spin_unlock(&lock);
    pthread_setspecific(key, &core_id[my_id]);
    return 0;
}
uint32_t thread_id_get()
{
    uint32_t my_id = *(uint32_t *)pthread_getspecific(key);
    return my_id;
}

uint32_t thread_fini_local()
{
    return 0;
}

uint32_t thread_fini_global()
{
    pthread_key_delete(key);
    return 0;
}





