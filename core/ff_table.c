#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "ff_table.h"
#define FF_TABLE_CHECK
static int32_t __ff_item_compare(void *this, void *user_data, void *table)
{
    ff_item_t *this_item, *table_item;

    this_item = (ff_item_t *)this;
    table_item = (ff_item_t *)table;

    if ((this_item->ip == table_item->ip) && (this_item->port == table_item->port)) {
        sys_get_time(&table_item->last_time);
        return 0;
    } else {
        return 1;
    }
}

hash_table_hd_t *ff_table_init(uint32_t bucket_num)
{
    hash_table_hd_t *ff_table;
    ff_table = hash_table_init(bucket_num, FF_TABLE_LOCK);
    assert(ff_table);
    return ff_table;
}

uint32_t ff_table_hash(hash_table_hd_t* hd, uint32_t ip, uint16_t port)
{
    return (ip ^ port ^ 0x13570000) & hd->bucket_num;
}

ff_item_t *ff_table_insert(hash_table_hd_t* hd, session_item_t *parent, uint32_t hash, uint32_t ip, uint16_t port, uint32_t app_type)
{
    ff_item_t *ff;

    ff = zmalloc(ff_item_t *, sizeof(ff_item_t));
    if (ff != NULL) {
        ff->ip = ip;
        ff->port = port;
        ff->parent = parent;
        ff->app_type = app_type;
    }
    if (hash_table_insert(hd, hash, ff) == 0) {
        return ff;
    } else {
        free(ff);
        return NULL;
    }
}

ff_item_t *ff_table_search(hash_table_hd_t* hd, uint32_t hash, int32_t ip, int16_t port)
{
    ff_item_t this, *ff;
    this.ip = ip;
    this.port = port;
    ff = hash_table_search(hd, hash, NULL, __ff_item_compare, &this, NULL);
    return ff;
}

int32_t ff_table_delete(hash_table_hd_t* hd, uint32_t hash, ff_item_t *ff)
{
    int32_t rv;

    assert(ff);
    rv = hash_table_remove(hd, hash, ff);
    if (rv != 0) {
        return rv;
    } else {
        /*Get the next pointer before this function*/
        free(ff);
    }
    return 0;
}

int32_t ff_table_fini(hash_table_hd_t *hd)
{
    int32_t status = 0;
#ifdef FF_TABLE_CHECK
    uint32_t i;
    ff_item_t *item;

    for (i=0; i<hd->bucket_num; i++) {
        hash_table_one_bucket_for_each(hd, i, item) {
            log_error(syslog_p, "unclean item in ff_table, hash %d, ip 0x%x, port %d\n", i,
                    item->ip, item->port);
            status = -NOT_CLEAR_ERROR;
        }
    }
#endif
    hash_table_fini(&hd);
    return status;
}

