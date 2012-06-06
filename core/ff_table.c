#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "ff_table.h"

static int32_t __ff_item_compare(void *this, void *user_data, void *table)
{
    ff_item_t *this_item, *table_item;

    this_item = (ff_item_t *)this;
    table_item = (ff_item_t *)table;

    if ((this_item->ip == table_item->ip) && (this_item->port == table_item->port)) {
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

ff_item_t *ff_table_insert(hash_table_hd_t* hd, session_item_t *parent, uint32_t hash, uint32_t ip, uint16_t port)
{
    ff_item_t *ff;

    ff = zmalloc(ff_item_t *, sizeof(ff_item_t));
    if (ff != NULL) {
        ff->ip = ip;
        ff->port = port;
        ff->parent = parent;
    }
    return ff;
}

ff_item_t *ff_table_search(hash_table_hd_t* hd, uint32_t hash, int32_t ip, int16_t port)
{
    ff_item_t this, *ff;
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
