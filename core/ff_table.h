#ifndef __FF_TABLE__
#define __FF_TABLE__
#include "common.h"
#include "hash_table.h"

typedef struct session_item session_item_t;

typedef struct ff_item {
    uint32_t ip;
    uint16_t port;
    uint16_t reserved;
	uint32_t app_type;			/**<  协议小类*/
	uint32_t reserved2;
    session_item_t *parent;
    struct ff_item *next;
} ff_item_t;

#define FF_TABLE_LOCK SPINLOCK
#define ff_table_lock(hd, hash) hash_table_lock(hd, hash, FF_TABLE_LOCK)
#define ff_table_unlock(hd, hash) hash_table_unlock(hd, hash, FF_TABLE_LOCK)

uint32_t ff_table_hash(hash_table_hd_t *hd, uint32_t ip, uint16_t port);
hash_table_hd_t *ff_table_init(uint32_t bucket_num);
ff_item_t *ff_table_search(hash_table_hd_t* hd, uint32_t hash, int32_t ip, int16_t port);
ff_item_t *ff_table_insert(hash_table_hd_t* hd, session_item_t *parent, uint32_t hash, uint32_t ip, uint16_t port);

int32_t ff_table_delete(hash_table_hd_t* hd, uint32_t hash, ff_item_t *ff);
int32_t ff_table_fini(hash_table_hd_t *hd);
#endif
